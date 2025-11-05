#!/usr/bin/env python3

import socket
import subprocess
import requests
import concurrent.futures
import time
from datetime import datetime, timezone, timedelta
import re
import os
import ast
import logging
import shutil

# ===== 日志与参数配置 =====
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

def _is_valid_ipv4(addr: str) -> bool:
    return bool(re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", addr)) and all(0 <= int(x) <= 255 for x in addr.split("."))

def parse_dual_stack(env_val: str | None) -> bool | str:
    val = (env_val or "True").strip().upper()
    if val in {"TRUE", "IPV4", "IPV6"}:
        return True if val == "TRUE" else ("IPv4" if val == "IPV4" else "IPv6")
    logging.warning("DUAL_STACK 非法值(%s), 使用默认 True", env_val)
    return True

def parse_max_ips(env_val: str | None) -> int:
    try:
        n = int(env_val) if env_val is not None else 1
    except Exception:
        logging.warning("MAX_IPS 非法值(%s), 使用默认 1", env_val)
        return 1
    if n < 1 or n > 3:
        logging.warning("MAX_IPS 超出范围(%s), 取边界 1..3", n)
        n = max(1, min(3, n))
    return n

def parse_user_dns_map(env_val: str | None) -> dict[str, str]:
    """
    解析用户自定义 DNS 列表为 name->ip 的映射。

    支持两种输入格式（中文示例见下方环境变量说明）：
    1) 逗号分隔："223.5.5.5,Ali:223.5.5.5"
    2) Python 列表字符串：["223.5.5.5","Ali:223.5.5.5"]

    规则：
    - 仅 IP：使用 ip 作为 name 与 ip（如 {"223.5.5.5":"223.5.5.5"}）
    - 别名:IP：使用别名作为 name（如 {"Ali":"223.5.5.5"}）
    - 非法 IP 将被过滤
    """
    if not env_val:
        return {}
    raw = env_val.strip()
    try:
        if raw.startswith("[") and raw.endswith("]"):
            arr = ast.literal_eval(raw)
            if not isinstance(arr, list):
                raise ValueError("USER_DNS_SERVERS 需为列表或逗号分隔字符串")
        else:
            arr = [x.strip() for x in raw.split(",") if x.strip()]

        result: dict[str, str] = {}
        for item in arr:
            if not isinstance(item, str):
                continue
            if ":" in item:
                name, ip = item.split(":", 1)
                name, ip = name.strip(), ip.strip()
                if name and _is_valid_ipv4(ip):
                    result[name] = ip
            else:
                ip = item.strip()
                if _is_valid_ipv4(ip):
                    result[ip] = ip

        if not result and arr:
            logging.warning("USER_DNS_SERVERS 解析后无有效 IP（已全部过滤）")
        return result
    except Exception as e:
        logging.warning("USER_DNS_SERVERS 解析失败(%s), 使用默认", e)
        return {}

def check_dependencies() -> None:
    missing = []
    if shutil.which("dig") is None:
        missing.append("dig (dnsutils)")
    if shutil.which("ping") is None:
        missing.append("ping (iputils-ping)")
    # ping6 可选, 现代发行版常由 ping 统一
    if missing:
        logging.warning("缺少外部依赖: %s", ", ".join(missing))

MAX_IPS = parse_max_ips(os.getenv("MAX_IPS"))  # 每种协议最多保留 IP 数
TIMEOUT_REQUEST = 2.0
TIMEOUT_TCP = 2.0
PING_TIMEOUT = 1
RETRY = 3
THREADS = 8

# DUAL_STACK: True/IPv4/IPv6
DUAL_STACK = parse_dual_stack(os.getenv("DUAL_STACK"))

# 用户自定义 DNS 来源优先级：环境变量 > 默认内置
USER_DNS_MAP = parse_user_dns_map(os.getenv("USER_DNS_SERVERS"))

# ===== 默认 DNS 服务器 =====
DEFAULT_DNS_SERVERS = {
    "AliDNS": "223.5.5.5",
    "TencentDNS": "119.29.29.29",
    "BaiduDNS": "180.76.76.76",
    "DNS114": "114.114.114.114"
}

DNS_SERVERS = USER_DNS_MAP if USER_DNS_MAP else DEFAULT_DNS_SERVERS.copy()

# ===== 域名分组 =====
DOMAIN_GROUPS = {
    "==== GitHub ====": [
        "github.githubassets.com",
        "central.github.com",
        "desktop.githubusercontent.com",
        "camo.githubusercontent.com",
        "github.map.fastly.net",
        "github.global.ssl.fastly.net",
        "gist.github.com",
        "github.io",
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "user-images.githubusercontent.com",
        "favicons.githubusercontent.com",
        "avatars5.githubusercontent.com",
        "avatars4.githubusercontent.com",
        "avatars3.githubusercontent.com",
        "avatars2.githubusercontent.com",
        "avatars1.githubusercontent.com",
        "avatars0.githubusercontent.com",
        "avatars.githubusercontent.com",
        "codeload.github.com",
        "github-cloud.s3.amazonaws.com",
        "github-com.s3.amazonaws.com",
        "github-production-release-asset-2e65be.s3.amazonaws.com",
        "github-production-user-asset-6210df.s3.amazonaws.com",
        "github-production-repository-file-5c1aeb.s3.amazonaws.com",
        "githubstatus.com",
        "github.community",
        "media.githubusercontent.com",
        "objects.githubusercontent.com",
        "raw.github.com",
        "copilot-proxy.githubusercontent.com"
    ],
    "==== TMDB ====": [
        "themoviedb.org",
        "www.themoviedb.org",
        "api.themoviedb.org",
        "tmdb.org",
        "api.tmdb.org",
        "image.tmdb.org"
    ],
    "==== OpenSubtitles ====": [
        "opensubtitles.org",
        "www.opensubtitles.org",
        "api.opensubtitles.org"
    ],
    "==== Fanart ====": [
        "assets.fanart.tv"
    ]
}

# ===== 工具函数 =====
def is_ipv4(addr):
    """宽松 IPv4 判断, 仅用于初筛; 严格校验用 _is_valid_ipv4。"""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", addr))

def dns_query(domain, dns_ip):
    """向指定 DNS 服务器查询 A/AAAA 记录, 返回 IP 列表。"""
    try:
        result = subprocess.run(["dig", f"@{dns_ip}", "+short", "A", domain],
                                capture_output=True, text=True, timeout=5)
        ipv4s = [line.strip() for line in result.stdout.splitlines() if is_ipv4(line.strip())]
        result6 = subprocess.run(["dig", f"@{dns_ip}", "+short", "AAAA", domain],
                                 capture_output=True, text=True, timeout=5)
        ipv6s = [line.strip() for line in result6.stdout.splitlines() if ":" in line.strip()]
        return ipv4s + ipv6s
    except Exception as e:
        logging.debug("dns_query 失败: domain=%s dns=%s err=%s", domain, dns_ip, e)
        return []

def check_https(domain, ip):
    url = f"https://{domain}/"
    headers = {"Host": domain}
    delay = 0.3
    for _ in range(RETRY):
        try:
            r = requests.get(url, headers=headers, timeout=TIMEOUT_REQUEST, verify=False)
            if isinstance(r.status_code, int):
                return "https"
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2, 1.2)
            continue
    return None

def check_tcp(ip):
    delay = 0.2
    for _ in range(RETRY):
        try:
            conn = socket.create_connection((ip, 443), timeout=TIMEOUT_TCP)
            conn.close()
            return "tcp"
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2, 0.8)
            continue
    return None

def check_ping(ip):
    cmd = ["ping6" if ":" in ip else "ping", "-c", "1", "-W", str(PING_TIMEOUT), ip]
    delay = 0.2
    for _ in range(RETRY):
        try:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if proc.returncode == 0:
                return "ping"
        except Exception:
            pass
        time.sleep(delay)
        delay = min(delay * 2, 0.8)
    return None

def test_ip(domain, ip):
    for check in (check_https, check_tcp, check_ping):
        res = check(domain, ip) if check is check_https else check(ip)
        if res:
            return res
    return None

def resolve_all_dns(domain):
    """汇总各 DNS 源解析到的去重 IP 列表。"""
    records, seen = [], set()
    for dns_name, dns_ip in DNS_SERVERS.items():
        for ip in dns_query(domain, dns_ip):
            if ip not in seen:
                seen.add(ip)
                records.append((ip, dns_name))
    return records

def beijing_now_str():
    tz = timezone(timedelta(hours=8))
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S Beijing Time")

def resolve_and_test(domain):
    """解析域名并测试可达性, 返回 [(ip, method, dns_name), ...]。"""
    records = resolve_all_dns(domain)
    if not records:
        return []

    results_v4, results_v6 = [], []

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(test_ip, domain, ip): (ip, dns_name) for ip, dns_name in records}
        for fut in concurrent.futures.as_completed(futures):
            ip, dns_name = futures[fut]
            try:
                res = fut.result()
            except Exception:
                continue
            if not res:
                continue

            if ":" in ip and (DUAL_STACK is True or DUAL_STACK == "IPv6"):
                if len(results_v6) < MAX_IPS:
                    results_v6.append((ip, res, dns_name))
            elif is_ipv4(ip) and (DUAL_STACK is True or DUAL_STACK == "IPv4"):
                if len(results_v4) < MAX_IPS:
                    results_v4.append((ip, res, dns_name))

    return results_v4 + results_v6

# ===== 主逻辑 =====
def main():
    """主入口: 检测依赖, 生成 hosts 文件, 打印摘要日志。"""
    check_dependencies()
    lines = []
    lines.append("# Kekylin Hosts Start")
    lines.append("# 项目主页: https://github.com/kekylin/hosts")
    lines.append(f"# 更新时间: {beijing_now_str()}")
    lines.append("")

    for group_name, domains in DOMAIN_GROUPS.items():
        lines.append(f"# {group_name}")
        for domain in domains:
            results = resolve_and_test(domain)
            if not results:
                lines.append(f"# {domain}  # 完全无法访问")
                logging.warning("不可达: %s", domain)
                continue
            for ip, method, dns_name in results:
                lines.append(f"{ip} {domain}  # {method} | DNS: {dns_name}")
                logging.info("可用: %s -> %s (%s | %s)", domain, ip, method, dns_name)
        lines.append("")

    lines.append("# Kekylin Hosts End")

    with open("hosts", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # 边界提示: 若所有分组均无可用结果
    only_comments = all(line.startswith("#") or line == "" for line in lines[4:-1])
    if only_comments:
        logging.error("生成完成, 但所有域名均不可达或解析失败")
    else:
        logging.info("hosts 文件更新完成")


if __name__ == "__main__":
    main()