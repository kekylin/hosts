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
    """HTTPS检测，返回延迟（毫秒）或None。"""
    url = f"https://{domain}/"
    headers = {"Host": domain}
    delay = 0.3
    for _ in range(RETRY):
        try:
            start = time.time()
            r = requests.get(url, headers=headers, timeout=TIMEOUT_REQUEST, verify=False)
            elapsed = (time.time() - start) * 1000
            if isinstance(r.status_code, int):
                return elapsed
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2, 1.2)
            continue
    return None

def check_tcp(ip):
    """TCP连接检测，返回延迟（毫秒）或None。"""
    delay = 0.2
    for _ in range(RETRY):
        try:
            start = time.time()
            conn = socket.create_connection((ip, 443), timeout=TIMEOUT_TCP)
            elapsed = (time.time() - start) * 1000
            conn.close()
            return elapsed
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2, 0.8)
            continue
    return None

def check_ping(ip):
    """Ping检测，返回延迟（毫秒）或None。"""
    cmd = ["ping6" if ":" in ip else "ping", "-c", "1", "-W", str(PING_TIMEOUT), ip]
    delay = 0.2
    for _ in range(RETRY):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                # 解析ping输出获取延迟（兼容多种格式：time=XX.X ms, time<XX ms, time=XX.X）
                for line in proc.stdout.splitlines():
                    # 匹配 time=XX.X 或 time<XX 格式
                    match = re.search(r'time[<=](\d+\.?\d*)', line, re.IGNORECASE)
                    if match:
                        return float(match.group(1))
                    # 匹配 "XX ms" 格式（某些系统可能直接显示延迟）
                    match = re.search(r'(\d+\.?\d*)\s*ms', line, re.IGNORECASE)
                    if match:
                        return float(match.group(1))
                # 如果无法解析但ping成功，返回默认值（表示成功但延迟未知）
                return 0.0
        except Exception:
            pass
        time.sleep(delay)
        delay = min(delay * 2, 0.8)
    return None

def test_ip(domain, ip):
    """
    测试IP的连通性并计算综合分数。
    返回 (score, best_method, ping_ms) 或 None。
    
    评分规则：
    - function_score = HTTPS成功?100 : TCP成功?50 : Ping成功?25 : 0
    - latency_penalty = ping_ms / 10（如果有ping）或 15（如果没有）
    - score = function_score - latency_penalty
    """
    https_latency = check_https(domain, ip)
    tcp_latency = check_tcp(ip)
    ping_latency = check_ping(ip)
    
    # 计算功能分
    function_score = 0
    best_method = None
    if https_latency is not None:
        function_score = 100
        best_method = "https"
    elif tcp_latency is not None:
        function_score = 50
        best_method = "tcp"
    elif ping_latency is not None:
        function_score = 25
        best_method = "ping"
    else:
        return None
    
    # 计算延迟惩罚
    if ping_latency is not None:
        latency_penalty = ping_latency / 10
    else:
        latency_penalty = 15
    
    score = function_score - latency_penalty
    return (score, best_method, ping_latency if ping_latency is not None else None)

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
    """
    解析域名并测试可达性，按评分排序返回最优IP。
    返回 [(ip, method, dns_name), ...]，已按分数从高到低排序并取前MAX_IPS个。
    """
    records = resolve_all_dns(domain)
    if not records:
        return []

    results_v4, results_v6 = [], []

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = {ex.submit(test_ip, domain, ip): (ip, dns_name) for ip, dns_name in records}
        for fut in concurrent.futures.as_completed(futures):
            ip, dns_name = futures[fut]
            try:
                test_result = fut.result()
            except Exception:
                continue
            if test_result is None:
                continue
            
            score, best_method, ping_ms = test_result
            
            if ":" in ip and (DUAL_STACK is True or DUAL_STACK == "IPv6"):
                results_v6.append((score, ip, best_method, dns_name, ping_ms))
            elif is_ipv4(ip) and (DUAL_STACK is True or DUAL_STACK == "IPv4"):
                results_v4.append((score, ip, best_method, dns_name, ping_ms))

    # 按分数从高到低排序，取前MAX_IPS个
    results_v4.sort(key=lambda x: x[0], reverse=True)
    results_v6.sort(key=lambda x: x[0], reverse=True)
    
    # 返回格式：(ip, method, dns_name)
    final_v4 = [(ip, method, dns_name) for _, ip, method, dns_name, _ in results_v4[:MAX_IPS]]
    final_v6 = [(ip, method, dns_name) for _, ip, method, dns_name, _ in results_v6[:MAX_IPS]]
    
    return final_v4 + final_v6

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