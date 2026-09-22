#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP 优选与测速命令行工具 (CLI 批处理全功能版)
基于 CloudFlareScan.py 核心算法重构，脱离 PySide6 GUI 依赖。
专为终端运行、自动化脚本、Shell / PowerShell / Batch 批处理调用深度优化。
"""

import sys
import os
import time
import random
import ipaddress
import asyncio
import aiohttp
import socket
import ssl
import csv
import json
import argparse
import warnings
from datetime import datetime
from typing import List, Optional, Dict

warnings.filterwarnings("ignore", category=DeprecationWarning)

# =====================================================================
# Windows 控制台编码及 ANSI 颜色支持
# =====================================================================
if sys.platform == 'win32':
    try:
        os.system('')  # 启用 VT100 转义码
        sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
        sys.stderr.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    except AttributeError:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


def purge_env_proxies() -> Dict[str, str]:
    """清除当前 Python 进程内的代理环境变量，确保本进程纯净直连测试真实延迟"""
    removed = {}
    for var in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        val = os.environ.pop(var, None)
        if val:
            removed[var] = val
    return removed

# =====================================================================
# Cloudflare 官方 IPv4 与 IPv6 推荐 CIDR 列表 (与 CloudFlareScan.py 保持完全一致)
# =====================================================================
CF_IPV4_CIDRS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/12",
    "172.64.0.0/17", "172.64.128.0/18", "172.64.192.0/19", "172.64.224.0/22",
    "172.64.229.0/24", "172.64.230.0/23", "172.64.232.0/21", "172.64.240.0/21",
    "172.64.248.0/21", "172.65.0.0/16", "172.66.0.0/16", "172.67.0.0/16",
    "131.0.72.0/22"
]

CF_IPV6_CIDRS = [
    "2400:cb00:2049::/48", "2400:cb00:f00e::/48", "2606:4700::/32",
    "2606:4700:10::/48", "2606:4700:130::/48", "2606:4700:3000::/48",
    "2606:4700:3001::/48", "2606:4700:3002::/48", "2606:4700:3003::/48",
    "2606:4700:3004::/48", "2606:4700:3005::/48", "2606:4700:3006::/48",
    "2606:4700:3007::/48", "2606:4700:3008::/48", "2606:4700:3009::/48",
    "2606:4700:3010::/48", "2606:4700:3011::/48", "2606:4700:3012::/48",
    "2606:4700:3013::/48", "2606:4700:3014::/48", "2606:4700:3015::/48",
    "2606:4700:3016::/48", "2606:4700:3017::/48", "2606:4700:3018::/48",
    "2606:4700:3019::/48", "2606:4700:3020::/48", "2606:4700:3021::/48",
    "2606:4700:3022::/48", "2606:4700:3023::/48", "2606:4700:3024::/48",
    "2606:4700:3025::/48", "2606:4700:3026::/48", "2606:4700:3027::/48",
    "2606:4700:3028::/48", "2606:4700:3029::/48", "2606:4700:3030::/48",
    "2606:4700:3031::/48", "2606:4700:3032::/48", "2606:4700:3033::/48",
    "2606:4700:3034::/48", "2606:4700:3035::/48", "2606:4700:3036::/48",
    "2606:4700:5a::/48", "2606:4700:52::/48", "2606:4700:57::/48",
    "2606:4700:a0::/48", "2606:4700:a1::/48", "2606:4700:a8::/48",
    "2606:4700:a9::/48", "2606:4700:a::/48", "2606:4700:b::/48",
    "2606:4700:c::/48", "2606:4700:d0::/48", "2606:4700:d1::/48",
    "2606:4700:d::/48", "2606:4700:e0::/48", "2606:4700:e1::/48",
    "2606:4700:e2::/48", "2606:4700:e3::/48", "2606:4700:e4::/48",
    "2606:4700:e5::/48", "2606:4700:e6::/48", "2606:4700:e7::/48",
    "2606:4700:e::/48", "2606:4700:f1::/48", "2606:4700:f2::/48",
    "2606:4700:f3::/48", "2606:4700:f4::/48", "2606:4700:f5::/48",
    "2606:4700:f::/48", "2803:f800:50::/48", "2803:f800:51::/48",
    "2a06:98c1:3100::/48", "2a06:98c1:3101::/48", "2a06:98c1:3102::/48",
    "2a06:98c1:3103::/48", "2a06:98c1:3104::/48", "2a06:98c1:3105::/48",
    "2a06:98c1:3106::/48", "2a06:98c1:3107::/48", "2a06:98c1:3108::/48",
    "2a06:98c1:3109::/48", "2a06:98c1:310a::/48", "2a06:98c1:310b::/48",
    "2a06:98c1:310c::/48", "2a06:98c1:310d::/48", "2a06:98c1:310e::/48",
    "2a06:98c1:310f::/48", "2a06:98c1:3120::/48", "2a06:98c1:3121::/48",
    "2a06:98c1:3122::/48", "2a06:98c1:3123::/48", "2a06:98c1:3200::/48",
    "2a06:98c1:50::/48", "2a06:98c1:51::/48", "2a06:98c1:54::/48",
    "2a06:98c1:58::/48"
]

# =====================================================================
# 机场三字代码 (IATA) 与机房地区中文映射字典
# =====================================================================
AIRPORT_CODES = {
    "HKG": "香港", "TPE": "台北", "KHH": "高雄", "MFM": "澳门",
    "NRT": "东京", "HND": "东京", "KIX": "大阪", "NGO": "名古屋",
    "FUK": "福冈", "CTS": "札幌", "OKA": "冲绳",
    "ICN": "首尔", "GMP": "首尔", "PUS": "釜山",
    "SIN": "新加坡", "BKK": "曼谷", "DMK": "曼谷",
    "KUL": "吉隆坡", "HKT": "普吉岛",
    "MNL": "马尼拉", "CEB": "宿务",
    "HAN": "河内", "SGN": "胡志明市",
    "JKT": "雅加达", "DPS": "巴厘岛",
    "DEL": "德里", "BOM": "孟买", "MAA": "金奈",
    "DXB": "迪拜", "AUH": "阿布扎比",
    "SJC": "圣何塞", "LAX": "洛杉矶", "SFO": "旧金山",
    "SEA": "西雅图", "PDX": "波特兰",
    "LAS": "拉斯维加斯", "PHX": "菲尼克斯",
    "DEN": "丹佛", "DFW": "达拉斯", "IAH": "休斯顿",
    "ORD": "芝加哥", "MSP": "明尼阿波利斯",
    "ATL": "亚特兰大", "MIA": "迈阿密", "MCO": "奥兰多",
    "JFK": "纽约", "EWR": "纽约", "LGA": "纽约",
    "BOS": "波士顿", "PHL": "费城", "IAD": "华盛顿",
    "CLT": "夏洛特", "DTW": "底特律", "SLC": "盐湖城", "SAN": "圣迭戈", "SMF": "萨克拉门托",
    "RDU": "罗利", "PIT": "匹兹堡", "CLE": "克利夫兰", "BNA": "纳什维尔", "MCI": "堪萨斯城",
    "YYZ": "多伦多", "YVR": "温哥华", "YUL": "蒙特利尔",
    "LHR": "伦敦", "LGW": "伦敦", "STN": "伦敦",
    "CDG": "巴黎", "ORY": "巴黎",
    "FRA": "法兰克福", "MUC": "慕尼黑", "TXL": "柏林",
    "AMS": "阿姆斯特丹", "EIN": "埃因霍温",
    "MAD": "马德里", "BCN": "巴塞罗那",
    "FCO": "罗马", "MXP": "米兰", "LIN": "米兰",
    "ZRH": "苏黎世", "GVA": "日内瓦",
    "VIE": "维也纳", "PRG": "布拉格",
    "WAW": "华沙", "KRK": "克拉科夫",
    "HEL": "赫尔辛基", "OSL": "奥斯陆", "ARN": "斯德哥尔摩",
    "CPH": "哥本哈根",
    "SYD": "悉尼", "MEL": "墨尔本", "BNE": "布里斯班",
    "PER": "珀斯", "ADL": "阿德莱德",
    "AKL": "奥克兰", "WLG": "惠灵顿",
    "GRU": "圣保罗", "GIG": "里约热内卢", "EZE": "布宜诺斯艾利斯",
    "SCL": "圣地亚哥", "LIM": "利马", "BOG": "波哥大",
    "JNB": "约翰内斯堡", "CPT": "开普敦", "CAI": "开罗",
}

PORT_OPTIONS = [443, 2053, 2083, 2087, 2096, 8443]


def get_iata_translation(iata_code: str) -> str:
    """将 IATA 机场代码翻译为地区中文名称"""
    if not iata_code:
        return "未知地区"
    return AIRPORT_CODES.get(iata_code.upper(), iata_code.upper())


# =====================================================================
# 核心网络探测模块：机房识别、延迟测试、下载吞吐测速
# =====================================================================

def get_iata_code_from_ip(ip: str, timeout: int = 3, host: str = "speed.cloudflare.com") -> Optional[str]:
    """通过原生 socket 请求 cdn-cgi/trace 获取机房 IATA 代码"""
    urls = (f"https://[{ip}]/cdn-cgi/trace", f"http://[{ip}]/cdn-cgi/trace") if ':' in ip else (f"https://{ip}/cdn-cgi/trace", f"http://{ip}/cdn-cgi/trace")
    for url in urls:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            use_ssl = url.startswith('https://')
            if '[' in url and ']' in url:
                target_ip = url[8:].split('/')[0].strip('[]') if use_ssl else url[7:].split('/')[0].strip('[]')
            else:
                target_ip = url[8:].split('/')[0] if use_ssl else url[7:].split('/')[0]
            port = 443 if use_ssl else 80
            if ':' in target_ip:
                addrinfo = socket.getaddrinfo(target_ip, port, socket.AF_INET6, socket.SOCK_STREAM)
                s = socket.socket(addrinfo[0][0], addrinfo[0][1], addrinfo[0][2])
                s.settimeout(timeout)
                s.connect(addrinfo[0][4])
            else:
                s = socket.create_connection((target_ip, port), timeout=timeout)
            if use_ssl:
                s = ctx.wrap_socket(s, server_hostname=host)
            req = f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
            s.sendall(req)
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\r\n\r\n" in data:
                        break
                except socket.timeout:
                    break
            s.close()
            response = data.decode('utf-8', errors='ignore')
            for line in response.splitlines():
                if line.startswith('colo='):
                    colo = line.split('=', 1)[1].strip()
                    if colo and colo.upper() != 'UNKNOWN':
                        return colo.upper()
            if b'CF-RAY' in data:
                cf_ray = data.decode('utf-8', errors='ignore').split('CF-RAY:', 1)[1].split('\r\n', 1)[0].strip()
                if '-' in cf_ray:
                    parts = cf_ray.split('-')
                    for part in parts[-2:]:
                        if len(part) == 3 and part.isalpha():
                            return part.upper()
        except Exception:
            continue
    return None


AIRPORT_COUNTRY = {
    "HKG": "HK", "TPE": "TW", "KHH": "TW", "MFM": "MO",
    "NRT": "JP", "HND": "JP", "KIX": "JP", "NGO": "JP", "FUK": "JP", "CTS": "JP", "OKA": "JP",
    "ICN": "KR", "GMP": "KR", "PUS": "KR",
    "SIN": "SG", "BKK": "TH", "DMK": "TH", "KUL": "MY", "HKT": "TH",
    "MNL": "PH", "CEB": "PH", "HAN": "VN", "SGN": "VN", "JKT": "ID", "DPS": "ID",
    "DEL": "IN", "BOM": "IN", "MAA": "IN", "DXB": "AE", "AUH": "AE",
    # 美国 (US)
    "SJC": "US", "LAX": "US", "SFO": "US", "SEA": "US", "PDX": "US",
    "LAS": "US", "PHX": "US", "DEN": "US", "DFW": "US", "IAH": "US",
    "ORD": "US", "MSP": "US", "ATL": "US", "MIA": "US", "MCO": "US",
    "JFK": "US", "EWR": "US", "LGA": "US", "BOS": "US", "PHL": "US", "IAD": "US",
    "CLT": "US", "DTW": "US", "SLC": "US", "SAN": "US", "SMF": "US",
    "RDU": "US", "PIT": "US", "CLE": "US", "BNA": "US", "MCI": "US",
    # 加拿大
    "YYZ": "CA", "YVR": "CA", "YUL": "CA",
    # 欧洲
    "LHR": "GB", "LGW": "GB", "STN": "GB", "MAN": "GB",
    "CDG": "FR", "ORY": "FR", "MRS": "FR",
    # 德国 (DE)
    "FRA": "DE", "MUC": "DE", "TXL": "DE", "BER": "DE", "DUS": "DE", "HAM": "DE", "STR": "DE",
    "AMS": "NL", "EIN": "NL", "BRU": "BE", "LIS": "PT",
    "MAD": "ES", "BCN": "ES", "FCO": "IT", "MXP": "IT", "LIN": "IT",
    "ZRH": "CH", "GVA": "CH", "VIE": "AT", "PRG": "CZ", "WAW": "PL", "KRK": "PL",
    "HEL": "FI", "OSL": "NO", "ARN": "SE", "CPH": "DK",
    "SYD": "AU", "MEL": "AU", "BNE": "AU", "PER": "AU", "ADL": "AU",
    "AKL": "NZ", "WLG": "NZ", "GRU": "BR", "GIG": "BR", "EZE": "AR",
    "SCL": "CL", "LIM": "PE", "BOG": "CO", "JNB": "ZA", "CPT": "ZA", "CAI": "EG",
}


async def get_iata_code_async(session: aiohttp.ClientSession, ip: str, timeout: float = 1.5, host: str = "speed.cloudflare.com") -> Optional[str]:
    """通过 aiohttp 发起极速 trace 请求获取机房代码，优先利用免握手的 HTTP 瞬间直达，兼顾 HTTPS 回退与 CF-RAY 头秒解"""
    headers = {"User-Agent": "Mozilla/5.0", "Host": host}
    urls = [
        f"http://[{ip}]/cdn-cgi/trace" if ':' in ip else f"http://{ip}/cdn-cgi/trace",
        f"https://[{ip}]/cdn-cgi/trace" if ':' in ip else f"https://{ip}/cdn-cgi/trace"
    ]
    ssl_ctx = None
    for url in urls:
        try:
            kwargs = {
                "headers": headers,
                "timeout": aiohttp.ClientTimeout(total=timeout),
                "allow_redirects": False
            }
            if url.startswith('https://'):
                if ssl_ctx is None:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                kwargs["ssl"] = ssl_ctx
                kwargs["server_hostname"] = host

            async with session.get(url, **kwargs) as resp:
                # 无论状态码是 200 还是 403，CF-RAY 均带有机房代码
                if 'CF-RAY' in resp.headers:
                    cf_ray = resp.headers['CF-RAY']
                    if '-' in cf_ray:
                        parts = cf_ray.split('-')
                        for part in parts[-2:]:
                            if len(part) == 3 and part.isalpha():
                                return part.upper()
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.strip().split('\n'):
                        if line.startswith('colo='):
                            colo = line.split('=', 1)[1].strip()
                            if colo and colo.upper() != 'UNKNOWN':
                                return colo.upper()
        except Exception:
            continue
    return None



async def async_tcp_ping(ip: str, port: int, timeout: float = 0.8) -> Optional[float]:
    """单次异步 TCP 连接测延迟，严格释放套接字句柄以杜绝 Windows IOCP 句柄泄漏"""
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        latency = (time.monotonic() - start) * 1000
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return round(latency, 2)
    except Exception:
        return None


async def measure_tcp_latency(ip: str, port: int, ping_times: int = 2, timeout: float = 0.8) -> Optional[float]:
    """极速延迟测试：第一次连接超时直接判定不通并丢弃死节点，杜绝无意义重试；存活节点才测第二次取最低值"""
    lat1 = await async_tcp_ping(ip, port, timeout)
    if lat1 is None:
        return None
    if ping_times <= 1:
        return lat1
    await asyncio.sleep(0.02)
    lat2 = await async_tcp_ping(ip, port, timeout)
    if lat2 is not None:
        return min(lat1, lat2)
    return lat1


# =====================================================================
# 扫描器核心类 (CloudflareScanner - 满血极速两阶段架构)
# =====================================================================

class CloudflareScanner:
    def __init__(self, cidrs: List[str], ip_version: int = 4, custom_ips: Optional[List[str]] = None,
                 log_callback=None, progress_callback=None,
                 port: int = 443, max_workers: int = 150, latency_threshold: int = 220,
                 ping_times: int = 2, timeout: float = 0.8,
                 ipv4_sample_per_subnet: int = 1, ipv6_sample_per_cidr: int = 100,
                 host: str = "speed.cloudflare.com",
                 target_region: Optional[str] = None, target_count: int = 10):
        self.cidrs = cidrs
        self.ip_version = ip_version
        self.custom_ips = custom_ips
        self.max_workers = max_workers
        self.timeout = timeout
        self.ping_times = ping_times
        self.running = True
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.port = port
        self.latency_threshold = latency_threshold
        self.ipv4_sample_per_subnet = ipv4_sample_per_subnet
        self.ipv6_sample_per_cidr = ipv6_sample_per_cidr
        self.host = host
        self.target_region = target_region
        self.target_count = target_count

    def log(self, msg: str):
        if self.log_callback:
            self.log_callback(msg)

    def generate_ips(self) -> List[str]:
        # 如果用户直接指定了 IP 列表，则优先使用
        if self.custom_ips:
            return list(dict.fromkeys(self.custom_ips))

        ip_list = []
        for cidr in self.cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if self.ip_version == 4:
                    for subnet in network.subnets(new_prefix=24):
                        if subnet.num_addresses > 12:
                            hosts = list(subnet.hosts())
                            if hosts:
                                n = min(self.ipv4_sample_per_subnet, len(hosts))
                                sampled_ips = random.sample(hosts, n)
                                for ip in sampled_ips:
                                    ip_list.append(str(ip))
                else:
                    if network.num_addresses > 2:
                        sample = min(self.ipv6_sample_per_cidr, network.num_addresses - 2)
                        for _ in range(sample):
                            rand_int = random.randint(int(network.network_address) + 1, int(network.broadcast_address) - 1)
                            ip_list.append(str(ipaddress.IPv6Address(rand_int)))
            except ValueError as e:
                self.log(f"处理 CIDR {cidr} 时出错: {e}")
                continue
        return ip_list

    async def run_scan_async(self):
        try:
            self.log(f"正在从 IPv{self.ip_version} 地址源准备测试 IP... (端口: {self.port})")
            ip_list = self.generate_ips()
            if not ip_list:
                self.log(f"错误: 未能生成或获取到任何 IPv{self.ip_version} IP 地址")
                return None
            total = len(ip_list)
            self.log(f"已就绪 {total} 个 IP，并发初筛线程数: {self.max_workers}，延迟上限: {self.latency_threshold}ms")

            # ----------------- 阶段 1/2：高并发纯 TCP 延迟初筛 -----------------
            semaphore = asyncio.Semaphore(self.max_workers)
            alive_ips = []  # [(ip, latency)]
            start_time = time.time()
            last_update = 0.0
            completed = 0

            async def _tcp_worker(ip):
                if not self.running:
                    return None
                async with semaphore:
                    lat = await measure_tcp_latency(ip, self.port, ping_times=self.ping_times, timeout=self.timeout)
                    if lat is not None and lat <= self.latency_threshold:
                        return (ip, lat)
                    return None

            tcp_tasks = [asyncio.create_task(_tcp_worker(ip)) for ip in ip_list]

            for fut in asyncio.as_completed(tcp_tasks):
                if not self.running:
                    break
                res = await fut
                completed += 1
                if res:
                    alive_ips.append(res)
                now = time.time()
                if now - last_update >= 0.15 or completed == total:
                    elapsed = now - start_time
                    speed = completed / elapsed if elapsed > 0 else 0
                    if self.progress_callback:
                        self.progress_callback("初筛", completed, total, len(alive_ips), speed)
                    last_update = now

            if not self.running:
                self.log("初筛已被手动中止")
                return None

            self.log(f"\n[*] 阶段一初筛完成！用时 {time.time()-start_time:.1f}s，发现 {len(alive_ips)} 个符合延迟门槛的存活节点。")

            if not alive_ips:
                return []

            # ----------------- 阶段 2/2：机房地区识别 (IATA 极速并发 + 早停优化) -----------------
            # 按 TCP 延迟升序排序，优先解析延迟最低的最优节点
            alive_ips.sort(key=lambda x: x[1])

            # 默认目标国家集合：美国 (US)、新加坡 (SG)、德国 (DE)
            default_preferred_countries = {"US", "SG", "DE"}
            is_default_target = (self.target_region is None)

            # 需要收集的优质目标候选数量（至少 10 个，或所需测速数量的 2 倍）
            target_quota = max(10, min(self.target_count * 2, 25))

            # 候选 IP 范围：优先锁定延迟最低的前 120 个优质存活节点
            candidate_alive = alive_ips[:120] if len(alive_ips) > 120 else alive_ips

            if is_default_target:
                self.log(f"[*] 阶段二：正在并发解析排名前 {len(candidate_alive)} 个优质节点的机房地区 (默认优选目标: 美国 / 新加坡 / 德国)...")
            else:
                self.log(f"[*] 阶段二：正在并发解析排名前 {len(candidate_alive)} 个优质节点的机房地区 (指定目标: {self.target_region.upper()})...")

            iata_workers = min(60, max(20, len(candidate_alive)))
            iata_semaphore = asyncio.Semaphore(iata_workers)
            family = socket.AF_INET6 if self.ip_version == 6 else socket.AF_INET
            connector = aiohttp.TCPConnector(
                limit=iata_workers,
                force_close=True,
                enable_cleanup_closed=True,
                limit_per_host=0,
                family=family
            )

            successful = []
            matched_targets = []
            start_time_iata = time.time()
            completed_iata = 0
            total_alive = len(candidate_alive)
            last_update = 0.0
            early_exit = False

            async with aiohttp.ClientSession(connector=connector) as session:
                async def _iata_worker(ip, lat):
                    if not self.running:
                        return None
                    async with iata_semaphore:
                        iata = None
                        try:
                            iata = await get_iata_code_async(session, ip, timeout=1.2, host=self.host)
                        except Exception:
                            pass
                        return {
                            'ip': ip,
                            'latency': lat,
                            'iata_code': iata.upper() if iata else 'UNKNOWN',
                            'chinese_name': get_iata_translation(iata) if iata else "未知地区",
                            'success': True,
                            'ip_version': 6 if ':' in ip else 4,
                            'scan_time': datetime.now().strftime("%H:%M:%S"),
                            'port': self.port,
                            'ping_times': self.ping_times
                        }

                iata_tasks = [asyncio.create_task(_iata_worker(ip, lat)) for ip, lat in candidate_alive]

                for fut in asyncio.as_completed(iata_tasks):
                    if not self.running:
                        break
                    try:
                        res = await fut
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        res = None

                    completed_iata += 1
                    if res and res.get('iata_code') and res['iata_code'] != 'UNKNOWN':
                        successful.append(res)
                        iata_code = res['iata_code']
                        country = AIRPORT_COUNTRY.get(iata_code, '')
                        if is_default_target:
                            if country in default_preferred_countries:
                                matched_targets.append(res)
                        else:
                            if (iata_code == self.target_region.upper() or 
                                country == self.target_region.upper() or 
                                self.target_region.upper() in res.get('chinese_name', '')):
                                matched_targets.append(res)

                    # 智能早停判定：已满足目标配额
                    if len(matched_targets) >= target_quota:
                        early_exit = True
                        for t in iata_tasks:
                            if not t.done():
                                t.cancel()
                        break

                    now = time.time()
                    if now - last_update >= 0.15 or completed_iata == total_alive:
                        elapsed = now - start_time_iata
                        speed = completed_iata / max(elapsed, 0.1)
                        if self.progress_callback:
                            target_count_display = len(matched_targets) if (is_default_target or self.target_region) else len(successful)
                            self.progress_callback("地区", completed_iata, total_alive, target_count_display, speed)
                        last_update = now

            elapsed_iata = time.time() - start_time_iata
            if early_exit:
                self.log(f"\n[*] 阶段二极速早停！用时 {elapsed_iata:.1f}s，已提前捕获 {len(matched_targets)} 个最优目标地区节点，瞬间切入测速！\n")
            else:
                self.log(f"\n[*] 阶段二完成！用时 {elapsed_iata:.1f}s，成功解析出 {len(successful)} 个已知机房节点。\n")
            return successful
        except Exception as e:
            self.log(f"扫描执行过程中出现异常: {str(e)}")
            return None

    def stop(self):
        self.running = False



# =====================================================================
# 测速器核心类 (SpeedTester)
# =====================================================================

class SpeedTester:
    def __init__(self, results: List[Dict], region_code: Optional[str] = None,
                 max_test_count: int = 10, current_port: int = 443,
                 download_time_limit: float = 3.0, min_speed_threshold: float = 0.0,
                 test_host: str = "speed.cloudflare.com",
                 status_callback=None, progress_callback=None):
        self.results = results
        self.region_code = region_code.upper() if region_code else None
        self.max_test_count = max_test_count
        self.download_time_limit = download_time_limit
        self.min_speed_threshold = min_speed_threshold
        self.test_host = test_host
        self.running = True
        self.current_port = current_port
        self.status_callback = status_callback
        self.progress_callback = progress_callback

    def log(self, msg: str):
        if self.status_callback:
            self.status_callback(msg)

    def download_speed(self, ip: str, port: int) -> float:
        """原生 HTTP/1.1 GET 测速下载，自动防御 429 限流并在规定时间内计算平均传输速率 (MB/s)"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        endpoints = [
            (self.test_host, "/__down?bytes=50000000"),
            ("cdnjs.cloudflare.com", "/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css")
        ]
        
        for host, path in endpoints:
            try:
                if ':' in ip:
                    addrinfo = socket.getaddrinfo(ip, port, socket.AF_INET6, socket.SOCK_STREAM)
                    sock = socket.socket(addrinfo[0][0], addrinfo[0][1], addrinfo[0][2])
                    sock.settimeout(3.5)
                    sock.connect(addrinfo[0][4])
                else:
                    sock = socket.create_connection((ip, port), timeout=3.5)

                ss = ctx.wrap_socket(sock, server_hostname=host)
                req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
                ss.sendall(req)
                start = time.time()
                data = b""
                header_done = False
                body = 0
                is_429 = False
                while time.time() - start < self.download_time_limit:
                    buf = ss.recv(8192)
                    if not buf:
                        break
                    if not header_done:
                        data += buf
                        if b"\r\n\r\n" in data:
                            header_done = True
                            if b"429 Too Many Requests" in data.split(b"\r\n\r\n", 1)[0]:
                                is_429 = True
                                break
                            body += len(data.split(b"\r\n\r\n", 1)[1])
                    else:
                        body += len(buf)
                ss.close()
                if is_429:
                    continue
                dur = time.time() - start
                return round((body / 1024 / 1024) / max(dur, 0.1), 2)
            except Exception:
                continue
        return 0.0


    def run(self) -> List[Dict]:
        try:
            if not self.results:
                self.log("错误：没有可用的 IP 列表进行测速")
                return []

            preferred_countries = {"US", "SG", "DE"}

            if self.region_code:
                # 明确指定了地区码 (支持机房码 SJC/LAX/SIN/FRA 或国家代码 US/SG/DE 或中文)
                filtered = [
                    r for r in self.results 
                    if r.get('iata_code') and (
                        r['iata_code'].upper() == self.region_code or
                        AIRPORT_COUNTRY.get(r['iata_code'].upper(), '') == self.region_code or
                        self.region_code in r.get('chinese_name', '')
                    )
                ]
                self.log(f"启动指定地区测速: {self.region_code} (端口: {self.current_port})")
                self.log(f"筛选到 {len(filtered)} 个候选 IP")
            else:
                # 未指定地区：默认强制锁定【美国 (US)、新加坡 (SG)、德国 (DE)】优质节点！
                pref_nodes = [
                    r for r in self.results 
                    if r.get('iata_code') and AIRPORT_COUNTRY.get(r['iata_code'].upper(), '') in preferred_countries
                ]
                if pref_nodes:
                    filtered = pref_nodes
                    self.log(f"[*] 未指定地区，已激活默认优选策略：锁定【美国(US) / 新加坡(SG) / 德国(DE)】优质节点进行测速 (筛选出 {len(filtered)} 个候选，端口: {self.current_port})")
                else:
                    filtered = self.results
                    self.log(f"[!] 提示：候选池中未发现美/新/德节点，回退为全量优质节点测速 (共 {len(filtered)} 个候选，端口: {self.current_port})")

            if not filtered:
                self.log("没有找到匹配条件的 IP 进行测速")
                return []

            # 按延迟升序排序，取最优的前 N 个
            filtered.sort(key=lambda x: x.get('latency', float('inf')))
            targets = filtered[:min(self.max_test_count, len(filtered))]
            self.log(f"{'地区测速' if self.region_code else '完全测速'}：开始对前 {len(targets)} 个候选 IP 进行实际下载测速...")

            speed_results = []
            for i, info in enumerate(targets):
                if not self.running:
                    break
                ip = info['ip']
                latency = info.get('latency', 0.0)
                self.log(f"[{i+1}/{len(targets)}] 正在测速 {ip} (延迟: {latency:.1f}ms)...")
                if self.progress_callback:
                    self.progress_callback(i + 1, len(targets))

                dl_speed = self.download_speed(ip, self.current_port)
                # 直接复用初筛阶段已解析出的机房代码，绝不发起多余的网络请求死等
                colo = info.get('iata_code', 'UNKNOWN')

                # 达标过滤
                if dl_speed >= self.min_speed_threshold:
                    res = {
                        'ip': ip,
                        'latency': latency,
                        'download_speed': dl_speed,
                        'iata_code': colo.upper() if colo else 'UNKNOWN',
                        'chinese_name': AIRPORT_CODES.get(colo.upper(), '未知地区') if colo else '未知地区',
                        'test_type': '地区测速' if self.region_code else '完全测速',
                        'port': self.current_port
                    }
                    speed_results.append(res)
                    self.log(f"  -> 测速完成: {dl_speed} MB/s | 机房: {colo} ({res['chinese_name']})")
                else:
                    self.log(f"  -> 测速结果: {dl_speed} MB/s (低于门槛 {self.min_speed_threshold} MB/s，已剔除)")

                if i < len(targets) - 1 and self.running:
                    time.sleep(0.2)

            # 按下载速度从大到小降序排列
            speed_results.sort(key=lambda x: x['download_speed'], reverse=True)
            self.log(f"测速完成！成功测出 {len(speed_results)} 个达标节点")
            return speed_results
        except Exception as e:
            self.log(f"测速过程中出现未捕获异常: {str(e)}")
            return []

    def stop(self):
        self.running = False


# =====================================================================
# 输出、导出与显示辅助函数
# =====================================================================

def print_scan_summary(results: List[Dict], port: int):
    """打印初筛完成后的统计信息 (对应 GUI 的 show_scan_summary)"""
    if not results:
        print("\n扫描完成：未找到任何可用节点。")
        return
    ipv4 = sum(1 for r in results if ':' not in r['ip'])
    ipv6 = len(results) - ipv4
    iata_stats = {}
    for r in results:
        code = r.get('iata_code')
        if code and code != 'UNKNOWN':
            key = f"{code} ({r.get('chinese_name', '未知')})"
            iata_stats[key] = iata_stats.get(key, 0) + 1

    print("\n" + "=" * 55)
    print("扫描初筛完成！统计信息：")
    if ipv4:
        print(f"  可用 IPv4 节点: {ipv4} 个 (端口: {port})")
    if ipv6:
        print(f"  可用 IPv6 节点: {ipv6} 个 (端口: {port})")
    if iata_stats:
        print(f"  机房分布（共发现 {len(iata_stats)} 个不同地区机房）：")
        for iata, cnt in sorted(iata_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"    - {iata}: {cnt} 个 IP")
    else:
        print("  提示：本次初筛未检测到有效的机房代码。")
    print(f"  测试端口: {port}")
    print("=" * 55 + "\n")


def print_speed_results_table(results: List[Dict]):
    """打印美观的测速排行榜表格"""
    if not results:
        print("测速完成：没有有效的达标节点。")
        return
    print("\n" + "=" * 78)
    print(f"{'排名':<4} {'IP地址':<38} {'机房地区':<12} {'延迟(ms)':<10} {'下载速度(MB/s)':<12}")
    print("-" * 78)
    for i, r in enumerate(results, 1):
        region_str = f"{r['iata_code']} {r['chinese_name']}"
        print(f"{i:<4} {r['ip']:<38} {region_str:<12} {r['latency']:<10.2f} {r['download_speed']:<12.2f}")
    print("=" * 78 + "\n")


def export_to_csv(speed_results: List[Dict], output_path: str):
    """导出与原版完全一致的 CSV 文件 (包含 UTF-8 BOM，Excel 直接打开不乱码)"""
    if not output_path.lower().endswith('.csv'):
        output_path += '.csv'
    try:
        abs_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=['排名', 'IP地址', '地区码', '地区', '延迟(ms)', '下载速度(MB/s)', '端口', '测速类型'])
            writer.writeheader()
            for i, r in enumerate(speed_results, 1):
                writer.writerow({
                    '排名': i,
                    'IP地址': r['ip'],
                    '地区码': r['iata_code'],
                    '地区': r['chinese_name'],
                    '延迟(ms)': f"{r['latency']:.2f}",
                    '下载速度(MB/s)': f"{r['download_speed']:.2f}",
                    '端口': r.get('port', 443),
                    '测速类型': r.get('test_type', '未知')
                })
        print(f"[*] 测速结果已成功导出到 CSV: {abs_path}")
    except Exception as e:
        print(f"[!] 导出 CSV 失败: {str(e)}", file=sys.stderr)


def export_to_json(speed_results: List[Dict], output_path: str):
    """导出结构化 JSON 文件供脚本自动化解析"""
    if not output_path.lower().endswith('.json'):
        output_path += '.json'
    try:
        abs_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, 'w', encoding='utf-8') as f:
            json.dump(speed_results, f, ensure_ascii=False, indent=2)
        print(f"[*] 测速结果已成功导出到 JSON: {abs_path}")
    except Exception as e:
        print(f"[!] 导出 JSON 失败: {str(e)}", file=sys.stderr)


def format_overnode_entry(r: Dict) -> str:
    """按规范格式化单个节点: 173.245.49.158:8443#US[xxMB/S]-8443"""
    ip = r.get('ip', '')
    port = r.get('port', 443)
    iata = r.get('iata_code', 'UNKNOWN').upper()
    country = AIRPORT_COUNTRY.get(iata, iata if iata != 'UNKNOWN' else 'US')
    speed = r.get('download_speed', 0.0)
    return f"{ip}:{port}#{country}[{speed:.2f}MB/S]-{port}"


def export_to_overnode(speed_results: List[Dict], output_path: str):
    """导出符合 OverNodes 格式的节点文本文件 (例如 173.245.49.158:8443#US[xxMB/S]-8443)"""
    try:
        abs_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        lines = [format_overnode_entry(r) for r in speed_results]
        with open(abs_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + ('\n' if lines else ''))
        print(f"[*] 节点列表已成功导出到 OverNodes 文件: {abs_path}")
    except Exception as e:
        print(f"[!] 导出 OverNodes 格式文件失败: {str(e)}", file=sys.stderr)


def load_ips_from_file(file_path: str) -> List[str]:
    """从指定文本文件读取 IP 列表 (支持 CIDR 展开或单 IP，自动去重与过滤注释)"""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"找不到指定的 IP 输入文件: {file_path}")
    ips = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # 处理可能的格式：例如 "ip:port" 或带备注
            token = line.split()[0].split('#')[0]
            if ':' in token and not token.startswith('[') and token.count(':') == 1:
                token = token.split(':')[0]
            # 验证合法性
            try:
                if '/' in token:
                    net = ipaddress.ip_network(token, strict=False)
                    if net.num_addresses <= 256:
                        ips.extend(str(h) for h in net.hosts())
                    else:
                        # 对于超大段随机采样 10 个
                        hosts = list(net.hosts())
                        ips.extend(str(h) for h in random.sample(hosts, min(10, len(hosts))))
                else:
                    ipaddress.ip_address(token)
                    ips.append(token)
            except ValueError:
                continue
    return list(dict.fromkeys(ips))


# =====================================================================
# 命令行参数解析 (Argparse)
# =====================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Cloudflare IP 优选与测速命令行工具 (CLI 批处理全功能版)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
批处理与脚本调用使用示例:
----------------------------------------------------------------------
1. 默认基础扫描并输出结果:
   py cf_scan_cli.py

2. 扫描 IPv4 并自动进行完全测速 (测速延迟最低的前 10 个 IP，导出 CSV):
   py cf_scan_cli.py --speed-test --count 10 --export best_ips.csv

3. 针对特定机房地区 (如 SJC 圣何塞、HKG 香港、LAX 洛杉矶) 筛选并测速:
   py cf_scan_cli.py --region SJC --count 5 --export sjc_top.csv

4. 批处理脚本一键捕获最优 IP 列表 (纯净 IP 格式，适合管道与脚本变量):
   IPS=$(py cf_scan_cli.py --speed-test --count 3 --ip-only -q)
   for /f "tokens=*" %i in ('py cf_scan_cli.py --speed-test --count 1 --ip-only -q') do set BEST_IP=%i

5. 从已有 IP 文件进行批量测速 (不重新从官方段采样):
   py cf_scan_cli.py --input ips_cfOverScan.txt --speed-test --count 10

6. 高级参数定制:
   py cf_scan_cli.py --port 8443 --workers 200 --latency 180 --min-speed 2.5 --duration 5
----------------------------------------------------------------------
"""
    )
    # 扫描与 IP 生成相关参数
    parser.add_argument("--ipv", type=int, choices=[4, 6], default=4,
                        help="IP 版本: 4 或 6 (默认: 4)")
    parser.add_argument("--port", type=int, default=443,
                        help="测试端口 (默认: 443，支持 443, 2053, 2083, 2087, 2096, 8443 等任意有效端口)")
    parser.add_argument("--workers", type=int, default=150,
                        help="并发扫描连接数 1-500 (默认: 150)")
    parser.add_argument("--latency", type=int, default=220,
                        help="延迟初筛上限阈值 (ms)，超过将被丢弃 (默认: 220)")
    parser.add_argument("--v4-sample", type=int, default=1,
                        help="IPv4 每个 /24 子网随机采样数 1-5 (默认: 1)")
    parser.add_argument("--v6-sample", type=int, default=100,
                        help="IPv6 每个 CIDR 随机采样数 100-300 (默认: 100)")
    parser.add_argument("--input", type=str, default=None,
                        help="从指定文件读取已有 IP 列表进行测速 (支持 txt/iplist 文件)")

    # 测速相关参数
    parser.add_argument("--speed-test", action="store_true",
                        help="初筛后自动执行真实下载完全测速")
    parser.add_argument("--region", type=str, default=None,
                        help="初筛后仅对指定机房地区进行测速 (如 HKG, SJC, LAX, SIN, NRT, TPE 等)")
    parser.add_argument("--count", type=int, default=10,
                        help="测速节点数量 1-99 (默认: 10)")
    parser.add_argument("--duration", type=float, default=3.0,
                        help="每个节点测速下载时长 (秒) (默认: 3.0)")
    parser.add_argument("--min-speed", type=float, default=0.0,
                        help="测速达标最低下载速度门槛 (MB/s)，低于该速度将被过滤 (默认: 0.0)")
    parser.add_argument("--host", type=str, default="speed.cloudflare.com",
                        help="自定义测速使用的 Host 头 (默认: speed.cloudflare.com)")

    # 输出与脚本批处理相关参数
    parser.add_argument("--export", type=str, default=None,
                        help="导出测速结果到指定文件路径 (若为 .txt 则导出为 OverNodes 节点格式，若为 .csv 则导出表格)")
    parser.add_argument("--export-overnode", type=str, default=None,
                        help="导出测速结果到指定 OverNodes 文本文件 (格式: IP:PORT#COUNTRY[xxMB/S]-PORT)")
    parser.add_argument("--json-output", type=str, default=None,
                        help="导出测速结果到指定 JSON 文件路径")
    parser.add_argument("--ip-only", action="store_true",
                        help="纯净输出：仅输出优选出的 IP 地址列表（每行一个），专为脚本直接提取设计")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="静默模式：不显示动态进度条与中间日志，仅在标准输出展示最终结果")

    return parser.parse_args()


# =====================================================================
# 主执行入口 (Main)
# =====================================================================

def main():
    args = parse_args()

    # 参数范围合法性检查
    if not (1 <= args.workers <= 500):
        print("错误: 并发线程数必须在 1-500 之间", file=sys.stderr)
        sys.exit(1)

    if not (1 <= args.port <= 65535):
        print("错误: 端口号必须在 1-65535 之间", file=sys.stderr)
        sys.exit(1)

    if args.ipv == 4 and not (1 <= args.v4_sample <= 5):
        print("错误: IPv4 采样数必须在 1-5 之间", file=sys.stderr)
        sys.exit(1)

    if args.ipv == 6 and not (50 <= args.v6_sample <= 500):
        print("错误: IPv6 采样数必须在 50-500 之间", file=sys.stderr)
        sys.exit(1)

    if not (1 <= args.count <= 99):
        print("错误: 测速数量必须在 1-99 之间", file=sys.stderr)
        sys.exit(1)

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # 日志输出函数处理 (根据 quiet 模式分流)
    def log_msg(msg: str):
        if not args.quiet:
            print(msg, flush=True)

    # 外部输入 IP 处理
    custom_ips = None
    if args.input:
        try:
            custom_ips = load_ips_from_file(args.input)
            log_msg(f"[*] 成功从文件 {args.input} 载入 {len(custom_ips)} 个有效 IP")
            if not custom_ips:
                print(f"错误: 文件 {args.input} 中未解析到任何有效 IP 地址", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"载入输入文件失败: {e}", file=sys.stderr)
            sys.exit(1)

    cidrs = CF_IPV4_CIDRS if args.ipv == 4 else CF_IPV6_CIDRS

    log_msg(f"==================================================")
    log_msg(f"   Cloudflare IP 优选测速工具 (CLI 批处理版)")
    log_msg(f" 模式: IPv{args.ipv} | 端口: {args.port} | 并发: {args.workers} | 延迟上限: {args.latency}ms")
    if args.region:
        log_msg(f" 目标机房地区: {args.region.upper()} ({AIRPORT_CODES.get(args.region.upper(), '未知地区')})")
    log_msg(f"==================================================")

    # 动态进度条回调
    def progress_cb(phase, cur, total, ok, speed):
        if args.quiet:
            return
        percent = (cur / total * 100) if total else 0
        sys.stdout.write(f"\r[{phase}进度] {cur:>4}/{total} ({percent:>5.1f}%) | 存活: {ok:<4} | 速率: {speed:>5.1f} IP/s   ")
        sys.stdout.flush()

    # 1. 第一阶段：延迟测试与地区机房初筛
    scanner = CloudflareScanner(
        cidrs=cidrs,
        ip_version=args.ipv,
        custom_ips=custom_ips,
        log_callback=log_msg,
        progress_callback=progress_cb,
        port=args.port,
        max_workers=args.workers,
        latency_threshold=args.latency,
        ipv4_sample_per_subnet=args.v4_sample,
        ipv6_sample_per_cidr=args.v6_sample,
        host=args.host,
        target_region=args.region,
        target_count=args.count
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        results = loop.run_until_complete(scanner.run_scan_async())
    except KeyboardInterrupt:
        if not args.quiet:
            print("\n[!] 扫描已被手动中断")
        scanner.stop()
        sys.exit(2)
    finally:
        loop.close()

    if not args.quiet:
        print()  # 进度条结束后换行

    if results:
        known_results = [r for r in results if r.get('iata_code') and r.get('iata_code') != 'UNKNOWN']
    else:
        known_results = []

    if not args.quiet:
        print_scan_summary(known_results, args.port)

    # 判断是否需要执行第二阶段下载测速
    should_speed_test = args.speed_test or (args.region is not None) or (args.export is not None) or (args.export_overnode is not None) or (args.json_output is not None) or args.ip_only

    final_speed_results = []

    # 2. 第二阶段：真实下载测速
    if should_speed_test:
        if not known_results:
            log_msg("[-] 初筛未获得可用候选 IP，跳过测速阶段。")
            if args.ip_only:
                sys.exit(1)
            sys.exit(1)

        region_code = args.region.upper() if args.region else None
        tester = SpeedTester(
            results=known_results,
            region_code=region_code,
            max_test_count=args.count,
            current_port=args.port,
            download_time_limit=args.duration,
            min_speed_threshold=args.min_speed,
            test_host=args.host,
            status_callback=log_msg
        )

        try:
            final_speed_results = tester.run()
        except KeyboardInterrupt:
            if not args.quiet:
                print("\n[!] 测速已被手动中断")
            tester.stop()
            sys.exit(2)

        # 结果输出分支
        if args.ip_only:
            # 纯 IP 列表输出（每行一个 IP，专供 Shell/Batch 脚本捕获）
            for item in final_speed_results:
                print(item['ip'])
        else:
            if not args.quiet:
                print_speed_results_table(final_speed_results)

        # 导出文件处理
        if args.export and final_speed_results:
            if args.export.lower().endswith('.txt'):
                export_to_overnode(final_speed_results, args.export)
            else:
                export_to_csv(final_speed_results, args.export)

        if args.export_overnode and final_speed_results:
            export_to_overnode(final_speed_results, args.export_overnode)

        if args.json_output and final_speed_results:
            export_to_json(final_speed_results, args.json_output)

    else:
        # 如果未开启测速模式且指定了 ip-only，则直接输出初筛合格的 IP
        if args.ip_only:
            for item in known_results[:args.count]:
                print(item['ip'])

        if args.export and known_results:
            if args.export.lower().endswith('.txt'):
                export_to_overnode(known_results[:args.count], args.export)

        if args.export_overnode and known_results:
            export_to_overnode(known_results[:args.count], args.export_overnode)


    # 返回状态码 (找到节点返回 0，未找到返回 1)
    if should_speed_test:
        sys.exit(0 if len(final_speed_results) > 0 else 1)
    else:
        sys.exit(0 if len(known_results) > 0 else 1)


if __name__ == "__main__":
    main()
