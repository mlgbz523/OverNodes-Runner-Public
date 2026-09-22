#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ProxyIP Scanner & Filter for edgetunnel / Cloudflare Workers
自动从开源候选源及内置优质反代池中并发探测、筛选活跃低延迟 Proxy IP，并输出标准化列表。
"""

import sys
import os
import re
import time
import asyncio
import argparse
from typing import List, Tuple, Dict, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None

# 内置优质候选源与公共 ProxyIP 列表 (多路冗余)
ONLINE_SOURCES = [
    "https://raw.githubusercontent.com/ymyuuu/IPDB/main/proxy.txt",
    "https://raw.githubusercontent.com/LeilaoMi/cf-proxyip-us/main/proxyip.txt",
    "https://raw.githubusercontent.com/ip-pro/ip-pro.github.io/main/proxyip.txt",
]

# 内置高可靠种子反代 IP / 域名池 (防止公网源拉取失败时空转)
SEED_PROXIES = [
    # 常用高信誉公共反代节点
    "164.152.17.14:443",
    "47.57.233.126:443",
    "8.219.145.56:443",
    "154.213.176.10:443",
    "103.152.112.120:443",
    "170.106.118.174:443",
    "198.41.222.18:443",
    "198.41.223.18:443",
    "104.16.132.229:443",
    "104.16.133.229:443",
    "172.67.73.1:443",
    "104.21.32.1:443",
]


class ProxyScanner:
    def __init__(self, target_count: int = 15, timeout: float = 3.0, concurrency: int = 50):
        self.target_count = target_count
        self.timeout = timeout
        self.concurrency = concurrency

    async def fetch_candidates(self, session: aiohttp.ClientSession) -> List[str]:
        """从在线源和内置种子中收集候选 Proxy IP"""
        candidates = set(SEED_PROXIES)

        for url in ONLINE_SOURCES:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="ignore")
                        lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
                        for line in lines:
                            # 提取 ip:port 或纯 ip
                            match = re.search(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b)(?::(\d+))?", line)
                            if match:
                                ip = match.group(1)
                                port = match.group(2) if match.group(2) else "443"
                                candidates.add(f"{ip}:{port}")
                        print(f"[*] 从源 {url} 成功获取候选，当前累计候选池: {len(candidates)}")
            except Exception as e:
                print(f"[!] 访问源 {url} 失败: {e}")

        return list(candidates)

    async def test_proxy(self, session: aiohttp.ClientSession, proxy_entry: str, sem: asyncio.Semaphore) -> Optional[Dict]:
        """测试单个 Proxy IP 的真实可用性、延迟和出口地区"""
        parts = proxy_entry.split(":")
        ip = parts[0]
        port = parts[1] if len(parts) > 1 else "443"

        # 针对 80/8080 等非 TLS 端口走 http，针对 443/8443 走 https
        is_tls = port in ["443", "8443", "2053", "2083", "2087", "2096"]
        scheme = "https" if is_tls else "http"
        test_url = f"{scheme}://{ip}:{port}/cdn-cgi/trace"
        headers = {
            "Host": "cloudflare.com",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        async with sem:
            t_start = time.perf_counter()
            try:
                async with session.get(
                    test_url,
                    headers=headers,
                    ssl=False,  # 允许跳过主机名证书不匹配 (反代测试必需)
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False,
                ) as resp:
                    latency = round((time.perf_counter() - t_start) * 1000, 1)
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        if "colo=" in body or "ip=" in body or "fl=" in body:
                            # 提取出口机房或国家代码
                            loc_match = re.search(r"loc=([A-Z]{2})", body)
                            colo_match = re.search(r"colo=([A-Z]{3})", body)
                            loc = loc_match.group(1) if loc_match else (colo_match.group(1) if colo_match else "GLOBAL")
                            return {
                                "entry": f"{ip}:{port}",
                                "ip": ip,
                                "port": port,
                                "loc": loc,
                                "latency": latency,
                            }
            except Exception:
                pass
            return None

    async def scan(self) -> List[Dict]:
        """全流程并发扫描与优选"""
        conn = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        async with aiohttp.ClientSession(connector=conn) as session:
            print("[*] 正在拉取 Proxy IP 候选池...")
            candidates = await self.fetch_candidates(session)
            print(f"[*] 共收集到 {len(candidates)} 个候选 Proxy IP，启动并发测速 (并发数: {self.concurrency})...")

            sem = asyncio.Semaphore(self.concurrency)
            tasks = [self.test_proxy(session, c, sem) for c in candidates]
            results = await asyncio.gather(*tasks)

            valid_results = [r for r in results if r is not None]
            print(f"[*] 测速探测完成，共成功验证 {len(valid_results)} 个高可用 Proxy IP")

            # 按照延迟升序排序
            valid_results.sort(key=lambda x: x["latency"])

            # 保证地区多样性 (优先挑出不同地区的优质 IP)
            selected = []
            seen_locs = {}
            # 第一轮：每种地区最多选 3 个
            for item in valid_results:
                loc = item["loc"]
                if seen_locs.get(loc, 0) < 3:
                    selected.append(item)
                    seen_locs[loc] = seen_locs.get(loc, 0) + 1
                if len(selected) >= self.target_count:
                    break

            # 若不足 target_count，直接用剩余按延迟补齐
            if len(selected) < self.target_count:
                for item in valid_results:
                    if item not in selected:
                        selected.append(item)
                    if len(selected) >= self.target_count:
                        break

            return selected


def main():
    parser = argparse.ArgumentParser(description="ProxyIP Scanner for Cloudflare Workers")
    parser.add_argument("--output", "-o", default="proxyip.txt", help="输出文件路径")
    parser.add_argument("--count", "-c", type=int, default=12, help="最终保留的优选 IP 数量")
    parser.add_argument("--concurrency", type=int, default=60, help="并发扫描线程数")
    parser.add_argument("--timeout", type=float, default=2.5, help="单节点超时时间(秒)")
    args = parser.parse_args()

    if aiohttp is None:
        print("[!] 错误: aiohttp 未安装，请执行 pip install aiohttp")
        sys.exit(1)

    scanner = ProxyScanner(
        target_count=args.count,
        timeout=args.timeout,
        concurrency=args.concurrency,
    )

    t_start = time.time()
    best_proxies = asyncio.run(scanner.scan())
    cost = round(time.time() - t_start, 2)

    if not best_proxies:
        print("[!] 未筛选出可用 Proxy IP，将使用种子备选保障不中断。")
        for s in SEED_PROXIES[:args.count]:
            best_proxies.append({"entry": s, "loc": "AUTO", "latency": 150.0})

    print(f"\n[+] 优选完成！耗时 {cost}s，精选出 {len(best_proxies)} 个高可用 Proxy IP：")
    output_lines = []
    for idx, p in enumerate(best_proxies, 1):
        line = f"{p['entry']}#{p['loc']}-ProxyIP-{int(p['latency'])}ms"
        output_lines.append(line)
        print(f"  {idx:02d}. {line}")

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(output_lines) + "\n")

    print(f"[+] 结果已成功保存到: {args.output}")


if __name__ == "__main__":
    main()
