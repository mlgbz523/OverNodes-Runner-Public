#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-source SOCKS5 Proxy Scanner & Evaluator (cf-bestip style)
从全球高质量代理源(Proxifly, Monosans等)聚合SOCKS5，并发进行真实回源连通性与延迟测速，生成极速SOCKS5出站列表。
"""

import sys
import os
import re
import time
import socket
import ssl
import asyncio
import urllib.request
import json
import argparse
from typing import List, Dict, Optional, Tuple

# 多数据源配置 (参考 cf-bestip 聚合机制)
SOURCES = [
    {
        "name": "Proxifly",
        "url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.json",
        "type": "json"
    },
    {
        "name": "Monosans",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "type": "txt"
    },
    {
        "name": "TheSpeedX",
        "url": "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "type": "txt"
    },
    {
        "name": "Hookzof",
        "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "type": "txt"
    }
]

# 优先挑选的核心地区
PREFERRED_REGIONS = ["US", "HK", "SG", "JP", "DE", "GB", "CA", "NL", "FR"]


class Socks5Scanner:
    def __init__(self, target_count: int = 12, timeout: float = 3.5, concurrency: int = 80):
        self.target_count = target_count
        self.timeout = timeout
        self.concurrency = concurrency

    def fetch_candidates(self) -> List[Dict]:
        """多源并发抓取并归一化候选代理列表"""
        candidates = []
        seen = set()

        for src in SOURCES:
            try:
                print(f"[*] 正在拉取数据源: {src['name']} ({src['url']})...")
                req = urllib.request.Request(src["url"], headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
                    count = 0
                    if src["type"] == "json":
                        data = json.loads(raw)
                        for item in data:
                            ip = item.get("ip")
                            port = item.get("port")
                            geo = item.get("geolocation") or {}
                            country = geo.get("country") or "GLOBAL"
                            if ip and port:
                                key = f"{ip}:{port}"
                                if key not in seen:
                                    seen.add(key)
                                    candidates.append({"host": ip, "port": int(port), "country": country})
                                    count += 1
                    elif src["type"] == "txt":
                        for line in raw.splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split(":")
                            if len(parts) >= 2:
                                ip, port = parts[0].strip(), parts[1].strip()
                                key = f"{ip}:{port}"
                                if key not in seen:
                                    seen.add(key)
                                    candidates.append({"host": ip, "port": int(port), "country": "AUTO"})
                                    count += 1
                    print(f"  + {src['name']} 贡献 {count} 个代理，累计候选池: {len(candidates)}")
            except Exception as e:
                print(f"  - 拉取 {src['name']} 失败: {e}")

        return candidates

    def _sync_deep_probe(self, host: str, port: int) -> Optional[Tuple[float, str]]:
        """与 edgetunnel 1:1 同款真机深度探针 (SOCKS5握手 + 真实 TLS 握手 + HTTP /cdn-cgi/trace 校验)"""
        t0 = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((host, port))
            # 1. SOCKS5 握手认证协商
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            if resp != b"\x05\x00":
                return None

            # 2. 发起 CONNECT 请求到 cloudflare.com:443
            target = b"cloudflare.com"
            cmd = b"\x05\x01\x00\x03" + bytes([len(target)]) + target + (443).to_bytes(2, "big")
            s.sendall(cmd)
            rep = s.recv(10)
            if len(rep) < 2 or rep[1] != 0:
                return None

            # 3. 核心：通过 SOCKS5 隧道完成真实 TLS 握手 (彻底剔除假活与自签名截获)
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(s, server_hostname="cloudflare.com")

            # 4. 发起真实 HTTP GET 验证与应用层端到端 RTT 测速
            tls.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
            data = tls.recv(1024).decode("utf-8", errors="ignore")

            if "h=cloudflare.com" in data and "ip=" in data:
                latency = round((time.perf_counter() - t0) * 1000, 1)
                loc_match = re.search(r"loc=([A-Z]{2})", data)
                loc = loc_match.group(1) if loc_match else "AUTO"
                return latency, loc
            return None
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass

    async def probe_socks5(self, candidate: Dict, sem: asyncio.Semaphore) -> Optional[Dict]:
        """调度线程池执行深度真机探测"""
        host = candidate["host"]
        port = candidate["port"]
        country = candidate["country"]

        async with sem:
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(None, self._sync_deep_probe, host, port)
            if res:
                latency, loc = res
                final_country = loc if loc != "AUTO" else country
                return {
                    "host": host,
                    "port": port,
                    "entry": f"{host}:{port}",
                    "socks_url": f"socks5://{host}:{port}",
                    "country": final_country,
                    "latency": latency
                }
            return None

    async def scan(self) -> List[Dict]:
        candidates = self.fetch_candidates()
        if not candidates:
            print("[!] 未获取到任何候选 SOCKS5 代理")
            return []

        # 优先抽取优先地区的节点 + 部分随机采样，控制总测试规模在 1000 以内保证高效完成
        preferred = [c for c in candidates if c["country"] in PREFERRED_REGIONS]
        others = [c for c in candidates if c["country"] not in PREFERRED_REGIONS]

        test_pool = preferred[:600] + others[:400]
        print(f"[*] 从候选池精选 {len(test_pool)} 个高质量候选，启动异步高并发探测 (并发: {self.concurrency})...")

        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self.probe_socks5(c, sem) for c in test_pool]
        results = await asyncio.gather(*tasks)

        valid = [r for r in results if r is not None]
        print(f"[*] 探测完毕！共筛选出 {len(valid)} 个高可用活体 SOCKS5 节点")

        # 按延迟升序排序 (越快越前)
        valid.sort(key=lambda x: x["latency"])

        # 地区均衡选择
        selected = []
        seen_countries = {}
        for item in valid:
            ct = item["country"]
            if seen_countries.get(ct, 0) < 3:
                selected.append(item)
                seen_countries[ct] = seen_countries.get(ct, 0) + 1
            if len(selected) >= self.target_count:
                break

        if len(selected) < self.target_count:
            for item in valid:
                if item not in selected:
                    selected.append(item)
                if len(selected) >= self.target_count:
                    break

        return selected


def main():
    parser = argparse.ArgumentParser(description="Multi-source SOCKS5 Scanner")
    parser.add_argument("--output", "-o", default="socks5.txt", help="输出文件路径")
    parser.add_argument("--count", "-c", type=int, default=12, help="最终保留的最快节点数")
    parser.add_argument("--concurrency", type=int, default=120, help="并发探测协程数")
    parser.add_argument("--timeout", type=float, default=2.5, help="单节点超时时间(秒)")
    args = parser.parse_args()

    scanner = Socks5Scanner(
        target_count=args.count,
        timeout=args.timeout,
        concurrency=args.concurrency
    )

    t0 = time.time()
    best_nodes = asyncio.run(scanner.scan())
    cost = round(time.time() - t0, 2)

    print(f"\n[+] SOCKS5 优选完成！总耗时 {cost}s，精选出 {len(best_nodes)} 个极速出站中继：")
    output_lines = []
    for idx, node in enumerate(best_nodes, 1):
        line = f"{node['entry']}#{node['country']}-SOCKS5-{int(node['latency'])}ms"
        output_lines.append(line)
        print(f"  {idx:02d}. {line}")

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(output_lines) + "\n")

    print(f"[+] 结果成功保存到: {args.output}")


if __name__ == "__main__":
    main()
