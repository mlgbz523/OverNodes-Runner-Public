#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-source SOCKS5 Proxy Scanner & Throughput Evaluator (cf-bestip style)
核心机制：
1. 【真实数据吞吐量压测 (Throughput Benchmark)】：
   彻底淘汰仅测延迟的假活代理！通过 SOCKS5 隧道向 Cloudflare 测速专线请求真实数据流 (持续压测 1.5s)，实测下行带宽 (MB/s 与 Mbps)，按吞吐量定拔王者！
2. 【存量在岗优先复检 (Retention-First)】：
   优先深度探测已有节点，实测吞吐量达标 (>= 门槛) 坚决继续留任，杜绝频繁漂移换代理！
3. 【统一定锚主力王者 (Single Anchor Proxy)】：
   评选出当前综合吞吐量最大、延迟最低的 Top 1 王者代理，供所有优选 IP 统一绑定，出站 IP 绝对固定！
4. 【1:1 真机端到端深度探针】：
   真实 TLS 1.3 证书握手 + HTTP GET /cdn-cgi/trace 应用层双重校验，彻底杜绝假活与污染。
5. 【纯净命名规范与软备份】：统一标记 [socks5]，自动维护 _backup.txt。
"""

import sys
import os
import re
import time
import socket
import ssl
import asyncio
from concurrent.futures import ThreadPoolExecutor
import urllib.request
import json
import argparse
from typing import List, Dict, Optional, Tuple

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

PREFERRED_REGIONS = ["US", "HK", "SG", "JP", "DE", "GB", "CA", "NL", "FR"]


class Socks5Scanner:
    def __init__(self, target_count: int = 6, timeout: float = 3.0, concurrency: int = 80,
                 existing_file: Optional[str] = None, min_speed_mb: float = 0.8):
        self.target_count = target_count
        self.timeout = timeout
        self.concurrency = concurrency
        self.existing_file = existing_file
        self.min_speed_mb = min_speed_mb
        self.executor = ThreadPoolExecutor(max_workers=min(self.concurrency, 64))

    def load_existing_nodes(self, filepath: str) -> List[Dict]:
        """解析已有节点文件，提取在岗 SOCKS5 节点列表"""
        if not filepath or not os.path.exists(filepath):
            return []
        nodes = []
        seen = set()
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    entry_part = line.split("#")[0].strip()
                    if ":" in entry_part:
                        parts = entry_part.split(":")
                        host = parts[0].strip()
                        try:
                            port = int(parts[1].strip())
                            key = f"{host}:{port}"
                            if key not in seen:
                                seen.add(key)
                                nodes.append({"host": host, "port": port, "country": "AUTO"})
                        except ValueError:
                            continue
        except Exception as e:
            print(f"[!] 读取历史在岗节点文件失败: {e}", flush=True)
        return nodes

    def fetch_candidates(self, exclude_keys: set) -> List[Dict]:
        """多源并发抓取并归一化公网候选代理列表 (自动剔除已有节点)"""
        candidates = []
        seen = set(exclude_keys)

        for src in SOURCES:
            try:
                print(f"[*] 正在拉取数据源: {src['name']}...", flush=True)
                req = urllib.request.Request(src["url"], headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=6) as resp:
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
                    print(f"  + {src['name']} 贡献 {count} 个新候选，候选池累计: {len(candidates)}", flush=True)
            except Exception as e:
                print(f"  - 拉取 {src['name']} 失败: {e}", flush=True)

        return candidates

    def _measure_socks5_throughput(self, host: str, port: int, test_seconds: float = 1.5) -> float:
        """
        通过 SOCKS5 隧道连接 Cloudflare 测速专线进行真实数据流吞吐量测试 (返回 MB/s)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.5)
        try:
            s.connect((host, port))
            # SOCKS5 认证协商
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                return 0.0

            # CONNECT 到 speed.cloudflare.com:443
            target = b"speed.cloudflare.com"
            cmd = b"\x05\x01\x00\x03" + bytes([len(target)]) + target + (443).to_bytes(2, "big")
            s.sendall(cmd)
            rep = s.recv(10)
            if len(rep) < 2 or rep[1] != 0:
                return 0.0

            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(s, server_hostname="speed.cloudflare.com")

            # 请求 10MB 测试数据块
            tls.sendall(
                b"GET /__down?bytes=10000000 HTTP/1.1\r\n"
                b"Host: speed.cloudflare.com\r\n"
                b"User-Agent: Mozilla/5.0\r\n"
                b"Connection: close\r\n\r\n"
            )

            # 读取 HTTP 响应头
            header_data = b""
            while b"\r\n\r\n" not in header_data:
                chunk = tls.recv(1024)
                if not chunk:
                    break
                header_data += chunk

            # 开始计算纯数据下载吞吐速率
            total_bytes = 0
            t_start = time.perf_counter()
            while True:
                chunk = tls.recv(16384)
                if not chunk:
                    break
                total_bytes += len(chunk)
                t_elapsed = time.perf_counter() - t_start
                if t_elapsed >= test_seconds:
                    break

            t_elapsed = time.perf_counter() - t_start
            if t_elapsed > 0:
                speed_mb = (total_bytes / (1024 * 1024)) / t_elapsed
                return round(speed_mb, 2)
            return 0.0
        except Exception:
            return 0.0
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _sync_deep_probe(self, host: str, port: int) -> Optional[Tuple[float, str, float]]:
        """真机深度探针：握手 + TLS + HTTP trace 验真 + 真实数据吞吐量测速"""
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

            # 3. 通过 SOCKS5 隧道完成真实 TLS 握手
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(s, server_hostname="cloudflare.com")

            # 4. 发起真实 HTTP GET 验证与应用层端到端 RTT 测速
            tls.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
            data = tls.recv(1024).decode("utf-8", errors="ignore")

            if "h=cloudflare.com" in data and "ip=" in data:
                latency = round((time.perf_counter() - t0) * 1000, 1)
                loc_match = re.search(r"loc=([A-Z]{2})", data)
                loc = loc_match.group(1) if loc_match else "AUTO"
                try:
                    s.close()
                except Exception:
                    pass

                # 5. 核心追加：针对初筛存活的代理，执行第二阶段真实吞吐量带宽压测
                speed_mb = self._measure_socks5_throughput(host, port, test_seconds=1.5)
                return latency, loc, speed_mb
            return None
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass

    async def probe_candidate(self, candidate: Dict, sem: asyncio.Semaphore) -> Optional[Dict]:
        """调度线程池执行深度真机探针与吞吐测速"""
        host = candidate["host"]
        port = candidate["port"]
        country = candidate.get("country", "AUTO")

        async with sem:
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(self.executor, self._sync_deep_probe, host, port)
            if res:
                latency, loc, speed_mb = res
                final_country = loc if loc != "AUTO" else country
                speed_mbps = round(speed_mb * 8, 1)
                return {
                    "host": host,
                    "port": port,
                    "entry": f"{host}:{port}",
                    "socks_url": f"socks5://{host}:{port}",
                    "country": final_country,
                    "latency": latency,
                    "speed_mb": speed_mb,
                    "speed_mbps": speed_mbps,
                    "is_retained": candidate.get("is_retained", False)
                }
            return None

    async def scan(self) -> List[Dict]:
        survived_nodes = []
        existing_keys = set()

        # 阶段一：在岗节点优先真机复检与带宽测速 (Retention-First)
        if self.existing_file and os.path.exists(self.existing_file):
            existing_list = self.load_existing_nodes(self.existing_file)
            for item in existing_list:
                item["is_retained"] = True
                existing_keys.add(f"{item['host']}:{item['port']}")

            if existing_list:
                print(f"[*] 【在岗留任复检】检测到 {len(existing_list)} 个历史在岗节点，启动深度应用层验真与数据吞吐压测...", flush=True)
                sem = asyncio.Semaphore(self.concurrency)
                tasks = [self.probe_candidate(node, sem) for node in existing_list]
                results = await asyncio.gather(*tasks)

                for r in results:
                    if r is not None:
                        # 仅当下行带宽达标或基本合格时予以留任
                        if r["speed_mb"] >= self.min_speed_mb or r["speed_mb"] > 0.3:
                            survived_nodes.append(r)

                print(f"[+] 【复检结果】原在岗 {len(existing_list)} 个，吞吐与连通双达标留任: {len(survived_nodes)} 个，淘汰下线: {len(existing_list) - len(survived_nodes)} 个", flush=True)

        # 综合排序：吞吐量带宽最高优先，延迟最低次之
        survived_nodes.sort(key=lambda x: (-x["speed_mb"], x["latency"]))

        # 阶段二：计算缺口，按需从公网补位
        needed_count = self.target_count - len(survived_nodes)

        # 若在岗达标节点已满足，且至少有一个高带宽黄金主力（>= 1.0 MB/s 或 8 Mbps），直接零漂移闭环！
        if needed_count <= 0 and survived_nodes and survived_nodes[0]["speed_mb"] >= self.min_speed_mb:
            print(f"[+] 【零漂移闭环】在岗主力节点吞吐量达标 ({survived_nodes[0]['speed_mb']} MB/s / {survived_nodes[0]['speed_mbps']} Mbps)，保持现状，无需更换代理！", flush=True)
            return survived_nodes[:self.target_count]

        print(f"[*] 【增量补位】正在启动多源公网候选池，全力选拔高吞吐量大带宽新代理 (最低门槛: {self.min_speed_mb} MB/s)...", flush=True)
        candidates = self.fetch_candidates(exclude_keys=existing_keys)
        if not candidates:
            print("[!] 未获取到新候选代理，仅返回在岗存活节点", flush=True)
            return survived_nodes

        preferred = [c for c in candidates if c["country"] in PREFERRED_REGIONS]
        others = [c for c in candidates if c["country"] not in PREFERRED_REGIONS]

        probe_limit = min(len(candidates), max(80, needed_count * 25))
        half_limit = probe_limit // 2
        test_pool = preferred[:half_limit] + others[:(probe_limit - len(preferred[:half_limit]))]
        print(f"[*] 精选 {len(test_pool)} 个公网高质量候选进行深度验真与吞吐量压测 (并发: {self.concurrency})...", flush=True)

        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self.probe_candidate(c, sem) for c in test_pool]
        results = await asyncio.gather(*tasks)

        valid_replacements = [r for r in results if r is not None and r["speed_mb"] > 0.2]
        print(f"[*] 探测完毕！候选池产出 {len(valid_replacements)} 个测出真实下行吞吐量的活体节点", flush=True)

        # 按真实带宽由大到小排序！
        valid_replacements.sort(key=lambda x: (-x["speed_mb"], x["latency"]))

        final_pool = survived_nodes + valid_replacements
        # 全局再按吞吐带宽排序
        final_pool.sort(key=lambda x: (-x["speed_mb"], x["latency"]))

        selected = []
        seen = set()
        for node in final_pool:
            k = f"{node['host']}:{node['port']}"
            if k not in seen:
                seen.add(k)
                selected.append(node)
            if len(selected) >= self.target_count:
                break

        return selected


def main():
    parser = argparse.ArgumentParser(description="Multi-source SOCKS5 Scanner & Throughput Evaluator")
    parser.add_argument("--output", "-o", default="socks5.txt", help="输出文件路径")
    parser.add_argument("--existing-file", "-e", default=None, help="现有在岗节点文件，用于优先复检保活")
    parser.add_argument("--count", "-c", type=int, default=6, help="最终保留的最优节点数")
    parser.add_argument("--concurrency", type=int, default=80, help="并发探测协程数")
    parser.add_argument("--timeout", type=float, default=2.5, help="单节点超时时间(秒)")
    parser.add_argument("--min-speed", type=float, default=0.8, help="带宽吞吐达标门槛(MB/s，默认 0.8 MB/s ≈ 6.4 Mbps)")
    args = parser.parse_args()

    existing_file = args.existing_file
    if not existing_file and os.path.exists(args.output):
        existing_file = args.output

    scanner = Socks5Scanner(
        target_count=args.count,
        timeout=args.timeout,
        concurrency=args.concurrency,
        existing_file=existing_file,
        min_speed_mb=args.min_speed
    )

    t0 = time.time()
    best_nodes = asyncio.run(scanner.scan())
    cost = round(time.time() - t0, 2)

    print(f"\n[+] SOCKS5 吞吐压测完成！总耗时 {cost}s，总计优选出 {len(best_nodes)} 个高带宽出站中继：", flush=True)

    if len(best_nodes) < 1:
        print("[!] 警告：未探测到满足深度验真标准的 SOCKS5 活体，触发熔断保护，保留原有版本！", flush=True)
        return

    # 软备份机制
    backup_file = args.output.replace(".txt", "_backup.txt")
    if os.path.exists(args.output):
        try:
            import shutil
            shutil.copyfile(args.output, backup_file)
            print(f"[+] 已建立高可用软备份: {backup_file}", flush=True)
        except Exception as e:
            print(f"[-] 软备份失败: {e}", flush=True)

    output_lines = []
    for idx, node in enumerate(best_nodes, 1):
        status_tag = "[留任]" if node.get("is_retained") else "[替补]"
        star = "★王者主力" if idx == 1 else "  备用备选"
        line = f"{node['entry']}#{node['country']}-[socks5]"
        output_lines.append(line)
        print(f"  {idx:02d}. {star} {status_tag} {line} (吞吐带宽: {node['speed_mb']} MB/s / {node['speed_mbps']} Mbps | RTT: {node['latency']}ms)", flush=True)

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(output_lines) + "\n")

    print(f"\n[★黄金定锚] 当前锁定唯一主力出站代理: {best_nodes[0]['entry']} (带宽: {best_nodes[0]['speed_mb']} MB/s / {best_nodes[0]['speed_mbps']} Mbps)")
    print(f"[+] 结果成功保存至: {args.output}", flush=True)


if __name__ == "__main__":
    main()
