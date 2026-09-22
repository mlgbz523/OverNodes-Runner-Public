#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-source SOCKS5 Proxy Scanner & Health Evaluator (cf-bestip style)
核心机制：
1. 【存量在岗优先复检 (Retention-First)】：优先深度探测已有节点，达标继续留任，杜绝频繁漂移换IP
2. 【末位淘汰与增量补位 (Incremental Backfill)】：仅当下线/劣化产生槽位缺口时，才从多源公网池按需抓取新节点替补
3. 【1:1 真机端到端深度探针】：真实 TLS 1.3 证书握手 + HTTP GET /cdn-cgi/trace 应用层双重校验，彻底杜绝假活
4. 【独占高并发线程池加速】：突破 Python 默认线程池 32 限制，实现秒级高并发网络验真
5. 【纯净命名规范】：统一采用 [socks5] 纯净标识，杜绝虚荣假延迟尾缀
6. 【熔断防御与软备份】：自动轮转快照，空活体自动熔断拒绝覆写
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
    def __init__(self, target_count: int = 12, timeout: float = 2.5, concurrency: int = 80, existing_file: Optional[str] = None):
        self.target_count = target_count
        self.timeout = timeout
        self.concurrency = concurrency
        self.existing_file = existing_file
        # 独占自定义线程池，规避默认全局线程池仅 12~32 个 worker 的并发瓶颈
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

    async def probe_candidate(self, candidate: Dict, sem: asyncio.Semaphore) -> Optional[Dict]:
        """调度线程池执行深度真机探针"""
        host = candidate["host"]
        port = candidate["port"]
        country = candidate.get("country", "AUTO")

        async with sem:
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(self.executor, self._sync_deep_probe, host, port)
            if res:
                latency, loc = res
                final_country = loc if loc != "AUTO" else country
                return {
                    "host": host,
                    "port": port,
                    "entry": f"{host}:{port}",
                    "socks_url": f"socks5://{host}:{port}",
                    "country": final_country,
                    "latency": latency,
                    "is_retained": candidate.get("is_retained", False)
                }
            return None

    async def scan(self) -> List[Dict]:
        survived_nodes = []
        existing_keys = set()

        # 阶段一：在岗节点优先真机复检 (Retention-First)
        if self.existing_file and os.path.exists(self.existing_file):
            existing_list = self.load_existing_nodes(self.existing_file)
            for item in existing_list:
                item["is_retained"] = True
                existing_keys.add(f"{item['host']}:{item['port']}")

            if existing_list:
                print(f"[*] 【在岗留任复检】检测到 {len(existing_list)} 个历史在岗节点，启动深度应用层验真...", flush=True)
                sem = asyncio.Semaphore(self.concurrency)
                tasks = [self.probe_candidate(node, sem) for node in existing_list]
                results = await asyncio.gather(*tasks)

                for r in results:
                    if r is not None:
                        survived_nodes.append(r)

                print(f"[+] 【复检结果】原在岗 {len(existing_list)} 个，健康达标留任: {len(survived_nodes)} 个，淘汰下线: {len(existing_list) - len(survived_nodes)} 个", flush=True)

        # 计算槽位缺口
        needed_count = self.target_count - len(survived_nodes)

        # 阶段二：若在岗节点已满足目标数量，直接达成闭环，坚决不盲目轮换
        if needed_count <= 0:
            print(f"[+] 【零漂移闭环】在岗达标节点数 ({len(survived_nodes)}) 已满足目标配额 ({self.target_count})，保持现状，无需更换！", flush=True)
            survived_nodes.sort(key=lambda x: x["latency"])
            return survived_nodes[:self.target_count]

        print(f"[*] 【增量补位】当前存在 {needed_count} 个空缺槽位，正在启动多源公网候选池进行按需补位选拔...", flush=True)
        candidates = self.fetch_candidates(exclude_keys=existing_keys)
        if not candidates:
            print("[!] 未获取到新候选代理，仅返回在岗存活节点", flush=True)
            return survived_nodes

        # 优先抽取核心优质地区
        preferred = [c for c in candidates if c["country"] in PREFERRED_REGIONS]
        others = [c for c in candidates if c["country"] not in PREFERRED_REGIONS]

        # 按需动态规模：缺口 needed_count 对应小而精的高质量探测集 (约 60 ~ 150 个)
        probe_limit = min(len(candidates), max(60, needed_count * 20))
        half_limit = probe_limit // 2
        test_pool = preferred[:half_limit] + others[:(probe_limit - len(preferred[:half_limit]))]
        print(f"[*] 精选 {len(test_pool)} 个公网高质量候选进行高并发快测 (并发: {self.concurrency})...", flush=True)

        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self.probe_candidate(c, sem) for c in test_pool]
        results = await asyncio.gather(*tasks)

        valid_replacements = [r for r in results if r is not None]
        print(f"[*] 探测完毕！候选池产出 {len(valid_replacements)} 个合格活体节点", flush=True)

        # 按延迟升序排序挑选最优新节点填补槽位
        valid_replacements.sort(key=lambda x: x["latency"])

        chosen_replacements = []
        seen_countries = {node["country"]: 1 for node in survived_nodes}
        for item in valid_replacements:
            ct = item["country"]
            if seen_countries.get(ct, 0) < 3:
                chosen_replacements.append(item)
                seen_countries[ct] = seen_countries.get(ct, 0) + 1
            if len(chosen_replacements) >= needed_count:
                break

        if len(chosen_replacements) < needed_count:
            for item in valid_replacements:
                if item not in chosen_replacements:
                    chosen_replacements.append(item)
                if len(chosen_replacements) >= needed_count:
                    break

        print(f"[+] 成功补位 {len(chosen_replacements)} 个优质新节点！", flush=True)
        final_pool = survived_nodes + chosen_replacements
        final_pool.sort(key=lambda x: x["latency"])
        return final_pool


def main():
    parser = argparse.ArgumentParser(description="Multi-source SOCKS5 Scanner & Evaluator")
    parser.add_argument("--output", "-o", default="socks5.txt", help="输出文件路径")
    parser.add_argument("--existing-file", "-e", default=None, help="现有在岗节点文件，用于优先复检保活")
    parser.add_argument("--count", "-c", type=int, default=12, help="最终保留的最快节点数")
    parser.add_argument("--concurrency", type=int, default=80, help="并发探测协程数")
    parser.add_argument("--timeout", type=float, default=2.5, help="单节点超时时间(秒)")
    args = parser.parse_args()

    # 默认自动检测已有文件进行保活复检
    existing_file = args.existing_file
    if not existing_file and os.path.exists(args.output):
        existing_file = args.output

    scanner = Socks5Scanner(
        target_count=args.count,
        timeout=args.timeout,
        concurrency=args.concurrency,
        existing_file=existing_file
    )

    t0 = time.time()
    best_nodes = asyncio.run(scanner.scan())
    cost = round(time.time() - t0, 2)

    print(f"\n[+] SOCKS5 治理完成！总耗时 {cost}s，总计就位 {len(best_nodes)} 个稳定出站中继：", flush=True)

    # 熔断防御：如果深度探测活体不足，拒绝将空文件写入生产
    if len(best_nodes) < 1:
        print("[!] 警告：未探测到满足深度验真标准的 SOCKS5 活体，触发熔断保护，保留原有版本！", flush=True)
        return

    # 软备份机制：自动维护上一代高可用快照
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
        line = f"{node['entry']}#{node['country']}-[socks5]"
        output_lines.append(line)
        print(f"  {idx:02d}. {status_tag} {line} (RTT: {node['latency']}ms)", flush=True)

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(output_lines) + "\n")

    print(f"[+] 结果成功保存至: {args.output}", flush=True)


if __name__ == "__main__":
    main()
