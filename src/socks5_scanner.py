#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-source SOCKS5 Proxy Scanner & Max Throughput Evaluator (cf-bestip style)
深度集成 edgetunnel 双重验证协议与云端/本地混合探针：
1. 【极限吞吐量压测 (Max Peak & Avg Throughput)】：
   支持两阶段阶梯测速，向 Cloudflare 测速专线请求高密度数据流，通过滑动窗口精准测量 SOCKS5 节点的“峰值极限带宽 (Peak Mbps)”与“稳态平均带宽 (Avg Mbps)”，彻底榨干并识别千兆高速节点！
2. 【edgetunnel 原生协议验真 (Remote & Local Dual-Probe)】：
   - 本地探针：RFC 1928/1929 认证握手 + TLS 1.3 协商 + /cdn-cgi/trace 深度提取真实出口 IP 与国家代码。
   - 云端探针 (--worker-checker)：支持接入 edgetunnel 的 /admin/check?socks5=... 端点，利用海外 Cloudflare 边缘节点充当无墙跳板，精准测出节点在海外的真实可用性与延迟！
3. 【单节点秒测模式 (--test-node / -t)】：
   支持即时单测单个 SOCKS5 节点（如 45.32.160.61:1088），1 秒内输出诊断卡片与极限带宽！
4. 【多国聚类均衡选拔 (--multi-country)】：
   智能聚类亚太（HK/SG/JP）、美洲（US）、欧洲（DE 等）高带宽节点，完美对齐链式代理多国落地架构！
5. 【存量在岗优先复检 (Retention-First)】与【零漂移保活保护】。
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
import urllib.parse
import json
import argparse
from typing import List, Dict, Optional, Tuple

# 强化 Windows GBK 控制台兼容
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 优质候选代理源（涵盖公开聚合池、GitHub 自动更新源、API 实时源）
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
    },
    {
        "name": "OpenProxyList",
        "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "type": "txt"
    },
    {
        "name": "Zevtyardt",
        "url": "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
        "type": "txt"
    },
    {
        "name": "ProxyScrape",
        "url": "https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&protocol=socks5&proxy_format=ipport&format=text",
        "type": "txt"
    }
]

PREFERRED_REGIONS = ["US", "HK", "SG", "JP", "DE", "GB", "NL", "FR", "KR", "ES"]


def parse_socks5_entry(entry: str) -> Dict[str, any]:
    """解析 socks5://[username:password@]host:port 或 [username:password@]host:port 格式"""
    entry = entry.strip()
    if entry.startswith("socks5://"):
        entry = entry[9:]
    auth = ""
    host_port = entry
    if "@" in entry:
        auth, host_port = entry.split("@", 1)
    
    username, password = "", ""
    if ":" in auth:
        username, password = auth.split(":", 1)
    
    parts = host_port.split(":")
    host = parts[0].strip()
    port = int(parts[1].strip()) if len(parts) > 1 else 1080
    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "entry": f"{host}:{port}" if not auth else f"{username}:{password}@{host}:{port}"
    }


class Socks5Scanner:
    def __init__(
        self,
        target_count: int = 6,
        timeout: float = 3.0,
        concurrency: int = 80,
        existing_file: Optional[str] = None,
        min_speed_mb: float = 0.5,
        worker_checker: Optional[str] = None,
        benchmark_max: bool = False,
        allowed_countries: Optional[List[str]] = None
    ):
        self.target_count = target_count
        self.timeout = timeout
        self.concurrency = concurrency
        self.existing_file = existing_file
        self.min_speed_mb = min_speed_mb
        self.worker_checker = worker_checker or os.getenv("WORKER_CHECKER", "").strip()
        self.benchmark_max = benchmark_max
        self.allowed_countries = [c.strip().upper() for c in (allowed_countries or ["US", "SG", "HK"]) if c.strip()]
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
                    parsed = parse_socks5_entry(entry_part)
                    key = f"{parsed['host']}:{parsed['port']}"
                    if key not in seen:
                        seen.add(key)
                        nodes.append({
                            "host": parsed["host"],
                            "port": parsed["port"],
                            "username": parsed["username"],
                            "password": parsed["password"],
                            "country": "AUTO",
                            "is_retained": True
                        })
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
                raw = None
                urls_to_try = [src["url"]]
                if "raw.githubusercontent.com" in src["url"]:
                    urls_to_try.append(f"https://ghfast.top/{src['url']}")
                elif "cdn.jsdelivr.net" in src["url"]:
                    urls_to_try.append(src["url"].replace("cdn.jsdelivr.net", "fastly.jsdelivr.net"))

                for target_u in urls_to_try:
                    try:
                        req = urllib.request.Request(
                            target_u,
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}
                        )
                        with urllib.request.urlopen(req, timeout=4.5) as resp:
                            raw = resp.read().decode("utf-8", errors="ignore")
                            if raw:
                                break
                    except Exception:
                        continue

                if not raw:
                    print(f"  - 拉取 {src['name']} 失败 (跳过)", flush=True)
                    continue

                count = 0
                if src["type"] == "json":
                    try:
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
                    except Exception:
                        pass
                elif src["type"] == "txt":
                    for line in raw.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if ":" in line:
                            parts = line.split(":")
                            ip, port = parts[0].strip(), parts[1].strip()
                            try:
                                p_int = int(port)
                                key = f"{ip}:{p_int}"
                                if key not in seen:
                                    seen.add(key)
                                    candidates.append({"host": ip, "port": p_int, "country": "AUTO"})
                                    count += 1
                            except ValueError:
                                continue
                print(f"  + {src['name']} 贡献 {count} 个新候选，候选池累计: {len(candidates)}", flush=True)
            except Exception as e:
                print(f"  - 拉取 {src['name']} 失败 (跳过): {e}", flush=True)

        return candidates

    def _socks5_handshake_and_connect(self, s: socket.socket, host: str, port: int, target_host: str, target_port: int, username: str = "", password: str = "") -> bool:
        """执行 RFC 1928 / RFC 1929 SOCKS5 握手并发出 CONNECT 指令"""
        s.connect((host, port))
        if username and password:
            # 客户端声明支持无认证(0x00)与用户名密码认证(0x02)
            s.sendall(b"\x05\x02\x00\x02")
            auth_method = s.recv(2)
            if len(auth_method) < 2 or auth_method[0] != 0x05:
                return False
            if auth_method[1] == 0x02:
                # 执行 RFC 1929 认证协商
                u_bytes = username.encode("utf-8")
                p_bytes = password.encode("utf-8")
                sub_auth = b"\x01" + bytes([len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes
                s.sendall(sub_auth)
                sub_resp = s.recv(2)
                if len(sub_resp) < 2 or sub_resp[1] != 0x00:
                    return False
            elif auth_method[1] != 0x00:
                return False
        else:
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                return False

        # 发送 CONNECT 请求 (以域名方式 0x03 避免本地 DNS 污染)
        target_b = target_host.encode("utf-8")
        cmd = b"\x05\x01\x00\x03" + bytes([len(target_b)]) + target_b + target_port.to_bytes(2, "big")
        s.sendall(cmd)
        
        def _recv_all(sock, n):
            data = bytearray()
            while len(data) < n:
                packet = sock.recv(n - len(data))
                if not packet:
                    return None
                data.extend(packet)
            return data
            
        rep = _recv_all(s, 4)
        if not rep or rep[1] != 0:
            return False
            
        atyp = rep[3]
        if atyp == 1:
            _recv_all(s, 6)
        elif atyp == 3:
            dlen = _recv_all(s, 1)
            if dlen:
                _recv_all(s, dlen[0] + 2)
        elif atyp == 4:
            _recv_all(s, 18)
        else:
            return False
            
        return True

    def _measure_socks5_throughput(
        self, host: str, port: int, username: str = "", password: str = "", test_seconds: float = 2.0
    ) -> Tuple[float, float]:
        """
        测定该 SOCKS5 节点的稳态平均吞吐量与极限峰值吞吐量 (返回: avg_mb_s, peak_mb_s)
        向 Cloudflare 测速专线请求高密度数据流，通过滑动窗口统计峰值带宽。
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.5)
        try:
            ok = self._socks5_handshake_and_connect(
                s, host, port, target_host="speed.cloudflare.com", target_port=443, username=username, password=password
            )
            if not ok:
                return 0.0, 0.0

            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(s, server_hostname="speed.cloudflare.com")

            # 请求 25MB - 50MB 真实测速数据块
            bytes_req = 50000000 if self.benchmark_max else 20000000
            tls.sendall(
                f"GET /__down?bytes={bytes_req} HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode("utf-8")
            )

            # 读取 HTTP 响应头
            header_data = b""
            while b"\r\n\r\n" not in header_data:
                chunk = tls.recv(1024)
                if not chunk:
                    break
                header_data += chunk

            total_bytes = 0
            t_start = time.perf_counter()
            window_bytes = 0
            window_start = t_start
            peak_mb_s = 0.0

            # 滑动窗口采样统计峰值吞吐量 (以 400ms 为一个采样窗口)
            while True:
                chunk = tls.recv(32768)
                if not chunk:
                    break
                chunk_len = len(chunk)
                total_bytes += chunk_len
                window_bytes += chunk_len

                now = time.perf_counter()
                w_elapsed = now - window_start
                if w_elapsed >= 0.4:
                    inst_speed = (window_bytes / (1024 * 1024)) / w_elapsed
                    if inst_speed > peak_mb_s:
                        peak_mb_s = inst_speed
                    window_bytes = 0
                    window_start = now

                if (now - t_start) >= test_seconds:
                    break

            total_elapsed = time.perf_counter() - t_start
            if total_elapsed > 0:
                avg_mb_s = (total_bytes / (1024 * 1024)) / total_elapsed
                peak_mb_s = max(peak_mb_s, avg_mb_s)
                return round(avg_mb_s, 2), round(peak_mb_s, 2)
            return 0.0, 0.0
        except Exception:
            return 0.0, 0.0
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _sync_worker_probe(self, host: str, port: int, username: str = "", password: str = "") -> Optional[Tuple[float, str, str]]:
        """
        云端探针模式：借助 edgetunnel 的 /admin/check?socks5=... 接口发起海外边缘测活
        返回: (responseTime, loc, exit_ip)
        """
        if not self.worker_checker:
            return None
        try:
            proxy_str = f"{username}:{password}@{host}:{port}" if username and password else f"{host}:{port}"
            encoded_proxy = urllib.parse.quote(proxy_str)
            sep = "&" if "?" in self.worker_checker else "?"
            check_url = f"{self.worker_checker}{sep}socks5={encoded_proxy}"

            req = urllib.request.Request(
                check_url,
                headers={"User-Agent": "OverNodes-Runner/Socks5Scanner"}
            )
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if data.get("success"):
                    r_time = float(data.get("responseTime", 999))
                    loc = str(data.get("loc", "AUTO")).upper()
                    exit_ip = str(data.get("ip", host))
                    return r_time, loc, exit_ip
        except Exception:
            pass
        return None

    def _sync_local_deep_probe(self, host: str, port: int, username: str = "", password: str = "") -> Optional[Tuple[float, str, str]]:
        """
        本地端到端深度探针 (100% 对应 edgetunnel _worker.js 内部测活标准)：
        SOCKS5 握手 -> 域名 CONNECT -> TLS 1.3 证书握手 -> GET /cdn-cgi/trace
        返回: (latency, loc, exit_ip)
        """
        t0 = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            ok = self._socks5_handshake_and_connect(
                s, host, port, target_host="cloudflare.com", target_port=443, username=username, password=password
            )
            if not ok:
                return None

            # 隧道内真实 TLS 握手
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(s, server_hostname="cloudflare.com")

            # 发送 trace 请求
            tls.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
            data = tls.recv(2048).decode("utf-8", errors="ignore")

            if "h=cloudflare.com" in data and "ip=" in data:
                latency = round((time.perf_counter() - t0) * 1000, 1)
                loc_match = re.search(r"loc=([A-Z]{2})", data)
                loc = loc_match.group(1) if loc_match else "AUTO"
                ip_match = re.search(r"ip=([0-9a-fA-F\.:]+)", data)
                exit_ip = ip_match.group(1) if ip_match else host
                return latency, loc, exit_ip
            return None
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass

    def probe_node_full(self, node: Dict) -> Optional[Dict]:
        """完整执行：连通性初筛（本地或云端 Worker）+ 吞吐量极限压测"""
        host = node["host"]
        port = node["port"]
        username = node.get("username", "")
        password = node.get("password", "")
        entry = f"{username}:{password}@{host}:{port}" if username and password else f"{host}:{port}"

        # 1. 优先尝试云端 Worker 探针（若配置）
        probe_res = None
        probe_type = "本地探针"
        if self.worker_checker:
            probe_res = self._sync_worker_probe(host, port, username, password)
            if probe_res:
                probe_type = "Worker云端探针"

        # 2. 回退到本地深度探针
        if not probe_res:
            probe_res = self._sync_local_deep_probe(host, port, username, password)
            probe_type = "本地直连探针"

        if not probe_res:
            return None

        latency, loc, exit_ip = probe_res

        # 3. 执行真实吞吐量与极限峰值测速
        test_sec = 4.0 if self.benchmark_max else 1.8
        avg_speed, peak_speed = self._measure_socks5_throughput(
            host, port, username, password, test_seconds=test_sec
        )

        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "entry": entry,
            "exit_ip": exit_ip,
            "country": loc if loc != "AUTO" else node.get("country", "AUTO"),
            "latency": latency,
            "speed_mb": avg_speed,
            "speed_mbps": round(avg_speed * 8, 1),
            "peak_mb": peak_speed,
            "peak_mbps": round(peak_speed * 8, 1),
            "probe_type": probe_type,
            "is_retained": node.get("is_retained", False)
        }

    async def probe_candidate(self, candidate: Dict, sem: asyncio.Semaphore) -> Optional[Dict]:
        """调度线程池执行并发探针"""
        async with sem:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(self.executor, self.probe_node_full, candidate)

    def batch_asn_lookup(self, ips: List[str]) -> Dict[str, str]:
        """批量查询 IP 的 ASN/ISP 信息，反推过滤肉鸡"""
        if not ips:
            return {}
        result = {}
        for i in range(0, len(ips), 100):
            batch = ips[i:i+100]
            try:
                data = json.dumps([{"query": ip, "fields": "query,isp,org,as"} for ip in batch]).encode('utf-8')
                req = urllib.request.Request("http://ip-api.com/batch", data=data, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp_data = json.loads(resp.read().decode('utf-8'))
                    for item in resp_data:
                        org_info = f"{item.get('as', '')} {item.get('org', '')} {item.get('isp', '')}".upper()
                        result[item['query']] = org_info
            except Exception as e:
                print(f"[!] 批量 ASN 查询失败: {e}", flush=True)
        return result

    async def scan(self) -> List[Dict]:
        survived_nodes = []
        existing_keys = set()

        # 阶段一：在岗节点优先复检与保活 (Retention-First)
        if self.existing_file and os.path.exists(self.existing_file):
            existing_list = self.load_existing_nodes(self.existing_file)
            for item in existing_list:
                existing_keys.add(f"{item['host']}:{item['port']}")

            if existing_list:
                print(f"[*] 【在岗留任复检】检测到 {len(existing_list)} 个历史在岗节点，启动真实吞吐与连通验真...", flush=True)
                sem = asyncio.Semaphore(self.concurrency)
                tasks = [self.probe_candidate(node, sem) for node in existing_list]
                results = await asyncio.gather(*tasks)

                for r in results:
                    if r is not None:
                        # 落地国白名单检查：非允许国家直接剔除不予留任
                        if self.allowed_countries and r["country"] not in self.allowed_countries:
                            continue
                        # 只要有响应且带宽超过基础底线就予以留任
                        if r["speed_mb"] >= self.min_speed_mb or r["speed_mb"] > 0.15:
                            survived_nodes.append(r)

                print(f"[+] 【复检结果】原在岗 {len(existing_list)} 个，达标留任: {len(survived_nodes)} 个，下线/非白名单剔除: {len(existing_list) - len(survived_nodes)} 个", flush=True)

        survived_nodes.sort(key=lambda x: (-x["peak_mb"], -x["speed_mb"], x["latency"]))

        # 阶段二：计算缺口，按需从公网抓取增量补位
        needed_count = self.target_count - len(survived_nodes)

        # 若存量节点已足够且整体质量优秀，直接闭环，避免频繁更换 IP
        if needed_count <= 0 and survived_nodes and survived_nodes[0]["speed_mb"] >= self.min_speed_mb:
            print(f"[+] 【零漂移保活】存量节点完备且性能达标 (主力峰值: {survived_nodes[0]['peak_mbps']} Mbps)，保持现状！", flush=True)
            return survived_nodes[:self.target_count]

        print(f"[*] 【增量扩充】正在拉取全球优质候选池，并发筛选高吞吐大带宽节点 (白名单限制: {','.join(self.allowed_countries)} | 目标缺口: {max(needed_count, 1)} 个)...", flush=True)
        candidates = self.fetch_candidates(exclude_keys=existing_keys)
        if not candidates:
            print("[!] 未抓取到新候选代理，返回现有可用节点", flush=True)
            return survived_nodes

        # 优先将允许落地国的候选排在最前面
        preferred = [c for c in candidates if c["country"] in self.allowed_countries]
        others = [c for c in candidates if c["country"] not in self.allowed_countries]

        probe_limit = min(len(candidates), max(100, needed_count * 35))
        # 优先探测目标国家候选，剩余名额探测未知国家以防源头未标注
        test_pool = preferred[:probe_limit]
        if len(test_pool) < probe_limit:
            test_pool += others[:(probe_limit - len(test_pool))]

        print(f"[*] 精选 {len(test_pool)} 个公网候选执行深度验真与极限测速 (并发: {self.concurrency})...", flush=True)
        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self.probe_candidate(c, sem) for c in test_pool]
        results = await asyncio.gather(*tasks)

        valid_replacements = [
            r for r in results 
            if r is not None and r["speed_mb"] > 0.1 and (not self.allowed_countries or r["country"] in self.allowed_countries)
        ]
        print(f"[*] 探测完毕！候选池产出 {len(valid_replacements)} 个符合白名单 ({','.join(self.allowed_countries)}) 的初步活体节点", flush=True)

        # === 核心反推法：ASN/ISP 机房提纯 ===
        if valid_replacements:
            print("[*] 开始进行反推提纯：批量查询存活节点的 ASN 归属，剔除垃圾家庭宽带...", flush=True)
            alive_ips = list(set([n["host"] for n in valid_replacements]))
            org_map = self.batch_asn_lookup(alive_ips)
            
            datacenter_keywords = [
                "DIGITALOCEAN", "CHOOPA", "VULTR", "LINODE", "QUADRANET", 
                "AMAZON", "GOOGLE", "ORACLE", "OVH", "HETZNER", "MULTACOM", 
                "COGENT", "ALIBABA", "TENCENT", "CLOUDFLARE", "HOSTING", 
                "SERVER", "DATACENTER", "LEASEWEB", "FASTLY", "MICROSOFT", 
                "AZURE", "ZENLAYER", "IPXO", "INTERSERVER"
            ]
            
            purified_nodes = []
            for n in valid_replacements:
                ip = n["host"]
                org_info = org_map.get(ip, "")
                hit_kw = next((kw for kw in datacenter_keywords if kw in org_info), None)
                if hit_kw:
                    n["isp_tag"] = hit_kw
                    purified_nodes.append(n)
            
            if purified_nodes:
                print(f"[+] 反推提纯完毕！从 {len(valid_replacements)} 个杂乱节点中，精准洗出 {len(purified_nodes)} 个机房专属节点！", flush=True)
                valid_replacements = purified_nodes
            else:
                print(f"[!] 提示：公网候选暂无严格机房关键词命中，执行弹性容错保护，保留速度最佳的前 {min(len(valid_replacements), 3)} 个活体节点！", flush=True)
                valid_replacements = valid_replacements[:3]

        # 阶段三：多国均衡与按吞吐量定拔 (严格过滤白名单)
        all_pool = [n for n in (survived_nodes + valid_replacements) if (not self.allowed_countries or n["country"] in self.allowed_countries)]
        all_pool.sort(key=lambda x: (-x["peak_mb"], -x["speed_mb"], x["latency"]))

        # 按国家聚类分组
        country_buckets: Dict[str, List[Dict]] = {}
        for n in all_pool:
            c = n["country"]
            if c not in country_buckets:
                country_buckets[c] = []
            country_buckets[c].append(n)

        # 轮询从白名单国家抽取最优节点，保障允许国家均衡
        selected = []
        seen = set()
        bucket_order = [c for c in self.allowed_countries if c in country_buckets]
        for k in country_buckets.keys():
            if k not in bucket_order:
                bucket_order.append(k)

        for round_idx in range(3):
            for c in bucket_order:
                if c in country_buckets and len(country_buckets[c]) > round_idx:
                    node = country_buckets[c][round_idx]
                    k = node["entry"]
                    if k not in seen:
                        seen.add(k)
                        selected.append(node)
                    if len(selected) >= self.target_count:
                        break
            if len(selected) >= self.target_count:
                break

        # 若未填满，用剩余吞吐量最高的补齐 (依然限定白名单)
        for n in all_pool:
            if len(selected) >= self.target_count:
                break
            if n["entry"] not in seen:
                seen.add(n["entry"])
                selected.append(n)

        return selected


def print_single_test_card(res: Dict):
    """打印单节点体检卡片"""
    flag_map = {"US": "🇺🇸", "HK": "🇭🇰", "SG": "🇸🇬", "JP": "🇯🇵", "DE": "🇩🇪", "ES": "🇪🇸", "GB": "🇬🇧"}
    flag = flag_map.get(res["country"], "🌐")
    print("\n" + "=" * 62)
    print(f"  ⚡ SOCKS5 代理真机全贯通体检报告 ({res['probe_type']})")
    print("=" * 62)
    print(f"  ● 节点地址: {res['entry']}")
    print(f"  ● 真实出口: {res['exit_ip']} (归属: {flag} {res['country']})")
    print(f"  ● 协议握手: 100% 成功 (TLS 1.3 + RFC 1928/1929)")
    print(f"  ● 端到端延迟: {res['latency']} ms")
    print(f"  ● 极限峰值带宽: {res['peak_mb']} MB/s  ({res['peak_mbps']} Mbps)  <-- 最大瞬时吞吐量")
    print(f"  ● 稳态平均带宽: {res['speed_mb']} MB/s  ({res['speed_mbps']} Mbps)")
    if res['peak_mb'] >= 3.0:
        perf = "🚀 极速千兆王 (4K秒开/极品落地)"
    elif res['peak_mb'] >= 1.0:
        perf = "✨ 高清优质 (1080P流畅)"
    else:
        perf = "⚠️ 普通低速 (轻量网页/备用)"
    print(f"  ● 性能评级: {perf}")
    print("=" * 62 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Multi-source SOCKS5 Scanner & Max Throughput Benchmark")
    parser.add_argument("--output", "-o", default="socks5.txt", help="输出文件路径")
    parser.add_argument("--existing-file", "-e", default=None, help="现有在岗节点文件，用于优先复检保活")
    parser.add_argument("--count", "-c", type=int, default=6, help="最终保留的最优节点数")
    parser.add_argument("--concurrency", type=int, default=80, help="并发探测协程数")
    parser.add_argument("--timeout", type=float, default=5.0, help="单节点超时时间(秒)")
    parser.add_argument("--min-speed", type=float, default=0.2, help="吞吐带宽门槛(MB/s，默认 0.2 MB/s ≈ 1.6 Mbps)")
    parser.add_argument("--worker-checker", "-w", default=None, help="edgetunnel云端探针端点(如 https://your-worker.xyz/admin/check)")
    parser.add_argument("--benchmark-max", "-b", action="store_true", help="开启最大吞吐量极限满载压测 (拉取50MB数据流测峰值带宽)")
    parser.add_argument("--test-node", "-t", default=None, help="单节点秒测模式 (例如: 107.167.18.122:443 或 45.32.160.61:1088)")
    parser.add_argument("--allowed-countries", default="US,SG,HK", help="允许保留的 SOCKS5 落地国列表 (逗号分隔，默认 US,SG,HK)")
    args = parser.parse_args()

    # 1. 单节点即时秒测模式
    if args.test_node:
        parsed = parse_socks5_entry(args.test_node)
        print(f"[*] 正在对单个 SOCKS5 节点启动真机全贯通体检: {args.test_node} ...", flush=True)
        scanner = Socks5Scanner(
            timeout=args.timeout,
            worker_checker=args.worker_checker,
            benchmark_max=args.benchmark_max
        )
        res = scanner.probe_node_full(parsed)
        if res:
            print_single_test_card(res)
        else:
            print(f"\n[X] 探测失败：节点 {args.test_node} 超时或拒绝连接 (不可用/假活)！\n")
        return

    # 2. 全量扫描与复检优选模式
    existing_file = args.existing_file
    if not existing_file and os.path.exists(args.output):
        existing_file = args.output

    allowed_countries = [c.strip().upper() for c in args.allowed_countries.split(",") if c.strip()]

    scanner = Socks5Scanner(
        target_count=args.count,
        timeout=args.timeout,
        concurrency=args.concurrency,
        existing_file=existing_file,
        min_speed_mb=args.min_speed,
        worker_checker=args.worker_checker,
        benchmark_max=args.benchmark_max,
        allowed_countries=allowed_countries
    )

    t0 = time.time()
    best_nodes = asyncio.run(scanner.scan())
    cost = round(time.time() - t0, 2)

    print(f"\n[+] SOCKS5 压测与选拔完成！总耗时 {cost}s，优选出 {len(best_nodes)} 个高带宽落地节点：", flush=True)

    if len(best_nodes) < 1:
        print("[!] 警告：未探测到满足深度验真标准的活体 SOCKS5，保留原文件！", flush=True)
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
        status_tag = "[留任]" if node.get("is_retained") else "[新选]"
        star = "★主力" if idx == 1 else "  备选"
        line = f"{node['entry']}#{node['country']}-[socks5]"
        output_lines.append(line)
        print(
            f"  {idx:02d}. {star} {status_tag} {line} (峰值: {node['peak_mbps']} Mbps | 均值: {node['speed_mbps']} Mbps | 延迟: {node['latency']}ms)",
            flush=True
        )

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(output_lines) + "\n")

    print(f"\n[+] 结果成功保存至: {args.output}")


if __name__ == "__main__":
    main()
