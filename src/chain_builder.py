#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OverNode Multi-Country Chain Assembler (多国 SOCKS5 落地 × CF 直连双轨装配引擎)

核心架构：
1. 【CF 优选直连节点 (CF-Direct)】：
   - 从 Actions 优选入站文件读取所有地区的低延迟 CF IP，按地区分组。
   - 命名规范：🇸🇬 SG-直连-[01]:443、🇺🇸 US-直连-[01]:2053、🇩🇪 DE-直连-[01]:443
   - 纯 Cloudflare 反代直出，出口为 CF 机房所在国，大带宽、低延迟、适合流媒体与下载。

2. 【SOCKS5 链式落地节点 (S5-Chain)】：
   - 读取 socks5.txt 全部验活代理（多国 US/GB/NL/CH/...），按 SOCKS5 落地国分组。
   - 每个 SOCKS5 与多个 CF 优选 IP × 多端口组装链式节点。
   - 命名以 **SOCKS5 落地国** 为准：🇺🇸 US-S5-[01]:443、🇬🇧 GB-S5-[01]:2053
   - 链式中继确保出口为 SOCKS5 所在国的真实固定 IP，适合 AI/地区锁定业务。

3. 【命名规范】：
   - 直连节点：{flag} {CC}-直连-[{rank}]:{port}
   - 链式节点：{flag} {socks5_CC}-S5-[{rank}]:{port}
   - 其中 CC 为 SOCKS5 落地国家代码，rank 为该国内的 SOCKS5 序号
"""

import os
import sys
import re
import socket
import argparse
import shutil
import time
from typing import List, Dict, Tuple, Optional
from collections import OrderedDict

# 终端 UTF-8 保障
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# 常用标准 Cloudflare 端口矩阵
DEFAULT_PORTS = [443, 2053, 2083, 2087, 2096, 8443]

# 国旗 Emoji 映射
FLAG_MAP = {
    "US": "🇺🇸", "GB": "🇬🇧", "NL": "🇳🇱", "CH": "🇨🇭", "DE": "🇩🇪",
    "SG": "🇸🇬", "JP": "🇯🇵", "HK": "🇭🇰", "KR": "🇰🇷", "FR": "🇫🇷",
    "IN": "🇮🇳", "AU": "🇦🇺", "CA": "🇨🇦", "BR": "🇧🇷", "ES": "🇪🇸",
    "IT": "🇮🇹", "SE": "🇸🇪", "NO": "🇳🇴", "FI": "🇫🇮", "PL": "🇵🇱",
    "CZ": "🇨🇿", "AT": "🇦🇹", "IE": "🇮🇪", "BE": "🇧🇪", "DK": "🇩🇰",
    "TW": "🇹🇼", "TH": "🇹🇭", "VN": "🇻🇳", "RU": "🇷🇺", "BG": "🇧🇬",
}

def get_flag(cc: str) -> str:
    return FLAG_MAP.get(cc.upper(), "🌐")


def test_ip_latency(ip: str, port: int = 443, timeout: float = 1.2) -> float:
    """快速探测主机连通性与 TCP 握手延迟 (ms)，若超时返回 9999.0"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    start = time.perf_counter()
    try:
        s.connect((ip, port))
        lat = (time.perf_counter() - start) * 1000.0
        return lat
    except Exception:
        return 9999.0
    finally:
        s.close()


def parse_actions_inbound(filepath: str, inbound_regions: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
    """
    读取 Actions 优选文件（支持逗号分隔多文件），
    按国家/地区分组归类，每地区保留延迟最低的前 2 个主机 (严格限制入站地区白名单)
    """
    valid_regions = set(r.strip().upper() for r in inbound_regions) if inbound_regions else None
    raw_paths = [p.strip() for p in filepath.split(",") if p.strip()]
    valid_files = []
    for p in raw_paths:
        if os.path.exists(p):
            valid_files.append(p)
        elif os.path.exists(os.path.basename(p)):
            valid_files.append(os.path.basename(p))
        elif os.path.exists(os.path.join("public_repo", os.path.basename(p))):
            valid_files.append(os.path.join("public_repo", os.path.basename(p)))
        else:
            print(f"[!] 找不到指定入站节点文件: {p}")

    if not valid_files:
        print(f"[!] 错误: 所有指定的入站节点文件均不存在: {filepath}")
        return {}

    # 按地区归类 IP 与其端口
    ip_order: Dict[str, List[str]] = {}  # region -> [ip1, ip2, ...]
    ip_ports: Dict[str, Dict[str, List[int]]] = {}  # region -> {ip: [port1, port2, ...]}

    for fpath in valid_files:
        print(f"[*] 正在载入入站优选节点: {fpath}")
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("#")
                entry = parts[0].strip()
                tag = parts[1].strip() if len(parts) > 1 else ""

                if ":" in entry:
                    ip, port_str = entry.split(":")
                    try:
                        port = int(port_str)
                    except ValueError:
                        continue

                    # 从 tag 中提取国家代码 (前两个大写字母)
                    region_match = re.match(r"^(?:🇸🇬|🇺🇸|🇩🇪|🇬🇧|🇯🇵|🇭🇰|🇰🇷|🇫🇷|🌐)?\s*([A-Z]{2})", tag)
                    region = region_match.group(1).upper() if region_match else None

                    if region:
                        if valid_regions and region not in valid_regions:
                            continue
                        if region not in ip_order:
                            ip_order[region] = []
                            ip_ports[region] = {}
                        if ip not in ip_order[region]:
                            ip_order[region].append(ip)
                            ip_ports[region][ip] = []
                        if port not in ip_ports[region][ip]:
                            ip_ports[region][ip].append(port)

    # 针对每个地区，对 IP 进行健康优选（挑选延迟最低的前 2 台主机）
    by_region: Dict[str, List[Dict]] = {}
    for region in sorted(ip_order.keys()):
        candidates = ip_order[region]
        scored_ips = []
        for ip in candidates:
            lat = test_ip_latency(ip, 443)
            scored_ips.append((ip, lat))
            print(f"  [{region}] 主机 {ip} 连通探测延迟: {lat:.1f}ms")

        scored_ips.sort(key=lambda x: x[1])

        healthy_ips = [item[0] for item in scored_ips if item[1] < 9999.0]
        if len(healthy_ips) < 2:
            for item in scored_ips:
                if item[0] not in healthy_ips:
                    healthy_ips.append(item[0])
                if len(healthy_ips) >= 2:
                    break

        selected_ips = healthy_ips[:2]
        by_region[region] = []

        for rank, ip in enumerate(selected_ips, 1):
            existing_p = ip_ports[region].get(ip, [])
            all_ports = sorted(list(set(existing_p if existing_p else DEFAULT_PORTS)))
            by_region[region].append({
                "ip": ip,
                "rank": rank,
                "ports": all_ports
            })
            print(f"  + [{region}] 锁定主机 [{rank:02d}]: {ip} (承载端口数: {len(all_ports)})")

    return by_region


def parse_socks5_file(filepath: str, allowed_countries: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
    """
    解析 socks5.txt 中所有代理节点，按落地国家分组 (仅保留允许的国家)。
    返回: {country_code: [{host, port, username, password, entry}, ...]}
    """
    allowed_set = set(c.strip().upper() for c in allowed_countries) if allowed_countries else None
    target_path = filepath
    if not os.path.exists(target_path):
        if os.path.exists(os.path.basename(target_path)):
            target_path = os.path.basename(target_path)
        else:
            print(f"[!] SOCKS5 代理文件不存在: {filepath}")
            return {}

    by_country: Dict[str, List[Dict]] = {}
    with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("#")
            entry_part = parts[0].strip()
            tag = parts[1].strip() if len(parts) > 1 else ""

            # 提取国家代码和机房信息
            # 格式: US-QUADRANET-[socks5]
            country_match = re.match(r"^([A-Z]{2})", tag)
            country = country_match.group(1).upper() if country_match else "UN"
            
            isp_match = re.match(r"^[A-Z]{2}-([A-Z0-9_]+)-", tag)
            isp = isp_match.group(1) if isp_match else "S5"

            # 严格国家白名单过滤
            if allowed_set and country not in allowed_set:
                continue

            # 解析 host:port (支持 user:pass@host:port)
            auth = ""
            host_port = entry_part
            if entry_part.startswith("socks5://"):
                entry_part = entry_part[9:]
            if "@" in entry_part:
                auth, host_port = entry_part.split("@", 1)

            username, password = "", ""
            if ":" in auth:
                username, password = auth.split(":", 1)

            hp_parts = host_port.split(":")
            host = hp_parts[0].strip()
            port = int(hp_parts[1].strip()) if len(hp_parts) > 1 else 1080

            proxy_entry = f"{host}:{port}" if not auth else f"{username}:{password}@{host}:{port}"

            if country not in by_country:
                by_country[country] = []
            by_country[country].append({
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "entry": proxy_entry,
                "isp": isp
            })

    for cc, proxies in by_country.items():
        print(f"[+] SOCKS5 落地国 [{cc}]: {len(proxies)} 个代理节点")
        for i, p in enumerate(proxies, 1):
            print(f"    {get_flag(cc)} [{i:02d}] {p['entry']}")

    return by_country


def assemble_chains(
    by_region: Dict[str, List[Dict]],
    socks5_by_country: Dict[str, List[Dict]],
    chain_ports: List[int]
) -> Tuple[List[str], List[str]]:
    """
    双轨装配：
    1. CF 直连节点：按地区生成纯直连节点
    2. SOCKS5 链式节点：每个 SOCKS5 落地国 × CF 优选 IP × 端口

    返回: (direct_lines, chain_lines)
    """
    direct_lines = []
    chain_lines = []

    # === 轨道一：CF 优选直连节点 ===
    print(f"\n{'='*60}")
    print(f"  [轨道一] CF 优选直连节点装配")
    print(f"{'='*60}")

    for region in sorted(by_region.keys()):
        hosts = by_region[region]
        flag = get_flag(region)
        for host in hosts:
            ip = host["ip"]
            rank = host["rank"]
            for port in host["ports"]:
                tag = f"{flag} 优选{region.lower()}{rank:02d}:{port}"
                direct_lines.append(f"{ip}:{port}#{tag}")
        region_count = sum(len(h["ports"]) for h in hosts)
        print(f"  + {flag} {region}: {len(hosts)} 台主机 × 共 {region_count} 个端口节点")

    print(f"  >> 直连节点总计: {len(direct_lines)} 个")

    # === 轨道二：SOCKS5 链式落地节点 ===
    print(f"\n{'='*60}")
    print(f"  [轨道二] SOCKS5 链式落地节点装配")
    print(f"{'='*60}")

    if not socks5_by_country:
        print("  [!] 无可用 SOCKS5 代理，跳过链式装配")
        return direct_lines, chain_lines

    # 选取用于链式中继的 CF 入站 IP（优先使用 US 区域，回退到任意可用区域）
    relay_hosts = []
    for prefer_region in ["US", "SG", "DE"]:
        if prefer_region in by_region and by_region[prefer_region]:
            relay_hosts = by_region[prefer_region]
            print(f"  [*] 链式中继入站 IP 池: 使用 {prefer_region} 区 ({len(relay_hosts)} 台主机)")
            break

    if not relay_hosts:
        # 使用任意第一个区域
        first_region = list(by_region.keys())[0] if by_region else None
        if first_region:
            relay_hosts = by_region[first_region]
            print(f"  [*] 链式中继入站 IP 池: 回退使用 {first_region} 区")
        else:
            print("  [!] 无可用 CF 入站 IP，跳过链式装配")
            return direct_lines, chain_lines

    # 为每个 SOCKS5 落地国组装链式节点
    for country in sorted(socks5_by_country.keys()):
        proxies = socks5_by_country[country]
        flag = get_flag(country)
        country_chain_count = 0

        for socks_rank, proxy in enumerate(proxies, 1):
            socks5_uri = f"socks5://{proxy['entry']}"
            letter = chr(96 + socks_rank) if 1 <= socks_rank <= 26 else str(socks_rank)
            
            # 使用中继 IP 的所有主机进行装配，实现多组匹配
            for host in relay_hosts:
                ip = host["ip"]
                port = 443 if 443 in chain_ports else chain_ports[0]
                cf_rank = host["rank"]
                
                tag = f"{flag} S5_{letter}{prefer_region.lower()}{cf_rank:02d}"
                chain_entry = f"{ip}:{port}#{tag}${socks5_uri}"
                chain_lines.append(chain_entry)
                country_chain_count += 1

        print(f"  + {flag} {country}: {len(proxies)} 个 SOCKS5 × 装配 {country_chain_count} 个链式节点")

    print(f"  >> 链式节点总计: {len(chain_lines)} 个")
    return direct_lines, chain_lines


def main():
    parser = argparse.ArgumentParser(description="OverNode Multi-Country Chain Assembler")
    parser.add_argument("--inbound", "-i", default="overNode_actions.txt", help="入站优选节点文件 (逗号分隔多文件)")
    parser.add_argument("--socks5", "-s", default="socks5.txt", help="出站 SOCKS5 代理文件")
    parser.add_argument("--output", "-o", default="overNode_chain.txt", help="输出链式订阅文件")
    parser.add_argument("--backup", "-b", default="overNode_chain_backup.txt", help="链式订阅软备份文件")
    parser.add_argument("--chain-ports", default="443,2053,8443", help="链式节点使用的端口列表 (逗号分隔，默认 443,2053,8443)")
    parser.add_argument("--allowed-countries", default="US,SG,HK", help="仅允许这些落地国的 SOCKS5 组装链式节点 (逗号分隔，默认 US,SG,HK)")
    parser.add_argument("--inbound-regions", default="SG,US", help="仅保留这些地区的入站直连节点 (逗号分隔，默认 SG,US)")
    args = parser.parse_args()

    chain_ports = [int(p.strip()) for p in args.chain_ports.split(",") if p.strip()]
    allowed_countries = [c.strip().upper() for c in args.allowed_countries.split(",") if c.strip()]
    inbound_regions = [r.strip().upper() for r in args.inbound_regions.split(",") if r.strip()]

    print("=" * 60)
    print("  OverNode 多国 SOCKS5 落地 × CF 直连双轨装配引擎")
    print(f"  入站节点文件: {args.inbound}")
    print(f"  出站代理文件: {args.socks5}")
    print(f"  入站优选地区: {inbound_regions}")
    print(f"  落地国白名单: {allowed_countries}")
    print(f"  链式端口矩阵: {chain_ports}")
    print(f"  目标输出订阅: {args.output}")
    print("=" * 60)

    # 1. 解析 CF 入站优选节点 (严格限制入站地区)
    by_region = parse_actions_inbound(args.inbound, inbound_regions=inbound_regions)
    if not by_region:
        print("[!] 错误：未读取到有效的入站节点！")
        return

    # 2. 解析 SOCKS5 出站代理（按落地国分组，仅保留白名单国家）
    socks5_by_country = parse_socks5_file(args.socks5, allowed_countries=allowed_countries)

    # 3. 双轨装配
    direct_lines, chain_lines = assemble_chains(by_region, socks5_by_country, chain_ports)

    # 4. 合并输出：直连节点在前，链式节点在后
    all_lines = direct_lines + chain_lines

    if not all_lines:
        print("[!] 装配结果为空，放弃写入！")
        return

    # 快照软备份
    if os.path.exists(args.output):
        try:
            shutil.copyfile(args.output, args.backup)
            print(f"\n[+] 已建立历史快照软备份: {args.backup}")
        except Exception as e:
            print(f"[-] 备份失败: {e}")

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(all_lines) + "\n")

    print(f"\n{'='*60}")
    print(f"  [✓] 装配完毕！")
    print(f"  >> CF 直连节点: {len(direct_lines)} 个")
    print(f"  >> SOCKS5 链式节点: {len(chain_lines)} 个")
    print(f"  >> 总计: {len(all_lines)} 个")
    print(f"  >> 文件保存至: {args.output}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
