#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OverNode Multi-Country Intelligent Chain Assembler (多国智能黄金配对链式装配引擎)

核心升级：
1. 【真·多国落地矩阵 (True Multi-Country Outbound Matrix)】：
   按国家/地区智能解析 socks5.txt 中所有代理锚点（US, SG, JP, DE, ES 等），彻底打破单一美国锚点限制。
2. 【智能黄金配对 (Golden Inbound-Outbound Affinity)】：
   - 亚太 SOCKS5 落地（SG/JP/HK）：优先绑定亚太优选 IP 入站（极低物理延迟，抗丢包）。
   - 美洲 SOCKS5 落地（US）：配对亚太（CF内网专线跨洋）与美西优选 IP 入站。
   - 欧洲 SOCKS5 落地（DE/ES/UK）：配对欧洲/通用优选 IP 入站。
3. 【语义规范命名 (Canonical Semantic Tagging)】：
   - 链式节点以【真实落地国家】为主体，格式如：🇺🇸 US-443-01-[socks5]、$socks5://...
   - 官方直出节点明确标识：🔗 直出-SG-443-01（纯净直出，破 429 与 Akamai 防线）。
4. 【订阅器轻量防超时控制】：
   智能配比节点密度，精简冗余，杜绝订阅转换器解析超时。
"""

import os
import sys
import re
import argparse
import shutil
from typing import List, Dict, Tuple

# 终端 UTF-8 保障 (防止 Windows GBK 下 Emoji 国旗编码异常)
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# 国家国旗图标映射表
COUNTRY_FLAGS = {
    "US": "🇺🇸",
    "SG": "🇸🇬",
    "JP": "🇯🇵",
    "DE": "🇩🇪",
    "ES": "🇪🇸",
    "HK": "🇭🇰",
    "TW": "🇹🇼",
    "KR": "🇰🇷",
    "UK": "🇬🇧",
    "FR": "🇫🇷",
    "CA": "🇨🇦",
    "AU": "🇦🇺"
}


def parse_multi_inbound_files(inbound_specs: str) -> List[Dict]:
    """同时读取并融合多个入站节点文件 (overNode_actions.txt + overNode.txt)，智能去重合并"""
    file_list = [f.strip() for f in inbound_specs.split(",") if f.strip()]
    nodes = []
    seen_entries = set()

    for fp in file_list:
        if not os.path.exists(fp):
            if os.path.exists(os.path.basename(fp)):
                fp = os.path.basename(fp)
            else:
                continue

        print(f"[*] 正在融合入站节点源: {fp}")
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            count = 0
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("#")
                entry = parts[0].strip()
                tag = parts[1].strip() if len(parts) > 1 else ""

                if ":" in entry:
                    if entry in seen_entries:
                        continue
                    seen_entries.add(entry)
                    ip, port_str = entry.split(":")
                    try:
                        port = int(port_str)
                    except ValueError:
                        continue

                    # 提取地区代码 (如 US, SG, DE)
                    region = "GLOBAL"
                    reg_m = re.match(r"^([A-Z]{2})", tag)
                    if reg_m:
                        region = reg_m.group(1)

                    nodes.append({
                        "entry": entry,
                        "ip": ip,
                        "port": port,
                        "region": region,
                        "raw_tag": tag
                    })
                    count += 1
            print(f"  + 从 {fp} 吸收有效入站节点: {count} 个，当前累计池规模: {len(nodes)}")

    return nodes


def parse_socks5_file(filepath: str) -> List[Dict]:
    """解析出站 SOCKS5 代理文件，提取主机、端口及国家属性"""
    if not os.path.exists(filepath):
        print(f"[!] SOCKS5 代理文件不存在: {filepath}")
        return []

    proxies = []
    seen_hosts = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("#")
            entry = parts[0].strip()
            tag = parts[1].strip() if len(parts) > 1 else ""

            if ":" in entry:
                if entry in seen_hosts:
                    continue
                seen_hosts.add(entry)
                host, port_str = entry.split(":")
                try:
                    port = int(port_str)
                except ValueError:
                    continue

                country = "US"  # 默认回退
                country_match = re.match(r"^([A-Z]{2})", tag)
                if country_match:
                    country = country_match.group(1).upper()

                proxies.append({
                    "entry": entry,
                    "host": host,
                    "port": port,
                    "country": country,
                    "tag": tag
                })
    return proxies


def assemble_multi_country_chains(inbound_nodes: List[Dict], outbound_proxies: List[Dict], max_nodes_per_country: int = 16, max_direct_total: int = 12) -> List[str]:
    """
    多国黄金配对双轨装配引擎：
    1. 链式轨道：按 SOCKS5 落地国聚类，智能匹配最优入站，生成具备真实落地价值的多国链式节点。
    2. 直出轨道：每个入站大区严格精简直出节点，供给 4K 视频分片与免中转服务。
    """
    chain_lines = []

    # 1. 出站代理按国家分组
    proxies_by_country: Dict[str, List[Dict]] = {}
    for p in outbound_proxies:
        c = p["country"]
        if c not in proxies_by_country:
            proxies_by_country[c] = []
        proxies_by_country[c].append(p)

    print(f"[*] 检测到 {len(proxies_by_country)} 个落地国家代理池: {list(proxies_by_country.keys())}")

    # 2. 区分入站优选 IP 区域
    inbound_by_region: Dict[str, List[Dict]] = {}
    for n in inbound_nodes:
        r = n["region"]
        if r not in inbound_by_region:
            inbound_by_region[r] = []
        inbound_by_region[r].append(n)

    # 3. 为每个落地国家装配链式节点
    for country, country_proxies in proxies_by_country.items():
        flag = COUNTRY_FLAGS.get(country, "🌐")
        anchor_proxy = country_proxies[0]  # 取该国第一顺位黄金代理

        # 智能匹配入站优先集 (Affinity)
        if country in ["SG", "JP", "HK", "TW", "KR"]:
            # 亚太落地：优先选用 SG 亚太入站，次选全局
            candidate_inbounds = inbound_by_region.get("SG", []) + inbound_by_region.get("US", [])
        elif country in ["DE", "ES", "FR", "UK", "NL"]:
            # 欧洲落地：优先选用 DE 入站，次选全局
            candidate_inbounds = inbound_by_region.get("DE", []) + inbound_by_region.get("US", [])
        else:
            # 美洲及默认：SG(CF专线跨洋) + US(直达)
            candidate_inbounds = inbound_by_region.get("SG", []) + inbound_by_region.get("US", [])

        if not candidate_inbounds:
            candidate_inbounds = inbound_nodes

        # 控制单国节点数量上限，确保订阅轻量不卡顿
        selected_inbounds = candidate_inbounds[:max_nodes_per_country]
        for idx, node in enumerate(selected_inbounds, 1):
            port = node["port"]
            clean_tag = f"{flag} {country}-{port}-{idx:02d}-[socks5]"
            chain_entry = f"{node['entry']}#{clean_tag}-$socks5://{anchor_proxy['entry']}"
            chain_lines.append(chain_entry)

        print(f"  + 装配 [{flag} {country}] 落地链式节点: {len(selected_inbounds)} 个 (绑定 SOCKS5: {anchor_proxy['entry']})")

    # 4. 精简直出节点 (纯净直连 Cloudflare Anycast，不挂 SOCKS5)
    direct_added = 0
    for r in ["SG", "US", "DE"]:
        nodes = inbound_by_region.get(r, [])
        for node in nodes[:max_direct_total // 3]:
            port = node["port"]
            flag = COUNTRY_FLAGS.get(r, "🌐")
            clean_tag = f"🔗 直出-{flag}{r}-{port}-{direct_added + 1:02d}"
            chain_lines.append(f"{node['entry']}#{clean_tag}")
            direct_added += 1

    print(f"[*] 节点矩阵装配完成：全量多国链式节点 {len(chain_lines) - direct_added} 个，精选直出节点 {direct_added} 个，总计: {len(chain_lines)} 个")
    return chain_lines


def main():
    parser = argparse.ArgumentParser(description="OverNode Multi-Country Intelligent Chain Assembler")
    parser.add_argument("--inbound", "-i", default="overNode_actions.txt,overNode.txt",
                        help="入站优选节点文件列表 (逗号分隔)")
    parser.add_argument("--socks5", "-s", default="socks5.txt", help="出站 SOCKS5 代理文件")
    parser.add_argument("--output", "-o", default="overNode_chain.txt", help="输出链式订阅文件")
    parser.add_argument("--backup", "-b", default="overNode_chain_backup.txt", help="链式订阅软备份文件")
    args = parser.parse_args()

    print("==================================================")
    print("      OverNode 多国智能黄金配对链式装配引擎      ")
    print(f" 入站多源融合: {args.inbound}")
    print(f" 出站代理文件: {args.socks5}")
    print(f" 目标输出订阅: {args.output}")
    print("==================================================")

    # 1. 吸纳入站节点
    inbound_nodes = parse_multi_inbound_files(args.inbound)
    if not inbound_nodes:
        print("[!] 致命错误：未能从指定的入站文件中提取到任何节点！")
        sys.exit(1)

    # 2. 读取出站 SOCKS5 多国池
    outbound_proxies = parse_socks5_file(args.socks5)
    if not outbound_proxies:
        fallback_s5 = args.socks5.replace(".txt", "_backup.txt")
        if os.path.exists(fallback_s5):
            print(f"[*] 切换至备用 SOCKS5 源: {fallback_s5}")
            outbound_proxies = parse_socks5_file(fallback_s5)

    if not outbound_proxies:
        print("[!] 致命错误：出站 SOCKS5 代理池为空，装配终止！")
        sys.exit(1)

    # 3. 执行多国配对装配
    chains = assemble_multi_country_chains(inbound_nodes, outbound_proxies)
    if not chains:
        print("[!] 生成链路失败！")
        sys.exit(1)

    # 软备份
    if os.path.exists(args.output) and args.backup:
        try:
            shutil.copyfile(args.output, args.backup)
            print(f"[+] 已建立历史快照软备份: {args.backup}")
        except Exception as e:
            print(f"[-] 备份失败: {e}")

    # 写入产物
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(chains) + "\n")

    print(f"\n[+] 多国装配圆满完成！共生成 {len(chains)} 个可用节点：")
    for idx, c in enumerate(chains[:6], 1):
        print(f"  {idx:02d}. {c}")
    print(f"  ... 其余 {len(chains) - 6} 条条目已保存至订阅输出 ...")
    print(f"\n[+] 产物已持久化至: {os.path.abspath(args.output)}")


if __name__ == "__main__":
    main()
