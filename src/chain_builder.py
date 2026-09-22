#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OverNode Chain Assembler (终极进化：入站优选 + 出站SOCKS5 链式订阅自动装配器)
核心机制：
1. 【解耦入站与出站】：
   - 入站：国内直连延迟极低的 Cloudflare Anycast 优选 IP (负责低延迟握手)
   - 出站：海外真实通畅的 SOCKS5 中继代理 (负责穿透回源与杜绝 1034 隔离)
2. 【edgetunnel 链式订阅原生协议】：
   自动拼装语法：{Anycast_IP}:{Port}#{Region}-{Port}-{Index}-[socks5]-$socks5://{Socks5_IP}:{Socks5_Port}
3. 【客户端物理防呆保护】：
   客户端拉取订阅后，节点只显示入站优选 IP 与纯净 [socks5] 标记，裸 SOCKS5 地址被 Worker 完全隐式消化，杜绝误选与混淆！
4. 【智能亲和力路由 (Affinity Routing)】：
   优先将相同地理区域 (如 US 优选 IP 与 US SOCKS5) 进行同域绑定，降低跨国回源跳数与延迟；跨区时自动平滑轮询。
5. 【高可用双重备份】：
   自动维护 overNode_chain_backup.txt 历史快照。
"""

import os
import sys
import re
import argparse
import shutil
from typing import List, Dict, Optional


def parse_overnode_file(filepath: str) -> List[Dict]:
    """解析入站 Anycast 优选 IP 文件"""
    if not os.path.exists(filepath):
        print(f"[!] 入站优选文件不存在: {filepath}")
        return []

    nodes = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 格式: 104.27.113.182:443#US-Actions-443-1
            parts = line.split("#")
            entry = parts[0].strip()
            tag = parts[1].strip() if len(parts) > 1 else ""

            if ":" in entry:
                ip, port_str = entry.split(":")
                try:
                    port = int(port_str)
                except ValueError:
                    continue

                # 提取地区代码 (如 US, SG, DE)
                region = "GLOBAL"
                region_match = re.match(r"^([A-Z]{2})", tag)
                if region_match:
                    region = region_match.group(1)

                nodes.append({
                    "entry": entry,
                    "ip": ip,
                    "port": port,
                    "region": region,
                    "raw_tag": tag
                })
    return nodes


def parse_socks5_file(filepath: str) -> List[Dict]:
    """解析出站 SOCKS5 代理文件"""
    if not os.path.exists(filepath):
        print(f"[!] SOCKS5 代理文件不存在: {filepath}")
        return []

    proxies = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 格式: 107.167.18.122:443#US-[socks5]
            parts = line.split("#")
            entry = parts[0].strip()
            tag = parts[1].strip() if len(parts) > 1 else ""

            if ":" in entry:
                host, port_str = entry.split(":")
                try:
                    port = int(port_str)
                except ValueError:
                    continue

                country = "AUTO"
                country_match = re.match(r"^([A-Z]{2})", tag)
                if country_match:
                    country = country_match.group(1)

                proxies.append({
                    "entry": entry,
                    "host": host,
                    "port": port,
                    "country": country
                })
    return proxies


def assemble_chains(inbound_nodes: List[Dict], outbound_proxies: List[Dict]) -> List[str]:
    """执行入站与出站的智能亲和力配对合成"""
    if not inbound_nodes or not outbound_proxies:
        return []

    # 按地区对 SOCKS5 进行归类分组
    socks_by_region: Dict[str, List[Dict]] = {}
    for p in outbound_proxies:
        ct = p["country"]
        socks_by_region.setdefault(ct, []).append(p)

    chain_lines = []
    proxy_cursor = 0
    total_proxies = len(outbound_proxies)

    # 统计各区域已编排序号
    region_counter: Dict[str, int] = {}

    for node in inbound_nodes:
        region = node["region"]
        port = node["port"]
        region_counter[region] = region_counter.get(region, 0) + 1
        idx = region_counter[region]

        # 智能匹配：优先寻找同地区的 SOCKS5
        matched_proxy = None
        if region in socks_by_region and socks_by_region[region]:
            # 轮询该地区的代理
            idx_in_region = (idx - 1) % len(socks_by_region[region])
            matched_proxy = socks_by_region[region][idx_in_region]
        else:
            # 无同区域则全局平滑轮询
            matched_proxy = outbound_proxies[proxy_cursor % total_proxies]
            proxy_cursor += 1

        # 构造纯净的前端展示备注 (客户端只能看到这个备注和入站IP)
        clean_tag = f"{region}-{port}-{idx:02d}-[socks5]"

        # 组装 edgetunnel 原生链式代理语法
        # 格式: AnycastIP:Port#备注-$socks5://SOCKS5_IP:SOCKS5_Port
        chain_entry = f"{node['entry']}#{clean_tag}-$socks5://{matched_proxy['entry']}"
        chain_lines.append(chain_entry)

    return chain_lines


def main():
    parser = argparse.ArgumentParser(description="OverNode Chain Assembler for edgetunnel")
    parser.add_argument("--inbound", "-i", default="overNode_actions.txt", help="入站 Anycast 优选 IP 文件")
    parser.add_argument("--socks5", "-s", default="socks5.txt", help="出站 SOCKS5 代理文件")
    parser.add_argument("--output", "-o", default="overNode_chain.txt", help="输出链式订阅文件")
    parser.add_argument("--backup", "-b", default="overNode_chain_backup.txt", help="链式订阅软备份文件")
    args = parser.parse_args()

    print("==================================================")
    print("      OverNode 链式订阅自动装配引擎 (终极进化)      ")
    print(f" 入站节点文件: {args.inbound}")
    print(f" 出站代理文件: {args.socks5}")
    print(f" 目标输出订阅: {args.output}")
    print("==================================================")

    inbound_nodes = parse_overnode_file(args.inbound)
    if not inbound_nodes:
        # 兜底尝试备用入站文件
        for fallback in ["overNode.txt", "overNode_actions_backup.txt"]:
            if os.path.exists(fallback):
                print(f"[*] 切换至备用入站源: {fallback}")
                inbound_nodes = parse_overnode_file(fallback)
                break

    outbound_proxies = parse_socks5_file(args.socks5)
    if not outbound_proxies:
        # 兜底尝试备用 SOCKS5 文件
        fallback_s5 = args.socks5.replace(".txt", "_backup.txt")
        if os.path.exists(fallback_s5):
            print(f"[*] 切换至备用 SOCKS5 源: {fallback_s5}")
            outbound_proxies = parse_socks5_file(fallback_s5)

    if not inbound_nodes:
        print("[!] 致命错误：入站 Anycast 优选节点为空，装配终止！")
        sys.exit(1)
    if not outbound_proxies:
        print("[!] 致命错误：出站 SOCKS5 代理池为空，装配终止！")
        sys.exit(1)

    print(f"[*] 成功解析入站 Anycast 节点: {len(inbound_nodes)} 个")
    print(f"[*] 成功解析出站 SOCKS5 代理: {len(outbound_proxies)} 个")

    chains = assemble_chains(inbound_nodes, outbound_proxies)
    if not chains:
        print("[!] 生成链式链路失败！")
        sys.exit(1)

    # 软备份机制
    if os.path.exists(args.output) and args.backup:
        try:
            shutil.copyfile(args.output, args.backup)
            print(f"[+] 已建立历史快照软备份: {args.backup}")
        except Exception as e:
            print(f"[-] 备份失败: {e}")

    # 写入最终装配产物
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(chains) + "\n")

    print(f"\n[+] 链式装配圆满完成！共生成 {len(chains)} 条端到端双优链路：")
    for idx, c in enumerate(chains[:5], 1):
        print(f"  {idx:02d}. {c}")
    if len(chains) > 5:
        print(f"  ... 篇幅原因省略其余 {len(chains) - 5} 条 ...")

    print(f"\n[+] 产物已安全持久化至: {os.path.abspath(args.output)}")


if __name__ == "__main__":
    main()
