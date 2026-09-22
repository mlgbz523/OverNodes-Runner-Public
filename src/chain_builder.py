#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OverNode Chain Assembler (终极进化：全量入站矩阵融合 + 单一王者代理统一定锚)
核心机制：
1. 【全量入站矩阵融合 (Complete Inbound Matrix)】：
   同时完整吸纳并融合 [overNode_actions.txt] (Actions云端实时优选) 与 [overNode.txt] (全量骨干优选)，去重整合出无遗漏的极速入站节点池。
2. 【单一主力王者代理统一定锚 (Single Anchor Egress)】：
   彻底杜绝不同优选 IP 使用不同代理导致的“跳IP/风控”问题！
   从高吞吐出站池中选取 Top 1 王者代理，将所有优选节点统一绑定到该同一代理上，出站 IP 绝对固定一致！
3. 【edgetunnel 原生链式订阅标准】：
   语法：{Anycast_IP}:{Port}#{Region}-{Port}-{Index}-[socks5]-$socks5://{Anchor_Socks5_IP}:{Port}
4. 【客户端物理防呆防护】：
   客户端拉取订阅后仅看到入站优选 IP 与 [socks5] 纯净标记，裸 SOCKS5 彻底隐式封装，不可选、不混淆！
5. 【高可用快照软备份】：
   自动维护 overNode_chain_backup.txt。
"""

import os
import sys
import re
import argparse
import shutil
from typing import List, Dict, Optional


def parse_multi_inbound_files(inbound_specs: str) -> List[Dict]:
    """同时读取并融合多个入站节点文件 (overNode_actions.txt + overNode.txt)，智能去重合并"""
    file_list = [f.strip() for f in inbound_specs.split(",") if f.strip()]
    nodes = []
    seen_entries = set()

    for fp in file_list:
        if not os.path.exists(fp):
            # 尝试在同级目录下寻找
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
            print(f"  + 从 {fp} 吸收有效入站节点: {count} 个，累计池规模: {len(nodes)}")

    return nodes


def parse_socks5_file(filepath: str) -> List[Dict]:
    """解析出站 SOCKS5 代理文件 (按吞吐量排序，第 1 个即为当前主力王者)"""
    if not os.path.exists(filepath):
        print(f"[!] SOCKS5 代理文件不存在: {filepath}")
        return []

    proxies = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
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


def assemble_chains_single_anchor(inbound_nodes: List[Dict], anchor_proxy: Dict) -> List[str]:
    """
    单一王者定锚模式：
    所有入站优选 IP 统一绑定同一个实测吞吐量最大、最稳定的出站 SOCKS5 代理！
    """
    chain_lines = []
    region_counter: Dict[str, int] = {}

    for node in inbound_nodes:
        region = node["region"]
        port = node["port"]
        region_counter[region] = region_counter.get(region, 0) + 1
        idx = region_counter[region]

        # 构造纯净的前端展示备注 (客户端界面仅能看到这个名字)
        clean_tag = f"{region}-{port}-{idx:02d}-[socks5]"

        # 统一绑定同一个主力 SOCKS5 代理！
        chain_entry = f"{node['entry']}#{clean_tag}-$socks5://{anchor_proxy['entry']}"
        chain_lines.append(chain_entry)

    return chain_lines


def main():
    parser = argparse.ArgumentParser(description="OverNode Complete Chain Assembler (Single Anchor Egress)")
    parser.add_argument("--inbound", "-i", default="overNode_actions.txt,overNode.txt",
                        help="入站优选节点文件列表(逗号分隔，全量融合 actions 与本地文件)")
    parser.add_argument("--socks5", "-s", default="socks5.txt", help="出站 SOCKS5 代理文件")
    parser.add_argument("--output", "-o", default="overNode_chain.txt", help="输出链式订阅文件")
    parser.add_argument("--backup", "-b", default="overNode_chain_backup.txt", help="链式订阅软备份文件")
    args = parser.parse_args()

    print("==================================================")
    print("      OverNode 全量融合与王者定锚链式装配引擎      ")
    print(f" 入站多源融合: {args.inbound}")
    print(f" 出站代理文件: {args.socks5}")
    print(f" 目标输出订阅: {args.output}")
    print("==================================================")

    # 1. 全量吸纳入站优选节点 (overNode_actions.txt + overNode.txt)
    inbound_nodes = parse_multi_inbound_files(args.inbound)
    if not inbound_nodes:
        print("[!] 致命错误：未能从指定的入站文件中提取到任何节点！")
        sys.exit(1)

    # 2. 读取出站 SOCKS5 代理池
    outbound_proxies = parse_socks5_file(args.socks5)
    if not outbound_proxies:
        fallback_s5 = args.socks5.replace(".txt", "_backup.txt")
        if os.path.exists(fallback_s5):
            print(f"[*] 切换至备用 SOCKS5 源: {fallback_s5}")
            outbound_proxies = parse_socks5_file(fallback_s5)

    if not outbound_proxies:
        print("[!] 致命错误：出站 SOCKS5 代理池为空，装配终止！")
        sys.exit(1)

    # 3. 锁定当前吞吐量最大的唯一王者代理
    anchor_proxy = outbound_proxies[0]
    print(f"\n[★王者定锚] 本次订阅所有优选 IP 统一锁定使用代理: {anchor_proxy['entry']} [{anchor_proxy['country']}]")
    print(f"[*] 无论用户切换哪个优选 IP，出站代理 IP 绝对保持一致，杜绝风控与跳 IP！")

    # 4. 执行全量装配
    chains = assemble_chains_single_anchor(inbound_nodes, anchor_proxy)
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

    print(f"\n[+] 链式装配圆满完成！共融合生成 {len(chains)} 个端到端双优节点：")
    for idx, c in enumerate(chains[:6], 1):
        print(f"  {idx:02d}. {c}")
    if len(chains) > 6:
        print(f"  ... 篇幅原因省略其余 {len(chains) - 6} 条 ...")

    print(f"\n[+] 产物已安全持久化至: {os.path.abspath(args.output)}")


if __name__ == "__main__":
    main()
