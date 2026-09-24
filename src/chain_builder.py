#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OverNode Streamlined Chain Assembler (精简极速双轨装配引擎)

核心升级：
1. 【仅保留 Actions 纯净入站 (Actions-Only)】：
   彻底放弃本地陈旧组 (overNode.txt)，仅采用 GitHub Actions 云端测速优选出的 overNode_actions.txt，保证高可用性。
2. 【聚焦核心地区 (SG & US Focused)】：
   入站节点严格聚焦中国大陆连接体验最佳的黄金双核：🇸🇬 新加坡 (SG) 与 🇺🇸 美国 (US)，移除冗余欧洲等低效地区。
3. 【双轨纯净架构 (Dual-Track Architecture)】：
   - 链式中继：统一挂载实测吞吐量达标的单一黄金主力 SOCKS5 代理，出站 IP 绝对固定。
   - 官方直出：纯净直连 Cloudflare Anycast，用于网盘、Steam下载、YouTube视频流与甲骨文官网。
4. 【纯净命名规范】：
   - 🇸🇬 SG-443-01-[socks5]
   - 🇺🇸 US-443-01-[socks5]
   - 🇸🇬 直出-SG-443-01
   - 🇺🇸 直出-US-443-02
"""

import os
import sys
import re
import argparse
import shutil
from typing import List, Dict

# 终端 UTF-8 保障
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

COUNTRY_FLAGS = {
    "US": "🇺🇸",
    "SG": "🇸🇬"
}
ALLOWED_REGIONS = ["SG", "US"]


def parse_inbound_file(filepath: str) -> List[Dict]:
    """读取 Actions 优选节点文件，仅提取 SG 和 US 节点"""
    if not os.path.exists(filepath):
        if os.path.exists(os.path.basename(filepath)):
            filepath = os.path.basename(filepath)
        else:
            print(f"[!] 找不到入站节点文件: {filepath}")
            return []

    print(f"[*] 正在载入 Actions 纯净入站节点: {filepath}")
    nodes = []
    seen = set()

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("#")
            entry = parts[0].strip()
            tag = parts[1].strip() if len(parts) > 1 else ""

            if ":" in entry:
                if entry in seen:
                    continue
                seen.add(entry)
                ip, port_str = entry.split(":")
                try:
                    port = int(port_str)
                except ValueError:
                    continue

                region = "GLOBAL"
                reg_m = re.match(r"^([A-Z]{2})", tag)
                if reg_m:
                    region = reg_m.group(1).upper()

                if region in ALLOWED_REGIONS:
                    nodes.append({
                        "entry": entry,
                        "ip": ip,
                        "port": port,
                        "region": region,
                        "raw_tag": tag
                    })

    print(f"  + 成功提取有效 Actions 入站优选节点: {len(nodes)} 个 (聚焦 SG/US)")
    return nodes


def parse_socks5_anchor(filepath: str) -> str:
    """提取在岗 SOCKS5 中经过测速认证的第一顺位王者代理作为统一定锚出口"""
    if not os.path.exists(filepath):
        print(f"[!] SOCKS5 代理文件不存在: {filepath}")
        return ""

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entry = line.split("#")[0].strip()
            if ":" in entry:
                print(f"[+] 成功锁定黄金主力 SOCKS5 出站代理: {entry}")
                return entry

    return ""


def assemble_streamlined_chains(inbound_nodes: List[Dict], anchor_socks5: str) -> List[str]:
    """生成精简双轨矩阵 (链式中继 + 官方直出)"""
    chain_lines = []
    by_region: Dict[str, List[Dict]] = {"SG": [], "US": []}

    for n in inbound_nodes:
        r = n["region"]
        if r in by_region:
            by_region[r].append(n)

    # 1. 组装链式中继节点 (挂载单一黄金主力代理)
    for r in ["SG", "US"]:
        flag = COUNTRY_FLAGS.get(r, "")
        nodes = by_region.get(r, [])
        for idx, node in enumerate(nodes, 1):
            port = node["port"]
            clean_tag = f"{flag} {r}-{port}-{idx:02d}-[socks5]"
            if anchor_socks5:
                chain_entry = f"{node['entry']}#{clean_tag}-$socks5://{anchor_socks5}"
            else:
                chain_entry = f"{node['entry']}#{clean_tag}"
            chain_lines.append(chain_entry)

    # 2. 组装官方纯净直出节点 (每区各挑前 4 个不同端口节点，不挂 SOCKS5)
    direct_added = 0
    for r in ["SG", "US"]:
        flag = COUNTRY_FLAGS.get(r, "")
        nodes = by_region.get(r, [])
        for node in nodes[:4]:
            port = node["port"]
            direct_tag = f"{flag} 直出-{r}-{port}-{direct_added + 1:02d}"
            chain_lines.append(f"{node['entry']}#{direct_tag}")
            direct_added += 1

    print(f"[*] 节点装配完毕：链式中继节点 {len(chain_lines) - direct_added} 个，官方直出节点 {direct_added} 个，总计: {len(chain_lines)} 个")
    return chain_lines


def main():
    parser = argparse.ArgumentParser(description="OverNode Streamlined Chain Assembler")
    parser.add_argument("--inbound", "-i", default="overNode_actions.txt", help="入站优选节点文件 (默认仅使用 actions 纯净组)")
    parser.add_argument("--socks5", "-s", default="socks5.txt", help="出站 SOCKS5 代理文件")
    parser.add_argument("--output", "-o", default="overNode_chain.txt", help="输出链式订阅文件")
    parser.add_argument("--backup", "-b", default="overNode_chain_backup.txt", help="链式订阅软备份文件")
    args = parser.parse_args()

    print("==================================================")
    print("      OverNode 纯净精简双轨链式装配引擎 (SG/US)      ")
    print(f" 入站节点文件: {args.inbound}")
    print(f" 出站代理文件: {args.socks5}")
    print(f" 目标输出订阅: {args.output}")
    print("==================================================")

    inbound_nodes = parse_inbound_file(args.inbound)
    if not inbound_nodes:
        print("[!] 错误：未读取到有效的 SG/US 入站节点！")
        return

    anchor_socks5 = parse_socks5_anchor(args.socks5)
    if not anchor_socks5:
        print("[!] 警告：未找到有效 SOCKS5 代理，将仅生成直连节点！")

    chain_lines = assemble_streamlined_chains(inbound_nodes, anchor_socks5)

    # 快照软备份
    if os.path.exists(args.output):
        try:
            shutil.copyfile(args.output, args.backup)
            print(f"[+] 已建立历史快照软备份: {args.backup}")
        except Exception as e:
            print(f"[-] 备份失败: {e}")

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(chain_lines) + "\n")

    print(f"\n[+] 精简装配圆满完成！共生成 {len(chain_lines)} 个优质节点：")
    for line in chain_lines[:6]:
        print(f"  ● {line}")
    print(f"  ... 其余 {len(chain_lines) - 6} 个节点已成功持久化至: {args.output}")


if __name__ == "__main__":
    main()
