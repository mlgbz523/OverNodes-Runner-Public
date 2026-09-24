#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OverNode Real-Landing Dual-Track Assembler (去伪存真·真物理落地双轨装配引擎)

核心升级：
1. 【真·物理归属对齐 (True Physical Alignment)】：
   - 🇸🇬 新加坡节点：全部由 Actions 新加坡优选 IP 承载【官方纯净直出】！
     数据从 Cloudflare 新加坡机房直接出站，出口 100% 为真实新加坡 IP，彻底消灭跨洋绕路，延迟降至最低！
   - 🇺🇸 美国节点：由 Actions 美西优选 IP + 美国高速黄金 SOCKS5 承载【链式中继】！
     美西直达美西，不折返、不绕路，出口为真实纯净美国固定 IP，专供 AI 与特定欧美业务。
2. 【严格聚焦 Actions 纯净组 (Actions-Only)】：
   彻底放弃本地陈旧组，仅采用 GitHub Actions 实时测速优选出的 overNode_actions.txt。
3. 【精简纯净命名】：
   - 🇸🇬 SG-443-01-[直出]
   - 🇺🇸 US-443-01-[socks5]
   - 🇺🇸 US-443-01-[直出]
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


def parse_actions_inbound(filepath: str) -> Dict[str, List[Dict]]:
    """读取 Actions 优选文件，按 SG 和 US 归类"""
    if not os.path.exists(filepath):
        if os.path.exists(os.path.basename(filepath)):
            filepath = os.path.basename(filepath)
        else:
            print(f"[!] 找不到入站节点文件: {filepath}")
            return {"SG": [], "US": []}

    print(f"[*] 正在载入 Actions 纯净入站优选节点: {filepath}")
    by_region = {"SG": [], "US": []}
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

                if "SG" in tag:
                    by_region["SG"].append({"entry": entry, "ip": ip, "port": port})
                elif "US" in tag:
                    by_region["US"].append({"entry": entry, "ip": ip, "port": port})

    print(f"  + 成功提取 SG 节点: {len(by_region['SG'])} 个，US 节点: {len(by_region['US'])} 个")
    return by_region


def parse_socks5_anchor(filepath: str) -> str:
    """提取在岗 SOCKS5 中经过测速认证的第一顺位王者代理作为美国链式中继锚点"""
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
                print(f"[+] 成功锁定美国黄金主力 SOCKS5 出口: {entry}")
                return entry

    return ""


def assemble_real_landing_chains(by_region: Dict[str, List[Dict]], anchor_socks5: str) -> List[str]:
    """
    去伪存真双轨装配：
    1. 🇸🇬 新加坡节点 -> 纯净官方直出 (真实新加坡出口，延迟极低，杜绝跨洋绕路)
    2. 🇺🇸 美国节点 -> 美西链式落地 (美西直达美西，真实固定美国出口，专供 AI)
    3. 🇺🇸 直出节点 -> 纯净官方直出备用 (真实美国出口，大带宽下载)
    """
    chain_lines = []

    # 1. 组装真·新加坡落地节点 (官方直出专线，不经过美国代理)
    sg_nodes = by_region.get("SG", [])
    for idx, node in enumerate(sg_nodes, 1):
        port = node["port"]
        tag = f"🇸🇬 SG-{port}-{idx:02d}-[直出]"
        chain_lines.append(f"{node['entry']}#{tag}")
    print(f"  + 装配 [🇸🇬 新加坡真落地直出] 节点: {len(sg_nodes)} 个")

    # 2. 组装真·美国落地链式节点 (美西优选入站 + 美国黄金 SOCKS5 落地)
    us_nodes = by_region.get("US", [])
    for idx, node in enumerate(us_nodes, 1):
        port = node["port"]
        tag = f"🇺🇸 US-{port}-{idx:02d}-[socks5]"
        if anchor_socks5:
            chain_entry = f"{node['entry']}#{tag}-$socks5://{anchor_socks5}"
        else:
            chain_entry = f"{node['entry']}#{tag}"
        chain_lines.append(chain_entry)
    print(f"  + 装配 [🇺🇸 美国真落地链式] 节点: {len(us_nodes)} 个 (绑定 SOCKS5: {anchor_socks5})")

    # 3. 补充 4 个美区官方纯净直出备用节点 (用于大流量下载)
    for idx, node in enumerate(us_nodes[:4], 1):
        port = node["port"]
        tag = f"🇺🇸 直出-US-{port}-{idx:02d}"
        chain_lines.append(f"{node['entry']}#{tag}")
    print(f"  + 补充 [🇺🇸 美国真落地直出] 备用节点: 4 个")

    print(f"[*] 真实物理落地节点矩阵装配完毕，总计: {len(chain_lines)} 个纯净节点")
    return chain_lines


def main():
    parser = argparse.ArgumentParser(description="OverNode Real-Landing Dual-Track Assembler")
    parser.add_argument("--inbound", "-i", default="overNode_actions.txt", help="入站优选节点文件 (默认仅使用 actions 纯净组)")
    parser.add_argument("--socks5", "-s", default="socks5.txt", help="出站 SOCKS5 代理文件")
    parser.add_argument("--output", "-o", default="overNode_chain.txt", help="输出链式订阅文件")
    parser.add_argument("--backup", "-b", default="overNode_chain_backup.txt", help="链式订阅软备份文件")
    args = parser.parse_args()

    print("==================================================")
    print("      OverNode 去伪存真·真物理落地装配引擎      ")
    print(f" 入站节点文件: {args.inbound}")
    print(f" 出站代理文件: {args.socks5}")
    print(f" 目标输出订阅: {args.output}")
    print("==================================================")

    by_region = parse_actions_inbound(args.inbound)
    if not by_region["SG"] and not by_region["US"]:
        print("[!] 错误：未读取到有效的 SG/US 入站节点！")
        return

    anchor_socks5 = parse_socks5_anchor(args.socks5)
    chain_lines = assemble_real_landing_chains(by_region, anchor_socks5)

    # 快照软备份
    if os.path.exists(args.output):
        try:
            shutil.copyfile(args.output, args.backup)
            print(f"[+] 已建立历史快照软备份: {args.backup}")
        except Exception as e:
            print(f"[-] 备份失败: {e}")

    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(chain_lines) + "\n")

    print(f"\n[+] 真实落地订阅生成完毕！文件保存至: {args.output}")


if __name__ == "__main__":
    main()
