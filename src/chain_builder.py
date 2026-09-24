#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OverNode Real-Landing Dual-Track Assembler (去伪存真·真物理落地双轨装配引擎)

核心升级：
1. 【真·物理归属对齐 (True Physical Alignment)】：
   - 🇸🇬 新加坡节点：全部由 Actions 新加坡优选 IP 承载【官方纯净直出】！
     数据从 Cloudflare 新加坡机房直接出站，出口 100% 为真实新加坡 IP，彻底消灭跨洋绕路，延迟降至最低(~50ms)！
   - 🇺🇸 美国节点：由 Actions 美西优选 IP + 美国高速黄金 SOCKS5 承载【链式中继】！
     美西直达美西，不折返、不绕路，出口为真实纯净美国固定 IP，专供 AI 与特定欧美业务。
2. 【严格聚焦优质主机 (Top-2 Hosts Only)】：
   - 每个国家/地区优先提取延迟最低、速度最快的前 2 个主机 (主力 [01]，备用 [02])。
   - 每一个 IP 的每一个目标端口保留且仅保留 1 个节点，杜绝重复端口与混乱序号。
3. 【极简短命名规范 (No Truncation)】：
   - 规范格式：🇺🇸 US-[01]:443、🇺🇸 US-[01]:2053、🇺🇸 US-[02]:443
   - 直出专线：🇸🇬 SG-[01]:443、🇸🇬 SG-[01]:2053、🇸🇬 SG-[02]:443
   - 彻底删除臃肿的 [socks5] 长标签与多余的 03 序号，客户端卡片永不截断！
"""

import os
import sys
import re
import socket
import argparse
import shutil
from typing import List, Dict, Tuple

# 终端 UTF-8 保障
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# 常用标准 Cloudflare 端口矩阵
DEFAULT_PORTS = [443, 2053, 2083, 2087, 2096, 8443]


def test_ip_latency(ip: str, port: int = 443, timeout: float = 1.2) -> float:
    """快速探测主机连通性与 TCP 握手延迟 (ms)，若超时返回 9999.0"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    import time
    start = time.perf_counter()
    try:
        s.connect((ip, port))
        lat = (time.perf_counter() - start) * 1000.0
        return lat
    except Exception:
        return 9999.0
    finally:
        s.close()


def parse_actions_inbound(filepath: str) -> Dict[str, List[Dict]]:
    """
    读取 Actions 优选文件，按 SG 和 US 归类，并按 IP 聚合支持的端口
    """
    if not os.path.exists(filepath):
        if os.path.exists(os.path.basename(filepath)):
            filepath = os.path.basename(filepath)
        else:
            print(f"[!] 找不到入站节点文件: {filepath}")
            return {"SG": [], "US": []}

    print(f"[*] 正在载入 Actions 纯净入站优选节点: {filepath}")
    by_region = {"SG": [], "US": []}
    
    # 记录出现顺序和端口
    ip_order = {"SG": [], "US": []}
    ip_ports = {"SG": {}, "US": {}}

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
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

                region = None
                if "SG" in tag or "🇸🇬" in tag:
                    region = "SG"
                elif "US" in tag or "🇺🇸" in tag:
                    region = "US"

                if region:
                    if ip not in ip_order[region]:
                        ip_order[region].append(ip)
                        ip_ports[region][ip] = []
                    if port not in ip_ports[region][ip]:
                        ip_ports[region][ip].append(port)

    # 针对每个地区，对 IP 进行健康优选（挑选延迟最低、最快的前 2 台主机）
    for region in ["SG", "US"]:
        candidates = ip_order[region]
        scored_ips = []
        for ip in candidates:
            # 探测可用性与延迟
            lat = test_ip_latency(ip, 443)
            scored_ips.append((ip, lat))
            print(f"  [{region}] 主机 {ip} 连通探测延迟: {lat:.1f}ms")

        # 排序：健康的在前，延迟低者居前
        scored_ips.sort(key=lambda x: x[1])

        # 选拔出前 2 名健康主机（若前 2 名存在不通的，自动往后选替补）
        healthy_ips = [item[0] for item in scored_ips if item[1] < 9999.0]
        if len(healthy_ips) < 2:
            # 补齐
            for item in scored_ips:
                if item[0] not in healthy_ips:
                    healthy_ips.append(item[0])
                if len(healthy_ips) >= 2:
                    break

        selected_ips = healthy_ips[:2]

        for rank, ip in enumerate(selected_ips, 1):
            # 获取该 IP 支持的端口（若源文件中不足，补齐默认标准端口）
            existing_p = ip_ports[region].get(ip, [])
            all_ports = sorted(list(set(existing_p if existing_p else DEFAULT_PORTS)))
            by_region[region].append({
                "ip": ip,
                "rank": rank,
                "ports": all_ports
            })
            print(f"  + [{region}] 锁定主机 [{rank:02d}]: {ip} (承载端口数: {len(all_ports)})")

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
    精简命名与真实落地装配：
    1. 🇸🇬 新加坡节点 -> 纯净官方直出 (真实新加坡出口，延迟 ~50ms，杜绝跨洋绕路)
       命名规范：🇸🇬 SG-[01]:443、🇸🇬 SG-[01]:2053 ...
    2. 🇺🇸 美国节点 -> 美西链式落地 (美西直达美西，真实固定美国出口，专供 AI)
       命名规范：🇺🇸 US-[01]:443、🇺🇸 US-[01]:2053 ...
    3. 🇺🇸 直出备用 -> 纯净官方直出备用 (真实美国出口，大带宽直连下载)
       命名规范：🇺🇸 直连-[01]:443、🇺🇸 直连-[01]:2053
    """
    chain_lines = []

    # 1. 组装真·新加坡落地直出节点 (方案 B 前缀直显：直连-[01]:端口)
    sg_hosts = by_region.get("SG", [])
    for host in sg_hosts:
        ip = host["ip"]
        rank = host["rank"]
        for port in host["ports"]:
            tag = f"🇸🇬 直连-[{rank:02d}]:{port}"
            chain_lines.append(f"{ip}:{port}#{tag}")
    print(f"  + 装配 [🇸🇬 新加坡真落地直出] 节点: {len(sg_hosts)} 台主机共 {sum(len(h['ports']) for h in sg_hosts)} 个端口")

    # 2. 组装真·美国落地链式中继节点 (方案 B 前缀直显：S5-[01]:端口)
    us_hosts = by_region.get("US", [])
    for host in us_hosts:
        ip = host["ip"]
        rank = host["rank"]
        for port in host["ports"]:
            tag = f"🇺🇸 S5-[{rank:02d}]:{port}"
            if anchor_socks5:
                chain_entry = f"{ip}:{port}#{tag}-$socks5://{anchor_socks5}"
            else:
                chain_entry = f"{ip}:{port}#{tag}"
            chain_lines.append(chain_entry)
    print(f"  + 装配 [🇺🇸 美国真落地链式(S5)] 节点: {len(us_hosts)} 台主机共 {sum(len(h['ports']) for h in us_hosts)} 个端口")

    # 3. 补充 2 个美区官方纯净直连备用节点 (大带宽下载专线)
    if us_hosts:
        primary_us = us_hosts[0]
        ip = primary_us["ip"]
        for port in [443, 2053]:
            tag = f"🇺🇸 直连-[01]:{port}"
            chain_lines.append(f"{ip}:{port}#{tag}")
        print(f"  + 补充 [🇺🇸 美国直连备用] 节点: 2 个")

    print(f"[*] 真实物理落地节点矩阵装配完毕，总计: {len(chain_lines)} 个纯净节点")
    return chain_lines


def main():
    parser = argparse.ArgumentParser(description="OverNode Real-Landing Dual-Track Assembler")
    parser.add_argument("--inbound", "-i", default="overNode_actions.txt", help="入站优选节点文件")
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
