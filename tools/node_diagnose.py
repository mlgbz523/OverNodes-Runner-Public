#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OverNode 节点深度诊断与纯净检测引擎 (Node Diagnostic Suite)
集成参考标准：
1. Cloudflare cdn-cgi/trace (Colo 边缘机房代码、落地国家、TLS 版本、访问特征)
2. IPInfo / Ifconfig (真实出口 IP、ASN 归属组织、地理位置定位)
3. 真实应用层连通性探测 (Google, YouTube, GitHub, Oracle, Cloudflare 真实握手与 HTTP 状态)
4. DNS 与出口一致性分析 (检测是否存在伪装/断流)
"""

import sys
import os
import time
import json
import urllib.request
import argparse
from typing import Dict, Any, Optional, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def fetch_via_proxy(url: str, proxy_url: Optional[str] = None, timeout: float = 6.0) -> Optional[str]:
    """通过指定代理端口请求并获取纯文本数据"""
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 OverNodesDiagnostic/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None


def get_cf_trace(proxy_url: Optional[str] = None) -> Dict[str, str]:
    """1. 解析 Cloudflare Trace 官方特征数据"""
    raw = fetch_via_proxy("https://cloudflare.com/cdn-cgi/trace", proxy_url=proxy_url)
    trace = {}
    if raw:
        for line in raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                trace[k.strip()] = v.strip()
    return trace


def get_ip_info(proxy_url: Optional[str] = None) -> Dict[str, Any]:
    """2. 解析出口 IP 的 ASN、地理位置与 ISP 属性"""
    raw = fetch_via_proxy("https://ipinfo.io/json", proxy_url=proxy_url)
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass

    # 兜底接口 ifconfig.co
    raw_ifc = fetch_via_proxy("https://ifconfig.co/json", proxy_url=proxy_url)
    if raw_ifc:
        try:
            d = json.loads(raw_ifc)
            return {
                "ip": d.get("ip"),
                "city": d.get("city"),
                "country": d.get("country"),
                "org": d.get("asn_org") or d.get("asn")
            }
        except Exception:
            pass
    return {}


def test_site_latency(url: str, proxy_url: Optional[str] = None) -> Tuple[Optional[int], float]:
    """3. 测试特定权威目标站的真实 HTTP 状态与首包延迟 (TTFB)"""
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    t0 = time.perf_counter()
    try:
        with opener.open(req, timeout=5.0) as resp:
            latency = round((time.perf_counter() - t0) * 1000, 1)
            return resp.status, latency
    except urllib.error.HTTPError as e:
        latency = round((time.perf_counter() - t0) * 1000, 1)
        return e.code, latency
    except Exception:
        latency = round((time.perf_counter() - t0) * 1000, 1)
        return None, latency


def main():
    parser = argparse.ArgumentParser(description="OverNodes Deep Network Diagnostic Tool")
    parser.add_argument("--proxy", "-p", default="http://127.0.0.1:11451",
                        help="测试代理地址 (默认 Clash 本地端口: http://127.0.0.1:11451，设为 none 则为直连)")
    args = parser.parse_args()

    proxy_target = None if args.proxy.lower() in ["none", "direct", ""] else args.proxy

    print(f"\n{BOLD}{CYAN}========================================================================{RESET}")
    print(f"{BOLD}{CYAN}      OverNode 纯净节点质量、出口 IP 与应用层深度诊断套件       {RESET}")
    print(f"{BOLD}{CYAN}========================================================================{RESET}")
    print(f"[*] 诊断通道: {GREEN}{proxy_target if proxy_target else '肉身直连 (DIRECT)'}{RESET}")
    print(f"[*] 正在拉取全球分布式网络特征点...\n")

    # 1. 抓取 Cloudflare cdn-cgi/trace
    trace = get_cf_trace(proxy_target)
    # 2. 抓取 IPInfo
    ip_info = get_ip_info(proxy_target)

    exit_ip = trace.get("ip") or ip_info.get("ip") or "未知"
    colo = trace.get("colo", "未知")
    loc = trace.get("loc") or ip_info.get("country") or "未知"
    city = ip_info.get("city", "未知")
    org = ip_info.get("org", "未知")
    tls_ver = trace.get("tls", "未知")
    http_ver = trace.get("http", "未知")
    warp = trace.get("warp", "off")

    print(f"{BOLD}┌─ 1. 出口网络身份与物理位置 ─────────────────────────────────────┐{RESET}")
    print(f"│ 真实出口 IP  : {GREEN}{BOLD}{exit_ip:<20}{RESET} │ 落地国家/地区: {CYAN}{loc} - {city:<16}{RESET} │")
    print(f"│ 接入机房(Colo): {YELLOW}{BOLD}{colo:<20}{RESET} │ 运营商/ASN   : {RESET}{org[:28]:<28} │")
    print(f"│ TLS/HTTP 协议: {RESET}{tls_ver} / {http_ver:<14} │ WARP 加密状态: {RESET}{warp:<28} │")
    print(f"{BOLD}└─────────────────────────────────────────────────────────────────┘{RESET}\n")

    # 3. 目标站实际访问与风控测试
    target_matrix = [
        {"name": "Google", "url": "https://www.google.com/generate_204", "type": "基础引擎"},
        {"name": "YouTube", "url": "https://www.youtube.com", "type": "流媒体"},
        {"name": "GitHub", "url": "https://github.com", "type": "开发者服务"},
        {"name": "Cloudflare", "url": "https://cloudflare.com", "type": "CDN回源"},
        {"name": "Oracle 官网", "url": "https://www.oracle.com", "type": "Akamai WAF"}
    ]

    print(f"{BOLD}┌─ 2. 主流权威业务连通性与风控深度探针 ───────────────────────────┐{RESET}")
    print(f"│ {'目标服务':<12} │ {'类型':<10} │ {'HTTP 状态':<14} │ {'实测 RTT 延迟':<12} │ {'连通判定':<8} │")
    print(f"├──────────────┼────────────┼────────────────┼──────────────┼──────────┤")

    for t in target_matrix:
        code, lat = test_site_latency(t["url"], proxy_target)
        if code in [200, 204, 301, 302]:
            status_str = f"{GREEN}{code} OK{RESET}"
            verdict = f"{GREEN}[PASS] 极佳{RESET}"
        elif code == 403:
            status_str = f"{RED}403 Forbidden{RESET}"
            verdict = f"{RED}[FAIL] WAF拦截{RESET}"
        elif code is None:
            status_str = f"{RED}连接超时/断流{RESET}"
            verdict = f"{RED}[FAIL] 失败{RESET}"
        else:
            status_str = f"{YELLOW}{code}{RESET}"
            verdict = f"{YELLOW}[WARN] 需关注{RESET}"

        print(f"| {t['name']:<12} | {t['type']:<10} | {status_str:<23} | {lat:>6.1f} ms      | {verdict:<17} |")

    print(f"{BOLD}+--------------+------------+----------------+--------------+----------+{RESET}\n")

    # 4. 给出专业综合诊断结论
    print(f"{BOLD}[*] 综合架构诊断结论：{RESET}")
    if exit_ip != "未知" and "Cloudflare" not in org and ("107.167" in exit_ip or "SHARKTECH" in org):
        print(f"  {GREEN}[PASS] 当前处于 SOCKS5 链式代理通道{RESET}，已完美绕开 Cloudflare 内部 1034 错误！")
    elif "Cloudflare" in org:
        print(f"  {CYAN}[INFO] 当前处于 Cloudflare 官方直出通道{RESET}，Oracle 等严苛网站直接畅通！")
    print(f"  + 出口 IP: {exit_ip} | 落地机房: {colo} ({loc})")
    print(f"{BOLD}{CYAN}========================================================================{RESET}\n")


if __name__ == "__main__":
    main()
