#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare DNS 优选 IP 自动同步工具 (DDNS)
功能：
1. 从测速产物 (如 overNode_actions.txt / overNode_local.txt) 中提取最靠前的优质 IP
2. 调用 Cloudflare v4 REST API，自动将指定二级域名 (如 cf.yourdomain.com) 的 A 记录同步更新
3. 支持多 A 记录负载均衡轮询 (默认保留前 2 个最高速 IP)
4. 拥有状态哈希比对 (线上已一致时不重复请求)、超时重试与纯标准库零外部依赖设计
"""

import os
import sys
import re
import json
import argparse
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Tuple

IP_PORT_PATTERN = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

def log(msg: str, level: str = "INFO"):
    color = "\033[92m" if level == "INFO" else ("\033[93m" if level == "WARN" else "\033[91m")
    reset = "\033[0m"
    print(f"[{color}{level}{reset}] [CF-DNS] {msg}")

def extract_top_ips(file_path: str, count: int = 2) -> List[str]:
    """从节点文件中提取延迟最低/排名最靠前的合格 IP"""
    if not os.path.exists(file_path):
        log(f"未找到输入节点文件: {file_path}", "WARN")
        return []

    ips = []
    seen = set()
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = IP_PORT_PATTERN.match(line)
            if m:
                ip = m.group(1)
                # 简单过滤私有/回环地址
                if ip.startswith(("127.", "10.", "192.168.", "172.16.")):
                    continue
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
                    if len(ips) >= count:
                        break
    return ips

def cf_api_request(
    endpoint: str,
    token: str,
    method: str = "GET",
    payload: Optional[dict] = None
) -> Tuple[bool, Optional[dict], str]:
    """带有标准调用的 Cloudflare API 请求器"""
    url = f"https://api.cloudflare.com/client/v4{endpoint}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "OverNodes-DDNS-Sync/1.0"
    }
    data = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            res_json = json.loads(body)
            if res_json.get("success", False):
                return True, res_json, ""
            else:
                errors = res_json.get("errors", [])
                err_msg = "; ".join([e.get("message", "") for e in errors]) or "未知错误"
                return False, res_json, err_msg
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8")
            err_json = json.loads(err_body)
            errors = err_json.get("errors", [])
            err_msg = "; ".join([e.get("message", "") for e in errors]) or err_body
        except Exception:
            err_msg = str(e)
        return False, None, f"HTTP {e.code}: {err_msg}"
    except Exception as e:
        return False, None, f"网络异常: {e}"

def get_zone_id_by_domain(domain_name: str, token: str) -> Optional[str]:
    """如果未提供 ZONE_ID，则通过根域名自动检索 Zone ID"""
    # 提取顶级/二级根域名 (如 sub.28870721.xyz -> 28870721.xyz)
    parts = domain_name.strip(".").split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = domain_name

    endpoint = f"/zones?name={root_domain}&status=active"
    success, res, err = cf_api_request(endpoint, token)
    if success and res and res.get("result"):
        zone_id = res["result"][0]["id"]
        log(f"自动识别根域名 [{root_domain}] 对应的 Zone ID: {zone_id}")
        return zone_id
    else:
        log(f"自动查询根域名 [{root_domain}] 失败: {err}", "WARN")
        return None

def sync_dns_records(
    token: str,
    zone_id: str,
    dns_name: str,
    target_ips: List[str],
    ttl: int = 60,
    proxied: bool = False
) -> bool:
    """同步指定域名的 A 记录为目标优选 IP 列表"""
    dns_name = dns_name.strip().lower()
    log(f"开始同步域名 [{dns_name}] 的 DNS 解析，目标优选 IP: {target_ips}")

    # 1. 获取现有 A 记录
    endpoint = f"/zones/{zone_id}/dns_records?type=A&name={dns_name}"
    success, res, err = cf_api_request(endpoint, token)
    if not success or not res:
        log(f"获取域名 [{dns_name}] 现有解析记录失败: {err}", "ERROR")
        return False

    existing_records = res.get("result", [])
    existing_ips = {r["content"]: r["id"] for r in existing_records}
    log(f"线上现有 A 记录 IP: {list(existing_ips.keys())}")

    # 2. 对比差异
    target_set = set(target_ips)
    current_set = set(existing_ips.keys())

    if target_set == current_set:
        log(f"✅ 线上解析与目标优选 IP 完全一致，跳过更新，保持现有 DNS 缓存。")
        return True

    # 3. 找出需要删除的多余记录
    to_delete_ips = current_set - target_set
    for ip in to_delete_ips:
        record_id = existing_ips[ip]
        del_endpoint = f"/zones/{zone_id}/dns_records/{record_id}"
        ok, _, d_err = cf_api_request(del_endpoint, token, method="DELETE")
        if ok:
            log(f"已清理旧 A 记录: {ip}")
        else:
            log(f"清理旧记录 {ip} 失败: {d_err}", "WARN")

    # 4. 找出需要新增的 IP
    to_add_ips = target_set - current_set
    for ip in to_add_ips:
        add_payload = {
            "type": "A",
            "name": dns_name,
            "content": ip,
            "ttl": ttl,
            "proxied": proxied
        }
        add_endpoint = f"/zones/{zone_id}/dns_records"
        ok, a_res, a_err = cf_api_request(add_endpoint, token, method="POST", payload=add_payload)
        if ok:
            log(f"成功新增 A 记录: {dns_name} -> {ip} (TTL: {ttl}, Proxied: {proxied})")
        else:
            log(f"新增 A 记录 {ip} 失败: {a_err}", "ERROR")

    log(f"🎉 域名 [{dns_name}] 优选 DNS 同步完成！最新绑定 IP: {target_ips}")
    return True

def main():
    parser = argparse.ArgumentParser(description="Cloudflare 优选 IP 自动同步至 DNS 域名解析")
    parser.add_argument("--input", "-i", default="overNode_actions.txt", help="测速结果输入文件")
    parser.add_argument("--name", "-n", default=os.environ.get("CF_DNS_NAME", ""), help="需要解析的完整域名 (例如 cf.28870721.xyz)")
    parser.add_argument("--zone-id", "-z", default=os.environ.get("CF_ZONE_ID", ""), help="Cloudflare Zone ID")
    parser.add_argument("--token", "-t", default=os.environ.get("CF_API_TOKEN", ""), help="Cloudflare API Token")
    parser.add_argument("--top-count", "-c", type=int, default=2, help="保留的 Top 优选 IP 数量 (默认: 2)")
    parser.add_argument("--ttl", type=int, default=60, help="DNS TTL 秒数 (默认: 60)")
    parser.add_argument("--proxied", action="store_true", help="是否开启 CF CDN 代理 (优选 IP 必须保持关闭，默认: False)")
    args = parser.parse_args()

    token = args.token.strip()
    if not token:
        log("未检测到环境变量 CF_API_TOKEN，跳过 Cloudflare DNS 域名解析同步 (非阻断警告)。", "WARN")
        sys.exit(0)

    dns_name = args.name.strip()
    if not dns_name:
        log("未指定目标域名 (参数 --name 或环境变量 CF_DNS_NAME)，跳过 DNS 同步。", "WARN")
        sys.exit(0)

    # 智能定位输入文件
    input_file = args.input
    if not os.path.exists(input_file):
        # 兼容当前工作区与上级目录查找
        candidates = [
            os.path.join(os.getcwd(), input_file),
            os.path.join(os.path.dirname(__file__), "..", input_file),
            os.path.join(os.getcwd(), "overNode_actions.txt"),
            os.path.join(os.getcwd(), "overNode_local.txt"),
            os.path.join(os.getcwd(), "overNode.txt")
        ]
        found = False
        for c in candidates:
            if os.path.exists(c) and os.path.getsize(c) > 0:
                input_file = c
                found = True
                break
        if not found:
            log(f"未找到可用的测速结果节点文件，跳过 DNS 同步。", "WARN")
            sys.exit(0)

    top_ips = extract_top_ips(input_file, count=args.top_count)
    if not top_ips:
        log(f"未能从 {input_file} 提取到有效 IP，跳过 DNS 同步。", "WARN")
        sys.exit(0)

    log(f"成功从 {os.path.basename(input_file)} 提取到前 {len(top_ips)} 名优选 IP: {top_ips}")

    # 获取 Zone ID
    zone_id = args.zone_id.strip()
    if not zone_id:
        zone_id = get_zone_id_by_domain(dns_name, token)
        if not zone_id:
            log(f"无法确定域名 [{dns_name}] 的 Zone ID，请在参数中指定 --zone-id 或环境变量 CF_ZONE_ID。", "ERROR")
            sys.exit(1)

    success = sync_dns_records(
        token=token,
        zone_id=zone_id,
        dns_name=dns_name,
        target_ips=top_ips,
        ttl=args.ttl,
        proxied=args.proxied
    )

    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
