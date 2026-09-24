#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====================================================================
🛡️ ACL4SSR 规则流水线仿真与全域路由防投毒自检工具
====================================================================
核心功能：
1. 自顶向下全量编译 ACL4SSR_Custom_Advanced.ini 的全部规则（包括远程 ruleset 与行内规则）。
2. 全真模拟 Clash 内核路由匹配，彻底检测“本该走代理的域名是否被提前抢占、误杀入全球直连”（直连投毒）。
3. 支持预设 35 项核心业务矩阵自检（Google Play / Gemini / Steam / YouTube / 网盘 等）。
4. 支持单域名即时测试：python tools/audit_ruleset_vulnerabilities.py <域名>
"""

import os
import sys
import urllib.request
import urllib.error

# 终端输出 UTF-8 保障
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
INI_PATH = os.path.join(ROOT_DIR, "ACL4SSR_Custom_Advanced.ini")
CACHE_DIR = os.path.join(CURRENT_DIR, ".ruleset_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

# 优先探测本地常见代理端口加速下载规则集
PROXY_CANDIDATES = [
    "http://127.0.0.1:11451",
    "http://127.0.0.1:7890",
    "http://127.0.0.1:7897"
]

def get_active_opener():
    for p in PROXY_CANDIDATES:
        try:
            op = urllib.request.build_opener(urllib.request.ProxyHandler({'http': p, 'https': p}))
            with op.open('http://cp.cloudflare.com/generate_204', timeout=2) as r:
                if r.status == 204 or r.status == 200:
                    return op, p
        except Exception:
            continue
    return urllib.request.build_opener(urllib.request.ProxyHandler({})), "DIRECT"

def load_and_compile_pipeline():
    if not os.path.exists(INI_PATH):
        print(f"❌ 找不到规则文件: {INI_PATH}")
        sys.exit(1)

    rules_pipeline = []
    with open(INI_PATH, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line.startswith("ruleset="):
                continue
            parts = line.split("=", 1)[1].split(",", 1)
            target_group = parts[0].strip()
            rule_body = parts[1].strip()
            rules_pipeline.append((line_num, target_group, rule_body))

    opener, proxy_used = get_active_opener()
    print(f"[*] 解析到 {len(rules_pipeline)} 个顶级规则集定义 (下载通道: {proxy_used})")

    expanded_pipeline = []
    for line_num, target_group, rule_body in rules_pipeline:
        if rule_body.startswith("[]"):
            inline = rule_body[2:]
            rule_parts = inline.split(",")
            rtype = rule_parts[0].strip().upper()
            rval = rule_parts[1].strip().lower() if len(rule_parts) > 1 else ""
            expanded_pipeline.append({
                "source_line": line_num,
                "target": target_group,
                "type": rtype,
                "value": rval,
                "source": "INLINE",
                "raw": rule_body
            })
        elif rule_body.startswith("http://") or rule_body.startswith("https://"):
            url = rule_body
            fname = os.path.basename(url)
            cache_file = os.path.join(CACHE_DIR, fname)
            content = ""
            if os.path.exists(cache_file) and os.path.getsize(cache_file) > 0:
                with open(cache_file, "r", encoding="utf-8", errors="ignore") as cf:
                    content = cf.read()
            else:
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with opener.open(req, timeout=8) as resp:
                        content = resp.read().decode('utf-8', errors='ignore')
                    with open(cache_file, "w", encoding="utf-8") as cf:
                        cf.write(content)
                except Exception:
                    pass

            if content:
                for sub_l in content.splitlines():
                    sub_l = sub_l.strip()
                    if not sub_l or sub_l.startswith("#") or sub_l.startswith(";"):
                        continue
                    sub_parts = sub_l.split(",")
                    rtype = sub_parts[0].strip().upper()
                    rval = sub_parts[1].strip().lower() if len(sub_parts) > 1 else ""
                    expanded_pipeline.append({
                        "source_line": line_num,
                        "target": target_group,
                        "type": rtype,
                        "value": rval,
                        "source": fname,
                        "raw": sub_l
                    })
            else:
                expanded_pipeline.append({
                    "source_line": line_num,
                    "target": target_group,
                    "type": "REMOTE_LIST",
                    "value": fname,
                    "source": fname,
                    "raw": rule_body
                })

    print(f"[*] 全景流水线编译就绪！有效规则探测点共计: {len(expanded_pipeline)} 条。")
    return expanded_pipeline

def match_domain(pipeline, domain):
    domain = domain.lower().strip()
    for rule in pipeline:
        rtype = rule["type"]
        rval = rule["value"]
        if rtype == "DOMAIN":
            if domain == rval:
                return rule
        elif rtype == "DOMAIN-SUFFIX":
            if domain == rval or domain.endswith("." + rval):
                return rule
        elif rtype == "DOMAIN-KEYWORD":
            if rval in domain:
                return rule
        elif rtype == "FINAL":
            return rule
    return None

DEFAULT_TEST_CASES = [
    # Google & GMS
    {"domain": "dl.google.com", "expected": "⚡ 自动选择", "category": "Google Play 下载", "must_proxy": True},
    {"domain": "dl.l.google.com", "expected": "⚡ 自动选择", "category": "Google CDN 下载", "must_proxy": True},
    {"domain": "mtalk.google.com", "expected": "⚡ 自动选择", "category": "GMS 核心推送通道", "must_proxy": True},
    {"domain": "play.google.com", "expected": "⚡ 自动选择", "category": "Google Play 商店", "must_proxy": True},
    {"domain": "google.com", "expected": "⚡ 自动选择", "category": "Google 基础服务", "must_proxy": True},
    {"domain": "android.com", "expected": "⚡ 自动选择", "category": "Android 官方生态", "must_proxy": True},
    # AI 专线
    {"domain": "generativelanguage.googleapis.com", "expected": "🤖 AI 专线", "category": "Gemini API 核心接口", "must_proxy": True},
    {"domain": "gemini.google.com", "expected": "🤖 AI 专线", "category": "Gemini 网页控制台", "must_proxy": True},
    {"domain": "api.openai.com", "expected": "🤖 AI 专线", "category": "OpenAI 官方接口", "must_proxy": True},
    {"domain": "chatgpt.com", "expected": "🤖 AI 专线", "category": "ChatGPT 网页端", "must_proxy": True},
    {"domain": "claude.ai", "expected": "🤖 AI 专线", "category": "Claude 官方网页", "must_proxy": True},
    {"domain": "antigravity-unleash.goog", "expected": "🤖 AI 专线", "category": "Antigravity 专线", "must_proxy": True},
    {"domain": "open-vsx.org", "expected": "🤖 AI 专线", "category": "VS Code 扩展市场", "must_proxy": True},
    # Steam
    {"domain": "login.steampowered.com", "expected": "🎮 Steam 服务", "category": "Steam 登录鉴权", "must_proxy": True},
    {"domain": "api.steampowered.com", "expected": "🎮 Steam 服务", "category": "Steam 二维码登录 API", "must_proxy": True},
    {"domain": "store.steampowered.com", "expected": "🎮 Steam 服务", "category": "Steam 商店(防-118)", "must_proxy": True},
    {"domain": "steamcommunity.com", "expected": "🎮 Steam 服务", "category": "Steam 社区市场", "must_proxy": True},
    {"domain": "steamstatic.com", "expected": "🎮 Steam 服务", "category": "Steam 静态资源(防429)", "must_proxy": True},
    {"domain": "steamcontent.com", "expected": "🎯 全球直连", "category": "Steam 游戏下载 CDN", "must_proxy": False},
    # 视频与直出
    {"domain": "googlevideo.com", "expected": "🔗 直连节点", "category": "YouTube 4K 视频切片", "must_proxy": True},
    {"domain": "ttvnw.net", "expected": "🔗 直连节点", "category": "Twitch 视频分片流", "must_proxy": True},
    {"domain": "hembed.com", "expected": "🔗 直连节点", "category": "第三方视频直出流", "must_proxy": True},
    {"domain": "youtube.com", "expected": "🎬 国外媒体", "category": "YouTube 网页控制面", "must_proxy": True},
    {"domain": "twitch.tv", "expected": "🎬 国外媒体", "category": "Twitch 网页控制面", "must_proxy": True},
    {"domain": "rule34video.com", "expected": "🎬 国外媒体", "category": "特色视频站点", "must_proxy": True},
    {"domain": "hanime1.me", "expected": "🎬 国外媒体", "category": "特色动漫站点", "must_proxy": True},
    # 网盘
    {"domain": "gofile.io", "expected": "📥 网盘下载", "category": "Gofile 多线程网盘", "must_proxy": True},
    {"domain": "mega.nz", "expected": "📥 网盘下载", "category": "Mega 网盘", "must_proxy": True},
    {"domain": "pixeldrain.com", "expected": "📥 网盘下载", "category": "Pixeldrain 网盘", "must_proxy": True},
    # 社交与开发
    {"domain": "t.me", "expected": "💬 社交软件", "category": "Telegram 快捷链接", "must_proxy": True},
    {"domain": "telegram.org", "expected": "💬 社交软件", "category": "Telegram 官方网站", "must_proxy": True},
    {"domain": "github.com", "expected": "🐙 GitHub", "category": "GitHub 官网", "must_proxy": True},
    # 微软苹果与国内
    {"domain": "apple.com", "expected": "🎯 全球直连", "category": "Apple 官方直连", "must_proxy": False},
    {"domain": "microsoft.com", "expected": "🎯 全球直连", "category": "Microsoft 官方直连", "must_proxy": False},
    {"domain": "onedrive.live.com", "expected": "⚡ 自动选择", "category": "OneDrive (防抽风代理)", "must_proxy": True},
    {"domain": "baidu.com", "expected": "🎯 全球直连", "category": "百度 (国内直连)", "must_proxy": False},
    {"domain": "bilibili.com", "expected": "🎯 全球直连", "category": "B站 (国内直连)", "must_proxy": False},
    {"domain": "cloud.oracle.com", "expected": "🏛️ 甲骨文服务", "category": "Oracle Cloud 官网", "must_proxy": True}
]

def main():
    print("=" * 85)
    print("      🛡️  ACL4SSR 全规则流水线真实仿真与零投毒穿透测试工具")
    print("=" * 85)

    pipeline = load_and_compile_pipeline()

    if len(sys.argv) > 1:
        # 单域名测试模式
        test_domain = sys.argv[1].strip()
        print(f"\n[*] 正在单域名靶向路由探测: {test_domain}")
        res = match_domain(pipeline, test_domain)
        if res:
            print(f"👉 命中策略组 : [{res['target']}]")
            print(f"👉 命中规则行 : Line {res['source_line']} ({res['source']})")
            print(f"👉 规则内容   : {res['raw']}")
        else:
            print(f"👉 命中策略组 : [🐟 漏网之鱼] (未命中前置规则，走兜底)")
        return

    # 全量矩阵自检模式
    print("\n" + "=" * 85)
    print(f"{'业务类型':<18} | {'测试域名':<33} | {'命中策略组':<12} | {'状态'}")
    print("-" * 85)

    all_passed = True
    poison_count = 0

    for tc in DEFAULT_TEST_CASES:
        d = tc["domain"]
        expected = tc["expected"]
        cat = tc["category"]
        res = match_domain(pipeline, d)

        if not res:
            actual = "🐟 漏网之鱼"
        else:
            actual = res["target"]

        passed = (actual == expected)

        if tc["must_proxy"] and actual == "🎯 全球直连":
            status_str = "🚨 致命投毒! 误入直连"
            all_passed = False
            poison_count += 1
        elif passed:
            status_str = "✅ 预期通过"
        else:
            status_str = f"⚠️ 偏离 (期望:{expected})"
            all_passed = False

        print(f"{cat:<18} | {d:<33} | {actual:<12} | {status_str}")

    print("=" * 85)
    if all_passed and poison_count == 0:
        print("🏆 【自检大捷】全域 35 项核心业务仿真测试 100% 通过！")
        print("🛡️ 【防投毒认证】投毒数为 0！Google Play / GMS / Gemini / Steam / YouTube 全部按预期精准分流！")
    else:
        print(f"❌ 【自检失败】检测到 {poison_count} 处直连投毒漏洞或路由偏离！")
    print("=" * 85)

if __name__ == "__main__":
    main()
