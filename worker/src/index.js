export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 解析路径与鉴权 Token
    let token = url.searchParams.get("token");
    let pathname = url.pathname.replace(/^\/+/, "");

    const parts = pathname.split("/");
    if (parts.length >= 2 && parts[0] === env.SUB_TOKEN) {
      token = parts[0];
      pathname = parts.slice(1).join("/");
    }

    // 鉴权校验
    if (!env.SUB_TOKEN || token !== env.SUB_TOKEN) {
      return new Response("403 Forbidden: Invalid Token", {
        status: 403,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    if (!pathname) {
      return new Response("Missing filename. Example: /overNode_actions.txt", {
        status: 400,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }

    const owner = env.GH_OWNER || "mlgbz523";
    const repo = env.GH_REPO || "OverNodes";
    const branch = env.GH_BRANCH || "main";

    async function fetchGitHubRaw(file) {
      const ghUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${file}?ref=${branch}`;
      const res = await fetch(ghUrl, {
        headers: {
          "Authorization": `Bearer ${env.GH_PAT}`,
          "User-Agent": "Cloudflare-Worker-Sub",
          "Accept": "application/vnd.github.raw"
        }
      });
      return res.ok ? await res.text() : null;
    }

    try {
      let content = await fetchGitHubRaw(pathname);
      if (!content) {
        return new Response(`[Error] File not found: ${pathname}`, { status: 404 });
      }

      // ==================== 智能链式与动态节点注入 ====================
      // 当 edgetunnel 请求节点源 (overNode_actions.txt / overNode_test_1.txt) 时：
      if (pathname.includes("overNode") && pathname.endsWith(".txt")) {
        // 1. 动态获取当前最新测速且通过安全审计的 SOCKS5 节点
        const SOCKS5_BLACKLIST = ["198.199.86.11"];
        let socks5Exit = "107.150.41.226:18080"; // 默认经过 TLS 1.3 验证的高信誉安全节点
        try {
          const s5List = await fetchGitHubRaw("socks5.txt");
          if (s5List) {
            const firstValid = s5List.split("\n")
              .map(l => l.trim())
              .find(l => {
                if (!l || l.startsWith("#") || !l.includes(":")) return false;
                const ipPort = l.split("#")[0].trim();
                const ip = ipPort.split(":")[0];
                return !SOCKS5_BLACKLIST.includes(ip) && !SOCKS5_BLACKLIST.includes(ipPort);
              });
            if (firstValid) {
              socks5Exit = firstValid.split("#")[0].trim();
            }
          }
        } catch (_) {}

        // 2. 提取前两个优质新加坡节点
        const lines = content.split("\n").map(l => l.trim()).filter(Boolean);
        const sgNodes = lines.filter(l => l.toUpperCase().includes("SG"));
        
        let chainLines = [];
        if (sgNodes.length >= 1) {
          const hostPort1 = sgNodes[0].split("#")[0].trim();
          chainLines.push(`${hostPort1}#SG-01-S5$socks5://${socks5Exit}`);
        }
        if (sgNodes.length >= 2) {
          const hostPort2 = sgNodes[1].split("#")[0].trim();
          chainLines.push(`${hostPort2}#SG-02-S5$socks5://${socks5Exit}`);
        } else if (sgNodes.length === 1) {
          const hostPort1 = sgNodes[0].split("#")[0].trim();
          chainLines.push(`${hostPort1}#SG-02-S5$socks5://${socks5Exit}`);
        }

        if (chainLines.length > 0 && !content.includes("$socks5://")) {
          content = content.trimEnd() + "\n" + chainLines.join("\n") + "\n";
        }
      }

      return new Response(content, {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "public, max-age=60",
          "Access-Control-Allow-Origin": "*"
        }
      });
    } catch (err) {
      return new Response(`Worker Error: ${err.message}`, {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }
  }
};
