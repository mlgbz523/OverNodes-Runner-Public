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
