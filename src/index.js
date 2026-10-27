// Cloudflare Worker: YouTube OAuth connect + admin panel + futuristic public site
// Bindings: KV (namespace)
// Secrets: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, ADMIN_PASSWORD, SECRET_KEY

const SCOPE = "https://www.googleapis.com/auth/youtube.readonly";
const enc = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    const m = request.method;
    try {
      if (p === "/") return html(siteHTML());
      if (p === "/admin") return html(adminHTML(await isAdmin(request, env)));
      if (p === "/admin/login" && m === "POST") return adminLogin(request, env);
      if (p === "/admin/logout") return setCookie(redirect("/admin"), "adm", "", 0);
      if (p === "/auth/start") return authStart(url, request, env);
      if (p === "/auth/callback") return authCallback(url, request, env);
      if (p === "/api/site" && m === "GET") return getSite(env);
      if (p === "/api/logout" && m === "POST") return setCookie(json({ ok: true }), "own", "", 0);

      const vm = p.match(/^\/api\/channel\/([\w-]+)\/videos$/);
      if (vm && m === "GET") return channelVideos(vm[1], request, env);

      if (p.startsWith("/api/admin/")) {
        if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
        return adminApi(p, m, request, env);
      }
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },
};

/* ---------- helpers ---------- */

const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json" } });
const html = (b, s = 200) =>
  new Response(b, { status: s, headers: { "Content-Type": "text/html;charset=utf-8" } });
const redirect = (to) => new Response(null, { status: 302, headers: { Location: to } });
const pub = (c) => ({ id: c.id, title: c.title, thumb: c.thumb });

function setCookie(res, name, val, maxAge) {
  res.headers.append("Set-Cookie", `${name}=${val}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`);
  return res;
}
function getCookie(req, name) {
  const m = (req.headers.get("Cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return m ? m[1] : null;
}

async function hmacKey(env) {
  return crypto.subtle.importKey("raw", enc.encode(env.SECRET_KEY),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function sign(env, data) {
  return b64url(await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(data)));
}
async function makeToken(env, data, ttlSec) {
  const body = data + "|" + (Date.now() + ttlSec * 1000);
  return body + "." + (await sign(env, body));
}
async function checkToken(env, token) {
  if (!token || !token.includes(".")) return null;
  const i = token.lastIndexOf(".");
  const body = token.slice(0, i);
  if ((await sign(env, body)) !== token.slice(i + 1)) return null;
  const [data, exp] = body.split("|");
  return Date.now() > +exp ? null : data;
}

async function isAdmin(request, env) {
  return (await checkToken(env, getCookie(request, "adm"))) === "admin";
}

async function getSettings(env) {
  return (await env.KV.get("settings", "json")) || {
    title: "NEXUS TUBE", subtitle: "Neural video archive", accent: "#00f0ff",
    published: false, featured: null,
  };
}
async function listChannels(env) {
  const ids = (await env.KV.get("index", "json")) || [];
  const out = [];
  for (const id of ids) {
    const c = await env.KV.get("ch:" + id, "json");
    if (c) out.push(c);
  }
  return out;
}

async function yt(path, token) {
  const r = await fetch("https://www.googleapis.com/youtube/v3/" + path, {
    headers: { Authorization: "Bearer " + token },
  });
  const d = await r.json();
  if (d.error) throw new Error(d.error.message);
  return d;
}
async function accessToken(env, refresh) {
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
      refresh_token: refresh, grant_type: "refresh_token",
    }),
  });
  const d = await r.json();
  if (!d.access_token) throw new Error("Token refresh failed. Reconnect the channel.");
  return d.access_token;
}

/* ---------- admin login ---------- */

async function adminLogin(request, env) {
  const form = await request.formData();
  if (form.get("password") !== env.ADMIN_PASSWORD) return redirect("/admin?err=1");
  const tok = await makeToken(env, "admin", 60 * 60 * 12);
  return setCookie(redirect("/admin"), "adm", tok, 60 * 60 * 12);
}

/* ---------- OAuth ---------- */

async function authStart(url, request, env) {
  const role = url.searchParams.get("role") === "admin" ? "admin" : "user";
  if (role === "admin" && !(await isAdmin(request, env))) return redirect("/admin");
  const nonce = crypto.randomUUID();
  const q = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: url.origin + "/auth/callback",
    response_type: "code",
    scope: SCOPE,
    access_type: "offline",
    prompt: "consent",
    state: nonce,
  });
  return setCookie(redirect("https://accounts.google.com/o/oauth2/v2/auth?" + q),
    "oauth", nonce + "." + role, 600);
}

async function authCallback(url, request, env) {
  const [nonce, role] = (getCookie(request, "oauth") || "").split(".");
  if (!nonce || url.searchParams.get("state") !== nonce)
    return html("Invalid OAuth state. <a href='/'>Back</a>", 400);
  const code = url.searchParams.get("code");
  if (!code) return html("Connection cancelled. <a href='/'>Back</a>", 400);

  const tr = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: url.origin + "/auth/callback", grant_type: "authorization_code",
    }),
  });
  const tok = await tr.json();
  if (!tok.access_token) return json(tok, 400);

  const d = await yt("channels?part=snippet&mine=true", tok.access_token);
  const ch = d.items && d.items[0];
  if (!ch) return html("This Google account has no YouTube channel.", 400);

  const old = await env.KV.get("ch:" + ch.id, "json");
  const refresh = tok.refresh_token || (old && old.refreshToken);
  if (!refresh) return html("No refresh token received. Remove the app at myaccount.google.com/permissions and retry.", 400);

  const kind = role === "admin" ? "admin" : (old && old.kind) || "user";
  await env.KV.put("ch:" + ch.id, JSON.stringify({
    id: ch.id, title: ch.snippet.title,
    thumb: (ch.snippet.thumbnails && ch.snippet.thumbnails.default && ch.snippet.thumbnails.default.url) || "",
    kind, refreshToken: refresh, connectedAt: Date.now(),
  }));

  const ids = (await env.KV.get("index", "json")) || [];
  if (!ids.includes(ch.id)) {
    ids.push(ch.id);
    await env.KV.put("index", JSON.stringify(ids));
  }

  if (kind === "admin") {
    const s = await getSettings(env);
    if (!s.featured) {
      s.featured = ch.id;
      await env.KV.put("settings", JSON.stringify(s));
    }
    return setCookie(redirect("/admin"), "oauth", "", 0);
  }

  // Regular user: grant owner cookie so they can see their own private videos
  const own = await makeToken(env, "owner:" + ch.id, 60 * 60 * 24 * 30);
  return setCookie(setCookie(redirect("/#/c/" + ch.id), "own", own, 60 * 60 * 24 * 30),
    "oauth", "", 0);
}

/* ---------- public API ---------- */

async function getSite(env) {
  const s = await getSettings(env);
  const all = await listChannels(env);
  const featured = s.published && s.featured ? all.find((c) => c.id === s.featured) : null;
  return json({
    title: s.title, subtitle: s.subtitle, accent: s.accent, published: s.published,
    featured: featured ? pub(featured) : null,
    users: all.filter((c) => c.kind === "user").map(pub),
  });
}

async function channelVideos(id, request, env) {
  const ch = await env.KV.get("ch:" + id, "json");
  if (!ch) return json({ error: "Channel not found" }, 404);

  const s = await getSettings(env);
  const visible = ch.kind === "user" || (s.published && s.featured === id);
  if (!visible) return json({ error: "Channel not public" }, 403);

  const owner = (await checkToken(env, getCookie(request, "own"))) === "owner:" + id;
  const admin = ch.kind === "admin" && (await isAdmin(request, env));
  const canPrivate = owner || admin;

  const token = await accessToken(env, ch.refreshToken);
  const cd = await yt("channels?part=contentDetails&mine=true", token);
  const uploads = cd.items[0].contentDetails.relatedPlaylists.uploads;
  const pl = await yt("playlistItems?part=snippet,status&maxResults=50&playlistId=" + uploads, token);

  let videos = pl.items.map((i) => ({
    id: i.snippet.resourceId.videoId,
    title: i.snippet.title,
    thumb: (i.snippet.thumbnails && i.snippet.thumbnails.medium && i.snippet.thumbnails.medium.url) || "",
    privacy: i.status.privacyStatus,
    published: i.snippet.publishedAt,
  }));
  if (!canPrivate) videos = videos.filter((v) => v.privacy !== "private");
  return json({ channel: pub(ch), canPrivate, videos });
}

/* ---------- admin API ---------- */

async function adminApi(p, m, request, env) {
  if (p === "/api/admin/state" && m === "GET") {
    const s = await getSettings(env);
    const chans = await listChannels(env);
    return json({
      settings: s,
      channels: chans.map((c) => ({ ...pub(c), kind: c.kind, connectedAt: c.connectedAt })),
    });
  }

  if (p === "/api/admin/settings" && m === "POST") {
    const body = await request.json();
    const s = { ...(await getSettings(env)) };
    for (const k of ["title", "subtitle", "accent", "published", "featured"]) {
      if (k in body) s[k] = body[k];
    }
    if (s.published && !s.featured) return json({ error: "Connect and feature a channel before publishing." }, 400);
    await env.KV.put("settings", JSON.stringify(s));
    return json({ ok: true, settings: s });
  }

  const dm = p.match(/^\/api\/admin\/channel\/([\w-]+)$/);
  if (dm && m === "DELETE") {
    const id = dm[1];
    const c = await env.KV.get("ch:" + id, "json");
    if (c) {
      await fetch("https://oauth2.googleapis.com/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: c.refreshToken }),
      }).catch(() => {});
    }
    await env.KV.delete("ch:" + id);
    const ids = ((await env.KV.get("index", "json")) || []).filter((x) => x !== id);
    await env.KV.put("index", JSON.stringify(ids));
    const s = await getSettings(env);
    if (s.featured === id) {
      s.featured = null;
      s.published = false;
      await env.KV.put("settings", JSON.stringify(s));
    }
    return json({ ok: true });
  }

  return json({ error: "not found" }, 404);
}

/* ---------- pages ---------- */

const BASE_CSS = `
:root{--accent:#00f0ff;--pink:#ff00e6;--bg:#05060d}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:#e6f7ff;font-family:ui-monospace,Menlo,Consolas,monospace;
  background:radial-gradient(circle at 15% 0%,#1d0b3f 0,transparent 40%),
             radial-gradient(circle at 90% 100%,#003a4a 0,transparent 45%),var(--bg)}
body::before{content:"";position:fixed;inset:0;pointer-events:none;
  background-image:linear-gradient(rgba(0,240,255,.07) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(0,240,255,.07) 1px,transparent 1px);
  background-size:42px 42px}
.wrap{position:relative;max-width:1200px;margin:0 auto;padding:28px 20px}
h1{font-size:clamp(22px,4vw,40px);letter-spacing:.25em;text-transform:uppercase;margin:0;
  color:#fff;text-shadow:0 0 14px var(--accent),0 0 40px var(--accent)}
.sub{opacity:.6;letter-spacing:.15em;font-size:12px;margin-top:6px}
.glass{background:rgba(255,255,255,.04);border:1px solid rgba(0,240,255,.28);
  backdrop-filter:blur(14px);border-radius:18px;box-shadow:0 0 30px rgba(0,240,255,.12),inset 0 0 20px rgba(255,0,230,.04)}
.btn{display:inline-block;cursor:pointer;text-decoration:none;color:#00121a;font-weight:700;letter-spacing:.1em;
  border:0;padding:12px 20px;border-radius:12px;background:linear-gradient(90deg,var(--accent),var(--pink));
  box-shadow:0 0 22px rgba(0,240,255,.45);font-family:inherit;font-size:14px}
.btn.ghost{background:transparent;color:var(--accent);border:1px solid var(--accent);box-shadow:none}
.btn.danger{background:transparent;color:#ff4d6d;border:1px solid #ff4d6d;box-shadow:none;padding:8px 12px}
input[type=text],input[type=password]{background:rgba(0,0,0,.4);border:1px solid rgba(0,240,255,.35);
  color:#e6f7ff;border-radius:10px;padding:10px 12px;font-family:inherit;width:100%}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(230px,1fr))}
.dim{opacity:.5}
.topbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;margin-bottom:28px}
.ch{padding:14px;display:flex;gap:12px;align-items:center;cursor:pointer;transition:transform .2s}
.ch:hover{transform:translateY(-3px);box-shadow:0 0 40px rgba(255,0,230,.3)}
.ch img{width:56px;height:56px;border-radius:50%;border:2px solid var(--accent)}
.ch small,.row small{display:block;opacity:.6;font-size:11px;letter-spacing:.1em}
.vid{padding:10px;cursor:pointer;transition:transform .2s}
.vid:hover{transform:translateY(-3px)}
.thumb{position:relative;border-radius:12px;overflow:hidden}
.thumb img{width:100%;display:block}
.badge{position:absolute;top:8px;right:8px;font-size:10px;padding:4px 8px;border-radius:8px;
  background:rgba(0,0,0,.7);text-transform:uppercase;letter-spacing:.1em;color:var(--accent)}
.badge.private{color:var(--pink)}
.vid p{font-size:13px;margin:10px 4px 2px;line-height:1.4}
#player{margin:20px 0}
#player iframe{width:100%;aspect-ratio:16/9;border:0;border-radius:18px;
  box-shadow:0 0 50px rgba(0,240,255,.25)}
.section{margin-top:34px}
.section h2{font-size:14px;letter-spacing:.2em;text-transform:uppercase;color:var(--accent);margin:0 0 14px}
.row{padding:14px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.row img{width:48px;height:48px;border-radius:50%}
.row div{flex:1;min-width:160px}
.panel{padding:22px}
label.inline{font-size:13px;display:flex;gap:6px;align-items:center}
`;

function siteHTML() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nexus Tube</title><style>${BASE_CSS}</style></head>
<body><div class="wrap">
  <div class="topbar">
    <div><h1 id="title">Loading</h1><div class="sub" id="subtitle"></div></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a class="btn" href="/auth/start?role=user">CONNECT YOUR CHANNEL</a>
      <button class="btn ghost" id="logout">DISCONNECT SESSION</button>
    </div>
  </div>

  <div class="section"><h2>// Channels</h2><div class="grid" id="channels"></div></div>

  <div id="videos-wrap" hidden class="section">
    <h2 id="vtitle"></h2>
    <div id="player"></div>
    <div class="grid" id="videos"></div>
  </div>
</div>
<script>(${SITE_JS})();</script>
</body></html>`;
}

function adminHTML(loggedIn) {
  const body = loggedIn ? `
  <div class="topbar">
    <div><h1>Control Room</h1><div class="sub">ADMIN PANEL</div></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a class="btn" href="/auth/start?role=admin">CONNECT MY CHANNEL</a>
      <a class="btn ghost" href="/">VIEW SITE</a>
      <a class="btn ghost" href="/admin/logout">LOGOUT</a>
    </div>
  </div>
  <div id="panel">
    <div class="glass panel section">
      <h2>// Site settings</h2>
      <p>Status: <b id="pub-state">--</b></p>
      <label>Title<input type="text" id="s-title"></label><br><br>
      <label>Subtitle<input type="text" id="s-sub"></label><br><br>
      <label>Accent color <input type="color" id="s-accent"></label><br><br>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button class="btn ghost" data-act="save">SAVE</button>
        <button class="btn" id="pub-btn" data-act="pub" data-pub="1">PUBLISH SITE</button>
      </div>
    </div>
    <div class="section"><h2>// Connected channels</h2><div id="chs"></div></div>
  </div>` : `
  <div class="glass panel" style="max-width:380px;margin:12vh auto">
    <h1 style="font-size:20px">Admin Login</h1><br>
    <form method="POST" action="/admin/login">
      <input type="password" name="password" placeholder="Admin password" required>
      <br><br><button class="btn" type="submit">ENTER</button>
    </form>
  </div>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin · Nexus Tube</title><style>${BASE_CSS}</style></head>
<body><div class="wrap">${body}</div>
${loggedIn ? `<script>(${ADMIN_JS})();</script>` : ""}
</body></html>`;
}

/* ---------- client scripts (plain functions, serialized into the page) ---------- */

function SITE_JS() {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

  function card(c, tag) {
    return '<div class="glass ch" data-id="' + esc(c.id) + '"><img src="' + esc(c.thumb) +
      '"><div><b>' + esc(c.title) + '</b><small>' + tag + '</small></div></div>';
  }

  async function load() {
    const s = await (await fetch("/api/site")).json();
    document.title = s.title;
    $("#title").textContent = s.title;
    $("#subtitle").textContent = s.subtitle;
    document.documentElement.style.setProperty("--accent", s.accent || "#00f0ff");
    const cards = [];
    if (s.featured) cards.push(card(s.featured, "FEATURED"));
    s.users.forEach((u) => cards.push(card(u, "MEMBER")));
    $("#channels").innerHTML = cards.join("") || '<p class="dim">No channels yet.</p>';
    if (location.hash.startsWith("#/c/")) openChannel(location.hash.slice(4));
  }

  async function openChannel(id) {
    const r = await fetch("/api/channel/" + encodeURIComponent(id) + "/videos");
    const d = await r.json();
    if (!r.ok) return alert(d.error || "Could not load channel");
    location.hash = "#/c/" + id;
    $("#vtitle").textContent = d.channel.title + " // " + d.videos.length + " videos" +
      (d.canPrivate ? " (owner view: includes private)" : "");
    $("#videos").innerHTML = d.videos.map((v) =>
      '<div class="glass vid" data-vid="' + esc(v.id) + '" data-priv="' + esc(v.privacy) + '">' +
      '<div class="thumb"><img src="' + esc(v.thumb) + '"><span class="badge ' + esc(v.privacy) + '">' +
      esc(v.privacy) + '</span></div><p>' + esc(v.title) + '</p></div>').join("") ||
      '<p class="dim">No videos found.</p>';
    $("#videos-wrap").hidden = false;
    $("#player").innerHTML = "";
    $("#videos-wrap").scrollIntoView({ behavior: "smooth" });
  }

  function play(id, privacy) {
    if (privacy === "private") {
      $("#player").innerHTML = '<p class="dim">Private videos open on YouTube. They play only in the browser where the owner is signed into that Google account.</p>';
      window.open("https://www.youtube.com/watch?v=" + encodeURIComponent(id), "_blank");
      return;
    }
    $("#player").innerHTML = '<iframe src="https://www.youtube.com/embed/' + encodeURIComponent(id) +
      '?autoplay=1" allow="autoplay; encrypted-media; picture-in-picture" allowfullscreen></iframe>';
    $("#player").scrollIntoView({ behavior: "smooth" });
  }

  document.addEventListener("click", (e) => {
    const ch = e.target.closest(".ch");
    if (ch) return openChannel(ch.dataset.id);
    const v = e.target.closest(".vid");
    if (v) return play(v.dataset.vid, v.dataset.priv);
    if (e.target.id === "logout") {
      fetch("/api/logout", { method: "POST" }).then(() => alert("Session cleared"));
    }
  });

  load();
}

function ADMIN_JS() {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

  async function post(url, body) {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const d = await r.json();
    if (!r.ok) alert(d.error || "Request failed");
    return d;
  }

  async function load() {
    const d = await (await fetch("/api/admin/state")).json();
    const s = d.settings;
    $("#s-title").value = s.title;
    $("#s-sub").value = s.subtitle;
    $("#s-accent").value = s.accent || "#00f0ff";
    $("#pub-state").textContent = s.published ? "LIVE" : "DRAFT";
    $("#pub-btn").textContent = s.published ? "UNPUBLISH" : "PUBLISH SITE";
    $("#pub-btn").dataset.pub = s.published ? "0" : "1";
    $("#chs").innerHTML = d.channels.map((c) =>
      '<div class="glass row"><img src="' + esc(c.thumb) + '"><div><b>' + esc(c.title) +
      '</b><small>' + esc(c.kind) + ' · ' + esc(c.id) + '</small></div>' +
      '<label class="inline"><input type="radio" name="feat" value="' + esc(c.id) + '"' +
      (s.featured === c.id ? " checked" : "") + '> featured</label>' +
      '<button class="btn danger" data-act="del" data-id="' + esc(c.id) + '">REMOVE</button></div>'
    ).join("") || '<p class="dim">No channels connected yet. Click CONNECT MY CHANNEL.</p>';
  }

  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-act]");
    if (!b) return;
    const act = b.dataset.act;
    if (act === "save") {
      await post("/api/admin/settings", { title: $("#s-title").value, subtitle: $("#s-sub").value, accent: $("#s-accent").value });
    } else if (act === "pub") {
      await post("/api/admin/settings", { published: b.dataset.pub === "1" });
    } else if (act === "del" && confirm("Remove this channel?")) {
      await fetch("/api/admin/channel/" + encodeURIComponent(b.dataset.id), { method: "DELETE" });
    }
    load();
  });

  document.addEventListener("change", async (e) => {
    if (e.target.name === "feat") await post("/api/admin/settings", { featured: e.target.value });
    load();
  });

  load();
}
