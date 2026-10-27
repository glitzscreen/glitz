// ============================================================================
// youtube-worker.js  —  YouTube channel <-> Admin panel <-> Site (Cloudflare Worker)
//
// What it does
//   1. Admin panel  (/admin/youtube): paste a "Copy as cURL (bash)" command (or a raw
//      Cookie header) from your logged-in YouTube tab. The Worker extracts the cookie,
//      stores it in D1, verifies it, detects your channel and syncs ALL channel videos.
//   2. Admin panel shows the connected channel + every video (hide / show per video).
//   3. Site: /youtube (video grid + player) and /api/youtube/videos (JSON for your
//      existing site). Visitors never see the cookie.
//
// Bindings needed (wrangler.toml)
//   [[d1_databases]]  binding = "DB"  database_name = "glitz-screen-db"  database_id = "..."
//   [triggers]        crons = ["0 */6 * * *"]        # optional auto-sync every 6h
//   Secret:           wrangler secret put ADMIN_PASSWORD
//
// Use standalone (export default below) OR inside your existing index.js:
//   import { handleYouTube, syncYouTube } from "./youtube-worker.js";
//   const yt = await handleYouTube(request, env, ctx); if (yt) return yt;
//   // and in scheduled(): ctx.waitUntil(syncYouTube(env));
// ============================================================================

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

// ----------------------------------------------------------------- utilities
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const html = (body, status = 200, cache = "no-store") =>
  new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": cache } });

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha1hex(s) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ------------------------------------------------------------------ D1 setup
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS yt_settings (k TEXT PRIMARY KEY, v TEXT)").run();
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS yt_videos (
      video_id TEXT PRIMARY KEY, title TEXT, thumb TEXT, duration TEXT, views TEXT,
      published TEXT, position INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0, updated_at INTEGER)`
  ).run();
  schemaReady = true;
}
async function getSetting(env, k) {
  const r = await env.DB.prepare("SELECT v FROM yt_settings WHERE k=?").bind(k).first();
  return r ? r.v : null;
}
async function setSetting(env, k, v) {
  await env.DB.prepare("INSERT INTO yt_settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(k, v).run();
}
async function delSetting(env, k) {
  await env.DB.prepare("DELETE FROM yt_settings WHERE k=?").bind(k).run();
}

// ---------------------------------------------------- cURL / cookie parsing
// Accepts: full "Copy as cURL (bash)" text, a "Cookie: ..." line, or just "a=b; c=d".
export function extractCookie(input) {
  let text = String(input || "").replace(/\\\r?\n/g, " ").trim();
  if (!text) return "";

  // Tokenize shell-ish quoting: '...', "...", $'...'
  const tokens = [];
  const re = /\$'((?:\\.|[^'\\])*)'|'([^']*)'|"((?:\\.|[^"\\])*)"|(\S+)/g;
  let m;
  while ((m = re.exec(text))) tokens.push(m[1] ?? m[2] ?? m[3] ?? m[4]);

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if ((t === "-H" || t === "--header") && tokens[i + 1]) {
      const h = tokens[i + 1];
      const mm = h.match(/^\s*cookie\s*:\s*(.+)$/i);
      if (mm) return mm[1].trim();
    }
    if ((t === "-b" || t === "--cookie") && tokens[i + 1]) return tokens[i + 1].trim();
    if (/^cookie:/i.test(t)) return t.replace(/^cookie:\s*/i, "").trim();
  }
  const line = text.match(/^\s*cookie\s*:\s*(.+)$/im);
  if (line) return line[1].trim();
  if (/^[^\s=;]+=[^;]*(;|$)/.test(text) && !/^curl\b/i.test(text)) return text;
  return "";
}

function cookieNames(cookie) {
  return cookie.split(";").map((c) => c.trim().split("=")[0]).filter(Boolean);
}
function getCookieValue(cookie, name) {
  const m = cookie.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return m ? m[1] : null;
}

// -------------------------------------------------------------- YouTube calls
async function sapisidHash(cookie, origin) {
  const sid = getCookieValue(cookie, "SAPISID") || getCookieValue(cookie, "__Secure-3PAPISID");
  if (!sid) return null;
  const ts = Math.floor(Date.now() / 1000);
  return `SAPISIDHASH ${ts}_${await sha1hex(`${ts} ${sid} ${origin}`)}`;
}

function ytHeaders(cookie) {
  return {
    cookie,
    "user-agent": UA,
    "accept-language": "en-US,en;q=0.9",
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  };
}

async function fetchYT(url, cookie, init = {}) {
  return fetch(url, { redirect: "follow", ...init, headers: { ...ytHeaders(cookie), ...(init.headers || {}) } });
}

function parseInitialData(page) {
  const m = page.match(/var ytInitialData\s*=\s*(\{.+?\});\s*<\/script>/s) || page.match(/ytInitialData"\]\s*=\s*(\{.+?\});/s);
  if (!m) return null;
  try { return JSON.parse(m[1]); } catch { return null; }
}

function walk(node, visit) {
  if (Array.isArray(node)) { for (const n of node) walk(n, visit); return; }
  if (node && typeof node === "object") {
    visit(node);
    for (const k in node) walk(node[k], visit);
  }
}

function extractVideos(data) {
  const out = new Map();
  let continuation = null;
  walk(data, (o) => {
    const r = o.videoRenderer || o.gridVideoRenderer;
    if (r && r.videoId) {
      const thumbs = r.thumbnail?.thumbnails || [];
      out.set(r.videoId, {
        id: r.videoId,
        title: r.title?.runs?.map((x) => x.text).join("") || r.title?.simpleText || "Untitled",
        thumb: thumbs.length ? thumbs[thumbs.length - 1].url.split("?")[0] : `https://i.ytimg.com/vi/${r.videoId}/hqdefault.jpg`,
        duration: r.lengthText?.simpleText || "",
        views: r.viewCountText?.simpleText || "",
        published: r.publishedTimeText?.simpleText || "",
      });
    }
    // newer layout
    if (o.lockupViewModel && o.lockupViewModel.contentType === "LOCKUP_CONTENT_TYPE_VIDEO" && o.lockupViewModel.contentId) {
      const l = o.lockupViewModel;
      const id = l.contentId;
      let duration = "", meta = [];
      walk(l, (x) => {
        if (x.thumbnailBadgeViewModel?.text) duration = x.thumbnailBadgeViewModel.text;
        if (Array.isArray(x.metadataParts)) x.metadataParts.forEach((p) => p.text?.content && meta.push(p.text.content));
      });
      out.set(id, {
        id,
        title: l.metadata?.lockupMetadataViewModel?.title?.content || "Untitled",
        thumb: `https://i.ytimg.com/vi/${id}/hqdefault.jpg`,
        duration,
        views: meta[0] || "",
        published: meta[1] || "",
      });
    }
    const c = o.continuationItemRenderer?.continuationEndpoint?.continuationCommand?.token;
    if (c) continuation = c;
  });
  return { videos: [...out.values()], continuation };
}

async function detectChannel(cookie) {
  const res = await fetchYT("https://www.youtube.com/account_advanced", cookie);
  if (/accounts\.google\.com|ServiceLogin/.test(res.url)) return { error: "Cookie is not logged in (expired or incomplete)." };
  const page = await res.text();
  const m = page.match(/"channelId":"(UC[\w-]{22})"/) || page.match(/\/channel\/(UC[\w-]{22})/) || page.match(/(UC[\w-]{22})/);
  if (!m) return { error: "Logged in, but could not detect a channel id. Enter your channel handle/ID manually." };
  return { channelId: m[1] };
}

async function resolveChannelInput(input, cookie) {
  const s = String(input || "").trim();
  if (!s) return detectChannel(cookie);
  let m = s.match(/(UC[\w-]{22})/);
  if (m) return { channelId: m[1] };
  m = s.match(/@[\w.\-]+/);
  const handle = m ? m[0] : s.startsWith("@") ? s : "@" + s;
  const res = await fetchYT(`https://www.youtube.com/${handle}`, cookie);
  const page = await res.text();
  const c = page.match(/"channelId":"(UC[\w-]{22})"/) || page.match(/channel\/(UC[\w-]{22})/);
  return c ? { channelId: c[1] } : { error: "Could not resolve that handle: " + handle };
}

export async function syncYouTube(env) {
  await ensureSchema(env);
  const cookie = await getSetting(env, "cookie");
  if (!cookie) return { ok: false, error: "No cookie connected." };
  let channelId = await getSetting(env, "channel_id");
  if (!channelId) {
    const d = await detectChannel(cookie);
    if (d.error) return { ok: false, error: d.error };
    channelId = d.channelId;
    await setSetting(env, "channel_id", channelId);
  }

  const res = await fetchYT(`https://www.youtube.com/channel/${channelId}/videos`, cookie);
  if (/accounts\.google\.com|ServiceLogin/.test(res.url)) {
    await setSetting(env, "status", "expired");
    return { ok: false, error: "Cookie expired. Paste a fresh cURL in the admin panel." };
  }
  const page = await res.text();
  const data = parseInitialData(page);
  if (!data) return { ok: false, error: "Could not read the channel page (YouTube layout/consent page)." };

  // Channel info
  const meta = data.metadata?.channelMetadataRenderer;
  if (meta?.title) await setSetting(env, "channel_title", meta.title);
  if (meta?.avatar?.thumbnails?.[0]?.url) await setSetting(env, "channel_avatar", meta.avatar.thumbnails[0].url);

  const clientVersion = (page.match(/"INNERTUBE_CLIENT_VERSION":"([^"]+)"/) || [])[1] || "2.20251020.01.00";
  const apiKey = (page.match(/"INNERTUBE_API_KEY":"([^"]+)"/) || [])[1];

  let { videos, continuation } = extractVideos(data);
  const all = new Map(videos.map((v) => [v.id, v]));

  // Pagination through the whole channel (cap at 60 pages ≈ thousands of videos)
  for (let page_i = 0; continuation && page_i < 60; page_i++) {
    const auth = await sapisidHash(cookie, "https://www.youtube.com");
    const r = await fetch(
      "https://www.youtube.com/youtubei/v1/browse?prettyPrint=false" + (apiKey ? "&key=" + apiKey : ""),
      {
        method: "POST",
        headers: {
          ...ytHeaders(cookie),
          "content-type": "application/json",
          origin: "https://www.youtube.com",
          "x-origin": "https://www.youtube.com",
          "x-goog-authuser": "0",
          ...(auth ? { authorization: auth } : {}),
        },
        body: JSON.stringify({
          context: { client: { clientName: "WEB", clientVersion, hl: "en", gl: "US" } },
          continuation,
        }),
      }
    );
    if (!r.ok) break;
    const d = await r.json().catch(() => null);
    if (!d) break;
    const next = extractVideos(d);
    next.videos.forEach((v) => all.set(v.id, v));
    if (!next.videos.length) break;
    continuation = next.continuation;
  }

  const list = [...all.values()];
  if (!list.length) return { ok: false, error: "Connected, but no videos were found on the channel's Videos tab." };

  const now = Date.now();
  const stmts = list.map((v, i) =>
    env.DB.prepare(
      `INSERT INTO yt_videos (video_id,title,thumb,duration,views,published,position,updated_at)
       VALUES (?,?,?,?,?,?,?,?)
       ON CONFLICT(video_id) DO UPDATE SET title=excluded.title, thumb=excluded.thumb,
         duration=excluded.duration, views=excluded.views, published=excluded.published,
         position=excluded.position, updated_at=excluded.updated_at`
    ).bind(v.id, v.title, v.thumb, v.duration, v.views, v.published, i, now)
  );
  for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));

  await setSetting(env, "last_sync", String(now));
  await setSetting(env, "status", "connected");
  return { ok: true, count: list.length };
}

// ------------------------------------------------------------- admin session
async function isAdmin(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const c = request.headers.get("cookie") || "";
  const m = c.match(/(?:^|;\s*)yt_admin=([^;]+)/);
  if (!m) return false;
  const [exp, sig] = decodeURIComponent(m[1]).split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEqual(sig, await hmac(env.ADMIN_PASSWORD, "yt|" + exp));
}

// ------------------------------------------------------------------- router
export async function handleYouTube(request, env, ctx) {
  const url = new URL(request.url);
  const p = url.pathname.replace(/\/+$/, "") || "/";
  const isYT =
    p === "/youtube" || p === "/api/youtube/videos" || p.startsWith("/admin/youtube") || p.startsWith("/admin/api/yt");
  if (!isYT) return null;
  if (!env.DB) return json({ error: "D1 binding DB is missing" }, 500);
  await ensureSchema(env);

  // ---------- public
  if (p === "/api/youtube/videos") {
    const { results } = await env.DB.prepare(
      "SELECT video_id AS id,title,thumb,duration,views,published FROM yt_videos WHERE hidden=0 ORDER BY position ASC"
    ).all();
    const res = json({
      channel: { id: await getSetting(env, "channel_id"), title: await getSetting(env, "channel_title"), avatar: await getSetting(env, "channel_avatar") },
      videos: results,
    });
    res.headers.set("cache-control", "public, max-age=120");
    res.headers.set("access-control-allow-origin", "*");
    return res;
  }
  if (p === "/youtube") {
    const { results } = await env.DB.prepare(
      "SELECT video_id AS id,title,thumb,duration,views,published FROM yt_videos WHERE hidden=0 ORDER BY position ASC"
    ).all();
    return html(sitePage(results, await getSetting(env, "channel_title"), await getSetting(env, "channel_avatar")), 200, "public, max-age=120");
  }

  // ---------- admin login
  if (p === "/admin/youtube/login" && request.method === "POST") {
    const form = await request.formData();
    if (!env.ADMIN_PASSWORD || !safeEqual(String(form.get("password") || ""), env.ADMIN_PASSWORD))
      return html(loginPage("Wrong password"), 401);
    const exp = String(Date.now() + 7 * 864e5);
    const token = encodeURIComponent(exp + "." + (await hmac(env.ADMIN_PASSWORD, "yt|" + exp)));
    return new Response(null, {
      status: 302,
      headers: { location: "/admin/youtube", "set-cookie": `yt_admin=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800` },
    });
  }
  if (p === "/admin/youtube/logout") {
    return new Response(null, { status: 302, headers: { location: "/admin/youtube", "set-cookie": "yt_admin=; Path=/; Max-Age=0" } });
  }
  if (!(await isAdmin(request, env))) {
    if (p.startsWith("/admin/api/")) return json({ error: "unauthorized" }, 401);
    return html(loginPage(env.ADMIN_PASSWORD ? "" : "Set the ADMIN_PASSWORD secret first"));
  }

  // ---------- admin API
  if (p === "/admin/youtube") return html(adminPage());

  if (p === "/admin/api/yt/status") {
    const cookie = await getSetting(env, "cookie");
    const cnt = await env.DB.prepare("SELECT COUNT(*) c, SUM(hidden) h FROM yt_videos").first();
    const { results } = await env.DB.prepare(
      "SELECT video_id AS id,title,thumb,duration,views,published,hidden FROM yt_videos ORDER BY position ASC"
    ).all();
    return json({
      connected: !!cookie,
      status: await getSetting(env, "status"),
      channel: { id: await getSetting(env, "channel_id"), title: await getSetting(env, "channel_title"), avatar: await getSetting(env, "channel_avatar") },
      cookieInfo: cookie ? { length: cookie.length, names: cookieNames(cookie) } : null, // values are never returned
      lastSync: Number(await getSetting(env, "last_sync")) || null,
      total: cnt.c || 0,
      hidden: cnt.h || 0,
      videos: results,
    });
  }

  if (p === "/admin/api/yt/connect" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const cookie = extractCookie(body.curl);
    if (!cookie) return json({ ok: false, error: "No Cookie header found in what you pasted." }, 400);
    const names = cookieNames(cookie);
    if (!names.includes("SAPISID") && !names.includes("__Secure-3PAPISID") && !names.includes("SID"))
      return json({ ok: false, error: "This cookie has no Google login (SID / SAPISID). Copy the cURL from a logged-in youtube.com request." }, 400);
    const ch = await resolveChannelInput(body.channel, cookie);
    if (ch.error) return json({ ok: false, error: ch.error }, 400);
    await setSetting(env, "cookie", cookie);
    await setSetting(env, "channel_id", ch.channelId);
    const sync = await syncYouTube(env);
    return json(sync, sync.ok ? 200 : 502);
  }

  if (p === "/admin/api/yt/sync" && request.method === "POST") {
    const sync = await syncYouTube(env);
    return json(sync, sync.ok ? 200 : 502);
  }

  if (p === "/admin/api/yt/disconnect" && request.method === "POST") {
    for (const k of ["cookie", "channel_id", "channel_title", "channel_avatar", "status", "last_sync"]) await delSetting(env, k);
    if (new URL(request.url).searchParams.get("purge") === "1") await env.DB.prepare("DELETE FROM yt_videos").run();
    return json({ ok: true });
  }

  if (p === "/admin/api/yt/hide" && request.method === "POST") {
    const { id, hidden } = await request.json();
    await env.DB.prepare("UPDATE yt_videos SET hidden=? WHERE video_id=?").bind(hidden ? 1 : 0, String(id)).run();
    return json({ ok: true });
  }

  return json({ error: "not found" }, 404);
}

// ------------------------------------------------------------------- HTML
const BASE_CSS = `
*{box-sizing:border-box}body{margin:0;background:#0f1115;color:#e8eaf0;font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
a{color:inherit}.wrap{max-width:1200px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px}
.card{background:#181b22;border:1px solid #262a35;border-radius:12px;overflow:hidden;cursor:pointer;position:relative}
.card img{width:100%;aspect-ratio:16/9;object-fit:cover;display:block;background:#222}
.card .t{padding:10px 12px 12px;font-weight:600;font-size:14px}.card .m{padding:0 12px 12px;color:#8b93a7;font-size:12px}
.dur{position:absolute;right:8px;top:calc(56.25% * 1 - 30px);background:#000c;color:#fff;font-size:12px;padding:1px 6px;border-radius:4px}
button,.btn{background:#e62117;color:#fff;border:0;border-radius:8px;padding:9px 14px;font-weight:600;cursor:pointer;font-size:14px}
button.sec{background:#2a2f3b}button:disabled{opacity:.5}
input,textarea{width:100%;background:#12141a;color:#e8eaf0;border:1px solid #2b3040;border-radius:8px;padding:10px;font:13px ui-monospace,Consolas,monospace}
`;

function loginPage(msg) {
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>YouTube Admin</title>
<style>${BASE_CSS}form{max-width:340px;margin:12vh auto;background:#181b22;padding:24px;border-radius:14px;border:1px solid #262a35}input{margin:12px 0}</style>
<form method=post action=/admin/youtube/login><h2 style="margin:0">YouTube Admin</h2>
<input type=password name=password placeholder=Password autofocus><button style="width:100%">Login</button>
<p style="color:#ff6b6b">${esc(msg)}</p></form>`;
}

function adminPage() {
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>YouTube Admin</title>
<style>${BASE_CSS}
.panel{background:#181b22;border:1px solid #262a35;border-radius:12px;padding:16px;margin-bottom:16px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}.pill{padding:3px 10px;border-radius:99px;font-size:12px;font-weight:700}
.ok{background:#12351f;color:#4ade80}.bad{background:#3a1616;color:#ff6b6b}.card.hid{opacity:.35}
.chan{display:flex;gap:12px;align-items:center}.chan img{width:48px;height:48px;border-radius:50%}
details summary{cursor:pointer;color:#8b93a7}pre{white-space:pre-wrap;background:#12141a;padding:10px;border-radius:8px;font-size:12px}
</style>
<div class=wrap>
<div class=row style="justify-content:space-between"><h2 style="margin:0">YouTube Channel — Admin</h2>
<div class=row><a class="btn sec" href=/youtube target=_blank>View site page</a><a class="btn sec" href=/admin/youtube/logout>Logout</a></div></div>

<div class=panel id=statusBox style="margin-top:16px">Loading…</div>

<div class=panel>
<h3 style="margin-top:0">Connect with cookie (cURL bash)</h3>
<details><summary>How to get it</summary><pre>1. Open youtube.com in Chrome, logged in to the channel's account.
2. F12 → Network tab → reload → click the first "www.youtube.com" request.
3. Right click → Copy → Copy as cURL (bash).
4. Paste below. A bare "Cookie: ..." line also works.</pre></details>
<textarea id=curl rows=6 placeholder="curl 'https://www.youtube.com/' -H 'cookie: SID=...; SAPISID=...' ..." style="margin-top:10px"></textarea>
<input id=chan placeholder="Channel handle or ID (optional — auto-detected from the cookie)" style="margin-top:8px;font-family:inherit">
<div class=row style="margin-top:10px"><button id=btnConnect>Connect &amp; sync</button><span id=msg></span></div>
</div>

<div class=row style="margin-bottom:12px"><h3 style="margin:0" id=vidTitle>Videos</h3>
<button class=sec id=btnSync>Sync now</button><button class=sec id=btnDisc>Disconnect</button></div>
<div class=grid id=grid></div>
</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,opts){const r=await fetch(path,opts);let d={};try{d=await r.json()}catch(e){}if(r.status===401)location.reload();return d}
function setMsg(t,bad){$('msg').textContent=t;$('msg').style.color=bad?'#ff6b6b':'#4ade80'}
async function load(){
  const s=await api('/admin/api/yt/status');
  let h='';
  if(s.connected){
    h+='<div class=chan>'+(s.channel.avatar?'<img src="'+esc(s.channel.avatar)+'">':'')+
    '<div><b>'+esc(s.channel.title||s.channel.id||'Channel')+'</b><div style="color:#8b93a7;font-size:12px">'+esc(s.channel.id||'')+'</div></div>'+
    '<span class="pill '+(s.status==='connected'?'ok':'bad')+'">'+(s.status==='connected'?'CONNECTED':'COOKIE '+esc((s.status||'?').toUpperCase()))+'</span></div>'+
    '<div style="margin-top:8px;color:#8b93a7;font-size:13px">Cookie stored ('+s.cookieInfo.names.length+' cookies: '+esc(s.cookieInfo.names.slice(0,8).join(', '))+'…) · '+s.total+' videos ('+s.hidden+' hidden) · last sync '+(s.lastSync?new Date(s.lastSync).toLocaleString():'never')+'</div>';
  } else h='<span class="pill bad">NOT CONNECTED</span> Paste a cURL below to connect your channel.';
  $('statusBox').innerHTML=h;
  $('vidTitle').textContent='Videos ('+s.total+')';
  $('grid').innerHTML=s.videos.map(v=>'<div class="card'+(v.hidden?' hid':'')+'"><img loading=lazy src="'+esc(v.thumb)+'"><div class=t>'+esc(v.title)+'</div>'+
   '<div class=m>'+esc([v.duration,v.views,v.published].filter(Boolean).join(' · '))+'</div>'+
   '<div class=m><button class=sec data-id="'+esc(v.id)+'" data-h="'+(v.hidden?0:1)+'">'+(v.hidden?'Show on site':'Hide from site')+'</button> <a href="https://youtu.be/'+esc(v.id)+'" target=_blank>open</a></div></div>').join('');
}
$('grid').onclick=async e=>{const b=e.target.closest('button[data-id]');if(!b)return;
  await api('/admin/api/yt/hide',{method:'POST',body:JSON.stringify({id:b.dataset.id,hidden:b.dataset.h==='1'})});load()};
$('btnConnect').onclick=async()=>{
  $('btnConnect').disabled=true;setMsg('Connecting & syncing…');
  const d=await api('/admin/api/yt/connect',{method:'POST',body:JSON.stringify({curl:$('curl').value,channel:$('chan').value})});
  $('btnConnect').disabled=false;
  if(d.ok){setMsg('Connected — '+d.count+' videos synced.');$('curl').value='';}else setMsg(d.error||'Failed',true);
  load()};
$('btnSync').onclick=async()=>{$('btnSync').disabled=true;const d=await api('/admin/api/yt/sync',{method:'POST'});
  $('btnSync').disabled=false;setMsg(d.ok?('Synced '+d.count+' videos.'):(d.error||'Failed'),!d.ok);load()};
$('btnDisc').onclick=async()=>{if(!confirm('Remove the stored cookie? (videos stay on the site)'))return;
  await api('/admin/api/yt/disconnect',{method:'POST'});load()};
load();
</script>`;
}

function sitePage(videos, title, avatar) {
  const data = JSON.stringify(videos).replace(/</g, "\\u003c");
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>${esc(title || "Videos")}</title>
<style>${BASE_CSS}
.head{display:flex;align-items:center;gap:12px;margin-bottom:18px}.head img{width:44px;height:44px;border-radius:50%}
#player{display:none;margin-bottom:20px}#player .box{position:relative;aspect-ratio:16/9;background:#000;border-radius:12px;overflow:hidden}
#player iframe{position:absolute;inset:0;width:100%;height:100%;border:0}#ptitle{font-weight:700;font-size:18px;margin:10px 0}
</style>
<div class=wrap>
<div class=head>${avatar ? `<img src="${esc(avatar)}">` : ""}<h2 style="margin:0">${esc(title || "Videos")}</h2></div>
<div id=player><div class=box id=pbox></div><div id=ptitle></div></div>
<div class=grid id=grid></div></div>
<script>
const V=${data};
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
document.getElementById('grid').innerHTML=V.map(v=>'<div class=card data-id="'+esc(v.id)+'"><img loading=lazy src="'+esc(v.thumb)+'"><div class=t>'+esc(v.title)+'</div><div class=m>'+esc([v.duration,v.views,v.published].filter(Boolean).join(' · '))+'</div></div>').join('');
function play(id){const v=V.find(x=>x.id===id);if(!v)return;
  document.getElementById('pbox').innerHTML='<iframe src="https://www.youtube-nocookie.com/embed/'+encodeURIComponent(id)+'?autoplay=1&rel=0" allow="autoplay; encrypted-media; picture-in-picture; fullscreen" allowfullscreen></iframe>';
  document.getElementById('ptitle').textContent=v.title;document.getElementById('player').style.display='block';
  history.replaceState(null,'','#'+id);scrollTo({top:0,behavior:'smooth'})}
document.getElementById('grid').onclick=e=>{const c=e.target.closest('.card');if(c)play(c.dataset.id)};
if(location.hash.length>1)play(location.hash.slice(1));
</script>`;
}

// ---------------------------------------------------------- standalone mode
export default {
  async fetch(request, env, ctx) {
    const r = await handleYouTube(request, env, ctx);
    if (r) return r;
    return Response.redirect(new URL("/youtube", request.url).toString(), 302);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(syncYouTube(env));
  },
};
