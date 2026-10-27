/**
 * Cloudflare Worker - YouTube-style video site + admin panel
 *
 * SETUP
 * 1. Create KV namespace:   npx wrangler kv namespace create VIDEOS
 * 2. wrangler.toml:
 *      name = "my-tube"
 *      main = "worker.js"
 *      compatibility_date = "2024-11-01"
 *      [[kv_namespaces]]
 *      binding = "VIDEOS"
 *      id = "<ID from step 1>"
 * 3. Set admin password:    npx wrangler secret put ADMIN_PASSWORD
 * 4. Deploy:                npx wrangler deploy
 *
 * ROUTES
 *   /              home grid + search (?q=)        (published videos only)
 *   /watch?v=ID    official YouTube embed player + details
 *   /admin         login, then:
 *                    - connect YouTube account (paste curl/bash/cookie)
 *                    - see that channel's videos, Publish / Unpublish to the site
 *                    - add / delete videos manually
 */

const esc = (s = "") =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Accepts full URLs (watch, youtu.be, shorts, embed) or a bare 11-char ID
function parseYouTubeId(input = "") {
  const s = input.trim();
  if (/^[\w-]{11}$/.test(s)) return s;
  try {
    const u = new URL(s);
    if (u.hostname === "youtu.be") return u.pathname.slice(1, 12);
    const v = u.searchParams.get("v");
    if (v) return v.slice(0, 11);
    const m = u.pathname.match(/\/(embed|shorts|live)\/([\w-]{11})/);
    if (m) return m[2];
  } catch {}
  return null;
}

async function getVideos(env) {
  return JSON.parse((await env.VIDEOS.get("videos")) || "[]");
}
const saveVideos = (env, list) => env.VIDEOS.put("videos", JSON.stringify(list));
// A video with no "published" field (added before this feature) counts as published
const isPublished = (v) => v.published !== false;

/* ---------- auth: signed, expiring cookie ---------- */
const enc = new TextEncoder();
async function sign(env, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(env.ADMIN_PASSWORD), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function isAdmin(req, env) {
  if (!env.ADMIN_PASSWORD) return false;
  const m = (req.headers.get("Cookie") || "").match(/session=(\d+)\.([a-f0-9]+)/);
  if (!m || Number(m[1]) < Date.now()) return false;
  return safeEqual(m[2], await sign(env, m[1]));
}

/* ---------- encrypted storage for the pasted YouTube cookie ---------- */
// The cookie is a full login to the Google account, so it is never stored in plain text.
// AES-GCM key is derived from ADMIN_PASSWORD (changing the password requires reconnecting).
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function aesKey(env) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode("yt-cookie:" + env.ADMIN_PASSWORD));
  return crypto.subtle.importKey("raw", d, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function encrypt(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env), enc.encode(text));
  return b64(iv) + "." + b64(ct);
}
async function decrypt(env, blob) {
  const [iv, ct] = blob.split(".");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, await aesKey(env), unb64(ct));
  return new TextDecoder().decode(pt);
}
async function getCookie(env) {
  const blob = await env.VIDEOS.get("yt_cookie");
  if (!blob) return null;
  try {
    return await decrypt(env, blob);
  } catch {
    return null;
  }
}

/* ---------- YouTube account (cookie) integration ---------- */
// Accepts: "Copy as cURL (bash)" text, a "Cookie: a=b; c=d" header, a bare "a=b; c=d" string,
// or a Netscape cookies.txt export.
function parseCookieInput(raw = "") {
  raw = raw.trim();
  let m = raw.match(/(?:-H|--header)\s+(['"])\s*cookie:\s*([\s\S]*?)\1/i);
  if (m) return m[2].trim();
  m = raw.match(/(?:-b|--cookie)\s+(['"])([\s\S]*?)\1/);
  if (m) return m[2].trim();
  const lines = raw.split(/\r?\n/).map((l) => l.replace(/^#HttpOnly_/, "")).filter((l) => l && !l.startsWith("#"));
  if (lines.length && lines.every((l) => l.split("\t").length >= 7)) {
    return lines
      .map((l) => l.split("\t"))
      .filter((f) => /youtube\.com|google\.com/.test(f[0]))
      .map((f) => `${f[5]}=${f[6]}`)
      .join("; ");
  }
  return raw.replace(/^cookie:\s*/i, "").replace(/\s*[\r\n]+\s*/g, "; ");
}
const cookieVal = (cookie, name) => (cookie.match(new RegExp("(?:^|;\\s*)" + name.replace(/[-_]/g, "\\$&") + "=([^;]+)")) || [])[1];

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
const YT_ORIGIN = "https://www.youtube.com";
const YT_KEY = "AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"; // public InnerTube web key
const VIDEOS_TAB = "EgZ2aWRlb3PyBgQKAjoA"; // channel "Videos" tab

async function sapisidAuth(cookie) {
  const sid = cookieVal(cookie, "SAPISID") || cookieVal(cookie, "__Secure-3PAPISID");
  if (!sid) throw new Error("Cookie has no SAPISID / __Secure-3PAPISID - copy it while signed in to youtube.com");
  const ts = Math.floor(Date.now() / 1000);
  const hash = async (v) =>
    [...new Uint8Array(await crypto.subtle.digest("SHA-1", enc.encode(`${ts} ${v} ${YT_ORIGIN}`)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  let out = `SAPISIDHASH ${ts}_${await hash(sid)}`;
  const s1 = cookieVal(cookie, "__Secure-1PAPISID");
  const s3 = cookieVal(cookie, "__Secure-3PAPISID");
  if (s1) out += ` SAPISID1PHASH ${ts}_${await hash(s1)}`;
  if (s3) out += ` SAPISID3PHASH ${ts}_${await hash(s3)}`;
  return out;
}

async function ytCall(cookie, endpoint, body) {
  const res = await fetch(`${YT_ORIGIN}/youtubei/v1/${endpoint}?prettyPrint=false&key=${YT_KEY}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: cookie,
      Authorization: await sapisidAuth(cookie),
      Origin: YT_ORIGIN,
      "X-Origin": YT_ORIGIN,
      "X-Goog-AuthUser": "0",
      "User-Agent": UA,
    },
    body: JSON.stringify({ context: { client: { clientName: "WEB", clientVersion: "2.20241022.01.00", hl: "en", gl: "US" } }, ...body }),
  });
  if (res.status === 401 || res.status === 403) throw new Error("YouTube rejected the cookie (expired or signed out). Paste a fresh one.");
  if (!res.ok) throw new Error(`YouTube returned HTTP ${res.status}`);
  return res.json();
}

// Walk any JSON tree, calling fn(key, value) for every property
function walk(node, fn) {
  if (Array.isArray(node)) return node.forEach((n) => walk(n, fn));
  if (node && typeof node === "object")
    for (const [k, v] of Object.entries(node)) {
      fn(k, v);
      walk(v, fn);
    }
}
const textOf = (t) => (t && (t.simpleText || (t.runs || []).map((r) => r.text).join(""))) || "";

async function fetchChannel(cookie) {
  // 1. who is signed in?
  const menu = await ytCall(cookie, "account/account_menu", {});
  let name = "", handle = "", channelId = "";
  walk(menu, (k, v) => {
    if (k === "activeAccountHeaderRenderer") {
      name = textOf(v.accountName);
      handle = textOf(v.channelHandle);
    }
    if (k === "browseId" && typeof v === "string" && v.startsWith("UC") && !channelId) channelId = v;
  });
  if (!channelId) throw new Error("No YouTube channel found for this account (is the cookie signed in, and does the account have a channel?)");

  // 2. channel's Videos tab (+ a few continuation pages)
  const videos = new Map();
  let data = await ytCall(cookie, "browse", { browseId: channelId, params: VIDEOS_TAB });
  for (let page = 0; page < 5; page++) {
    let token = "";
    walk(data, (k, v) => {
      if ((k === "videoRenderer" || k === "gridVideoRenderer") && v.videoId && !videos.has(v.videoId))
        videos.set(v.videoId, { id: v.videoId, title: textOf(v.title) });
      if (k === "lockupViewModel" && v.contentType === "LOCKUP_CONTENT_TYPE_VIDEO" && v.contentId && !videos.has(v.contentId))
        videos.set(v.contentId, { id: v.contentId, title: v.metadata?.lockupMetadataViewModel?.title?.content || "" });
      if (k === "continuationCommand" && v.token) token = v.token;
    });
    if (!token) break;
    data = await ytCall(cookie, "browse", { continuation: token });
  }
  return { channel: { id: channelId, name: name || "My channel", handle }, videos: [...videos.values()], fetched: Date.now() };
}

const getYt = async (env) => JSON.parse((await env.VIDEOS.get("yt_channel")) || "null");

/* ---------- html ---------- */
const CSS = `
:root{--bg:#0f0f0f;--card:#272727;--tx:#f1f1f1;--mut:#aaa;--red:#f00}
@media(prefers-color-scheme:light){:root{--bg:#fff;--card:#f2f2f2;--tx:#0f0f0f;--mut:#606060}}
*{box-sizing:border-box}body{margin:0;font-family:Roboto,Arial,sans-serif;background:var(--bg);color:var(--tx)}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;z-index:5;display:flex;gap:16px;align-items:center;padding:10px 16px;background:var(--bg);border-bottom:1px solid var(--card)}
.logo{font-weight:700;font-size:20px;display:flex;align-items:center;gap:6px}
.logo i{background:var(--red);color:#fff;border-radius:6px;padding:2px 8px;font-style:normal;font-size:14px}
header form{flex:1;display:flex;max-width:600px;margin:auto}
input,textarea,button{font:inherit}
input,textarea{width:100%;padding:9px 14px;border:1px solid var(--mut);background:transparent;color:var(--tx);border-radius:20px}
textarea{border-radius:10px}
header input{border-radius:20px 0 0 20px}
header button{border-radius:0 20px 20px 0;border:1px solid var(--mut);border-left:0;background:var(--card);color:var(--tx);padding:0 18px;cursor:pointer}
main{padding:20px;max-width:1400px;margin:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:20px}
.thumb{position:relative;aspect-ratio:16/9;border-radius:12px;overflow:hidden;background:var(--card)}
.thumb img{width:100%;height:100%;object-fit:cover}
.card h3{margin:10px 0 4px;font-size:15px;line-height:1.3;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.mut{color:var(--mut);font-size:13px}
.player{aspect-ratio:16/9;width:100%;border-radius:12px;overflow:hidden;background:#000}
.player iframe{width:100%;height:100%;border:0}
.watch{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:24px}
@media(max-width:900px){.watch{grid-template-columns:1fr}}
.side a{display:flex;gap:10px;margin-bottom:12px}.side img{width:150px;aspect-ratio:16/9;object-fit:cover;border-radius:8px}
.desc{background:var(--card);padding:12px;border-radius:12px;white-space:pre-wrap;margin-top:12px}
.btn{background:var(--red);color:#fff;border:0;border-radius:20px;padding:9px 18px;cursor:pointer}
.btn.sec{background:var(--card);color:var(--tx)}
.btn.ok{background:#2e7d32}
.panel{background:var(--card);padding:20px;border-radius:12px;margin-bottom:24px;display:grid;gap:12px;max-width:640px}
.panel.wide{max-width:none}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;background:var(--card);color:var(--mut)}
.badge.on{background:#2e7d32;color:#fff}
.badge.off{background:#8d6e00;color:#fff}
pre.hint{white-space:pre-wrap;margin:0;font-size:12px;color:var(--mut)}
table{width:100%;border-collapse:collapse}td,th{padding:8px;text-align:left;border-bottom:1px solid var(--card)}
td img{width:90px;border-radius:6px}
`;

function page(title, body, admin = false, q = "") {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style></head><body>
<header><a class="logo" href="/"><i>▶</i> MyTube</a>
<form action="/" method="get"><input name="q" placeholder="Search" value="${esc(q)}"><button>Search</button></form>
<a href="/admin" class="mut">${admin ? "Admin" : "Sign in"}</a></header>
<main>${body}</main></body></html>`,
    { headers: { "Content-Type": "text/html;charset=utf-8" } }
  );
}

const thumb = (id) => `https://i.ytimg.com/vi/${esc(id)}/hqdefault.jpg`;
const cardHtml = (v) => `<a class="card" href="/watch?v=${esc(v.id)}">
<div class="thumb"><img loading="lazy" src="${thumb(v.id)}" alt=""></div>
<h3>${esc(v.title)}</h3><div class="mut">${esc(v.channel || "")}</div></a>`;

/* ---------- pages ---------- */
function home(videos, q) {
  const pub = videos.filter(isPublished);
  const list = q ? pub.filter((v) => (v.title + " " + (v.channel || "") + " " + (v.description || "")).toLowerCase().includes(q.toLowerCase())) : pub;
  return page("MyTube", list.length ? `<div class="grid">${list.map(cardHtml).join("")}</div>` : `<p class="mut">No videos found.</p>`, false, q);
}

function watch(videos, id, admin = false) {
  const v = videos.find((x) => x.id === id && (admin || isPublished(x)));
  if (!v) return page("Not found", `<p>Video not found.</p>`);
  const others = videos.filter((x) => x.id !== id && isPublished(x));
  return page(
    v.title,
    `<div class="watch"><section>
<div class="player"><iframe src="https://www.youtube-nocookie.com/embed/${esc(v.id)}?rel=0" title="${esc(v.title)}"
 allow="accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture;web-share" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>
<h2>${esc(v.title)}</h2><div class="mut">${esc(v.channel || "")} · ${esc(new Date(v.added).toDateString())}${isPublished(v) ? "" : " · <b>Unpublished (admin preview)</b>"}</div>
${v.description ? `<div class="desc">${esc(v.description)}</div>` : ""}</section>
<aside class="side">${others.map((o) => `<a href="/watch?v=${esc(o.id)}"><img loading="lazy" src="${thumb(o.id)}" alt=""><div><b>${esc(o.title)}</b><div class="mut">${esc(o.channel || "")}</div></div></a>`).join("")}</aside></div>`,
    admin
  );
}

const loginPage = (err = "") =>
  page("Admin login", `<form class="panel" method="post" action="/admin/login"><h2>Admin login</h2>
${err ? `<div style="color:#f44">${esc(err)}</div>` : ""}
<input type="password" name="password" placeholder="Password" required autofocus><button class="btn">Sign in</button></form>`);

function ytSection(yt, connected, videos) {
  if (!connected)
    return `<form class="panel" method="post" action="/admin/yt/connect"><h3>Connect YouTube account</h3>
<div class="mut">In Chrome, open youtube.com while signed in &rarr; DevTools (F12) &rarr; Network &rarr; click any request to
<code>youtube.com</code> &rarr; right-click &rarr; <b>Copy &rarr; Copy as cURL (bash)</b>, then paste it here. A plain
<code>Cookie:</code> header or a cookies.txt export also works.</div>
<textarea name="cookie" rows="6" placeholder="curl 'https://www.youtube.com/...' -H 'cookie: SID=...; SAPISID=...; ...'" required></textarea>
<button class="btn">Connect</button>
<pre class="hint">The cookie is a full login to that Google account. It is stored encrypted (AES-GCM, key derived from ADMIN_PASSWORD) and is only sent to youtube.com. Use a dedicated channel/account if you can.</pre></form>`;

  const byId = new Map(videos.map((v) => [v.id, v]));
  const list = yt?.videos || [];
  return `<div class="panel wide"><div class="row"><h3 style="margin:0">YouTube: ${esc(yt?.channel?.name || "connected")} ${yt?.channel?.handle ? `<span class="mut">${esc(yt.channel.handle)}</span>` : ""}</h3>
<span class="badge on">connected</span><span class="mut">${list.length} videos${yt?.fetched ? " · refreshed " + esc(new Date(yt.fetched).toUTCString()) : ""}</span></div>
<div class="row"><form method="post" action="/admin/yt/refresh"><button class="btn sec">Refresh videos</button></form>
<form method="post" action="/admin/yt/disconnect" onsubmit="return confirm('Disconnect and delete the stored cookie?')"><button class="btn sec">Disconnect</button></form></div>
${
  list.length
    ? `<table><tr><th></th><th>Title</th><th>Site status</th><th></th></tr>${list
        .map((c) => {
          const local = byId.get(c.id);
          const on = local && isPublished(local);
          return `<tr><td><img src="${thumb(c.id)}" alt=""></td><td>${esc(c.title)}<div class="mut">${esc(c.id)}</div></td>
<td><span class="badge ${on ? "on" : local ? "off" : ""}">${on ? "Published" : local ? "Unpublished" : "Not on site"}</span></td>
<td><form method="post" action="/admin/${on ? "unpublish" : "publish"}"><input type="hidden" name="id" value="${esc(c.id)}">
<button class="btn ${on ? "sec" : "ok"}">${on ? "Unpublish" : "Publish"}</button></form></td></tr>`;
        })
        .join("")}</table>`
    : `<p class="mut">No public videos found on this channel. (Private/unlisted videos are not shown.)</p>`
}</div>`;
}

function adminPage(videos, msg = "", yt = null, connected = false, isErr = false) {
  return page(
    "Admin",
    `<h2>Admin panel</h2>${msg ? `<p style="color:${isErr ? "#f44" : "#4caf50"}">${esc(msg)}</p>` : ""}
${ytSection(yt, connected, videos)}
<form class="panel" method="post" action="/admin/add"><h3>Add video manually</h3>
<input name="url" placeholder="YouTube URL or video ID" required>
<input name="title" placeholder="Title" required maxlength="150">
<input name="channel" placeholder="Channel name" maxlength="80">
<textarea name="description" rows="4" placeholder="Description" maxlength="2000"></textarea>
<button class="btn">Add video</button></form>
<h3>Site library (${videos.length}) <span class="mut">· ${videos.filter(isPublished).length} published</span></h3>
<table><tr><th></th><th>Title</th><th>Status</th><th></th></tr>${videos
      .map(
        (v) => `<tr><td><img src="${thumb(v.id)}" alt=""></td><td><a href="/watch?v=${esc(v.id)}">${esc(v.title)}</a><div class="mut">${esc(v.channel || "")}</div></td>
<td><span class="badge ${isPublished(v) ? "on" : "off"}">${isPublished(v) ? "Published" : "Unpublished"}</span></td>
<td><div class="row"><form method="post" action="/admin/${isPublished(v) ? "unpublish" : "publish"}"><input type="hidden" name="id" value="${esc(v.id)}"><button class="btn ${isPublished(v) ? "sec" : "ok"}">${isPublished(v) ? "Unpublish" : "Publish"}</button></form>
<form method="post" action="/admin/delete" onsubmit="return confirm('Delete this video?')"><input type="hidden" name="id" value="${esc(v.id)}"><button class="btn sec">Delete</button></form></div></td></tr>`
      )
      .join("")}</table>
<form method="post" action="/admin/logout" style="margin-top:24px"><button class="btn sec">Log out</button></form>`,
    true
  );
}

async function renderAdmin(env, msg = "", isErr = false, videos = null) {
  videos = videos || (await getVideos(env));
  const connected = !!(await env.VIDEOS.get("yt_cookie"));
  return adminPage(videos, msg, connected ? await getYt(env) : null, connected, isErr);
}

/* ---------- router ---------- */
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === "GET") {
      if (path === "/") return home(await getVideos(env), url.searchParams.get("q") || "");
      if (path === "/watch") return watch(await getVideos(env), url.searchParams.get("v") || "", await isAdmin(req, env));
      if (path === "/admin") {
        if (!env.ADMIN_PASSWORD) return page("Setup", `<p>Set the <code>ADMIN_PASSWORD</code> secret first.</p>`);
        return (await isAdmin(req, env)) ? renderAdmin(env) : loginPage();
      }
      return page("404", `<p>Page not found.</p>`);
    }

    if (req.method === "POST") {
      const form = await req.formData();

      if (path === "/admin/login") {
        const pw = String(form.get("password") || "");
        if (!env.ADMIN_PASSWORD || !safeEqual(pw, env.ADMIN_PASSWORD)) return loginPage("Wrong password");
        const exp = String(Date.now() + 7 * 864e5);
        return new Response(null, {
          status: 303,
          headers: { Location: "/admin", "Set-Cookie": `session=${exp}.${await sign(env, exp)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800` },
        });
      }

      if (path === "/admin/logout")
        return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": "session=; Max-Age=0; Path=/; HttpOnly; Secure" } });

      if (!(await isAdmin(req, env))) return new Response("Unauthorized", { status: 401 });
      const videos = await getVideos(env);

      /* ----- YouTube account ----- */
      if (path === "/admin/yt/connect") {
        const cookie = parseCookieInput(String(form.get("cookie") || ""));
        if (!cookie || !/(^|;\s*)(SAPISID|__Secure-3PAPISID)=/.test(cookie))
          return renderAdmin(env, "Could not find a signed-in YouTube cookie (SAPISID missing). Copy the request while logged in to youtube.com.", true, videos);
        try {
          const data = await fetchChannel(cookie);
          await env.VIDEOS.put("yt_cookie", await encrypt(env, cookie));
          await env.VIDEOS.put("yt_channel", JSON.stringify(data));
          return renderAdmin(env, `Connected to ${data.channel.name} (${data.videos.length} videos)`, false, videos);
        } catch (e) {
          return renderAdmin(env, "Connect failed: " + e.message, true, videos);
        }
      }

      if (path === "/admin/yt/refresh") {
        const cookie = await getCookie(env);
        if (!cookie) return renderAdmin(env, "Not connected", true, videos);
        try {
          const data = await fetchChannel(cookie);
          await env.VIDEOS.put("yt_channel", JSON.stringify(data));
          return renderAdmin(env, `Refreshed: ${data.videos.length} videos`, false, videos);
        } catch (e) {
          return renderAdmin(env, "Refresh failed: " + e.message, true, videos);
        }
      }

      if (path === "/admin/yt/disconnect") {
        await env.VIDEOS.delete("yt_cookie");
        await env.VIDEOS.delete("yt_channel");
        return renderAdmin(env, "Disconnected - stored cookie deleted", false, videos);
      }

      /* ----- publish / unpublish ----- */
      if (path === "/admin/publish") {
        const id = String(form.get("id") || "");
        const existing = videos.find((v) => v.id === id);
        if (existing) existing.published = true;
        else {
          const yt = await getYt(env);
          const c = yt?.videos?.find((v) => v.id === id);
          if (!c) return renderAdmin(env, "Video not found", true, videos);
          videos.unshift({ id, title: (c.title || id).slice(0, 150), channel: (yt.channel?.name || "").slice(0, 80), description: "", added: Date.now(), published: true, source: "channel" });
        }
        await saveVideos(env, videos);
        return renderAdmin(env, "Published to site", false, videos);
      }

      if (path === "/admin/unpublish") {
        const v = videos.find((x) => x.id === String(form.get("id") || ""));
        if (!v) return renderAdmin(env, "Video not found", true, videos);
        v.published = false;
        await saveVideos(env, videos);
        return renderAdmin(env, "Unpublished - hidden from the site", false, videos);
      }

      /* ----- manual add / delete ----- */
      if (path === "/admin/add") {
        const id = parseYouTubeId(String(form.get("url") || ""));
        if (!id) return renderAdmin(env, "Invalid YouTube URL / ID", true, videos);
        if (videos.some((v) => v.id === id)) return renderAdmin(env, "Video already added", true, videos);
        videos.unshift({
          id,
          title: String(form.get("title")).slice(0, 150),
          channel: String(form.get("channel") || "").slice(0, 80),
          description: String(form.get("description") || "").slice(0, 2000),
          added: Date.now(),
          published: true,
        });
        await saveVideos(env, videos);
        return renderAdmin(env, "Video added", false, videos);
      }

      if (path === "/admin/delete") {
        const next = videos.filter((v) => v.id !== form.get("id"));
        await saveVideos(env, next);
        return renderAdmin(env, "Video deleted", false, next);
      }
    }
    return new Response("Method not allowed", { status: 405 });
  },
};
