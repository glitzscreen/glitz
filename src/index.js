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
 *   /              home grid + search (?q=)
 *   /watch?v=ID    official YouTube embed player + details
 *   /admin         login, then add/delete videos
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
.panel{background:var(--card);padding:20px;border-radius:12px;margin-bottom:24px;display:grid;gap:12px;max-width:640px}
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
  const list = q ? videos.filter((v) => (v.title + " " + (v.channel || "") + " " + (v.description || "")).toLowerCase().includes(q.toLowerCase())) : videos;
  return page("MyTube", list.length ? `<div class="grid">${list.map(cardHtml).join("")}</div>` : `<p class="mut">No videos found.</p>`, false, q);
}

function watch(videos, id) {
  const v = videos.find((x) => x.id === id);
  if (!v) return page("Not found", `<p>Video not found.</p>`);
  const others = videos.filter((x) => x.id !== id);
  return page(
    v.title,
    `<div class="watch"><section>
<div class="player"><iframe src="https://www.youtube-nocookie.com/embed/${esc(v.id)}?rel=0" title="${esc(v.title)}"
 allow="accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture;web-share" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>
<h2>${esc(v.title)}</h2><div class="mut">${esc(v.channel || "")} · ${esc(new Date(v.added).toDateString())}</div>
${v.description ? `<div class="desc">${esc(v.description)}</div>` : ""}</section>
<aside class="side">${others.map((o) => `<a href="/watch?v=${esc(o.id)}"><img loading="lazy" src="${thumb(o.id)}" alt=""><div><b>${esc(o.title)}</b><div class="mut">${esc(o.channel || "")}</div></div></a>`).join("")}</aside></div>`
  );
}

const loginPage = (err = "") =>
  page("Admin login", `<form class="panel" method="post" action="/admin/login"><h2>Admin login</h2>
${err ? `<div style="color:#f44">${esc(err)}</div>` : ""}
<input type="password" name="password" placeholder="Password" required autofocus><button class="btn">Sign in</button></form>`);

function adminPage(videos, msg = "") {
  return page(
    "Admin",
    `<h2>Admin panel</h2>${msg ? `<p style="color:#4caf50">${esc(msg)}</p>` : ""}
<form class="panel" method="post" action="/admin/add"><h3>Add video</h3>
<input name="url" placeholder="YouTube URL or video ID" required>
<input name="title" placeholder="Title" required maxlength="150">
<input name="channel" placeholder="Channel name" maxlength="80">
<textarea name="description" rows="4" placeholder="Description" maxlength="2000"></textarea>
<button class="btn">Add video</button></form>
<h3>Videos (${videos.length})</h3>
<table><tr><th></th><th>Title</th><th></th></tr>${videos
      .map(
        (v) => `<tr><td><img src="${thumb(v.id)}" alt=""></td><td><a href="/watch?v=${esc(v.id)}">${esc(v.title)}</a><div class="mut">${esc(v.channel || "")}</div></td>
<td><form method="post" action="/admin/delete" onsubmit="return confirm('Delete this video?')"><input type="hidden" name="id" value="${esc(v.id)}"><button class="btn sec">Delete</button></form></td></tr>`
      )
      .join("")}</table>
<form method="post" action="/admin/logout" style="margin-top:24px"><button class="btn sec">Log out</button></form>`,
    true
  );
}

/* ---------- router ---------- */
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === "GET") {
      if (path === "/") return home(await getVideos(env), url.searchParams.get("q") || "");
      if (path === "/watch") return watch(await getVideos(env), url.searchParams.get("v") || "");
      if (path === "/admin") {
        if (!env.ADMIN_PASSWORD) return page("Setup", `<p>Set the <code>ADMIN_PASSWORD</code> secret first.</p>`);
        return (await isAdmin(req, env)) ? adminPage(await getVideos(env)) : loginPage();
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

      if (path === "/admin/add") {
        const id = parseYouTubeId(String(form.get("url") || ""));
        if (!id) return adminPage(videos, "Invalid YouTube URL / ID");
        if (videos.some((v) => v.id === id)) return adminPage(videos, "Video already added");
        videos.unshift({
          id,
          title: String(form.get("title")).slice(0, 150),
          channel: String(form.get("channel") || "").slice(0, 80),
          description: String(form.get("description") || "").slice(0, 2000),
          added: Date.now(),
        });
        await saveVideos(env, videos);
        return adminPage(videos, "Video added");
      }

      if (path === "/admin/delete") {
        const next = videos.filter((v) => v.id !== form.get("id"));
        await saveVideos(env, next);
        return adminPage(next, "Video deleted");
      }
    }
    return new Response("Method not allowed", { status: 405 });
  },
};
