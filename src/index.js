/**
 * MyTube - Cloudflare Worker (v2)
 * Cookie-session login, multi-user accounts, "my videos" panel.
 *
 * Put this file at src/index.js
 * Secrets:  npx wrangler secret put ADMIN_PASSWORD     (login as user "admin", sees/deletes ALL videos)
 *           npx wrangler secret put SESSION_SECRET     (optional, random string used to sign cookies)
 * Optional var in wrangler.toml:  [vars] ALLOW_SIGNUP = "false"   (to close public registration)
 */

const enc = new TextEncoder();
const esc = (s = "") =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

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

/* ---------- storage ---------- */
const getVideos = async (env) => JSON.parse((await env.VIDEOS.get("videos")) || "[]");
const saveVideos = (env, list) => env.VIDEOS.put("videos", JSON.stringify(list));
const owner = (v) => v.owner || "admin";

/* ---------- crypto / cookie sessions ---------- */
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function hmac(env, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(env.SESSION_SECRET || env.ADMIN_PASSWORD || "unset"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}
async function hashPw(pw, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
async function makeCookie(env, name, remember) {
  const ttl = remember ? 30 * 864e5 : 864e5;
  const v = `${name}.${Date.now() + ttl}`;
  return `session=${v}.${await hmac(env, v)}; HttpOnly; Secure; SameSite=Strict; Path=/` + (remember ? `; Max-Age=${ttl / 1000}` : "");
}
async function getUser(req, env) {
  const m = (req.headers.get("Cookie") || "").match(/session=([a-z0-9_]+)\.(\d+)\.([a-f0-9]+)/);
  if (!m || Number(m[2]) < Date.now()) return null;
  if (!safeEqual(m[3], await hmac(env, `${m[1]}.${m[2]}`))) return null;
  if (m[1] === "admin") return env.ADMIN_PASSWORD ? { name: "admin", admin: true } : null;
  return (await env.VIDEOS.get("user:" + m[1])) ? { name: m[1], admin: false } : null;
}
const redirect = (to, cookie) =>
  new Response(null, { status: 303, headers: cookie ? { Location: to, "Set-Cookie": cookie } : { Location: to } });

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
input[type=checkbox]{width:auto}textarea{border-radius:10px}
header input{border-radius:20px 0 0 20px}
header button{border-radius:0 20px 20px 0;border:1px solid var(--mut);border-left:0;background:var(--card);color:var(--tx);padding:0 18px;cursor:pointer}
main{padding:20px;max-width:1400px;margin:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:20px}
.thumb{aspect-ratio:16/9;border-radius:12px;overflow:hidden;background:var(--card)}
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
td img{width:90px;border-radius:6px}.err{color:#f44}.ok{color:#4caf50}
`;

function page(title, body, user, q = "") {
  const who = user ? `<a href="/admin" class="mut">${esc(user.name)}${user.admin ? " (admin)" : ""}</a>` : `<a href="/login" class="mut">Sign in</a>`;
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style></head><body>
<header><a class="logo" href="/"><i>▶</i> MyTube</a>
<form action="/" method="get"><input name="q" placeholder="Search" value="${esc(q)}"><button>Search</button></form>${who}</header>
<main>${body}</main></body></html>`,
    { headers: { "Content-Type": "text/html;charset=utf-8" } }
  );
}
const thumb = (id) => `https://i.ytimg.com/vi/${esc(id)}/hqdefault.jpg`;
const cardHtml = (v) => `<a class="card" href="/watch?v=${esc(v.id)}"><div class="thumb"><img loading="lazy" src="${thumb(v.id)}" alt=""></div>
<h3>${esc(v.title)}</h3><div class="mut">${esc(v.channel || owner(v))}</div></a>`;

function home(videos, q, u, user) {
  let list = videos;
  if (u) list = list.filter((v) => owner(v) === u);
  if (q) list = list.filter((v) => `${v.title} ${v.channel || ""} ${v.description || ""}`.toLowerCase().includes(q.toLowerCase()));
  const head = u ? `<h2>Videos by ${esc(u)}</h2>` : "";
  return page("MyTube", head + (list.length ? `<div class="grid">${list.map(cardHtml).join("")}</div>` : `<p class="mut">No videos found.</p>`), user, q);
}

function watch(videos, id, user) {
  const v = videos.find((x) => x.id === id);
  if (!v) return page("Not found", `<p>Video not found.</p>`, user);
  const others = videos.filter((x) => x.id !== id);
  return page(
    v.title,
    `<div class="watch"><section>
<div class="player"><iframe src="https://www.youtube-nocookie.com/embed/${esc(v.id)}?rel=0" title="${esc(v.title)}"
 allow="accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture;web-share" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>
<h2>${esc(v.title)}</h2>
<div class="mut">${esc(v.channel || "")} · uploaded by <a href="/?u=${esc(owner(v))}"><b>${esc(owner(v))}</b></a> · ${esc(new Date(v.added).toDateString())}</div>
${v.description ? `<div class="desc">${esc(v.description)}</div>` : ""}</section>
<aside class="side">${others.map((o) => `<a href="/watch?v=${esc(o.id)}"><img loading="lazy" src="${thumb(o.id)}" alt=""><div><b>${esc(o.title)}</b><div class="mut">${esc(o.channel || owner(o))}</div></div></a>`).join("")}</aside></div>`,
    user
  );
}

const authPage = (mode, env, err = "") => {
  const reg = mode === "register";
  return page(
    reg ? "Create account" : "Sign in",
    `<form class="panel" method="post" action="/${reg ? "register" : "login"}"><h2>${reg ? "Create account" : "Sign in"}</h2>
${err ? `<div class="err">${esc(err)}</div>` : ""}
<input name="username" placeholder="Username (a-z, 0-9, _)" pattern="[A-Za-z0-9_]{3,20}" required autofocus autocomplete="username">
<input type="password" name="password" placeholder="Password${reg ? " (min 8 chars)" : ""}" minlength="${reg ? 8 : 1}" required autocomplete="${reg ? "new" : "current"}-password">
<label class="mut"><input type="checkbox" name="remember" checked> Keep me signed in (30 days cookie)</label>
<button class="btn">${reg ? "Register" : "Sign in"}</button>
${reg ? `<a class="mut" href="/login">Already have an account? Sign in</a>` : env.ALLOW_SIGNUP !== "false" ? `<a class="mut" href="/register">No account? Register</a>` : ""}
</form>`,
    null
  );
};

function panel(user, all, msg = "") {
  const mine = user.admin ? all : all.filter((v) => owner(v) === user.name);
  return page(
    "My videos",
    `<h2>${user.admin ? "Admin panel – all videos" : "My videos"}</h2>${msg ? `<p class="ok">${esc(msg)}</p>` : ""}
<form class="panel" method="post" action="/admin/add"><h3>Add video</h3>
<input name="url" placeholder="YouTube URL or video ID" required>
<input name="title" placeholder="Title" required maxlength="150">
<input name="channel" placeholder="Channel name (optional)" maxlength="80">
<textarea name="description" rows="4" placeholder="Description" maxlength="2000"></textarea>
<button class="btn">Add video</button></form>
<h3>${user.admin ? "All videos" : "Your videos"} (${mine.length})</h3>
${mine.length ? `<table><tr><th></th><th>Title</th>${user.admin ? "<th>Owner</th>" : ""}<th></th></tr>${mine
      .map(
        (v) => `<tr><td><img src="${thumb(v.id)}" alt=""></td><td><a href="/watch?v=${esc(v.id)}">${esc(v.title)}</a><div class="mut">${esc(v.channel || "")}</div></td>
${user.admin ? `<td>${esc(owner(v))}</td>` : ""}<td><form method="post" action="/admin/delete" onsubmit="return confirm('Delete this video?')">
<input type="hidden" name="id" value="${esc(v.id)}"><button class="btn sec">Delete</button></form></td></tr>`
      )
      .join("")}</table>` : `<p class="mut">You haven't added any videos yet.</p>`}
<p><a class="mut" href="/?u=${esc(user.name)}">View my public page</a></p>
<form method="post" action="/logout" style="margin-top:24px"><button class="btn sec">Log out</button></form>`,
    user
  );
}

/* ---------- router ---------- */
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const user = await getUser(req, env);

    if (req.method === "GET") {
      if (path === "/") return home(await getVideos(env), url.searchParams.get("q") || "", url.searchParams.get("u") || "", user);
      if (path === "/watch") return watch(await getVideos(env), url.searchParams.get("v") || "", user);
      if (path === "/login") return user ? redirect("/admin") : authPage("login", env);
      if (path === "/register") return user || env.ALLOW_SIGNUP === "false" ? redirect("/login") : authPage("register", env);
      if (path === "/admin") return user ? panel(user, await getVideos(env)) : redirect("/login");
      return page("404", `<p>Page not found.</p>`, user);
    }

    if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
    const form = await req.formData();

    if (path === "/logout") return redirect("/", "session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict");

    if (path === "/login") {
      const name = String(form.get("username") || "").toLowerCase();
      const pw = String(form.get("password") || "");
      const remember = !!form.get("remember");
      let ok = false;
      if (name === "admin") {
        ok = !!env.ADMIN_PASSWORD && safeEqual(pw, env.ADMIN_PASSWORD);
      } else {
        const rec = JSON.parse((await env.VIDEOS.get("user:" + name)) || "null");
        const h = await hashPw(pw, rec ? rec.salt : "dummy-salt"); // same work either way
        ok = !!rec && safeEqual(h, rec.hash);
      }
      return ok ? redirect("/admin", await makeCookie(env, name, remember)) : authPage("login", env, "Wrong username or password");
    }

    if (path === "/register") {
      if (env.ALLOW_SIGNUP === "false") return redirect("/login");
      const name = String(form.get("username") || "").toLowerCase();
      const pw = String(form.get("password") || "");
      if (!/^[a-z0-9_]{3,20}$/.test(name) || name === "admin") return authPage("register", env, "Invalid or reserved username");
      if (pw.length < 8) return authPage("register", env, "Password must be at least 8 characters");
      if (await env.VIDEOS.get("user:" + name)) return authPage("register", env, "Username already taken");
      const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
      await env.VIDEOS.put("user:" + name, JSON.stringify({ salt, hash: await hashPw(pw, salt), created: Date.now() }));
      return redirect("/admin", await makeCookie(env, name, !!form.get("remember")));
    }

    if (!user) return new Response("Unauthorized", { status: 401 });
    const videos = await getVideos(env);

    if (path === "/admin/add") {
      const id = parseYouTubeId(String(form.get("url") || ""));
      if (!id) return panel(user, videos, "Invalid YouTube URL / ID");
      if (videos.some((v) => v.id === id)) return panel(user, videos, "Video already exists on the site");
      videos.unshift({
        id,
        owner: user.name,
        title: String(form.get("title")).slice(0, 150),
        channel: String(form.get("channel") || "").slice(0, 80),
        description: String(form.get("description") || "").slice(0, 2000),
        added: Date.now(),
      });
      await saveVideos(env, videos);
      return panel(user, videos, "Video added");
    }

    if (path === "/admin/delete") {
      const id = form.get("id");
      const next = videos.filter((v) => !(v.id === id && (user.admin || owner(v) === user.name)));
      await saveVideos(env, next);
      return panel(user, next, "Video deleted");
    }

    return new Response("Not found", { status: 404 });
  },
};
