/**
 * Cloudflare Worker - MyTube: YouTube-style video site + admin panel
 *
 * SETUP
 * 1. Create KV namespace:   npx wrangler kv namespace create VIDEOS
 * 2. wrangler.toml:
 *      name = "my-tube"
 *      main = "index.js"
 *      compatibility_date = "2024-11-01"
 *      [[kv_namespaces]]
 *      binding = "VIDEOS"
 *      id = "<ID from step 1>"
 * 3. Set admin password:    npx wrangler secret put ADMIN_PASSWORD
 * 4. Deploy:                npx wrangler deploy
 *
 * VISIBILITY MODEL
 *   Public   = shown to everyone (home grid, search, watch page)
 *   Private  = shown ONLY to the logged-in admin (home grid, watch page, admin panel)
 *
 * PLAYERS (chosen per video)
 *   youtube  YouTube embed for visitors. Admin can also use the "Secure stream" custom player.
 *   file     Direct https video file (.mp4 / .webm) played in the custom neon player.
 *   iframe   Any https embed page (Vimeo, etc.) in a sandboxed iframe.
 *
 * SECURE STREAM
 *   Videos that are PRIVATE on YouTube cannot be embedded. With your connected channel cookie,
 *   the Worker asks YouTube for the video's stream as you and pipes it out.
 *   - Admin:  /admin/stream?v=ID
 *   - Public: /stream?v=ID  (only for videos you OWN and chose to publish here)
 *
 * ROUTES
 *   /                 home grid + search (?q=)
 *   /watch?v=ID       player page  (&p=embed | &p=stream  -> admin player switch)
 *   /stream?v=ID      public secure stream (only published private YouTube videos)
 *   /admin            login, then the admin panel
 *   /admin/stream?v=  admin-only video stream (Range supported)
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

// Returns a clean https URL or "" if the input is not a valid https link
function httpsUrl(input = "") {
  try {
    const u = new URL(String(input).trim());
    return u.protocol === "https:" ? u.href : "";
  } catch {
    return "";
  }
}

const randomId = () => [...crypto.getRandomValues(new Uint8Array(11))].map((b) => "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]).join("");

async function getVideos(env) {
  return JSON.parse((await env.VIDEOS.get("videos")) || "[]");
}
const saveVideos = (env, list) => env.VIDEOS.put("videos", JSON.stringify(list));
// Public on the site. A video with no "published" field (older data) counts as public.
const isPublished = (v) => v.published !== false;
// Videos that live on YouTube (embed / secure stream). Others use file / iframe players.
const isYt = (v) => !v.player || v.player === "youtube";

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
const VIDEOS_TAB = "EgZ2aWRlb3PyBgQKAjoA"; // channel "Videos" tab (public videos only)
const STUDIO_ORIGIN = "https://studio.youtube.com";
const STUDIO_KEY = "AIzaSyBUPetSUmoZL-OhlxA7wSac5XinrygCqMo"; // YouTube Studio web key

const WEB_CLIENT = { clientName: "WEB", clientVersion: "2.20241022.01.00", hl: "en", gl: "US" };
// Clients tried (in order) when asking YouTube for a playable stream
const PLAYER_CLIENTS = [
  { clientName: "TVHTML5", clientVersion: "7.20241016.15.00", hl: "en", gl: "US" },
  { clientName: "MWEB", clientVersion: "2.20241022.01.00", hl: "en", gl: "US" },
  WEB_CLIENT,
];

async function sapisidAuth(cookie, origin = YT_ORIGIN) {
  const sid = cookieVal(cookie, "SAPISID") || cookieVal(cookie, "__Secure-3PAPISID");
  if (!sid) throw new Error("Cookie has no SAPISID / __Secure-3PAPISID - copy it while signed in to youtube.com");
  const ts = Math.floor(Date.now() / 1000);
  const hash = async (v) =>
    [...new Uint8Array(await crypto.subtle.digest("SHA-1", enc.encode(`${ts} ${v} ${origin}`)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  let out = `SAPISIDHASH ${ts}_${await hash(sid)}`;
  const s1 = cookieVal(cookie, "__Secure-1PAPISID");
  const s3 = cookieVal(cookie, "__Secure-3PAPISID");
  if (s1) out += ` SAPISID1PHASH ${ts}_${await hash(s1)}`;
  if (s3) out += ` SAPISID3PHASH ${ts}_${await hash(s3)}`;
  return out;
}

async function ytCall(cookie, endpoint, body, client = WEB_CLIENT) {
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
    body: JSON.stringify({ context: { client }, ...body }),
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

// YouTube Studio lists EVERY upload on the channel, including Private and Unlisted ones.
// Returns [{id, title, privacy: "PUBLIC" | "UNLISTED" | "PRIVATE"}]
async function fetchStudioVideos(cookie, channelId) {
  const out = new Map();
  let pageToken = "";
  for (let i = 0; i < 6; i++) {
    const res = await fetch(`${STUDIO_ORIGIN}/youtubei/v1/creator/list_creator_videos?alt=json&key=${STUDIO_KEY}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
        Authorization: await sapisidAuth(cookie, STUDIO_ORIGIN),
        Origin: STUDIO_ORIGIN,
        "X-Origin": STUDIO_ORIGIN,
        "X-Goog-AuthUser": "0",
        "User-Agent": UA,
      },
      body: JSON.stringify({
        context: { client: { clientName: 62, clientVersion: "1.20241022.01.00", hl: "en", gl: "US" } },
        filter: { and: { operands: [{ channelIdIs: { value: channelId } }, { videoOriginIs: { value: "VIDEO_ORIGIN_UPLOAD" } }] } },
        order: "VIDEO_ORDER_DISPLAY_TIME_DESC",
        pageSize: 50,
        mask: { videoId: true, title: true, privacy: true },
        ...(pageToken ? { pageToken } : {}),
      }),
    });
    if (!res.ok) throw new Error(`Studio returned HTTP ${res.status}`);
    const data = await res.json();
    for (const v of data.videos || [])
      if (v.videoId) out.set(v.videoId, { id: v.videoId, title: v.title || "", privacy: String(v.privacy || "").replace("VIDEO_PRIVACY_", "") });
    pageToken = data.nextPageToken || "";
    if (!pageToken) break;
  }
  return [...out.values()];
}

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

  // 2. channel's public Videos tab (+ a few continuation pages)
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

  // 3. YouTube Studio list: adds Private + Unlisted videos and each video's privacy
  let studioErr = "";
  try {
    for (const s of await fetchStudioVideos(cookie, channelId)) {
      const prev = videos.get(s.id) || {};
      videos.set(s.id, { ...prev, ...s, title: s.title || prev.title || "" });
    }
  } catch (e) {
    studioErr = e.message;
  }
  return { channel: { id: channelId, name: name || "My channel", handle }, videos: [...videos.values()], studioErr, fetched: Date.now() };
}

// True if YouTube lets the public embed this video. Private, deleted or embed-disabled videos
// fail oEmbed, and they show YouTube's "This video is private - sign in" screen in the player.
async function embedStatus(id) {
  try {
    const r = await fetch(`https://www.youtube.com/oembed?format=json&url=${encodeURIComponent("https://www.youtube.com/watch?v=" + id)}`, { headers: { "User-Agent": UA } });
    return r.ok;
  } catch {
    return true; // network hiccup: don't flag
  }
}
const BLOCKED_MSG =
  "YouTube reports this video as private or not embeddable, so the YouTube embed would only show a sign-in screen. If your YouTube account is connected, you can still publish it here: visitors will watch it through the secure stream in the custom player. Otherwise set it to Unlisted/Public on YouTube, or connect the account first.";

const getYt = async (env) => JSON.parse((await env.VIDEOS.get("yt_channel")) || "null");

// Add a channel video to the site library (as Private) if it isn't there yet
async function importFromChannel(env, videos, id) {
  let v = videos.find((x) => x.id === id);
  if (v) return v;
  const yt = await getYt(env);
  const c = yt?.videos?.find((x) => x.id === id);
  if (!c) return null;
  v = {
    id,
    title: (c.title || id).slice(0, 150),
    channel: (yt.channel?.name || "").slice(0, 80),
    description: "",
    added: Date.now(),
    published: false,
    source: "channel",
    ytPrivacy: c.privacy || "",
    blocked: c.privacy === "PRIVATE",
  };
  videos.unshift(v);
  return v;
}

// After a connect/refresh: copy each video's YouTube privacy into the library.
// NOTE: we no longer force `published = false` for YouTube-private videos.
// Admin decides Public/Private here; a Public private-on-YouTube video is served
// to visitors through the secure stream.
async function syncPrivacy(videos, data) {
  const map = new Map(data.videos.map((c) => [c.id, c]));
  for (const v of videos) {
    const c = map.get(v.id);
    if (!c || !c.privacy || !isYt(v)) continue;
    const was = v.ytPrivacy;
    v.ytPrivacy = c.privacy;
    if (c.privacy === "PRIVATE") {
      v.blocked = true; // embed will fail; stream is used instead
    } else if (was !== c.privacy) {
      v.blocked = !(await embedStatus(v.id));
    }
  }
}

/* ---------- secure stream ---------- */
const streamCache = new Map(); // id -> { url, exp }

// Ask YouTube for a playable progressive MP4 URL, as the signed-in channel owner
async function resolveStream(cookie, id, fresh = false) {
  const hit = streamCache.get(id);
  if (hit && !fresh && hit.exp > Date.now()) return hit;
  let lastErr = "no playable format returned";
  for (const client of PLAYER_CLIENTS) {
    try {
      const data = await ytCall(cookie, "player", { videoId: id, contentCheckOk: true, racyCheckOk: true }, client);
      const st = data.playabilityStatus?.status;
      if (st && st !== "OK") {
        lastErr = `${st}${data.playabilityStatus.reason ? ": " + data.playabilityStatus.reason : ""}`;
        continue;
      }
      const formats = (data.streamingData?.formats || []).filter((f) => f.url && /^video\/mp4/.test(f.mimeType || ""));
      formats.sort((a, b) => (b.height || 0) - (a.height || 0));
      const f = formats[0];
      if (!f) {
        lastErr = "YouTube returned only protected (ciphered) formats for this client";
        continue;
      }
      if (!new URL(f.url).hostname.endsWith(".googlevideo.com")) continue;
      if (streamCache.size > 50) streamCache.clear();
      const out = { url: f.url, height: f.height || 0, exp: Date.now() + 20 * 60 * 1000 };
      streamCache.set(id, out);
      return out;
    } catch (e) {
      lastErr = e.message;
    }
  }
  throw new Error(lastErr);
}

async function streamVideo(req, env, id) {
  const cookie = await getCookie(env);
  if (!cookie) return new Response("YouTube account is not connected (Admin > Connect YouTube account).", { status: 409 });
  for (let attempt = 0; attempt < 2; attempt++) {
    let s;
    try {
      s = await resolveStream(cookie, id, attempt > 0);
    } catch (e) {
      return new Response("Stream unavailable: " + e.message, { status: 502 });
    }
    const h = { "User-Agent": UA };
    const range = req.headers.get("Range");
    if (range) h.Range = range;
    const up = await fetch(s.url, { headers: h });
    if (up.status === 403 || up.status === 410) {
      streamCache.delete(id); // expired / IP-bound URL: fetch a fresh one and retry once
      continue;
    }
    const out = new Headers();
    for (const k of ["Content-Type", "Content-Length", "Content-Range", "Accept-Ranges", "ETag"]) {
      const v = up.headers.get(k);
      if (v) out.set(k, v);
    }
    if (!out.has("Accept-Ranges")) out.set("Accept-Ranges", "bytes");
    out.set("Cache-Control", "private, no-store");
    return new Response(up.body, { status: up.status, headers: out });
  }
  return new Response("YouTube refused the stream (HTTP 403). Refresh the cookie in the admin panel and try again.", { status: 502 });
}

/* ---------- html ---------- */
const CSS = `
:root{--bg:#05060f;--glass:rgba(255,255,255,.05);--glass2:rgba(255,255,255,.09);--line:rgba(140,160,255,.18);--card:rgba(255,255,255,.06);--tx:#e8ecff;--mut:#8b93b8;--c1:#00e5ff;--c2:#8a5cff;--c3:#ff2e9a;--red:#ff2e9a}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:Rajdhani,Roboto,Arial,sans-serif;font-size:17px;background:var(--bg);color:var(--tx);min-height:100vh;overflow-x:hidden;
background-image:linear-gradient(rgba(120,140,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(120,140,255,.05) 1px,transparent 1px);background-size:44px 44px}
body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:50;background:repeating-linear-gradient(0deg,rgba(255,255,255,.015) 0 1px,transparent 1px 3px)}
.orb{position:fixed;border-radius:50%;filter:blur(110px);opacity:.38;z-index:-1;pointer-events:none;animation:float 16s ease-in-out infinite alternate}
.o1{width:520px;height:520px;background:var(--c2);top:-140px;left:-120px}
.o2{width:460px;height:460px;background:var(--c1);bottom:-160px;right:-100px;animation-delay:-8s}
@keyframes float{to{transform:translate(70px,50px) scale(1.15)}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
a{color:inherit;text-decoration:none}
header{position:sticky;top:0;z-index:5;display:flex;gap:16px;align-items:center;padding:12px 20px;background:rgba(5,6,15,.6);backdrop-filter:blur(18px) saturate(160%);-webkit-backdrop-filter:blur(18px) saturate(160%);border-bottom:1px solid var(--line);box-shadow:0 1px 30px rgba(0,229,255,.08)}
.logo{font-family:Orbitron,sans-serif;font-weight:800;font-size:20px;letter-spacing:1px;display:flex;align-items:center;gap:8px;background:linear-gradient(90deg,var(--c1),var(--c2),var(--c3));-webkit-background-clip:text;background-clip:text;color:transparent}
.logo i{background:linear-gradient(135deg,var(--c3),var(--c2));color:#fff;border-radius:8px;padding:3px 9px;font-style:normal;font-size:13px;box-shadow:0 0 18px rgba(255,46,154,.6);-webkit-text-fill-color:#fff}
header form{flex:1;display:flex;max-width:600px;margin:auto}
input,textarea,button,select{font:inherit}
input,textarea{width:100%;padding:10px 16px;border:1px solid var(--line);background:var(--glass);color:var(--tx);border-radius:22px;outline:0;transition:.25s}
select{padding:10px 14px;border:1px solid var(--line);background:var(--glass);color:var(--tx);border-radius:22px;outline:0}
option{background:#0b0d1c;color:var(--tx)}
input:focus,textarea:focus,select:focus{border-color:var(--c1);box-shadow:0 0 0 3px rgba(0,229,255,.15),0 0 22px rgba(0,229,255,.2)}
::placeholder{color:var(--mut)}
textarea{border-radius:14px}
header input{border-radius:22px 0 0 22px}
header button{border-radius:0 22px 22px 0;border:1px solid var(--line);border-left:0;background:var(--glass2);color:var(--tx);padding:0 20px;cursor:pointer;transition:.25s}
header button:hover{background:linear-gradient(90deg,var(--c2),var(--c1));color:#05060f}
main{padding:26px 20px;max-width:1400px;margin:auto}
h2,h3{font-family:Orbitron,sans-serif;letter-spacing:.5px}
h2{font-size:22px}h3{font-size:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:24px}
.card{display:block;padding:10px;border-radius:18px;background:var(--glass);border:1px solid var(--line);backdrop-filter:blur(8px);transition:transform .3s,box-shadow .3s,border-color .3s;animation:rise .6s both}
.card:hover{transform:translateY(-6px) scale(1.015);border-color:var(--c1);box-shadow:0 12px 40px rgba(0,229,255,.2),0 0 0 1px rgba(138,92,255,.4)}
@keyframes rise{from{opacity:0;transform:translateY(18px)}}
.thumb{position:relative;aspect-ratio:16/9;border-radius:12px;overflow:hidden;background:#0b0d1c}
.thumb::after{content:"▶";position:absolute;inset:0;display:grid;place-items:center;font-size:34px;color:#fff;background:linear-gradient(135deg,rgba(138,92,255,.45),rgba(0,229,255,.25));opacity:0;transition:.3s;text-shadow:0 0 20px #fff}
.card:hover .thumb::after{opacity:1}
.thumb img{width:100%;height:100%;object-fit:cover;transition:transform .5s}
.card:hover .thumb img{transform:scale(1.08)}
.tag{position:absolute;top:8px;left:8px;z-index:2;padding:3px 10px;border-radius:12px;font-size:12px;background:rgba(5,6,15,.78);border:1px solid rgba(255,200,60,.55);color:#ffc83d;backdrop-filter:blur(6px)}
.card h3{font-family:Rajdhani,sans-serif;font-weight:600;margin:12px 4px 4px;font-size:17px;line-height:1.25;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.card .mut{margin:0 4px 4px}
.mut{color:var(--mut);font-size:14px}
.player{aspect-ratio:16/9;width:100%;border-radius:18px;overflow:hidden;background:#000;border:1px solid var(--line);box-shadow:0 0 0 1px rgba(138,92,255,.25),0 0 50px rgba(138,92,255,.25),0 0 90px rgba(0,229,255,.12)}
.player iframe{width:100%;height:100%;border:0}
.modes{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.modes a{padding:4px 14px;border-radius:14px;border:1px solid var(--line);background:var(--glass);font-size:14px;color:var(--mut);transition:.25s}
.modes a:hover{border-color:var(--c1);color:var(--tx)}
.modes a.cur{border-color:var(--c1);color:var(--c1);box-shadow:0 0 14px rgba(0,229,255,.25)}
/* custom player */
.vp{position:relative;aspect-ratio:16/9;width:100%;border-radius:18px;overflow:hidden;background:#000;border:1px solid var(--line);box-shadow:0 0 0 1px rgba(138,92,255,.25),0 0 50px rgba(138,92,255,.25),0 0 90px rgba(0,229,255,.12)}
.vp:fullscreen{border-radius:0;aspect-ratio:auto;border:0}
.vp video{width:100%;height:100%;display:block;background:#000;object-fit:contain}
.vp-big{position:absolute;inset:0;display:grid;place-items:center;font-size:64px;color:#fff;text-shadow:0 0 30px var(--c1);cursor:pointer;transition:.25s}
.vp.playing .vp-big{opacity:0;pointer-events:none}
.vp-bar{position:absolute;left:0;right:0;bottom:0;display:flex;gap:10px;align-items:center;padding:12px 14px;background:linear-gradient(transparent,rgba(5,6,15,.94));opacity:0;transition:.25s}
.vp:hover .vp-bar,.vp:not(.playing) .vp-bar,.vp:focus-within .vp-bar{opacity:1}
.vp-bar button{background:var(--glass2);border:1px solid var(--line);color:var(--tx);border-radius:10px;min-width:34px;height:32px;cursor:pointer;transition:.2s}
.vp-bar button:hover{border-color:var(--c1);box-shadow:0 0 14px rgba(0,229,255,.35)}
.vp input{width:auto;padding:0;border:0;background:none;box-shadow:none;accent-color:var(--c1);border-radius:0}
.vp #vseek{flex:1;min-width:60px}
.vp #vvol{width:76px}
.vp select{padding:4px 8px;border-radius:10px;font-size:14px}
.vp #vtime{font-size:14px;white-space:nowrap;color:var(--tx)}
.vp-err{position:absolute;inset:0;display:grid;place-items:center;text-align:center;padding:24px;background:rgba(5,6,15,.92);color:#ffd0e8}
@media(max-width:600px){.vp #vvol,.vp #vspeed{display:none}}
.watch{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:26px}
@media(max-width:900px){.watch{grid-template-columns:1fr}}
.watch h2{margin:18px 0 6px}
.side a{display:flex;gap:12px;margin-bottom:12px;padding:8px;border-radius:14px;background:var(--glass);border:1px solid transparent;transition:.25s}
.side a:hover{border-color:var(--c2);background:var(--glass2);transform:translateX(4px)}
.side img{width:150px;aspect-ratio:16/9;object-fit:cover;border-radius:9px}
.desc{background:var(--glass);border:1px solid var(--line);padding:14px;border-radius:14px;white-space:pre-wrap;margin-top:12px;backdrop-filter:blur(8px)}
.btn{background:linear-gradient(135deg,var(--c3),var(--c2));color:#fff;border:0;border-radius:22px;padding:9px 20px;cursor:pointer;font-weight:600;letter-spacing:.4px;transition:.25s;box-shadow:0 0 18px rgba(138,92,255,.35)}
.btn:hover{transform:translateY(-2px);box-shadow:0 0 28px rgba(255,46,154,.55)}
.btn.sec{background:var(--glass2);color:var(--tx);border:1px solid var(--line);box-shadow:none}
.btn.sec:hover{border-color:var(--c1);box-shadow:0 0 18px rgba(0,229,255,.3)}
.btn.ok{background:linear-gradient(135deg,#00c98d,var(--c1));color:#03111a;box-shadow:0 0 18px rgba(0,229,255,.35)}
.btn[disabled]{opacity:.85;cursor:default;transform:none}
.btn.sm{padding:6px 14px;font-size:14px}
.panel{background:var(--glass);border:1px solid var(--line);backdrop-filter:blur(14px);padding:22px;border-radius:18px;margin-bottom:26px;display:grid;gap:12px;max-width:640px;box-shadow:0 8px 40px rgba(0,0,0,.35)}
.panel.wide{max-width:none}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.badge{display:inline-block;padding:3px 11px;border-radius:12px;font-size:12px;letter-spacing:.5px;background:var(--glass2);color:var(--mut);border:1px solid var(--line)}
.badge.on{background:rgba(0,229,255,.12);color:var(--c1);border-color:rgba(0,229,255,.5);box-shadow:0 0 12px rgba(0,229,255,.25)}
.badge.off{background:rgba(255,190,0,.1);color:#ffc83d;border-color:rgba(255,200,60,.5)}
.badge.bad{background:rgba(255,46,154,.12);color:var(--c3);border-color:rgba(255,46,154,.55);box-shadow:0 0 12px rgba(255,46,154,.25)}
.badge.via{background:rgba(138,92,255,.14);color:#b9a6ff;border-color:rgba(138,92,255,.55);box-shadow:0 0 12px rgba(138,92,255,.25)}
.notice{border:1px solid rgba(255,46,154,.5);background:rgba(255,46,154,.08);color:#ffd0e8;padding:12px 16px;border-radius:14px;margin-bottom:14px;box-shadow:0 0 24px rgba(255,46,154,.15)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:26px}
.stat{padding:16px;border-radius:16px;background:var(--glass);border:1px solid var(--line);box-shadow:inset 0 0 30px rgba(138,92,255,.06)}
.stat b{display:block;font-family:Orbitron,sans-serif;font-size:26px;background:linear-gradient(90deg,var(--c1),var(--c2));-webkit-background-clip:text;background-clip:text;color:transparent}
pre.hint{white-space:pre-wrap;margin:0;font-size:12px;color:var(--mut)}
table{width:100%;border-collapse:collapse}td,th{padding:10px 8px;text-align:left;border-bottom:1px solid var(--line)}
th{font-family:Orbitron,sans-serif;font-size:12px;color:var(--mut);letter-spacing:1px;font-weight:600}
td img{width:96px;aspect-ratio:16/9;object-fit:cover;border-radius:8px}
code{background:var(--glass2);padding:1px 6px;border-radius:6px;color:var(--c1)}
::-webkit-scrollbar{width:10px}::-webkit-scrollbar-thumb{background:linear-gradient(var(--c2),var(--c1));border-radius:10px}
`;

function page(title, body, admin = false, q = "") {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@600;800&family=Rajdhani:wght@400;500;600&display=swap" rel="stylesheet">
<style>${CSS}</style></head><body><div class="orb o1"></div><div class="orb o2"></div>
<header><a class="logo" href="/"><i>▶</i> MyTube</a>
<form action="/" method="get"><input name="q" placeholder="Search" value="${esc(q)}"><button>Search</button></form>
<a href="/admin" class="mut">${admin ? "Admin" : "Sign in"}</a></header>
<main>${body}</main></body></html>`,
    { headers: { "Content-Type": "text/html;charset=utf-8", "Cache-Control": admin ? "private, no-store" : "public, max-age=0" } }
  );
}

// Placeholder thumbnail (private YouTube videos and custom videos have no public thumbnail)
const PH =
  "data:image/svg+xml;utf8," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 9"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#1b1442"/><stop offset="1" stop-color="#062a3a"/></linearGradient></defs><rect width="16" height="9" fill="url(#g)"/><path d="M6.6 3.2v2.6L9.4 4.5z" fill="#00e5ff" opacity=".8"/></svg>'
  );
const thumbOf = (v) => (v.thumb ? esc(v.thumb) : isYt(v) ? `https://i.ytimg.com/vi/${esc(v.id)}/hqdefault.jpg` : PH);
const imgTag = (v) => `<img loading="lazy" src="${thumbOf(v)}" onerror="this.onerror=null;this.src='${PH}'" alt="">`;
const lockTag = (v) => (isPublished(v) ? "" : `<span class="tag">🔒 Private</span>`);
const cardHtml = (v) => `<a class="card" href="/watch?v=${esc(v.id)}">
<div class="thumb">${imgTag(v)}${lockTag(v)}</div>
<h3>${esc(v.title)}</h3><div class="mut">${esc(v.channel || "")}</div></a>`;

/* ---------- custom player ---------- */
function playerHtml(src, poster) {
  return `<div class="vp" id="vp"><video id="vv" src="${esc(src)}" poster="${esc(poster)}" preload="metadata" playsinline></video>
<div class="vp-big" id="vbig">▶</div>
<div class="vp-bar"><button id="vplay" title="Play / Pause">▶</button>
<input type="range" id="vseek" min="0" max="1000" value="0" aria-label="Seek">
<span id="vtime">0:00 / 0:00</span>
<button id="vmute" title="Mute">🔊</button><input type="range" id="vvol" min="0" max="1" step="0.05" value="1" aria-label="Volume">
<select id="vspeed" aria-label="Speed"><option value="0.5">0.5x</option><option value="1" selected>1x</option><option value="1.25">1.25x</option><option value="1.5">1.5x</option><option value="2">2x</option></select>
<button id="vpip" title="Picture in picture">⧉</button><button id="vfs" title="Fullscreen">⛶</button></div></div>
<script>
(function(){
var v=document.getElementById('vv'),p=document.getElementById('vplay'),s=document.getElementById('vseek'),t=document.getElementById('vtime'),
m=document.getElementById('vmute'),vol=document.getElementById('vvol'),sp=document.getElementById('vspeed'),big=document.getElementById('vbig'),box=document.getElementById('vp');
function f(x){x=Math.floor(x||0);var h=Math.floor(x/3600),mm=Math.floor(x%3600/60),ss=('0'+x%60).slice(-2);return h?h+':'+('0'+mm).slice(-2)+':'+ss:mm+':'+ss}
function toggle(){if(v.paused){v.play()}else{v.pause()}}
p.onclick=toggle;big.onclick=toggle;v.onclick=toggle;
v.onplay=function(){p.textContent='⏸';box.classList.add('playing')};
v.onpause=function(){p.textContent='▶';box.classList.remove('playing')};
v.ontimeupdate=function(){if(v.duration)s.value=v.currentTime/v.duration*1000;t.textContent=f(v.currentTime)+' / '+f(v.duration)};
v.onloadedmetadata=v.ontimeupdate;
s.oninput=function(){if(v.duration)v.currentTime=s.value/1000*v.duration};
m.onclick=function(){v.muted=!v.muted;m.textContent=v.muted?'🔇':'🔊'};
vol.oninput=function(){v.volume=vol.value;v.muted=false;m.textContent='🔊'};
sp.onchange=function(){v.playbackRate=parseFloat(sp.value)};
document.getElementById('vpip').onclick=function(){if(document.pictureInPictureEnabled){if(document.pictureInPictureElement){document.exitPictureInPicture()}else{v.requestPictureInPicture()}}};
document.getElementById('vfs').onclick=function(){if(document.fullscreenElement){document.exitFullscreen()}else{box.requestFullscreen()}};
v.onerror=function(){if(!box.querySelector('.vp-err'))box.insertAdjacentHTML('beforeend','<div class="vp-err"><div>This video could not be loaded.<br><span style="font-size:14px;opacity:.8">If it is a secure stream, check the YouTube connection in the admin panel, or switch to the YouTube embed.</span></div></div>')};
document.addEventListener('keydown',function(e){
if(/INPUT|SELECT|TEXTAREA/.test(e.target.tagName))return;
if(e.code==='Space'){e.preventDefault();toggle()}
else if(e.code==='ArrowRight'){v.currentTime+=5}
else if(e.code==='ArrowLeft'){v.currentTime-=5}
else if(e.key==='f'){document.getElementById('vfs').onclick()}
else if(e.key==='m'){m.onclick()}
});
})();
</script>`;
}

/* ---------- pages ---------- */
function home(videos, q, admin) {
  const vis = videos.filter((v) => admin || isPublished(v));
  const list = q ? vis.filter((v) => (v.title + " " + (v.channel || "") + " " + (v.description || "")).toLowerCase().includes(q.toLowerCase())) : vis;
  return page("MyTube", list.length ? `<div class="grid">${list.map(cardHtml).join("")}</div>` : `<p class="mut">No videos found.</p>`, admin, q);
}

function watch(videos, id, admin = false, mode = "", connected = false) {
  const v = videos.find((x) => x.id === id && (admin || isPublished(x)));
  if (!v) return page("Not found", `<p>Video not found.</p>`, admin);
  const others = videos.filter((x) => x.id !== id && (admin || isPublished(x)));

  // YouTube videos that can't be embedded (private / embed-disabled) are served through
  // the secure stream when the admin's YouTube account is connected. Visitors get this
  // automatically for published videos; the admin can switch with ?p=embed / ?p=stream.
  const ytPrivate = isYt(v) && (v.blocked || v.ytPrivacy === "PRIVATE");
  const secure = isYt(v) && (admin
    ? (mode === "stream" || (mode !== "embed" && ytPrivate))
    : (ytPrivate && connected));

  let player;
  let modes = "";
  if (v.player === "file") {
    player = playerHtml(v.src, thumbOf(v));
  } else if (v.player === "iframe") {
    player = `<div class="player"><iframe src="${esc(v.src)}" title="${esc(v.title)}" sandbox="allow-scripts allow-same-origin allow-presentation allow-popups"
 allow="autoplay;fullscreen;picture-in-picture;encrypted-media" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>`;
  } else if (secure) {
    player = playerHtml(`${admin ? "/admin/stream" : "/stream"}?v=${encodeURIComponent(v.id)}`, thumbOf(v));
  } else {
    player = `<div class="player"><iframe src="https://www.youtube-nocookie.com/embed/${esc(v.id)}?rel=0" title="${esc(v.title)}"
 allow="accelerometer;autoplay;clipboard-write;encrypted-media;gyroscope;picture-in-picture;web-share" allowfullscreen referrerpolicy="strict-origin-when-cross-origin"></iframe></div>`;
  }
  if (admin && isYt(v))
    modes = `<div class="modes"><span class="mut">Player:</span>
<a class="${secure ? "" : "cur"}" href="/watch?v=${esc(v.id)}&p=embed">YouTube embed</a>
<a class="${secure ? "cur" : ""}" href="/watch?v=${esc(v.id)}&p=stream">Secure stream (admin only)</a></div>`;

  return page(
    v.title,
    `<div class="watch"><section>
${admin && v.blocked ? `<div class="notice"><b>Admin notice:</b> ${esc(BLOCKED_MSG)}</div>` : ""}
${modes}${player}
<h2>${esc(v.title)}</h2><div class="mut">${esc(v.channel || "")} · ${esc(new Date(v.added).toDateString())}${isPublished(v) ? "" : " · <b>🔒 Private - only you can see this</b>"}</div>
${v.description ? `<div class="desc">${esc(v.description)}</div>` : ""}</section>
<aside class="side">${others.map((o) => `<a href="/watch?v=${esc(o.id)}">${imgTag(o)}<div><b>${esc(o.title)}</b><div class="mut">${esc(o.channel || "")}${isPublished(o) ? "" : " · 🔒"}</div></div></a>`).join("")}</aside></div>`,
    admin
  );
}

const loginPage = (err = "") =>
  page("Admin login", `<form class="panel" method="post" action="/admin/login"><h2>Admin login</h2>
${err ? `<div style="color:#f44">${esc(err)}</div>` : ""}
<input type="password" name="password" placeholder="Password" required autofocus><button class="btn">Sign in</button></form>`);

// Public / Private switch. Public = everyone, Private = admin only.
const visToggle = (id, on) => {
  const btn = (action, label, active) =>
    `<form method="post" action="/admin/${action}" style="display:inline"><input type="hidden" name="id" value="${esc(id)}">
<button class="btn sm ${active ? "ok" : "sec"}" ${active ? "disabled" : ""}>${label}</button></form>`;
  return `<div class="row">${btn("publish", "Public", on)}${btn("unpublish", "Private", !on)}</div>`;
};

const privBadge = (p) =>
  p ? `<span class="badge ${p === "PRIVATE" ? "bad" : p === "UNLISTED" ? "off" : "on"}" title="Visibility on YouTube">YouTube: ${esc(p.toLowerCase())}</span>` : "";

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
${yt?.studioErr ? `<div class="notice">Private and unlisted videos could not be listed (${esc(yt.studioErr)}). Only public videos are shown. You can still add a private video by its ID in "Add video manually".</div>` : ""}
<div class="row"><form method="post" action="/admin/yt/refresh"><button class="btn sec">Refresh videos</button></form>
<form method="post" action="/admin/yt/disconnect" onsubmit="return confirm('Disconnect and delete the stored cookie?')"><button class="btn sec">Disconnect</button></form></div>
${
  list.length
    ? `<table><tr><th></th><th>Title</th><th>Site visibility</th><th></th></tr>${list
        .map((c) => {
          const local = byId.get(c.id);
          const on = !!local && isPublished(local);
          return `<tr><td>${imgTag({ id: c.id })}</td><td>${esc(c.title)}<div class="row">${privBadge(c.privacy)}<span class="mut">${esc(c.id)}</span></div></td>
<td><span class="badge ${on ? "on" : local ? "off" : ""}">${on ? "Public" : local ? "Private" : "Not on site"}</span></td>
<td><div class="row">${visToggle(c.id, on)}${local ? `<a class="btn sm sec" href="/watch?v=${esc(c.id)}">Watch</a>` : ""}</div></td></tr>`;
        })
        .join("")}</table>`
    : `<p class="mut">No videos found on this channel.</p>`
}</div>`;
}

function adminPage(videos, msg = "", yt = null, connected = false, isErr = false) {
  const pub = videos.filter(isPublished).length;
  const ytPriv = videos.filter((v) => v.ytPrivacy === "PRIVATE" || v.blocked).length;
  return page(
    "Admin",
    `<h2>Admin panel</h2>${msg ? `<p style="color:${isErr ? "#f44" : "#4caf50"}">${esc(msg)}</p>` : ""}
<div class="stats"><div class="stat"><b>${videos.length}</b><span class="mut">On site</span></div>
<div class="stat"><b>${pub}</b><span class="mut">Public</span></div>
<div class="stat"><b>${videos.length - pub}</b><span class="mut">Private (admin only)</span></div>
<div class="stat"><b>${ytPriv}</b><span class="mut">Private on YouTube</span></div></div>
${ytSection(yt, connected, videos)}
<form class="panel" method="post" action="/admin/add"><h3>Add video manually</h3>
<select name="player">
<option value="youtube">YouTube video (embed, or secure stream if private)</option>
<option value="file">Direct video file link (.mp4 / .webm) in the custom player</option>
<option value="iframe">Embed page link (Vimeo, etc.) in an iframe</option></select>
<input name="url" placeholder="YouTube URL or video ID (YouTube type)">
<input name="src" placeholder="https:// link (file or embed type)">
<input name="thumb" placeholder="Thumbnail image link, https (optional)">
<input name="title" placeholder="Title" required maxlength="150">
<input name="channel" placeholder="Channel name" maxlength="80">
<textarea name="description" rows="4" placeholder="Description" maxlength="2000"></textarea>
<select name="visibility"><option value="public">Public - visible to everyone</option><option value="private">Private - only me (admin)</option></select>
<button class="btn">Add video</button></form>
<h3>Site library (${videos.length}) <span class="mut">· ${pub} public</span></h3>
<table><tr><th></th><th>Title</th><th>Visibility</th><th></th></tr>${videos
      .map(
        (v) => `<tr><td>${imgTag(v)}</td><td><a href="/watch?v=${esc(v.id)}">${esc(v.title)}</a>
<div class="row"><span class="mut">${esc(v.channel || "")}</span><span class="badge">${esc(v.player || "youtube")}</span>${isYt(v) ? privBadge(v.ytPrivacy) : ""}</div></td>
<td><span class="badge ${isPublished(v) ? "on" : "off"}">${isPublished(v) ? "Public" : "Private"}</span>${v.blocked ? ` <span class="badge ${isPublished(v) ? "via" : "bad"}" title="${isPublished(v) ? "Served through the secure stream" : "Private or not embeddable on YouTube"}">${isPublished(v) ? "Via stream" : "Not embeddable"}</span>` : ""}</td>
<td><div class="row">${visToggle(v.id, isPublished(v))}<a class="btn sm sec" href="/watch?v=${esc(v.id)}">Watch</a>
${v.blocked ? `<form method="post" action="/admin/recheck"><input type="hidden" name="id" value="${esc(v.id)}"><button class="btn sm sec">Re-check</button></form>` : ""}
<form method="post" action="/admin/delete" onsubmit="return confirm('Delete this video?')"><input type="hidden" name="id" value="${esc(v.id)}"><button class="btn sm sec">Delete</button></form></div></td></tr>`
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
      if (path === "/") return home(await getVideos(env), url.searchParams.get("q") || "", await isAdmin(req, env));
      if (path === "/watch") {
        const connected = !!(await env.VIDEOS.get("yt_cookie"));
        return watch(await getVideos(env), url.searchParams.get("v") || "", await isAdmin(req, env), url.searchParams.get("p") || "", connected);
      }
      if (path === "/stream") {
        const id = url.searchParams.get("v") || "";
        if (!/^[\w-]{11}$/.test(id)) return new Response("Bad video id", { status: 400 });
        const videos = await getVideos(env);
        const v = videos.find((x) => x.id === id);
        if (!v || !isPublished(v) || !isYt(v)) return new Response("Not found", { status: 404 });
        const needsStream = v.blocked || v.ytPrivacy === "PRIVATE";
        // Public-on-YouTube videos should use the embed (saves your bandwidth).
        if (!needsStream && !(await isAdmin(req, env)))
          return new Response("This video plays through the YouTube embed", { status: 400 });
        return streamVideo(req, env, id);
      }
      if (path === "/admin/stream") {
        if (!(await isAdmin(req, env))) return new Response("Unauthorized", { status: 401 });
        const id = url.searchParams.get("v") || "";
        if (!/^[\w-]{11}$/.test(id)) return new Response("Bad video id", { status: 400 });
        return streamVideo(req, env, id);
      }
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
          await syncPrivacy(videos, data);
          await saveVideos(env, videos);
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
          await syncPrivacy(videos, data);
          await saveVideos(env, videos);
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

      /* ----- Public / Private ----- */
      if (path === "/admin/publish") {
        const v = await importFromChannel(env, videos, String(form.get("id") || ""));
        if (!v) return renderAdmin(env, "Video not found", true, videos);
        if (isYt(v)) {
          v.blocked = v.ytPrivacy === "PRIVATE" || !(await embedStatus(v.id));
          if (v.blocked) {
            const connected = !!(await env.VIDEOS.get("yt_cookie"));
            if (!connected) {
              v.published = false;
              await saveVideos(env, videos);
              return renderAdmin(env, "Kept Private. " + BLOCKED_MSG, true, videos);
            }
            v.published = true;
            await saveVideos(env, videos);
            return renderAdmin(env, "Now Public - visitors will watch it through the secure stream", false, videos);
          }
        }
        v.published = true;
        await saveVideos(env, videos);
        return renderAdmin(env, "Now Public - visible to everyone", false, videos);
      }

      if (path === "/admin/unpublish") {
        const v = await importFromChannel(env, videos, String(form.get("id") || ""));
        if (!v) return renderAdmin(env, "Video not found", true, videos);
        v.published = false;
        await saveVideos(env, videos);
        return renderAdmin(env, "Now Private - only you can see it", false, videos);
      }

      if (path === "/admin/recheck") {
        const v = videos.find((x) => x.id === String(form.get("id") || ""));
        if (!v) return renderAdmin(env, "Video not found", true, videos);
        v.blocked = v.ytPrivacy === "PRIVATE" || !(await embedStatus(v.id));
        await saveVideos(env, videos);
        return v.blocked ? renderAdmin(env, BLOCKED_MSG, true, videos) : renderAdmin(env, "Plays fine - the video is embeddable now. You can set it Public.", false, videos);
      }

      /* ----- manual add / delete ----- */
      if (path === "/admin/add") {
        const type = ["youtube", "file", "iframe"].includes(String(form.get("player"))) ? String(form.get("player")) : "youtube";
        const wantPublic = String(form.get("visibility")) !== "private";
        const v = {
          title: String(form.get("title") || "").slice(0, 150),
          channel: String(form.get("channel") || "").slice(0, 80),
          description: String(form.get("description") || "").slice(0, 2000),
          added: Date.now(),
          player: type,
        };
        const thumb = httpsUrl(String(form.get("thumb") || ""));
        if (thumb) v.thumb = thumb;

        if (type === "youtube") {
          const id = parseYouTubeId(String(form.get("url") || ""));
          if (!id) return renderAdmin(env, "Invalid YouTube URL / ID", true, videos);
          if (videos.some((x) => x.id === id)) return renderAdmin(env, "Video already added", true, videos);
          v.id = id;
          v.blocked = !(await embedStatus(id));
          const connected = !!(await env.VIDEOS.get("yt_cookie"));
          v.published = wantPublic && (!v.blocked || connected);
        } else {
          const src = httpsUrl(String(form.get("src") || ""));
          if (!src) return renderAdmin(env, "Enter a valid https:// link for the " + (type === "file" ? "video file" : "embed page"), true, videos);
          v.id = randomId();
          v.src = src;
          v.published = wantPublic;
        }
        videos.unshift(v);
        await saveVideos(env, videos);
        if (v.blocked && !v.published) return renderAdmin(env, "Video added as Private. " + BLOCKED_MSG, true, videos);
        if (v.blocked) return renderAdmin(env, "Video added as Public - it will play through the secure stream", false, videos);
        return renderAdmin(env, `Video added (${v.published ? "Public" : "Private"})`, false, videos);
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