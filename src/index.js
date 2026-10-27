/**
 * YouTube Link Core — Cloudflare Worker admin panel
 *
 * Bindings / secrets required:
 *   KV namespace  : YT_STORE
 *   Secrets       : ADMIN_PASSWORD, SESSION_SECRET, ENCRYPTION_KEY
 *
 * Setup:
 *   npx wrangler kv namespace create YT_STORE
 *   npx wrangler secret put ADMIN_PASSWORD
 *   npx wrangler secret put SESSION_SECRET     (any long random string)
 *   npx wrangler secret put ENCRYPTION_KEY     (any long random string)
 *   npx wrangler deploy
 */

const enc = new TextEncoder();
const dec = new TextDecoder();
const SESSION_TTL = 60 * 60 * 12; // 12h
const STORE_KEY = "yt:connection";

/* ───────────── helpers ───────────── */
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function safeEqual(a, b) {
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const xa = new Uint8Array(x), ya = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < xa.length; i++) diff |= xa[i] ^ ya[i];
  return diff === 0;
}

/* ───────────── session ───────────── */
async function makeSession(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const payload = String(exp);
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env.SESSION_SECRET), enc.encode(payload));
  return payload + "." + hex(sig);
}

async function isAuthed(request, env) {
  const m = (request.headers.get("cookie") || "").match(/(?:^|;\s*)yt_admin=([^;]+)/);
  if (!m) return false;
  const [exp, sig] = m[1].split(".");
  if (!exp || !sig || Number(exp) < Date.now() / 1000) return false;
  const expected = await crypto.subtle.sign("HMAC", await hmacKey(env.SESSION_SECRET), enc.encode(exp));
  return safeEqual(hex(expected), sig);
}

const sessionCookie = (value, maxAge) =>
  `yt_admin=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

/* ───────────── encryption (AES-GCM) ───────────── */
async function aesKey(env) {
  const raw = await crypto.subtle.digest("SHA-256", enc.encode(env.ENCRYPTION_KEY));
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}
async function encrypt(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(env), enc.encode(text));
  return b64(iv) + "." + b64(ct);
}
async function decrypt(env, packed) {
  const [iv, ct] = packed.split(".");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, await aesKey(env), unb64(ct));
  return dec.decode(pt);
}

/* ───────────── cookie / curl parsing ───────────── */
function extractCookie(input) {
  const text = input.replace(/\\\r?\n/g, " ").trim();
  let raw = null;

  // -H 'cookie: ...'  /  -H $'cookie: ...'  /  --header "Cookie: ..."
  let m = text.match(/(?:-H|--header)\s+\$?(['"])\s*cookie:\s*([\s\S]*?)\1/i);
  if (m) raw = m[2];

  // -b '...' / --cookie '...'
  if (!raw) {
    m = text.match(/(?:\s-b|--cookie)\s+\$?(['"])([\s\S]*?)\1/i);
    if (m) raw = m[2];
  }

  // "Cookie: a=b; c=d" header line
  if (!raw) {
    m = text.match(/^\s*cookie:\s*(.+)$/im);
    if (m) raw = m[1];
  }

  // plain "a=b; c=d"
  if (!raw && /=/.test(text) && !/^curl\s/i.test(text)) raw = text;

  if (!raw) return null;

  const pairs = {};
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) pairs[k] = v;
  }
  return Object.keys(pairs).length ? pairs : null;
}

const toHeader = (pairs) => Object.entries(pairs).map(([k, v]) => k + "=" + v).join("; ");

/* ───────────── YouTube check ───────────── */
async function sapisidHash(sapisid, origin) {
  const ts = Math.floor(Date.now() / 1000);
  const digest = await crypto.subtle.digest("SHA-1", enc.encode(ts + " " + sapisid + " " + origin));
  return "SAPISIDHASH " + ts + "_" + hex(digest);
}

async function checkYouTube(pairs) {
  const sapisid = pairs["SAPISID"] || pairs["__Secure-3PAPISID"];
  if (!sapisid) return { ok: false, error: "Missing SAPISID / __Secure-3PAPISID cookie. Copy the request from a logged-in youtube.com tab." };

  const origin = "https://www.youtube.com";
  const res = await fetch(origin + "/youtubei/v1/account/account_menu?prettyPrint=false", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: toHeader(pairs),
      authorization: await sapisidHash(sapisid, origin),
      origin,
      "x-origin": origin,
      "x-goog-authuser": "0",
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    },
    body: JSON.stringify({ context: { client: { clientName: "WEB", clientVersion: "2.20240501.00.00", hl: "en" } } }),
  });

  if (!res.ok) return { ok: false, error: "YouTube rejected the session (HTTP " + res.status + "). The cookie is likely expired." };

  const body = await res.text();
  const name = (body.match(/"accountName":\{"simpleText":"([^"]+)"/) || [])[1];
  const handle = (body.match(/"channelHandle":\{"simpleText":"([^"]+)"/) || [])[1];
  const photo = (body.match(/"accountPhoto":\{"thumbnails":\[\{"url":"([^"]+)"/) || [])[1];

  const channelId = (body.match(/"browseId":"(UC[\w-]{22})"/) || [])[1];

  if (!name) return { ok: false, error: "Session not logged in. Cookie is expired or incomplete." };
  return { ok: true, name, handle: handle || null, photo: photo || null, channelId: channelId || null };
}

/* ───────────── Studio list: public + unlisted + private (best effort) ───────────── */
async function fetchStudioVideos(pairs, channelId) {
  const sapisid = pairs["SAPISID"] || pairs["__Secure-3PAPISID"];
  const origin = "https://studio.youtube.com";
  const res = await fetch(origin + "/youtubei/v1/creator/list_creator_videos?alt=json", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: toHeader(pairs),
      authorization: await sapisidHash(sapisid, origin),
      origin,
      referer: origin + "/",
      "x-origin": origin,
      "x-goog-authuser": "0",
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    },
    body: JSON.stringify({
      context: {
        client: { clientName: 62, clientVersion: "1.20240501.01.00", hl: "en" },
        user: {
          delegationContext: {
            externalChannelId: channelId,
            roleType: { channelRoleType: "CREATOR_CHANNEL_ROLE_TYPE_OWNER" },
          },
          serializedDelegationContext: "",
        },
      },
      channelId,
      mask: {
        videoId: true, title: true, privacy: true, lengthSeconds: true,
        timeCreatedSeconds: true, thumbnailDetails: { all: true }, metrics: { all: true },
      },
      pageSize: 30,
      order: "VIDEO_ORDER_DISPLAY_TIME_DESC",
      filter: { and: { operands: [{ channelIdIs: { value: channelId } }] } },
    }),
  });
  if (!res.ok) return { ok: false, error: "Studio list refused (HTTP " + res.status + ")." };
  const d = await res.json().catch(() => null);
  if (!d || !Array.isArray(d.videos)) return { ok: false, error: "Studio list returned no videos." };

  const mmss = (s) => {
    s = Number(s) || 0;
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60;
    return (h ? h + ":" + String(m).padStart(2, "0") : m) + ":" + String(x).padStart(2, "0");
  };
  const videos = d.videos.filter((v) => v.videoId).map((v) => {
    const th = v.thumbnailDetails?.thumbnails || [];
    return {
      id: v.videoId,
      title: v.title || "Untitled",
      privacy: String(v.privacy || "VIDEO_PRIVACY_PUBLIC").replace("VIDEO_PRIVACY_", ""),
      views: v.metrics?.viewCount != null ? v.metrics.viewCount + " views" : "",
      published: v.timeCreatedSeconds ? new Date(Number(v.timeCreatedSeconds) * 1000).toISOString().slice(0, 10) : "",
      length: v.lengthSeconds ? mmss(v.lengthSeconds) : "",
      thumb: (th.length ? th[th.length - 1].url : "") || "https://i.ytimg.com/vi/" + v.videoId + "/mqdefault.jpg",
    };
  });
  return { ok: true, videos };
}

/* ───────────── channel videos (admin only) ───────────── */
async function fetchVideos(pairs, channelId) {
  const sapisid = pairs["SAPISID"] || pairs["__Secure-3PAPISID"];
  const origin = "https://www.youtube.com";
  const res = await fetch(origin + "/youtubei/v1/browse?prettyPrint=false", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: toHeader(pairs),
      authorization: await sapisidHash(sapisid, origin),
      origin,
      "x-origin": origin,
      "x-goog-authuser": "0",
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    },
    body: JSON.stringify({
      context: { client: { clientName: "WEB", clientVersion: "2.20240501.00.00", hl: "en" } },
      browseId: channelId,
      params: "EgZ2aWRlb3PyBgQKAjoA", // "Videos" tab
    }),
  });
  if (!res.ok) return { ok: false, error: "YouTube refused the videos request (HTTP " + res.status + ")." };

  const data = await res.json().catch(() => null);
  if (!data) return { ok: false, error: "Unreadable response from YouTube." };

  const videos = [];
  const seen = new Set();
  const stack = [data];
  while (stack.length && videos.length < 24) {
    const n = stack.pop();
    if (!n || typeof n !== "object") continue;
    if (Array.isArray(n)) { for (let i = n.length - 1; i >= 0; i--) stack.push(n[i]); continue; }

    const vr = n.videoRenderer;
    if (vr && vr.videoId && !seen.has(vr.videoId)) {
      seen.add(vr.videoId);
      const th = vr.thumbnail?.thumbnails || [];
      videos.push({
        id: vr.videoId,
        title: vr.title?.runs?.[0]?.text || vr.title?.simpleText || "Untitled",
        views: vr.viewCountText?.simpleText || "",
        published: vr.publishedTimeText?.simpleText || "",
        length: vr.lengthText?.simpleText || "",
        thumb: th.length ? th[th.length - 1].url : "",
      });
    }

    const lv = n.lockupViewModel;
    if (lv && lv.contentId && lv.contentType === "LOCKUP_CONTENT_TYPE_VIDEO" && !seen.has(lv.contentId)) {
      seen.add(lv.contentId);
      const md = lv.metadata?.lockupMetadataViewModel;
      const parts = (md?.metadata?.contentMetadataViewModel?.metadataRows || [])
        .flatMap((r) => (r.metadataParts || []).map((p) => p.text?.content).filter(Boolean));
      videos.push({
        id: lv.contentId,
        title: md?.title?.content || "Untitled",
        views: parts[0] || "",
        published: parts[1] || "",
        length: "",
        thumb: lv.contentImage?.thumbnailViewModel?.image?.sources?.[0]?.url || "",
      });
    }

    for (const k in n) if (n[k] && typeof n[k] === "object") stack.push(n[k]);
  }
  return { ok: true, videos };
}

/* ───────────── API ───────────── */
async function getConn(env) {
  const raw = await env.YT_STORE.get(STORE_KEY);
  return raw ? JSON.parse(raw) : null;
}

async function handleApi(request, env, path) {
  if (request.method !== "POST" && request.method !== "GET") return json({ error: "Method not allowed" }, 405);
  if (request.method === "POST" && !(request.headers.get("content-type") || "").includes("application/json"))
    return json({ error: "JSON only" }, 415);

  // Public: tells visitors ONLY whether the link is live. No profile, no cookies, no data.
  if (path === "/api/public-status") {
    const c = await getConn(env);
    return json({ connected: !!c });
  }

  if (path === "/api/login") {
    const { password } = await request.json().catch(() => ({}));
    if (!password || !(await safeEqual(password, env.ADMIN_PASSWORD))) return json({ error: "Access denied" }, 401);
    return json({ ok: true }, 200, { "set-cookie": sessionCookie(await makeSession(env), SESSION_TTL) });
  }

  if (!(await isAuthed(request, env))) return json({ error: "Unauthorized" }, 401);

  if (path === "/api/logout") return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });

  if (path === "/api/status") {
    const c = await getConn(env);
    return json({ connected: !!c, profile: c?.profile || null, cookies: c?.names || [], connectedAt: c?.connectedAt || null, checkedAt: c?.checkedAt || null });
  }

  if (path === "/api/videos") {
    const c = await getConn(env);
    if (!c) return json({ error: "Not connected" }, 400);
    const pairs = JSON.parse(await decrypt(env, c.cipher));
    const who = await checkYouTube(pairs);
    if (!who.ok) return json({ error: who.error, expired: true }, 400);
    if (!who.channelId) return json({ error: "Could not find the channel id for this account." }, 400);
    const studio = await fetchStudioVideos(pairs, who.channelId).catch((e) => ({ ok: false, error: "Studio list failed." }));
    if (studio.ok && studio.videos.length) {
      return json({ ok: true, source: "studio", profile: { name: who.name, handle: who.handle }, videos: studio.videos });
    }
    const r = await fetchVideos(pairs, who.channelId);
    if (!r.ok) return json({ error: r.error }, 400);
    r.videos.forEach((v) => (v.privacy = "PUBLIC"));
    return json({ ok: true, source: "public", note: studio.ok ? "" : studio.error, profile: { name: who.name, handle: who.handle }, videos: r.videos });
  }

  if (path === "/api/connect") {
    const { input } = await request.json().catch(() => ({}));
    if (!input || input.length > 100_000) return json({ error: "Paste a curl command or cookie string." }, 400);
    const pairs = extractCookie(input);
    if (!pairs) return json({ error: "No cookies found in the pasted text." }, 400);

    const result = await checkYouTube(pairs);
    if (!result.ok) return json({ error: result.error }, 400);

    const now = new Date().toISOString();
    await env.YT_STORE.put(
      STORE_KEY,
      JSON.stringify({
        cipher: await encrypt(env, JSON.stringify(pairs)),
        names: Object.keys(pairs),
        profile: { name: result.name, handle: result.handle, photo: result.photo },
        connectedAt: now,
        checkedAt: now,
      })
    );
    return json({ ok: true, profile: result });
  }

  if (path === "/api/refresh") {
    const c = await getConn(env);
    if (!c) return json({ error: "Not connected" }, 400);
    const pairs = JSON.parse(await decrypt(env, c.cipher));
    const result = await checkYouTube(pairs);
    if (!result.ok) return json({ error: result.error, expired: true }, 400);
    c.profile = { name: result.name, handle: result.handle, photo: result.photo };
    c.checkedAt = new Date().toISOString();
    await env.YT_STORE.put(STORE_KEY, JSON.stringify(c));
    return json({ ok: true, profile: c.profile });
  }

  if (path === "/api/disconnect") {
    await env.YT_STORE.delete(STORE_KEY);
    return json({ ok: true });
  }

  return json({ error: "Not found" }, 404);
}

/* ───────────── UI ───────────── */
const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>Link Core · YouTube</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --void:#05070f; --panel:#0b1020; --edge:#1b2a4a; --ice:#6ff3ff; --violet:#8a6bff;
  --text:#dfe8ff; --dim:#7d8db5; --ok:#5dffb0; --bad:#ff4d7d;
  --glow:0 0 24px rgba(111,243,255,.25);
}
*{box-sizing:border-box;margin:0}
html,body{height:100%}
body{
  background:var(--void); color:var(--text); font:15px/1.5 "Chakra Petch",system-ui,sans-serif;
  padding:env(safe-area-inset-top) 16px env(safe-area-inset-bottom);
  background-image:
    radial-gradient(900px 500px at 85% -10%,rgba(138,107,255,.18),transparent 60%),
    radial-gradient(700px 500px at -10% 110%,rgba(111,243,255,.12),transparent 60%),
    linear-gradient(rgba(111,243,255,.04) 1px,transparent 1px),
    linear-gradient(90deg,rgba(111,243,255,.04) 1px,transparent 1px);
  background-size:auto,auto,36px 36px,36px 36px;
}
main{max-width:760px;margin:0 auto;padding:28px 0 48px}
h1{font-size:26px;letter-spacing:.04em;font-weight:700}
.sub{color:var(--dim);margin-top:2px}
.mono{font-family:"JetBrains Mono",monospace}
.panel{
  background:linear-gradient(180deg,rgba(17,26,50,.85),rgba(9,14,30,.9));
  border:1px solid var(--edge); border-radius:14px; padding:20px; margin-top:20px;
  position:relative; backdrop-filter:blur(6px);
  clip-path:polygon(0 0,calc(100% - 18px) 0,100% 18px,100% 100%,18px 100%,0 calc(100% - 18px));
}
.panel::before{content:"";position:absolute;inset:0 0 auto 0;height:1px;background:linear-gradient(90deg,transparent,var(--ice),transparent);opacity:.6}
h2{font-size:17px;font-weight:600;margin-bottom:12px}

/* status core */
.core{display:flex;gap:18px;align-items:center}
.orb{width:84px;height:84px;flex:none;position:relative;display:grid;place-items:center}
.orb svg{position:absolute;inset:0;animation:spin 14s linear infinite}
.orb.on svg{animation-duration:6s}
.orb img,.orb .dot{width:52px;height:52px;border-radius:50%;object-fit:cover;background:#10182e;border:1px solid var(--edge)}
.orb .dot{display:grid;place-items:center;color:var(--dim);font-size:20px}
@keyframes spin{to{transform:rotate(360deg)}}
.state{font-size:20px;font-weight:700}
.state.on{color:var(--ok);text-shadow:0 0 14px rgba(93,255,176,.4)}
.state.off{color:var(--dim)}
.meta{color:var(--dim);font-size:13px;margin-top:2px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.chip{font:12px "JetBrains Mono",monospace;padding:3px 8px;border:1px solid var(--edge);border-radius:6px;color:var(--dim)}

/* form */
.tabs{display:flex;gap:6px;margin-bottom:12px}
.tab{background:none;border:1px solid var(--edge);color:var(--dim);padding:8px 14px;border-radius:8px;font:inherit;cursor:pointer}
.tab[aria-selected=true]{color:var(--void);background:var(--ice);border-color:var(--ice);box-shadow:var(--glow)}
textarea,input{
  width:100%;background:#060a17;border:1px solid var(--edge);color:var(--text);
  border-radius:10px;padding:12px;font:13px/1.5 "JetBrains Mono",monospace;outline:none;
}
textarea{min-height:170px;resize:vertical}
textarea:focus,input:focus{border-color:var(--ice);box-shadow:var(--glow)}
.hint{color:var(--dim);font-size:13px;margin:10px 0 14px}
.hint ol{padding-left:18px}
.row{display:flex;gap:10px;flex-wrap:wrap}
button.act{
  font:600 15px "Chakra Petch",sans-serif;padding:11px 20px;border-radius:10px;cursor:pointer;
  border:1px solid var(--ice);background:linear-gradient(135deg,var(--ice),var(--violet));color:#04060d;
  transition:transform .15s,box-shadow .15s;
}
button.act:hover{box-shadow:var(--glow);transform:translateY(-1px)}
button.act:disabled{opacity:.5;cursor:wait;transform:none}
button.ghost{background:none;color:var(--text);border-color:var(--edge)}
button.danger{background:none;color:var(--bad);border-color:rgba(255,77,125,.5)}
:focus-visible{outline:2px solid var(--ice);outline-offset:2px}
.msg{margin-top:12px;font-size:14px;min-height:20px}
.msg.err{color:var(--bad)} .msg.ok{color:var(--ok)}
.hidden{display:none!important}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.login{max-width:380px;margin:12vh auto 0}
.orb.on::after{content:"";position:absolute;inset:6px;border-radius:50%;box-shadow:0 0 22px rgba(93,255,176,.55),inset 0 0 14px rgba(93,255,176,.25);animation:pulse 2.4s ease-in-out infinite;pointer-events:none}
@keyframes pulse{50%{opacity:.35;transform:scale(1.06)}}
.vgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px;margin-top:6px}
.vid{display:block;text-decoration:none;color:inherit;border:1px solid var(--edge);border-radius:10px;overflow:hidden;background:#060a17;transition:border-color .15s,box-shadow .15s,transform .15s}
.vid:hover{border-color:var(--ice);box-shadow:var(--glow);transform:translateY(-2px)}
.vid .th{position:relative;aspect-ratio:16/9;background:#0a1226}
.vid img{width:100%;height:100%;object-fit:cover;display:block}
.vid .len{position:absolute;right:6px;bottom:6px;font:11px "JetBrains Mono",monospace;background:rgba(0,0,0,.75);padding:1px 6px;border-radius:4px}
.vid .tt{padding:9px 10px 2px;font-size:13px;font-weight:600;line-height:1.35;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.vid .mm{padding:0 10px 10px;color:var(--dim);font-size:12px}
.ftab{background:none;border:1px solid var(--edge);color:var(--dim);padding:6px 12px;border-radius:8px;font:inherit;font-size:13px;cursor:pointer}
.ftab[aria-selected=true]{color:var(--void);background:var(--ice);border-color:var(--ice)}
.vid{cursor:pointer;text-align:left;font:inherit;padding:0;width:100%}
.badge{position:absolute;left:6px;top:6px;font:600 10px "JetBrains Mono",monospace;letter-spacing:.08em;padding:2px 7px;border-radius:5px;background:rgba(5,7,15,.82);border:1px solid var(--edge)}
.badge.PUBLIC{color:var(--ok);border-color:rgba(93,255,176,.5)}
.badge.UNLISTED{color:var(--ice);border-color:rgba(111,243,255,.5)}
.badge.PRIVATE{color:#c4b4ff;border-color:rgba(138,107,255,.6)}
.modal{position:fixed;inset:0;z-index:50;background:rgba(2,4,10,.88);backdrop-filter:blur(6px);display:grid;place-items:center;padding:calc(env(safe-area-inset-top) + 12px) 12px calc(env(safe-area-inset-bottom) + 12px);overflow:auto}
.mbox{width:100%;max-width:880px;background:var(--panel);border:1px solid var(--edge);border-radius:14px;padding:12px;position:relative;box-shadow:var(--glow)}
.frame{aspect-ratio:16/9;background:#000;border-radius:10px;overflow:hidden}
.frame iframe{width:100%;height:100%;border:0;display:block}
.mclose{position:absolute;right:10px;top:-14px;z-index:2;width:34px;height:34px;border-radius:50%;border:1px solid var(--ice);background:var(--void);color:var(--ice);font-size:15px;cursor:pointer}
.mtitle{font-weight:700;font-size:16px;margin:12px 2px 2px}
.mmeta{color:var(--dim);font-size:13px;margin:0 2px 10px}
@media (prefers-reduced-motion:reduce){.orb svg,.orb.on::after{animation:none}}
</style>
</head>
<body>
<main>
  <!-- LOGIN -->
  <section id="loginView" class="hidden login">
    <h1>Link Core</h1>
    <p class="sub">Admin access for your YouTube channel.</p>
    <div class="panel">
      <h2>Sign in</h2>
      <input id="pw" type="password" placeholder="Admin password" autocomplete="current-password">
      <div class="row" style="margin-top:12px"><button class="act" id="loginBtn">Unlock panel</button></div>
      <div class="msg err" id="loginMsg"></div>
    </div>
  </section>

  <!-- APP -->
  <section id="appView" class="hidden">
    <div class="top">
      <div><h1>Link Core</h1><p class="sub">YouTube channel connection</p></div>
      <button class="act ghost" id="logoutBtn">Sign out</button>
    </div>

    <div class="panel">
      <div class="core">
        <div class="orb" id="orb">
          <svg viewBox="0 0 100 100" fill="none">
            <circle cx="50" cy="50" r="46" stroke="#1b2a4a" stroke-width="2"/>
            <path d="M50 4a46 46 0 0 1 40 23" stroke="#6ff3ff" stroke-width="3" stroke-linecap="round"/>
            <path d="M50 96a46 46 0 0 1-40-23" stroke="#8a6bff" stroke-width="3" stroke-linecap="round"/>
          </svg>
          <div class="dot" id="avatar">▶</div>
        </div>
        <div>
          <div class="state off" id="stateTxt">Offline</div>
          <div class="meta" id="stateMeta">No channel linked yet.</div>
        </div>
      </div>
      <div class="chips" id="chips"></div>
      <div class="row hidden" id="connectedActions" style="margin-top:16px">
        <button class="act ghost" id="refreshBtn">Re-check session</button>
        <button class="act danger" id="disconnectBtn">Disconnect</button>
      </div>
    </div>

    <div class="panel">
      <h2>Connect your account</h2>
      <div class="tabs" role="tablist">
        <button class="tab" role="tab" aria-selected="true" data-tab="curl">cURL (bash)</button>
        <button class="tab" role="tab" aria-selected="false" data-tab="cookie">Cookie string</button>
      </div>
      <textarea id="input" spellcheck="false" placeholder="curl 'https://www.youtube.com/...' -H 'cookie: SID=...; SAPISID=...'"></textarea>
      <div class="hint" id="hint">
        <ol>
          <li>Open <b>youtube.com</b> while signed in to your channel.</li>
          <li>DevTools → Network → right-click any youtube.com request → Copy → <b>Copy as cURL (bash)</b>.</li>
          <li>Paste it here. The cookie is encrypted before it is stored.</li>
        </ol>
      </div>
      <div class="row"><button class="act" id="connectBtn">Link channel</button></div>
      <div class="msg" id="msg"></div>
    </div>

    <div class="panel hidden" id="videosPanel">
      <h2>Channel videos <span class="mono" style="color:var(--dim);font-size:12px">· admin only</span></h2>
      <div class="tabs" id="vtabs">
        <button class="ftab" data-f="ALL" aria-selected="true">All</button>
        <button class="ftab" data-f="PUBLIC" aria-selected="false">Public</button>
        <button class="ftab" data-f="UNLISTED" aria-selected="false">Unlisted</button>
        <button class="ftab" data-f="PRIVATE" aria-selected="false">Private</button>
      </div>
      <div class="vgrid" id="videoGrid"></div>
      <div class="msg" id="vidMsg"></div>
    </div>
  </section>
</main>

<div class="modal hidden" id="player" role="dialog" aria-modal="true" aria-label="Video player">
  <div class="mbox">
    <button class="mclose" id="mclose" aria-label="Close player">✕</button>
    <div class="frame" id="frame"></div>
    <div class="mtitle" id="mtitle"></div>
    <div class="mmeta" id="mmeta"></div>
    <div class="row" id="mlinks"></div>
    <div class="hint" id="mhint"></div>
  </div>
</div>

<script>
const $ = (id) => document.getElementById(id);
let tab = "curl";

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

function say(text, kind) { const m = $("msg"); m.textContent = text || ""; m.className = "msg " + (kind || ""); }
function show(view) { $("loginView").classList.toggle("hidden", view !== "login"); $("appView").classList.toggle("hidden", view !== "app"); }

function render(s) {
  const on = s.connected;
  $("orb").className = "orb" + (on ? " on" : "");
  $("stateTxt").textContent = on ? "Linked" : "Offline";
  $("stateTxt").className = "state " + (on ? "on" : "off");
  $("connectedActions").classList.toggle("hidden", !on);
  const av = $("avatar");
  if (on && s.profile) {
    $("stateMeta").textContent = (s.profile.name || "Channel") + (s.profile.handle ? "  " + s.profile.handle : "") +
      (s.checkedAt ? "  · checked " + new Date(s.checkedAt).toLocaleString() : "");
    if (s.profile.photo) { av.outerHTML = '<img id="avatar" alt="" referrerpolicy="no-referrer" src="' + s.profile.photo.replace(/"/g, "") + '">'; }
  } else {
    $("stateMeta").textContent = "No channel linked yet.";
    if (av.tagName === "IMG") av.outerHTML = '<div class="dot" id="avatar">▶</div>';
  }
  loadVideos(on);
  $("chips").innerHTML = "";
  (s.cookies || []).slice(0, 14).forEach((n) => {
    const c = document.createElement("span"); c.className = "chip"; c.textContent = n; $("chips").appendChild(c);
  });
}

let allVideos = [], vfilter = "ALL";

function closePlayer() { $("frame").innerHTML = ""; $("player").classList.add("hidden"); }

function showEmbed(v) {
  const f = $("frame"); f.innerHTML = "";
  const ifr = document.createElement("iframe");
  ifr.src = "https://www.youtube.com/embed/" + encodeURIComponent(v.id) + "?autoplay=1&rel=0&playsinline=1";
  ifr.allow = "autoplay; encrypted-media; picture-in-picture; fullscreen";
  ifr.allowFullscreen = true;
  ifr.referrerPolicy = "strict-origin-when-cross-origin";
  ifr.title = v.title;
  f.appendChild(ifr);
}

function openPlayer(v) {
  $("mtitle").textContent = v.title;
  $("mmeta").textContent = [v.privacy, v.views, v.published].filter(Boolean).join(" · ");
  const L = $("mlinks"); L.innerHTML = "";
  const css = "text-decoration:none;display:inline-block;font:600 14px Chakra Petch,sans-serif;padding:9px 16px;border:1px solid var(--edge);border-radius:10px;color:var(--text)";
  [["Watch on YouTube", "https://www.youtube.com/watch?v=" + encodeURIComponent(v.id)],
   ["Open in Studio", "https://studio.youtube.com/video/" + encodeURIComponent(v.id) + "/edit"]].forEach((x) => {
    const a = document.createElement("a");
    a.textContent = x[0]; a.href = x[1]; a.target = "_blank"; a.rel = "noopener noreferrer"; a.style.cssText = css;
    L.appendChild(a);
  });
  $("mhint").textContent = v.privacy === "PUBLIC" ? "" :
    "Plays directly from YouTube. Private and unlisted videos need this browser to be signed in to the channel owner's Google account.";
  showEmbed(v);
  $("player").classList.remove("hidden");
}

function renderVideos() {
  const grid = $("videoGrid"); grid.innerHTML = "";
  const vs = allVideos.filter((v) => vfilter === "ALL" || v.privacy === vfilter);
  if (!vs.length) { grid.innerHTML = ""; }
  vs.forEach((v) => {
    const card = document.createElement("div");
    card.className = "vid"; card.tabIndex = 0; card.setAttribute("role", "button");
    const th = document.createElement("div"); th.className = "th";
    if (/^https:/.test(v.thumb || "")) {
      const img = document.createElement("img");
      img.loading = "lazy"; img.alt = ""; img.referrerPolicy = "no-referrer"; img.src = v.thumb;
      th.appendChild(img);
    }
    const bd = document.createElement("span"); bd.className = "badge " + v.privacy; bd.textContent = v.privacy; th.appendChild(bd);
    if (v.length) { const l = document.createElement("span"); l.className = "len"; l.textContent = v.length; th.appendChild(l); }
    const tt = document.createElement("div"); tt.className = "tt"; tt.textContent = v.title;
    const mm = document.createElement("div"); mm.className = "mm";
    mm.textContent = [v.views, v.published].filter(Boolean).join(" · ");
    card.append(th, tt, mm);
    card.onclick = () => openPlayer(v);
    card.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openPlayer(v); } };
    grid.appendChild(card);
  });
}

async function loadVideos(on) {
  const panel = $("videosPanel"), m = $("vidMsg");
  panel.classList.toggle("hidden", !on);
  if (!on) { allVideos = []; $("videoGrid").innerHTML = ""; return; }
  m.textContent = "Loading channel videos…"; m.className = "msg";
  const r = await api("/api/videos");
  if (r.status !== 200) { $("videoGrid").innerHTML = ""; m.textContent = r.data.error || "Could not load videos."; m.className = "msg err"; return; }
  allVideos = r.data.videos || [];
  renderVideos();
  if (!allVideos.length) m.textContent = "No videos found on this channel.";
  else if (r.data.source === "public") { m.textContent = "Showing public videos only" + (r.data.note ? " (" + r.data.note + ")" : "") + "."; m.className = "msg"; }
  else m.textContent = "";
}

document.querySelectorAll(".ftab").forEach((b) => b.onclick = () => {
  vfilter = b.dataset.f;
  document.querySelectorAll(".ftab").forEach((x) => x.setAttribute("aria-selected", x === b));
  renderVideos();
});
$("mclose").onclick = closePlayer;
$("player").addEventListener("click", (e) => { if (e.target === $("player")) closePlayer(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePlayer(); });

async function boot() {
  const r = await api("/api/status");
  if (r.status === 401) return show("login");
  show("app"); render(r.data);
}

$("loginBtn").onclick = async () => {
  const r = await api("/api/login", { password: $("pw").value });
  if (r.status === 200) { $("pw").value = ""; boot(); } else $("loginMsg").textContent = "Wrong password.";
};
$("pw").addEventListener("keydown", (e) => { if (e.key === "Enter") $("loginBtn").click(); });
$("logoutBtn").onclick = async () => { await api("/api/logout", {}); show("login"); };

document.querySelectorAll(".tab").forEach((b) => b.onclick = () => {
  tab = b.dataset.tab;
  document.querySelectorAll(".tab").forEach((x) => x.setAttribute("aria-selected", x === b));
  $("input").placeholder = tab === "curl"
    ? "curl 'https://www.youtube.com/...' -H 'cookie: SID=...; SAPISID=...'"
    : "SID=...; HSID=...; SSID=...; SAPISID=...; __Secure-3PAPISID=...";
  $("hint").classList.toggle("hidden", tab !== "curl");
});

$("connectBtn").onclick = async () => {
  const btn = $("connectBtn"); btn.disabled = true; say("Verifying session with YouTube…");
  const r = await api("/api/connect", { input: $("input").value });
  btn.disabled = false;
  if (r.status === 200) { $("input").value = ""; say("Channel linked: " + r.data.profile.name, "ok"); boot(); }
  else say(r.data.error || "Connection failed.", "err");
};

$("refreshBtn").onclick = async () => {
  say("Re-checking session…");
  const r = await api("/api/refresh", {});
  if (r.status === 200) { say("Session is still valid.", "ok"); boot(); } else say(r.data.error || "Check failed.", "err");
};

$("disconnectBtn").onclick = async () => {
  if (!confirm("Remove the stored session?")) return;
  await api("/api/disconnect", {}); say("Disconnected and cookie deleted.", "ok"); boot();
};

boot();
</script>
</body>
</html>`;


/* ───────────── public site section ───────────── */
const SITE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>Link Core</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;700&display=swap" rel="stylesheet">
<style>
:root{--void:#05070f;--edge:#1b2a4a;--ice:#6ff3ff;--violet:#8a6bff;--text:#dfe8ff;--dim:#7d8db5;--ok:#5dffb0;--bad:#ff4d7d}
*{box-sizing:border-box;margin:0}
html,body{height:100%}
body{
  background:var(--void);color:var(--text);font:15px/1.5 "Chakra Petch",system-ui,sans-serif;
  display:grid;place-items:center;overflow:hidden;
  padding:env(safe-area-inset-top) 16px env(safe-area-inset-bottom);
  background-image:
    radial-gradient(900px 500px at 85% -10%,rgba(138,107,255,.18),transparent 60%),
    radial-gradient(700px 500px at -10% 110%,rgba(111,243,255,.12),transparent 60%),
    linear-gradient(rgba(111,243,255,.04) 1px,transparent 1px),
    linear-gradient(90deg,rgba(111,243,255,.04) 1px,transparent 1px);
  background-size:auto,auto,36px 36px,36px 36px;
}
.wrap{text-align:center}
.core{--c:var(--ice);position:relative;width:220px;height:220px;margin:0 auto;display:grid;place-items:center}
.core.ok{--c:var(--ok)} .core.fail{--c:var(--bad)}
.ring{position:absolute;inset:0;animation:spin 16s linear infinite;transition:filter .4s}
.ring2{position:absolute;inset:18px;animation:spin 9s linear infinite reverse;opacity:.7}
.core.scanning .ring{animation-duration:1.2s}
.core.scanning .ring2{animation-duration:.9s}
.core.ok .ring,.core.ok .ring2{animation-duration:5s}
.ring circle,.ring path,.ring2 circle{stroke:var(--c);transition:stroke .4s}
.core.ok .ring{filter:drop-shadow(0 0 10px rgba(93,255,176,.8))}
.core.fail .ring{filter:drop-shadow(0 0 8px rgba(255,77,125,.7))}
@keyframes spin{to{transform:rotate(360deg)}}
button.go{
  position:relative;width:132px;height:132px;border-radius:50%;cursor:pointer;
  border:1px solid var(--c);color:var(--c);background:radial-gradient(circle at 50% 35%,rgba(111,243,255,.14),rgba(5,7,15,.9) 70%);
  font:700 13px "Chakra Petch",sans-serif;letter-spacing:.22em;
  box-shadow:0 0 28px color-mix(in srgb,var(--c) 35%,transparent),inset 0 0 22px color-mix(in srgb,var(--c) 18%,transparent);
  transition:transform .15s,box-shadow .4s,border-color .4s,color .4s;overflow:hidden;
}
button.go:hover{transform:scale(1.04)}
button.go:active{transform:scale(.97)}
button.go:disabled{cursor:default;transform:none}
.core.scanning button.go::after{
  content:"";position:absolute;left:0;right:0;height:30%;top:-30%;
  background:linear-gradient(180deg,transparent,rgba(111,243,255,.45),transparent);animation:sweep .9s linear infinite;
}
@keyframes sweep{to{top:100%}}
.core.fail button.go{animation:shake .45s}
@keyframes shake{20%{transform:translateX(-7px)}40%{transform:translateX(6px)}60%{transform:translateX(-4px)}80%{transform:translateX(3px)}}
.core.ok button.go{box-shadow:0 0 46px rgba(93,255,176,.55),inset 0 0 30px rgba(93,255,176,.28)}
.tick{position:absolute;width:58px;height:58px;pointer-events:none;opacity:0}
.tick path{fill:none;stroke:var(--ok);stroke-width:5;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:60;stroke-dashoffset:60}
.core.ok .tick{opacity:1}
.core.ok .tick path{animation:draw .6s .15s ease-out forwards;filter:drop-shadow(0 0 6px var(--ok))}
@keyframes draw{to{stroke-dashoffset:0}}
.core.ok .lbl{opacity:0}
.wave{position:absolute;inset:44px;border-radius:50%;border:2px solid var(--ok);opacity:0;pointer-events:none}
.core.ok .wave{animation:wave 1.6s ease-out 3}
.core.ok .wave:nth-of-type(2){animation-delay:.25s}
.core.ok .wave:nth-of-type(3){animation-delay:.5s}
@keyframes wave{0%{transform:scale(.7);opacity:.9}100%{transform:scale(2.3);opacity:0}}
.spark{position:absolute;left:50%;top:50%;width:4px;height:4px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);opacity:0;pointer-events:none;animation:burst 1.1s ease-out forwards}
@keyframes burst{0%{opacity:1;transform:translate(-50%,-50%)}100%{opacity:0;transform:translate(calc(-50% + var(--x)),calc(-50% + var(--y)))}}
.status{margin-top:26px;font-weight:700;font-size:18px;letter-spacing:.3em;min-height:28px;color:var(--dim);transition:color .3s,text-shadow .3s}
.status.ok{color:var(--ok);text-shadow:0 0 16px rgba(93,255,176,.6)}
.status.fail{color:var(--bad)}
.status.scan{color:var(--ice)}
@media (prefers-reduced-motion:reduce){.ring,.ring2,.wave,.core.scanning button.go::after{animation:none!important}}
</style>
</head>
<body>
<div class="wrap">
  <div class="core" id="core">
    <svg class="ring" viewBox="0 0 100 100" fill="none"><circle cx="50" cy="50" r="47" stroke-width="1" stroke-dasharray="2 4"/><path d="M50 3a47 47 0 0 1 40.7 23.5" stroke-width="2.5" stroke-linecap="round"/><path d="M50 97a47 47 0 0 1-40.7-23.5" stroke-width="2.5" stroke-linecap="round"/></svg>
    <svg class="ring2" viewBox="0 0 100 100" fill="none"><circle cx="50" cy="50" r="46" stroke-width="1" stroke-dasharray="14 10"/></svg>
    <span class="wave"></span><span class="wave"></span><span class="wave"></span>
    <button class="go" id="go" aria-label="Connect"><span class="lbl" id="lbl">CONNECT</span></button>
    <svg class="tick" viewBox="0 0 60 60"><path d="M14 31l11 11 21-23"/></svg>
  </div>
  <div class="status" id="status" role="status" aria-live="polite"></div>
</div>
<script>
const $ = (id) => document.getElementById(id);
const core = $("core"), go = $("go"), lbl = $("lbl"), st = $("status");

function sparks() {
  for (let i = 0; i < 26; i++) {
    const s = document.createElement("span");
    const a = Math.random() * Math.PI * 2, d = 90 + Math.random() * 70;
    s.className = "spark";
    s.style.setProperty("--x", Math.cos(a) * d + "px");
    s.style.setProperty("--y", Math.sin(a) * d + "px");
    core.appendChild(s);
    setTimeout(() => s.remove(), 1200);
  }
}

go.onclick = async () => {
  go.disabled = true;
  core.className = "core scanning"; lbl.textContent = "LINKING";
  st.className = "status scan"; st.textContent = "SCANNING";
  const t0 = Date.now();
  let ok = false;
  try {
    const r = await fetch("/api/public-status", { cache: "no-store" });
    ok = !!(await r.json()).connected;
  } catch (e) {}
  await new Promise((r) => setTimeout(r, Math.max(0, 1800 - (Date.now() - t0))));
  if (ok) {
    core.className = "core ok"; st.className = "status ok"; st.textContent = "CONNECTED";
    sparks();
  } else {
    core.className = "core fail"; lbl.textContent = "RETRY";
    st.className = "status fail"; st.textContent = "OFFLINE";
  }
  go.disabled = false;
};
</script>
</body>
</html>`;

/* ───────────── entry ───────────── */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url.pathname);
      } catch (e) {
        return json({ error: "Server error" }, 500);
      }
    }

    const isAdmin = url.pathname === "/admin" || url.pathname === "/admin/";
    return new Response(isAdmin ? PAGE : SITE, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-frame-options": "DENY",
        "referrer-policy": isAdmin ? "strict-origin-when-cross-origin" : "no-referrer",
      },
    });
  },
};
