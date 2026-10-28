/**
 * Link Core — Cloudflare Worker admin panel
 *
 * Bindings / secrets required:
 *   KV namespace  : LINK_STORE
 *   Secrets       : ADMIN_PASSWORD, SESSION_SECRET, ENCRYPTION_KEY
 *
 * Setup:
 *   npx wrangler kv namespace create LINK_STORE
 *   npx wrangler secret put ADMIN_PASSWORD
 *   npx wrangler secret put SESSION_SECRET     (any long random string)
 *   npx wrangler secret put ENCRYPTION_KEY     (any long random string)
 *   npx wrangler deploy
 */

const enc = new TextEncoder();
const dec = new TextDecoder();
const SESSION_TTL = 60 * 60 * 12; // 12h
const STORE_KEY = "fb:connection";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

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
    if (k && !/[^\x20-\x7e]/.test(v)) pairs[k] = v;
  }
  return Object.keys(pairs).length ? pairs : null;
}

const toHeader = (pairs) => Object.entries(pairs).map(([k, v]) => k + "=" + v).join("; ");

/* ───────────── Facebook session check ───────────── */
const FB_ORIGIN = "https://www.facebook.com";

// Verifies the cookies by loading the signed-in home page. Facebook's markup changes
// often, so the account name is best-effort; the id comes from the c_user cookie.
async function checkFacebook(pairs) {
  if (!pairs["c_user"] || !pairs["xs"]) {
    return { ok: false, error: "Missing c_user or xs cookie. Copy the request from a logged-in facebook.com tab." };
  }

  let res;
  try {
    res = await fetch(FB_ORIGIN + "/", {
      headers: {
        cookie: toHeader(pairs),
        "user-agent": UA,
        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "max-age=0",
        "upgrade-insecure-requests": "1",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
      },
      redirect: "follow",
    });
  } catch (e) {
    return { ok: false, error: "Could not reach Facebook (network error from the Worker)." };
  }

  const finalPath = new URL(res.url).pathname;
  if (!res.ok) {
    return { ok: false, error: "Facebook rejected the session (HTTP " + res.status + " at " + finalPath + ")." };
  }

  const html = await res.text();

  if (finalPath.startsWith("/checkpoint") || /id="checkpointSubmitButton"/.test(html)) {
    return {
      ok: false,
      error: "Facebook put this session into a checkpoint (identity/verification challenge) instead of logging it in — " +
        "likely because the request came from the Worker's IP rather than your browser. Open facebook.com in a normal " +
        "browser with these exact cookies, clear the checkpoint there, then try connecting again.",
    };
  }
  if (finalPath.startsWith("/login") || /id="login_form"/.test(html)) {
    return { ok: false, error: "Session not logged in (landed on " + finalPath + "). Cookie is expired or incomplete." };
  }

  let name = null;
  const m = html.match(/"NAME":"((?:[^"\\]|\\.)+)"/);
  if (m) {
    try { name = JSON.parse('"' + m[1] + '"'); } catch (e) { name = null; }
  }
  return { ok: true, id: pairs["c_user"], name: name || "Facebook user " + pairs["c_user"] };
}

/* ───────────── API ───────────── */
async function getConn(env) {
  if (!env.LINK_STORE) throw new Error("KV binding LINK_STORE is missing. Add it in wrangler.toml or Settings > Bindings, then redeploy.");
  const raw = await env.LINK_STORE.get(STORE_KEY);
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

  if (path === "/api/connect") {
    const { input } = await request.json().catch(() => ({}));
    if (!input || input.length > 100_000) return json({ error: "Paste a curl command or cookie string." }, 400);
    const pairs = extractCookie(input);
    if (!pairs) return json({ error: "No cookies found in the pasted text." }, 400);

    const result = await checkFacebook(pairs);
    if (!result.ok) return json({ error: result.error }, 400);

    const now = new Date().toISOString();
    await env.LINK_STORE.put(
      STORE_KEY,
      JSON.stringify({
        cipher: await encrypt(env, JSON.stringify(pairs)),
        names: Object.keys(pairs),
        profile: { id: result.id, name: result.name },
        connectedAt: now,
        checkedAt: now,
      })
    );
    return json({ ok: true, profile: { id: result.id, name: result.name } });
  }

  if (path === "/api/refresh") {
    const c = await getConn(env);
    if (!c) return json({ error: "Not connected" }, 400);
    const pairs = JSON.parse(await decrypt(env, c.cipher));
    const result = await checkFacebook(pairs);
    if (!result.ok) return json({ error: result.error, expired: true }, 400);
    c.profile = { id: result.id, name: result.name };
    c.checkedAt = new Date().toISOString();
    await env.LINK_STORE.put(STORE_KEY, JSON.stringify(c));
    return json({ ok: true, profile: c.profile });
  }

  if (path === "/api/disconnect") {
    await env.LINK_STORE.delete(STORE_KEY);
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
<title>Link Core · Admin</title>
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
.orb .dot{width:52px;height:52px;border-radius:50%;object-fit:cover;background:#10182e;border:1px solid var(--edge);display:grid;place-items:center;color:var(--dim);font-size:20px;font-weight:700}
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
@media (prefers-reduced-motion:reduce){.orb svg,.orb.on::after{animation:none}}
</style>
</head>
<body>
<main>
  <!-- LOGIN -->
  <section id="loginView" class="hidden login">
    <h1>Link Core</h1>
    <p class="sub">Admin access for your Facebook connection.</p>
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
      <div><h1>Link Core</h1><p class="sub">Facebook account connection</p></div>
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
          <div class="dot" id="avatar">●</div>
        </div>
        <div>
          <div class="state off" id="stateTxt">Offline</div>
          <div class="meta" id="stateMeta">No account linked yet.</div>
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
      <textarea id="input" spellcheck="false" placeholder="curl 'https://www.facebook.com/' -H 'cookie: c_user=...; xs=...'"></textarea>
      <div class="hint" id="hint">
        <ol>
          <li>Open <b>facebook.com</b> while signed in to your account.</li>
          <li>DevTools → Network → right-click any facebook.com request → Copy → <b>Copy as cURL (bash)</b>.</li>
          <li>Paste it here. The cookie is encrypted before it is stored.</li>
        </ol>
      </div>
      <div class="row"><button class="act" id="connectBtn">Link account</button></div>
      <div class="msg" id="msg"></div>
    </div>
  </section>
</main>

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
  $("avatar").textContent = on && s.profile && s.profile.name ? s.profile.name.trim()[0].toUpperCase() : "●";
  if (on && s.profile) {
    $("stateMeta").textContent = (s.profile.name || "Account") +
      (s.checkedAt ? "  · checked " + new Date(s.checkedAt).toLocaleString() : "");
  } else {
    $("stateMeta").textContent = "No account linked yet.";
  }
  $("chips").innerHTML = "";
  (s.cookies || []).slice(0, 14).forEach((n) => {
    const c = document.createElement("span"); c.className = "chip"; c.textContent = n; $("chips").appendChild(c);
  });
}

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
    ? "curl 'https://www.facebook.com/' -H 'cookie: c_user=...; xs=...'"
    : "c_user=...; xs=...; datr=...";
  $("hint").classList.toggle("hidden", tab !== "curl");
});

$("connectBtn").onclick = async () => {
  const btn = $("connectBtn"); btn.disabled = true; say("Verifying session with Facebook…");
  const r = await api("/api/connect", { input: $("input").value });
  btn.disabled = false;
  if (r.status === 200) { $("input").value = ""; say("Account linked: " + r.data.profile.name, "ok"); boot(); }
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
        // Show the real reason only to a signed-in admin.
        const detail = (await isAuthed(request, env).catch(() => false)) ? ": " + String((e && e.message) || e).slice(0, 200) : "";
        return json({ error: "Server error" + detail }, 500);
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
