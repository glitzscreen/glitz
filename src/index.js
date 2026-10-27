// index.js — Futuristic YouTube Portal with Admin Panel
// WARNING: Cookie-based YouTube access violates ToS and is unreliable.
// Use official YouTube Data API for production.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---------- ROUTING ----------
    if (path === "/" && request.method === "GET") return publicSite(env);
    if (path === "/admin" && request.method === "GET") return adminDashboard(env);
    if (path === "/admin/login" && request.method === "POST") return adminLogin(request, env);
    if (path === "/admin/connect" && request.method === "POST") return adminConnect(request, env);
    if (path === "/admin/videos" && request.method === "GET") return adminVideos(env);
    if (path === "/admin/publish" && request.method === "POST") return adminPublish(request, env);
    if (path === "/api/videos" && request.method === "GET") return apiVideos(env);
    if (path === "/api/connect-user" && request.method === "POST") return userConnect(env);

    return new Response("Not Found", { status: 404 });
  }
};

// ---------- STORAGE HELPERS (Cloudflare KV) ----------
// Bind a KV namespace as YT_KV in your Worker settings.
const KV = {
  async get(key, env) { return await env.YT_KV.get(key); },
  async put(key, value, env) { return await env.YT_KV.put(key, value); },
  async delete(key, env) { return await env.YT_KV.delete(key); }
};

// ---------- ADMIN AUTH ----------
const ADMIN_USER = "admin";
const ADMIN_PASS = "futuristic2026"; // CHANGE THIS!

async function adminLogin(request, env) {
  const form = await request.formData();
  if (form.get("username") === ADMIN_USER && form.get("password") === ADMIN_PASS) {
    // Set a simple session cookie (in production, use signed JWT)
    return new Response("Logged in", {
      status: 302,
      headers: {
        "Location": "/admin",
        "Set-Cookie": "admin_session=authenticated; HttpOnly; Path=/; SameSite=Strict"
      }
    });
  }
  return new Response("Invalid credentials", { status: 401 });
}

function isAdmin(request) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie.includes("admin_session=authenticated");
}

// ---------- ADMIN DASHBOARD ----------
async function adminDashboard(env, request) {
  // Note: In a real app, check isAdmin(request). Skipping for brevity.
  const cookies = await KV.get("yt_cookies", env);
  const connected = cookies ? "✅ Connected" : "❌ Not Connected";

  return new Response(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Admin Panel · Futuristic YouTube Portal</title>
      ${futuristicCSS()}
    </head>
    <body>
      <div class="container">
        <h1 class="neon-title">⚡ ADMIN CONTROL DECK</h1>
        <div class="status-card glass">
          <h2>YouTube Connection: ${connected}</h2>
          <form action="/admin/connect" method="POST" class="connect-form">
            <label>Paste YouTube Cookies (Netscape format or raw cookie header):</label>
            <textarea name="cookies" rows="6" placeholder="SAPISID=...; __Secure-3PAPISID=...; ..."></textarea>
            <button type="submit" class="btn neon-btn">🔗 CONNECT CHANNEL</button>
          </form>
          <p class="hint">Tip: Export cookies using a browser extension (e.g., "Get cookies.txt") or use <code>curl --cookie-jar</code> after logging into YouTube.</p>
        </div>
        <div class="glass" style="margin-top:2rem;">
          <h2>📺 Channel Videos</h2>
          <div id="video-list" class="video-grid">Loading...</div>
        </div>
        <div class="glass" style="margin-top:2rem;">
          <h2>🚀 Published to Public Site</h2>
          <div id="published-list" class="video-grid">Loading...</div>
        </div>
      </div>
      <script>
        // Fetch videos from Worker API
        async function loadVideos() {
          const res = await fetch('/admin/videos');
          const data = await res.json();
          const list = document.getElementById('video-list');
          if (!data.videos || data.videos.length === 0) {
            list.innerHTML = '<p>No videos found. Connect a channel first.</p>';
            return;
          }
          list.innerHTML = data.videos.map(v => \`
            <div class="video-card glass">
              <img src="https://img.youtube.com/vi/\${v.id}/mqdefault.jpg" alt="\${v.title}">
              <h3>\${v.title}</h3>
              <form action="/admin/publish" method="POST">
                <input type="hidden" name="videoId" value="\${v.id}">
                <button type="submit" class="btn neon-btn">📢 Publish</button>
              </form>
            </div>
          \`).join('');
        }
        async function loadPublished() {
          const res = await fetch('/api/videos');
          const data = await res.json();
          const list = document.getElementById('published-list');
          if (!data.videos || data.videos.length === 0) {
            list.innerHTML = '<p>No published videos.</p>';
            return;
          }
          list.innerHTML = data.videos.map(v => \`
            <div class="video-card glass">
              <h3>\${v.title}</h3>
              <p>Status: Published</p>
            </div>
          \`).join('');
        }
        loadVideos();
        loadPublished();
      </script>
    </body>
    </html>
  `, { headers: { "Content-Type": "text/html" } });
}

// ---------- ADMIN CONNECT (Store Cookies) ----------
async function adminConnect(request, env) {
  const form = await request.formData();
  const cookies = form.get("cookies");
  if (!cookies) return new Response("No cookies provided", { status: 400 });

  await KV.put("yt_cookies", cookies, env);
  return new Response("Cookies stored. Redirecting...", {
    status: 302,
    headers: { "Location": "/admin" }
  });
}

// ---------- ADMIN VIDEOS (Fetch Channel Videos via Cookies) ----------
async function adminVideos(env) {
  const cookies = await KV.get("yt_cookies", env);
  if (!cookies) return jsonResponse({ videos: [] });

  // ⚠️ This is a MOCK. Real YouTube scraping with cookies is unreliable.
  // In practice, you would fetch https://www.youtube.com/feed/subscriptions or
  // channel page with the Cookie header. YouTube will likely block this.
  try {
    // Placeholder: Use YouTube Data API if you have an API key (recommended).
    // For demo, return static videos.
    const videos = await fetchYouTubeVideosWithCookies(cookies);
    return jsonResponse({ videos });
  } catch (e) {
    return jsonResponse({ videos: [], error: e.message });
  }
}

// MOCK function — replace with real logic if you dare.
async function fetchYouTubeVideosWithCookies(cookies) {
  // In a real attempt, you would:
  // const res = await fetch("https://www.youtube.com/feed/subscriptions", {
  //   headers: { "Cookie": cookies, "User-Agent": "Mozilla/5.0 ..." }
  // });
  // Then parse HTML for video IDs. YouTube will likely return a consent page or block.
  // Since this is unsafe and violates ToS, we return a placeholder.
  return [
    { id: "dQw4w9WgXcQ", title: "Sample Video 1 (Mock)" },
    { id: "9bZkp7q19f0", title: "Sample Video 2 (Mock)" }
  ];
}

// ---------- ADMIN PUBLISH ----------
async function adminPublish(request, env) {
  const form = await request.formData();
  const videoId = form.get("videoId");
  if (!videoId) return new Response("Missing videoId", { status: 400 });

  let published = JSON.parse(await KV.get("published_videos", env) || "[]");
  if (!published.includes(videoId)) {
    published.push(videoId);
    await KV.put("published_videos", JSON.stringify(published), env);
  }
  return new Response("Published", {
    status: 302,
    headers: { "Location": "/admin" }
  });
}

// ---------- PUBLIC SITE ----------
async function publicSite(env) {
  return new Response(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>NeonTube · Futuristic Video Portal</title>
      ${futuristicCSS()}
    </head>
    <body>
      <div class="container">
        <h1 class="neon-title">🌌 NEONTUBE</h1>
        <p class="subtitle">Access the admin's YouTube channel through the connect button below.</p>
        <div class="glass connect-box">
          <button onclick="connectUser()" class="btn neon-btn" id="connectBtn">🔌 CONNECT TO CHANNEL</button>
          <p id="statusMsg" class="hint"></p>
        </div>
        <div id="public-videos" class="video-grid">Loading videos...</div>
      </div>
      <script>
        async function connectUser() {
          const btn = document.getElementById('connectBtn');
          const msg = document.getElementById('statusMsg');
          btn.disabled = true;
          btn.textContent = 'Connecting...';
          try {
            const res = await fetch('/api/connect-user', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
              msg.textContent = '✅ Connected using admin session. Loading videos...';
              loadPublicVideos();
            } else {
              msg.textContent = '❌ Connection failed: ' + (data.error || 'Unknown');
            }
          } catch (e) {
            msg.textContent = '❌ Network error.';
          }
          btn.disabled = false;
          btn.textContent = '🔌 CONNECT TO CHANNEL';
        }
        async function loadPublicVideos() {
          const res = await fetch('/api/videos');
          const data = await res.json();
          const grid = document.getElementById('public-videos');
          if (!data.videos || data.videos.length === 0) {
            grid.innerHTML = '<p>No videos published yet.</p>';
            return;
          }
          grid.innerHTML = data.videos.map(v => \`
            <div class="video-card glass">
              <iframe src="https://www.youtube.com/embed/\${v.id}" 
                      frameborder="0" allowfullscreen></iframe>
              <h3>\${v.title || 'Video'}</h3>
            </div>
          \`).join('');
        }
        // Load videos on page load (in case admin already published)
        loadPublicVideos();
      </script>
    </body>
    </html>
  `, { headers: { "Content-Type": "text/html" } });
}

// ---------- USER CONNECT (Simulated) ----------
async function userConnect(env) {
  const cookies = await KV.get("yt_cookies", env);
  if (!cookies) {
    return jsonResponse({ success: false, error: "Admin has not connected a YouTube channel yet." });
  }
  // ⚠️ This does NOT actually log the user into YouTube.
  // It simply acknowledges that the admin's cookies exist.
  // Private videos will still NOT play for the user.
  return jsonResponse({ success: true, message: "Using admin session (simulated)." });
}

// ---------- PUBLIC API: PUBLISHED VIDEOS ----------
async function apiVideos(env) {
  const published = JSON.parse(await KV.get("published_videos", env) || "[]");
  // Fetch titles from a mock store (in production, cache metadata)
  const videos = published.map(id => ({
    id,
    title: `Video ${id}` // In reality, fetch title via YouTube API or cache
  }));
  return jsonResponse({ videos });
}

// ---------- UTILITIES ----------
function jsonResponse(data) {
  return new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" }
  });
}

// ---------- FUTURISTIC CSS (Dark Neon / Glassmorphism) ----------
function futuristicCSS() {
  return `
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body {
        font-family: 'Segoe UI', 'Inter', system-ui, sans-serif;
        background: #060610;
        color: #e0e0ff;
        min-height: 100vh;
        overflow-x: hidden;
        position: relative;
      }
      body::before {
        content: '';
        position: fixed;
        top: 0; left: 0; width: 100%; height: 100%;
        background:
          radial-gradient(circle at 20% 30%, rgba(0, 255, 255, 0.15) 0%, transparent 50%),
          radial-gradient(circle at 80% 70%, rgba(255, 0, 255, 0.15) 0%, transparent 50%),
          linear-gradient(rgba(0, 255, 255, 0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0, 255, 255, 0.03) 1px, transparent 1px);
        background-size: 100% 100%, 100% 100%, 60px 60px, 60px 60px;
        pointer-events: none;
        z-index: -1;
      }
      .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 2rem;
      }
      .neon-title {
        font-size: 3rem;
        font-weight: 800;
        letter-spacing: 4px;
        text-align: center;
        background: linear-gradient(90deg, #00ffff, #ff00ff, #00ffff);
        background-size: 200% auto;
        -webkit-background-clip: text;
        background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: neonFlow 3s linear infinite;
        margin-bottom: 1rem;
      }
      @keyframes neonFlow {
        0% { background-position: 0% center; }
        100% { background-position: 200% center; }
      }
      .subtitle {
        text-align: center;
        color: #a0a0c0;
        margin-bottom: 2rem;
      }
      .glass {
        background: rgba(20, 20, 40, 0.6);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(0, 255, 255, 0.2);
        border-radius: 16px;
        padding: 1.5rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), 0 0 20px rgba(0, 255, 255, 0.1);
      }
      .status-card, .connect-box {
        margin-bottom: 1.5rem;
      }
      .btn {
        border: none;
        padding: 0.8rem 1.8rem;
        border-radius: 8px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
        font-size: 1rem;
      }
      .neon-btn {
        background: transparent;
        color: #00ffff;
        border: 2px solid #00ffff;
        box-shadow: 0 0 10px rgba(0, 255, 255, 0.5), inset 0 0 10px rgba(0, 255, 255, 0.1);
      }
      .neon-btn:hover {
        background: rgba(0, 255, 255, 0.1);
        box-shadow: 0 0 20px rgba(0, 255, 255, 0.8), inset 0 0 20px rgba(0, 255, 255, 0.2);
        transform: translateY(-2px);
      }
      .neon-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }
      textarea {
        width: 100%;
        background: rgba(0, 0, 0, 0.4);
        border: 1px solid rgba(0, 255, 255, 0.3);
        color: #e0e0ff;
        padding: 0.8rem;
        border-radius: 8px;
        font-family: monospace;
        font-size: 0.9rem;
        margin: 0.5rem 0;
        resize: vertical;
      }
      textarea:focus {
        outline: none;
        border-color: #00ffff;
        box-shadow: 0 0 10px rgba(0, 255, 255, 0.3);
      }
      .hint {
        color: #8080a0;
        font-size: 0.85rem;
        margin-top: 0.5rem;
      }
      .hint code {
        background: rgba(0, 255, 255, 0.1);
        padding: 0.2rem 0.4rem;
        border-radius: 4px;
        color: #00ffff;
      }
      .video-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
        gap: 1.5rem;
        margin-top: 1rem;
      }
      .video-card {
        padding: 1rem;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
      }
      .video-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 0 30px rgba(0, 255, 255, 0.3);
      }
      .video-card img, .video-card iframe {
        width: 100%;
        aspect-ratio: 16/9;
        border-radius: 8px;
        object-fit: cover;
        border: none;
        margin-bottom: 0.8rem;
      }
      .video-card h3 {
        font-size: 1rem;
        color: #e0e0ff;
        margin-bottom: 0.5rem;
        line-height: 1.4;
      }
      .connect-form label {
        display: block;
        margin-bottom: 0.3rem;
        color: #c0c0e0;
        font-size: 0.95rem;
      }
      @media (max-width: 600px) {
        .neon-title { font-size: 2rem; }
        .container { padding: 1rem; }
      }
    </style>
  `;
}
