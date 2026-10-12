const express = require("express");
const crypto = require("crypto");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json({ limit: "64kb" }));

const UPSTREAM_HOME = "https://ssosint.vercel.app/";
const UPSTREAM_API = "https://ssosint.vercel.app/?api=1";

// Cached upstream token (valid for its short lifetime).
let cachedToken = null;

// ======================================================
// Issued API keys store
// ======================================================
//
// Persistence on Render: the filesystem is ephemeral, so
// 1) set KEYS_FILE to a path on a persistent disk if you have one, and/or
// 2) seed durable keys via ISSUED_KEYS_JSON env (they are re-imported
//    on every boot). Without either, keys live in memory only.
//
const KEYS_FILE = process.env.KEYS_FILE || "";
const issuedKeys = new Map(); // id -> record

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function keyHash(k) {
  return crypto.createHash("sha256").update(String(k)).digest("hex");
}

function newId() {
  return crypto.randomBytes(8).toString("hex");
}

function newPlainKey() {
  return "sk_" + crypto.randomBytes(24).toString("base64url");
}

// Total is the hard ceiling: a daily limit higher than the total
// (or "unlimited daily" alongside a capped total) is clamped down
// so daily usage can never overshoot the total.
function clampDaily(maxTotal, maxDaily) {
  if (maxTotal > 0 && (maxDaily === 0 || maxDaily > maxTotal)) {
    return maxTotal;
  }
  return maxDaily;
}

function sanitizeRecord(rec) {
  return {
    id: rec.id,
    name: rec.name,
    prefix: rec.prefix,
    createdAt: rec.createdAt,
    expiresAt: rec.expiresAt,
    maxTotal: rec.maxTotal,
    maxDaily: rec.maxDaily,
    usedTotal: rec.usedTotal,
    usedToday: rec.usedDaily[todayStr()] || 0,
    numbers: rec.numbers,
    enabled: rec.enabled,
    lastUsedAt: rec.lastUsedAt
  };
}

function persistKeys() {
  if (!KEYS_FILE) return;
  try {
    fs.writeFileSync(
      KEYS_FILE,
      JSON.stringify([...issuedKeys.values()], null, 2)
    );
  } catch (e) {
    console.error("Failed to persist keys:", e.message);
  }
}

function importRecord(obj) {
  // Used by file load + env seed. Plaintext `key` is hashed, never stored.
  const plain = obj.key || newPlainKey();
  const h = keyHash(plain);
  for (const rec of issuedKeys.values()) {
    if (rec.keyHash === h) return { record: rec, created: false };
  }
  const rec = {
    id: obj.id || newId(),
    name: String(obj.name || "unnamed"),
    keyHash: h,
    prefix: plain.slice(0, 7),
    createdAt: obj.createdAt || new Date().toISOString(),
    expiresAt: obj.expiresAt || null,
    maxTotal: Math.max(0, Number(obj.maxTotal || 0)),
    // Daily can never exceed total: total is the hard ceiling.
    maxDaily: clampDaily(Math.max(0, Number(obj.maxTotal || 0)), Math.max(0, Number(obj.maxDaily || 0))),
    usedTotal: Number(obj.usedTotal || 0),
    usedDaily: obj.usedDaily && typeof obj.usedDaily === "object" ? obj.usedDaily : {},
    numbers: Array.isArray(obj.numbers)
      ? obj.numbers.map(String)
      : String(obj.numbers || "").split(",").map((s) => s.trim()).filter(Boolean),
    enabled: obj.enabled !== false,
    lastUsedAt: obj.lastUsedAt || null
  };
  issuedKeys.set(rec.id, rec);
  return { record: rec, created: true, plain };
}

(function loadKeys() {
  if (KEYS_FILE && fs.existsSync(KEYS_FILE)) {
    try {
      const arr = JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
      if (Array.isArray(arr)) arr.forEach((o) => importRecord(o));
      console.log(`Loaded ${issuedKeys.size} key(s) from ${KEYS_FILE}`);
    } catch (e) {
      console.error("Failed to load keys file:", e.message);
    }
  }
  if (process.env.ISSUED_KEYS_JSON) {
    try {
      const arr = JSON.parse(process.env.ISSUED_KEYS_JSON);
      if (Array.isArray(arr)) {
        let n = 0;
        arr.forEach((o) => { if (importRecord(o).created) n++; });
        console.log(`Seeded ${n} key(s) from ISSUED_KEYS_JSON`);
      }
    } catch (e) {
      console.error("Failed to parse ISSUED_KEYS_JSON:", e.message);
    }
  }
})();

function findIssuedKey(supplied) {
  const h = keyHash(supplied);
  for (const rec of issuedKeys.values()) {
    if (rec.keyHash === h) return rec;
  }
  return null;
}

// Returns null when the key may proceed, else { status, error, resetAfter }.
function checkIssuedKey(rec, query) {
  if (!rec.enabled) {
    return { status: 403, error: "API key disabled" };
  }
  if (rec.expiresAt && Date.now() > new Date(rec.expiresAt).getTime()) {
    return { status: 403, error: "API key expired" };
  }
  if (rec.maxTotal > 0 && rec.usedTotal >= rec.maxTotal) {
    return { status: 429, error: "Total quota exhausted" };
  }
  const usedToday = rec.usedDaily[todayStr()] || 0;
  if (rec.maxDaily > 0 && usedToday >= rec.maxDaily) {
    return { status: 429, error: "Daily quota exhausted" };
  }
  if (rec.numbers.length > 0 && !rec.numbers.includes(query)) {
    return { status: 403, error: "Number not allowed for this key" };
  }
  return null;
}

function consumeIssuedKey(rec) {
  rec.usedTotal += 1;
  const t = todayStr();
  rec.usedDaily[t] = (rec.usedDaily[t] || 0) + 1;
  rec.lastUsedAt = new Date().toISOString();
  persistKeys();
}

// ======================================================
// Dashboard auth (single admin password, signed sessions)
// ======================================================
const DASH_PASSWORD = process.env.DASH_PASSWORD || "";
const sessions = new Map(); // token -> expiresAt ms

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie;
  if (!header) return out;
  header.split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i > 0) {
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    }
  });
  return out;
}

function dashAuthed(req) {
  const token = parseCookies(req).dash_session;
  if (!token) return false;
  const exp = sessions.get(token);
  if (!exp) return false;
  if (Date.now() > exp) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function requireDashAuth(req, res, next) {
  if (!dashAuthed(req)) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  next();
}

// ======================================================
// Render health check
// ======================================================
app.get("/health", (req, res) => {
  res.status(200).json({ success: true, status: "ok" });
});

// ======================================================
// Helper: sleep
// ======================================================
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ======================================================
// Helper: extract token from HTML
// ======================================================
function extractToken(html) {
  if (!html || typeof html !== "string") return null;

  const patterns = [
    /\bvar\s+t\s*=\s*["']([^"']+)["']/i,
    /\blet\s+t\s*=\s*["']([^"']+)["']/i,
    /\bconst\s+t\s*=\s*["']([^"']+)["']/i,
    /\bt\s*=\s*["']([a-fA-F0-9]+)["']/i
  ];

  for (const regex of patterns) {
    const match = html.match(regex);
    if (match && match[1]) return match[1].trim();
  }

  return null;
}

// ======================================================
// Helper: get upstream token (cached, streamed homepage)
// ======================================================
async function getToken(forceRefresh = false) {
  if (!forceRefresh && cachedToken) return cachedToken;

  const response = await fetch(UPSTREAM_HOME, {
    method: "GET",
    redirect: "follow",
    cache: "no-store",
    headers: {
      "User-Agent":
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
      "Accept":
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Pragma": "no-cache",
      "Accept-Language": "en-US,en;q=0.9"
    }
  });

  if (!response.ok) {
    throw new Error(`Homepage request failed with status ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let token = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const m = extractToken(buf);
    if (m) { token = m; break; }
  }

  try { reader.cancel(); } catch {}

  if (!token) {
    console.error("Token not found. Partial HTML length:", buf.length);
    throw new Error("Upstream token not found");
  }

  cachedToken = token;
  return token;
}

function tokenFingerprint(token) {
  if (!token) return "none";
  if (token.length <= 8) return `${token.slice(0, 3)}...`;
  return `${token.slice(0, 4)}...${token.slice(-4)}`;
}

// ======================================================
// Helper: perform upstream POST
// ======================================================
async function callUpstream(query, token) {
  const body = new URLSearchParams();
  body.set("action", "num_info");
  body.set("query", query);
  body.set("token", token);

  const response = await fetch(UPSTREAM_API, {
    method: "POST",
    redirect: "follow",
    cache: "no-store",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent":
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 " +
        "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36",
      "Accept": "application/json,text/plain,*/*",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Pragma": "no-cache",
      "Referer": UPSTREAM_HOME,
      "Origin": "https://ssosint.vercel.app",
      "Accept-Language": "en-US,en;q=0.9"
    },
    body: body.toString()
  });

  const text = await response.text();
  return { response, text };
}

// ======================================================
// Main API handler
// ======================================================
async function handleApi(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ success: false, error: "Method not allowed" });
  }

  const suppliedKey = req.headers["x-api-key"] || req.query.key;

  if (!suppliedKey) {
    return res.status(401).json({ success: false, error: "Missing API key" });
  }

  // ---- Auth: master key = unlimited (unchanged behavior) ----
  let issued = null;
  const isMaster =
    process.env.MY_API_KEY && suppliedKey === process.env.MY_API_KEY;

  if (!isMaster) {
    if (!process.env.MY_API_KEY) {
      return res.status(401).json({ success: false, error: "Invalid API key" });
    }
    issued = findIssuedKey(suppliedKey);
    if (!issued) {
      return res.status(401).json({ success: false, error: "Invalid API key" });
    }
  }

  const query = String(req.query.query || "").trim();
  if (!query) {
    return res.status(400).json({ success: false, error: "Missing query" });
  }

  // ---- Issued-key limits (checked before spending quota) ----
  if (issued) {
    const blocked = checkIssuedKey(issued, query);
    if (blocked) {
      return res.status(blocked.status).json({ success: false, error: blocked.error });
    }
  } else {
    // Global allowlist still applies to the master key (unchanged).
    const allowedNumbers = String(process.env.ALLOWED_NUMBERS || "")
      .split(",").map((n) => n.trim()).filter(Boolean);
    if (allowedNumbers.length > 0 && !allowedNumbers.includes(query)) {
      return res.status(403).json({ success: false, error: "Number not allowed" });
    }
  }

  try {
    let token = await getToken();
    let upstream = await callUpstream(query, token);
    console.log(`Upstream attempt #1: HTTP ${upstream.response.status}`);

    let upstreamData = null;
    try { upstreamData = JSON.parse(upstream.text); } catch {}

    const responseLower = upstream.text.toLowerCase();
    const looksLikeTokenError =
      upstream.response.status === 401 ||
      upstream.response.status === 403 ||
      responseLower.includes("invalid token") ||
      responseLower.includes("token invalid") ||
      responseLower.includes("token expired") ||
      responseLower.includes("invalid_token") ||
      responseLower.includes("csrf") ||
      responseLower.includes("unauthorized");

    if (looksLikeTokenError) {
      console.log("Possible token failure. Fetching a COMPLETELY NEW token...");
      await sleep(150);
      token = await getToken(true);
      upstream = await callUpstream(query, token);
      console.log(`Upstream attempt #2: HTTP ${upstream.response.status}`);
      try { upstreamData = JSON.parse(upstream.text); } catch {}
    }

    if (!upstreamData) {
      return res.status(502).json({
        success: false, error: "Invalid JSON received from upstream"
      });
    }

    // Count quota only on a usable upstream answer.
    if (issued) {
      // Re-check quota in case of a race, then consume.
      const blocked = checkIssuedKey(issued, query);
      if (blocked) {
        return res.status(blocked.status).json({ success: false, error: blocked.error });
      }
      consumeIssuedKey(issued);
      res.setHeader("X-Key-Name", issued.name);
      if (issued.maxTotal > 0) {
        res.setHeader("X-Quota-Total-Remaining", String(issued.maxTotal - issued.usedTotal));
      }
      if (issued.maxDaily > 0) {
        let left = issued.maxDaily - (issued.usedDaily[todayStr()] || 0);
        // Daily remaining can never exceed total remaining.
        if (issued.maxTotal > 0) {
          left = Math.min(left, issued.maxTotal - issued.usedTotal);
        }
        res.setHeader("X-Quota-Daily-Remaining", String(Math.max(0, left)));
      }
    }
    upstreamData.api_by = "Mr_Unknown";

    delete upstreamData.proxy_by;
    delete upstreamData._contact;
    delete upstreamData._telegram_channel;

    res.status(upstream.response.status);
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    return res.json(upstreamData);

  } catch (error) {
    console.error("API Error:", error && error.stack ? error.stack : error);
    return res.status(502).json({
      success: false, error: "Upstream request failed", message: error.message
    });
  }
}

// ======================================================
// Dashboard API (protected by admin session)
// ======================================================
app.post("/dash/api/login", (req, res) => {
  if (!DASH_PASSWORD) {
    return res.status(500).json({
      success: false, error: "DASH_PASSWORD is not configured on the server"
    });
  }
  if (req.body && req.body.password === DASH_PASSWORD) {
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, Date.now() + 24 * 60 * 60 * 1000);
    res.setHeader(
      "Set-Cookie",
      `dash_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`
    );
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false, error: "Wrong password" });
});

app.post("/dash/api/logout", (req, res) => {
  const token = parseCookies(req).dash_session;
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", "dash_session=; HttpOnly; Path=/; Max-Age=0");
  return res.json({ success: true });
});

app.get("/dash/api/keys", requireDashAuth, (req, res) => {
  res.json({
    success: true,
    persistent: Boolean(KEYS_FILE),
    keys: [...issuedKeys.values()].map(sanitizeRecord)
  });
});

app.post("/dash/api/keys", requireDashAuth, (req, res) => {
  const b = req.body || {};
  let expiresAt = null;

  if (b.expiresAt) {
    const t = new Date(b.expiresAt).getTime();
    if (isNaN(t)) {
      return res.status(400).json({ success: false, error: "Bad expiresAt date" });
    }
    expiresAt = new Date(t).toISOString();
  } else if (b.expiresInHours) {
    const h = Number(b.expiresInHours);
    if (!isFinite(h) || h <= 0) {
      return res.status(400).json({ success: false, error: "Bad expiresInHours" });
    }
    expiresAt = new Date(Date.now() + h * 3600 * 1000).toISOString();
  }

  const { record, plain } = importRecord({
    name: b.name,
    expiresAt,
    maxTotal: b.maxTotal,
    maxDaily: b.maxDaily,
    numbers: b.numbers
  });
  persistKeys();

  // Full key is shown ONLY here — store it now, it can't be retrieved later.
  return res.json({ success: true, key: plain, record: sanitizeRecord(record) });
});

app.patch("/dash/api/keys/:id", requireDashAuth, (req, res) => {
  const rec = issuedKeys.get(req.params.id);
  if (!rec) {
    return res.status(404).json({ success: false, error: "Key not found" });
  }
  const b = req.body || {};

  if (b.name !== undefined) rec.name = String(b.name);
  if (b.enabled !== undefined) rec.enabled = Boolean(b.enabled);
  if (b.maxTotal !== undefined) rec.maxTotal = Math.max(0, Number(b.maxTotal) || 0);
  if (b.maxDaily !== undefined) rec.maxDaily = Math.max(0, Number(b.maxDaily) || 0);
  // Keep daily capped at total (also when only total was lowered).
  rec.maxDaily = clampDaily(rec.maxTotal, rec.maxDaily);
  if (b.expiresAt !== undefined) {
    rec.expiresAt = b.expiresAt ? new Date(b.expiresAt).toISOString() : null;
  }
  if (b.numbers !== undefined) {
    rec.numbers = Array.isArray(b.numbers)
      ? b.numbers.map(String)
      : String(b.numbers || "").split(",").map((s) => s.trim()).filter(Boolean);
  }
  if (b.resetUsage) {
    rec.usedTotal = 0;
    rec.usedDaily = {};
  }
  persistKeys();
  return res.json({ success: true, record: sanitizeRecord(rec) });
});

app.delete("/dash/api/keys/:id", requireDashAuth, (req, res) => {
  if (!issuedKeys.delete(req.params.id)) {
    return res.status(404).json({ success: false, error: "Key not found" });
  }
  persistKeys();
  return res.json({ success: true });
});

// ======================================================
// Dashboard UI
// ======================================================
const DASH_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0d1117">
<title>API Dashboard</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--accent:#7c3aed;--accent2:#a78bfa;--text:#e6edf3;--text2:#8b949e;--danger:#f85149;--success:#3fb950;--safe-t:env(safe-area-inset-top,0px);--safe-b:env(safe-area-inset-bottom,0px)}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{-webkit-text-size-adjust:100%}
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding-top:var(--safe-t);padding-bottom:var(--safe-b)}
.wrap{max-width:900px;margin:0 auto;padding:24px}
h1{font-size:1.6em;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
h3{font-size:1.05em;margin-bottom:4px}
.sub{color:var(--text2);font-size:.9em;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:18px}
label{display:block;font-size:.8em;color:var(--text2);margin:10px 0 4px}
input,select{width:100%;padding:11px;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:10px;color:#fff;font-size:.95em;outline:none;color-scheme:dark}
input:focus{border-color:var(--accent)}
.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
button{padding:11px 18px;border:none;border-radius:10px;cursor:pointer;font-weight:600;font-size:.9em;touch-action:manipulation;min-height:44px}
button:disabled{opacity:.55;cursor:wait}
.btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;margin-top:14px;width:100%}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--text);padding:7px 12px;margin:2px}
.btn-danger{background:rgba(248,81,73,.12);border:1px solid rgba(248,81,73,.4);color:var(--danger);padding:7px 12px;margin:2px}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{width:100%;border-collapse:collapse;font-size:.85em;margin-top:10px;min-width:560px}
th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--text2);font-weight:600;font-size:.78em;text-transform:uppercase;letter-spacing:1px}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:.75em;font-weight:600;white-space:nowrap}
.ok{background:rgba(63,185,80,.12);color:var(--success)}
.off{background:rgba(248,81,73,.12);color:var(--danger)}
.keybox{background:rgba(0,0,0,.4);padding:14px;border-radius:10px;word-break:break-all;font-family:monospace;font-size:.85em;margin-top:12px;border:1px solid var(--accent)}
.keybox button{width:100%;margin-top:10px}
.warn{background:rgba(210,153,29,.1);border:1px solid rgba(210,153,29,.35);color:#d2991d;padding:10px 14px;border-radius:10px;font-size:.85em;margin-bottom:14px}
.err{color:var(--danger);font-size:.85em;margin-top:8px;min-height:1.2em}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:16px}
.topbar button{width:auto;margin:0;flex-shrink:0}
.refreshbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:2px}
.refreshbar .sub{margin:0}
.mono{font-family:monospace;font-size:.82em;color:var(--accent2)}
#toast{position:fixed;left:50%;bottom:calc(18px + var(--safe-b));transform:translateX(-50%) translateY(20px);background:#1f2733;border:1px solid var(--accent);color:var(--text);padding:10px 18px;border-radius:12px;font-size:.85em;opacity:0;pointer-events:none;transition:.25s;z-index:50;max-width:92vw;text-align:center}
#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(max-width:640px){
.wrap{padding:12px}
h1{font-size:1.3em}
.card{padding:14px;border-radius:12px;margin-bottom:12px}
.row{grid-template-columns:1fr}
input,select,button{font-size:16px}
.topbar{position:sticky;top:0;z-index:10;background:rgba(13,17,23,.92);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);padding:10px 2px;margin:0 -2px 12px}
table{min-width:0}
table,thead,tbody,tr,td{display:block;width:100%}
thead{display:none}
tbody tr{border:1px solid var(--border);border-radius:12px;margin-bottom:10px;padding:4px 2px;background:rgba(255,255,255,.015)}
tbody td{border:none;padding:7px 12px}
tbody td[data-l]::before{content:attr(data-l);display:block;font-size:.68em;color:var(--text2);text-transform:uppercase;letter-spacing:1px;margin-bottom:2px}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.actions button{flex:1 1 30%;margin:2px 0;white-space:nowrap}
#loginView{margin:30px auto !important}
}
</style></head><body><div class="wrap" id="top">
<div id="loginView" class="card" style="max-width:420px;margin:60px auto">
<h1>🔐 Dashboard</h1><p class="sub">Enter admin password</p>
<label>Password</label><input type="password" id="pw" autocomplete="current-password" enterkeyhint="go">
<button class="btn" id="loginBtn" onclick="login()">Login</button>
<div class="err" id="loginErr"></div>
</div>
<div id="dashView" style="display:none">
<div class="topbar"><div><h1>🔑 API Keys</h1><p class="sub" style="margin:0">Master key unlimited · issued keys carry limits</p></div>
<button class="btn-ghost" onclick="logout()">Logout</button></div>
<div id="persistWarn"></div>
<div class="card"><h3>Create new key</h3>
<label>Name</label><input id="fName" placeholder="e.g. friend-1" autocomplete="off" enterkeyhint="next">
<div class="row"><div><label>Total limit (0 = ∞)</label><input id="fTotal" type="number" min="0" value="0" inputmode="numeric"></div>
<div><label>Daily limit (0 = ∞)</label><input id="fDaily" type="number" min="0" value="0" inputmode="numeric"></div></div>
<div class="row"><div><label>Expires in hours (blank = never)</label><input id="fHours" type="number" min="0" placeholder="e.g. 72" inputmode="numeric"></div>
<div><label>Allowed numbers, comma separated (blank = all)</label><input id="fNums" placeholder="98..., 91..." inputmode="numeric"></div></div>
<button class="btn" id="createBtn" onclick="createKey()">Create key</button>
<div id="newKey"></div><div class="err" id="createErr"></div></div>
<div class="card"><div class="refreshbar"><h3>Issued keys</h3><button class="btn-ghost" onclick="loadKeys(true)">↻ Refresh</button></div><div class="tablewrap" id="keyTable">Loading…</div></div>
</div></div>
<div id="toast"></div>
<script>
async function api(path, opts) {
  const r = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" } }, opts || {}));
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}
let toastTimer = null;
function toast(msg) {
  toast.textContent = msg;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2200);
}
function relTime(iso) {
  if (!iso) return "never used";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return new Date(iso).toLocaleString();
}
function copyKey(key, btn) {
  const done = () => { btn.textContent = "✅ Copied"; toast("Key copied"); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(key).then(done).catch(() => fallbackCopy(key) && done());
  } else if (fallbackCopy(key)) { done(); }
}
function fallbackCopy(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    return true;
  } catch { return false; }
}
async function login() {
  loginErr.textContent = "";
  loginBtn.disabled = true;
  try {
    await api("/dash/api/login", { method: "POST", body: JSON.stringify({ password: pw.value }) });
    pw.value = "";
    showDash();
  } catch (e) { loginErr.textContent = e.message; }
  finally { loginBtn.disabled = false; }
}
async function logout() {
  await api("/dash/api/logout", { method: "POST" }).catch(() => {});
  location.reload();
}
function showDash() {
  loginView.style.display = "none";
  dashView.style.display = "block";
  loadKeys();
}
async function loadKeys(manual) {
  if (manual) toast("Refreshing…");
  try {
    const j = await api("/dash/api/keys");
    if (!j.persistent) {
      persistWarn.innerHTML = '<div class="warn">⚠️ Keys live in memory and are lost on restart. Seed permanent keys via ISSUED_KEYS_JSON.</div>';
    } else { persistWarn.innerHTML = ""; }
    if (!j.keys.length) { keyTable.innerHTML = "<p class='sub'>No keys yet.</p>"; return; }
    let h = "<table><thead><tr><th>Key</th><th>Limits</th><th>Usage</th><th>Status</th><th></th></tr></thead><tbody>";
    for (const k of j.keys) {
      const lim = [];
      lim.push(k.maxTotal > 0 ? ("total " + k.usedTotal + "/" + k.maxTotal) : ("total " + k.usedTotal + "/∞"));
      lim.push(k.maxDaily > 0 ? ("today " + k.usedToday + "/" + k.maxDaily) : ("today " + k.usedToday + "/∞"));
      if (k.expiresAt) lim.push("exp " + new Date(k.expiresAt).toLocaleString());
      if (k.numbers && k.numbers.length) lim.push(k.numbers.length + " number(s)");
      h += "<tr><td data-l='Key'><b>" + esc(k.name) + "</b><br><span class='mono'>" + esc(k.prefix) + "••••</span></td>" +
        "<td data-l='Limits'>" + lim.map(esc).join("<br>") + "</td>" +
        "<td data-l='Usage'>last " + esc(relTime(k.lastUsedAt)) + "</td>" +
        "<td data-l='Status'><span class='badge " + (k.enabled ? "ok" : "off") + "'>" + (k.enabled ? "active" : "disabled") + "</span></td>" +
        "<td class='actions'><button class='btn-ghost' onclick='toggleKey(\\"" + k.id + "\\"," + (!k.enabled) + ")'>" + (k.enabled ? "Disable" : "Enable") + "</button>" +
        "<button class='btn-ghost' onclick='resetKey(\\"" + k.id + "\\")'>Reset</button>" +
        "<button class='btn-danger' onclick='delKey(\\"" + k.id + "\\")'>Delete</button></td></tr>";
    }
    keyTable.innerHTML = h + "</tbody></table>";
  } catch (e) {
    if (String(e.message).includes("Unauthorized")) { location.reload(); return; }
    keyTable.textContent = e.message;
  }
}
function esc(s) { return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
async function createKey() {
  createErr.textContent = ""; newKey.innerHTML = "";
  createBtn.disabled = true;
  try {
    const j = await api("/dash/api/keys", { method: "POST", body: JSON.stringify({
      name: fName.value || "unnamed",
      maxTotal: Number(fTotal.value || 0),
      maxDaily: Number(fDaily.value || 0),
      expiresInHours: fHours.value ? Number(fHours.value) : undefined,
      numbers: fNums.value
    }) });
    newKey.innerHTML = "<div class='keybox'>✅ Copy now — shown once:<br><span id='freshKey'>" + esc(j.key) + "</span><br><button class='btn-ghost' onclick='copyKey(freshKey.textContent,this)'>📋 Copy key</button></div>";
    copyKey(j.key, newKey.querySelector("button"));
    fName.value = ""; fHours.value = ""; fNums.value = "";
    loadKeys();
  } catch (e) { createErr.textContent = e.message; }
  finally { createBtn.disabled = false; }
}
async function toggleKey(id, on) {
  await api("/dash/api/keys/" + id, { method: "PATCH", body: JSON.stringify({ enabled: on }) });
  loadKeys();
}
async function resetKey(id) {
  if (!confirm("Reset usage counters for this key?")) return;
  await api("/dash/api/keys/" + id, { method: "PATCH", body: JSON.stringify({ resetUsage: true }) });
  loadKeys();
}
async function delKey(id) {
  if (!confirm("Delete this key permanently?")) return;
  await api("/dash/api/keys/" + id, { method: "DELETE" });
  loadKeys();
}
// If already logged in, skip the login form.
api("/dash/api/keys").then(() => showDash()).catch(() => {});
pw.addEventListener("keydown", (e) => { if (e.key === "Enter") login(); });
</script></body></html>`;

app.get("/dash", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.send(DASH_HTML);
});

// ======================================================
// Routes
// ======================================================
app.get("/", handleApi);
app.get("/api", handleApi);

// ======================================================
// Start server
// ======================================================
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  if (!DASH_PASSWORD) console.log("WARNING: DASH_PASSWORD is not set — /dash login is disabled");
  if (!KEYS_FILE) console.log("NOTE: KEYS_FILE not set — issued keys are in-memory only");
});
