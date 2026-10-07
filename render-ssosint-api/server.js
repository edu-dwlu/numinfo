const express = require("express");

const app = express();
const PORT = process.env.PORT || 10000;

const UPSTREAM_HOME = "https://ssosint.vercel.app/";
const UPSTREAM_API = "https://ssosint.vercel.app/?api=1";

// Cached upstream token (valid for its short lifetime).
// Warm calls skip the homepage fetch entirely.
let cachedToken = null;

// ======================================================
// Render health check
// ======================================================
app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "ok"
  });
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
// Helper: get token (cached, streamed homepage read)
// ======================================================
async function getToken(forceRefresh = false) {
  if (!forceRefresh && cachedToken) {
    return cachedToken;
  }

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
    throw new Error(
      `Homepage request failed with status ${response.status}`
    );
  }

  // Stream the homepage and abort as soon as the token is found,
  // instead of downloading the entire page.
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let token = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buf += decoder.decode(value, { stream: true });

    const m = extractToken(buf);
    if (m) {
      token = m;
      break;
    }
  }

  try { reader.cancel(); } catch {}

  if (!token) {
    console.error("Token not found. Partial HTML length:", buf.length);
    console.error(
      "HTML preview:",
      buf.slice(0, 300).replace(/\s+/g, " ")
    );
    throw new Error("Upstream token not found");
  }

  console.log(
    "Fresh token obtained:",
    tokenFingerprint(token)
  );

  cachedToken = token;
  return token;
}

// ======================================================
// Helper: safe token fingerprint for logs
// ======================================================
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
  // ====================================================
  // 1. GET only
  // ====================================================
  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  // ====================================================
  // 2. API key
  // ====================================================
  const suppliedKey =
    req.headers["x-api-key"] ||
    req.query.key;

  if (!suppliedKey) {
    return res.status(401).json({
      success: false,
      error: "Missing API key"
    });
  }

  if (
    !process.env.MY_API_KEY ||
    suppliedKey !== process.env.MY_API_KEY
  ) {
    return res.status(401).json({
      success: false,
      error: "Invalid API key"
    });
  }

  // ====================================================
  // 3. Query
  // ====================================================
  const query = String(req.query.query || "").trim();

  if (!query) {
    return res.status(400).json({
      success: false,
      error: "Missing query"
    });
  }

  // ====================================================
  // 4. Optional allowlist
  // ====================================================
  const allowedNumbers = String(
    process.env.ALLOWED_NUMBERS || ""
  )
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);

  if (
    allowedNumbers.length > 0 &&
    !allowedNumbers.includes(query)
  ) {
    return res.status(403).json({
      success: false,
      error: "Number not allowed"
    });
  }

  // ====================================================
  // 5. Cached token + POST
  // ====================================================
  try {
    let token = await getToken();

    let upstream = await callUpstream(query, token);

    console.log(
      `Upstream attempt #1: HTTP ${upstream.response.status}`
    );

    let upstreamData = null;
    try { upstreamData = JSON.parse(upstream.text); } catch {}

    // ==================================================
    // 6. Retry once with a fresh token on token failure
    // ==================================================
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
      console.log(
        "Possible token failure. Fetching a COMPLETELY NEW token..."
      );

      await sleep(150);

      token = await getToken(true);

      upstream = await callUpstream(query, token);

      console.log(
        `Upstream attempt #2: HTTP ${upstream.response.status}`
      );

      try { upstreamData = JSON.parse(upstream.text); } catch {}
    }

    if (!upstreamData) {
      return res.status(502).json({
        success: false,
        error: "Invalid JSON received from upstream"
      });
    }

    // ==================================================
    // 7. Modify ONLY top-level metadata fields
    // ==================================================
    upstreamData.api_by = "Mr_Unknown";

    delete upstreamData._contact;
    delete upstreamData._telegram_channel;

    // ==================================================
    // 8. Return modified result
    // ==================================================
    res.status(upstream.response.status);

    res.setHeader(
      "Content-Type",
      "application/json; charset=utf-8"
    );

    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, proxy-revalidate"
    );

    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    return res.json(upstreamData);

  } catch (error) {
    console.error(
      "API Error:",
      error && error.stack
        ? error.stack
        : error
    );

    return res.status(502).json({
      success: false,
      error: "Upstream request failed",
      message: error.message
    });
  }
}

// ======================================================
// Routes
// ======================================================
app.get("/", handleApi);
app.get("/api", handleApi);

// ======================================================
// Start server
// ======================================================
app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Server running on port ${PORT}`
  );
});
