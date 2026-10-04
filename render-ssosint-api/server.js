const express = require("express");

const app = express();
const PORT = process.env.PORT || 10000;

const UPSTREAM_HOME = "https://ssosint.vercel.app/";
const UPSTREAM_API = "https://ssosint.vercel.app/?api=1";

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
// Helper: fetch a completely fresh homepage
// ======================================================
async function getFreshHomepage() {
  const cacheBuster = `${Date.now()}-${Math.random()
    .toString(36)
    .slice(2)}`;

  const url = `${UPSTREAM_HOME}?_=${encodeURIComponent(cacheBuster)}`;

  const response = await fetch(url, {
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

  const html = await response.text();

  return {
    response,
    html
  };
}

// ======================================================
// Helper: extract token from homepage
// Supports:
// var t = "abcdef"
// var t='abcdef'
// var t = 'abcdef'
// let/const t = "abcdef" too
// ======================================================
function extractToken(html) {
  if (!html || typeof html !== "string") {
    return null;
  }

  const patterns = [
    /\bvar\s+t\s*=\s*["']([^"']+)["']/i,
    /\blet\s+t\s*=\s*["']([^"']+)["']/i,
    /\bconst\s+t\s*=\s*["']([^"']+)["']/i,
    /\bt\s*=\s*["']([a-fA-F0-9]+)["']/i
  ];

  for (const regex of patterns) {
    const match = html.match(regex);

    if (match && match[1]) {
      return match[1].trim();
    }
  }

  return null;
}

// ======================================================
// Helper: safe token fingerprint for logs
// Never log the real token
// ======================================================
function tokenFingerprint(token) {
  if (!token) {
    return "none";
  }

  if (token.length <= 8) {
    return `${token.slice(0, 3)}...`;
  }

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

      "Accept":
        "application/json,text/plain,*/*",

      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Pragma": "no-cache",

      "Referer": UPSTREAM_HOME,
      "Origin": "https://ssosint.vercel.app",

      "Accept-Language": "en-US,en;q=0.9"
    },

    body: body.toString()
  });

  const text = await response.text();

  return {
    response,
    text
  };
}

// ======================================================
// Helper: get a NEW token
// Always fetches homepage again
// ======================================================
async function getNewToken() {
  const { response, html } = await getFreshHomepage();

  if (!response.ok) {
    throw new Error(
      `Homepage request failed with status ${response.status}`
    );
  }

  const token = extractToken(html);

  if (!token) {
    // Print a tiny diagnostic only
    console.error(
      "Token not found. Homepage length:",
      html.length
    );

    console.error(
      "Homepage preview:",
      html.slice(0, 300).replace(/\s+/g, " ")
    );

    throw new Error("Upstream token not found");
  }

  console.log(
    "Fresh token obtained:",
    tokenFingerprint(token)
  );

  return token;
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
  const query = String(
    req.query.query || ""
  ).trim();

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
  // 5. Fresh token + POST
  // ====================================================
  try {
    // ALWAYS obtain a brand-new token
    let token = await getNewToken();

    let upstream = await callUpstream(query, token);

    console.log(
      `Upstream attempt #1: HTTP ${upstream.response.status}`
    );

    // ==================================================
    // 6. Retry once using a newly fetched token
    // ==================================================
    //
    // This protects against:
    // - cached/stale token
    // - token rotation
    // - temporary upstream token mismatch
    //
    // We do not assume every error means token failure,
    // so only retry on likely token/auth failures.
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

      // Tiny delay before retry
      await sleep(150);

      token = await getNewToken();

      upstream = await callUpstream(query, token);

      console.log(
        `Upstream attempt #2: HTTP ${upstream.response.status}`
      );
    }

    // ==================================================
    // 7. Return upstream result
    // ==================================================
    res.status(upstream.response.status);

    res.setHeader(
      "Content-Type",
      upstream.response.headers.get("content-type") ||
        "application/json; charset=utf-8"
    );

    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, proxy-revalidate"
    );

    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");

    return res.send(upstream.text);

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
