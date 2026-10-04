const express = require("express");

const app = express();
const PORT = process.env.PORT || 10000;

// Render health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    status: "ok"
  });
});

async function handleApi(req, res) {
  // =========================
  // 1. Allow GET only
  // =========================
  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  // =========================
  // 2. Read API key
  // =========================
  const suppliedKey =
    req.headers["x-api-key"] ||
    req.query.key;

  if (!suppliedKey) {
    return res.status(401).json({
      success: false,
      error: "Missing API key"
    });
  }

  if (suppliedKey !== process.env.MY_API_KEY) {
    return res.status(401).json({
      success: false,
      error: "Invalid API key"
    });
  }

  // =========================
  // 3. Read query
  // =========================
  const query = String(req.query.query || "").trim();

  if (!query) {
    return res.status(400).json({
      success: false,
      error: "Missing query"
    });
  }

  // =========================
  // 4. Optional number allowlist
  // =========================
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

  try {
    // =========================
    // 5. Get upstream homepage
    // =========================
    const homeResponse = await fetch(
      "https://ssosint.vercel.app/",
      {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0"
        }
      }
    );

    if (!homeResponse.ok) {
      return res.status(502).json({
        success: false,
        error: "Failed to fetch upstream homepage",
        upstream_status: homeResponse.status
      });
    }

    const html = await homeResponse.text();

    // =========================
    // 6. Extract token
    // Supports:
    // var t = "abcdef..."
    // var t = 'abcdef...'
    // =========================
    const tokenMatch = html.match(
      /var\s+t\s*=\s*["']([a-f0-9]+)["']/i
    );

    if (!tokenMatch) {
      return res.status(502).json({
        success: false,
        error: "Upstream token not found"
      });
    }

    const token = tokenMatch[1];

    // =========================
    // 7. Make the same POST
    // =========================
    const body = new URLSearchParams();

    body.set("action", "num_info");
    body.set("query", query);
    body.set("token", token);

    const upstreamResponse = await fetch(
      "https://ssosint.vercel.app/?api=1",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "Mozilla/5.0"
        },
        body: body.toString()
      }
    );

    const responseText = await upstreamResponse.text();

    // =========================
    // 8. Return upstream result
    // =========================
    res.status(upstreamResponse.status);
    res.setHeader(
      "Content-Type",
      "application/json; charset=utf-8"
    );
    res.setHeader("Cache-Control", "no-store");

    return res.send(responseText);
  } catch (error) {
    console.error("API Error:", error);

    return res.status(500).json({
      success: false,
      error: "Internal server error"
    });
  }
}

// Main API routes
app.get("/", handleApi);
app.get("/api", handleApi);

// Render Web Service listener
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
