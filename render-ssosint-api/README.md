# Render-ready Node/Express API

This project converts the original Vercel-style serverless handler into a standard Node.js + Express web service suitable for Render.

## Files

- `server.js` — complete API server
- `package.json` — Node/Express dependencies and start command
- `render.yaml` — Render Blueprint configuration
- `.env.example` — required environment variables
- `.gitignore` — keeps local secrets and dependencies out of Git

## Run locally

Requirements: Node.js 20 or newer.

```bash
npm install
```

Copy `.env.example` to `.env` and set your secret. Then export the variables in your shell (or use an environment loader) and start:

```bash
npm start
```

The server listens on:

- `http://localhost:10000/`
- `http://localhost:10000/api`
- `http://localhost:10000/health`

## Render deployment

### Option A: Render Dashboard

Create a **Web Service** from this repository.

Build Command:

```text
npm install
```

Start Command:

```text
npm start
```

Add these environment variables in Render:

```text
MY_API_KEY=your-strong-secret
ALLOWED_NUMBERS=1234567890,9876543210
```

`ALLOWED_NUMBERS` is optional. When it is empty, the allowlist is disabled. When it contains comma-separated values, only exact matches are accepted.

### Option B: Render Blueprint

Commit this folder to a Git repository and use `render.yaml` as a Blueprint. Render will prompt you for the `MY_API_KEY` and `ALLOWED_NUMBERS` values because they are marked `sync: false`.

## API usage

### With header authentication

```bash
curl "https://YOUR-SERVICE.onrender.com/api?query=1234567890" \
  -H "x-api-key: YOUR_API_KEY"
```

### With query-string authentication

```bash
curl "https://YOUR-SERVICE.onrender.com/api?query=1234567890&key=YOUR_API_KEY"
```

### Health check

```bash
curl "https://YOUR-SERVICE.onrender.com/health"
```

## Response behavior

- `401` — missing/invalid API key
- `400` — missing query
- `403` — query rejected by `ALLOWED_NUMBERS`
- `502` — upstream homepage/token problem
- upstream HTTP status — proxied for the POST result
- `500` — unexpected server error

## Notes

The implementation preserves the original upstream requests, token extraction, API-key authentication, optional allowlist, and response forwarding logic. It does not add database storage or background jobs.

Use the upstream service only in accordance with its terms and applicable privacy and data-protection requirements.
