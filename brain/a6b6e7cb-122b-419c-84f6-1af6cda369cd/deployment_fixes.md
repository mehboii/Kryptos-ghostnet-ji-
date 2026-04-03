# GhostNet Deployment Fixes — Summary

## Changes Applied

### 1. CORS — `ghostnet-bridge/bridge.js`
render_diffs(file:///c:/Users/novtw/.gemini/antigravity/ghostnet-bridge/bridge.js)

**What changed:** Default `CORS_ALLOWED_ORIGINS` now includes `https://ghostnet-ji.vercel.app`. The code already `.split(',')` into an array and uses `Array.includes(origin)`, so origin matching works correctly — no substring-match bug.

### 2. ETH_RPC_URL — `ghostnet-bridge/bridge.js`

**What changed:**
- Default changed from `http://127.0.0.1:8545` → `https://rpc.sepolia.org`
- Removed the hard crash on non-loopback URLs (the old code threw an `Error` that would kill the process on Railway)
- Added a clear warning log when no `ETH_RPC_URL` env var is set
- External hosts now log an informational message instead of crashing

### 3. GHOSTNET_MODE — `ghostnet-server.js`
render_diffs(file:///c:/Users/novtw/.gemini/antigravity/ghostnet-server.js)

**What changed:** Default now auto-detects from `NODE_ENV`:
```js
// Before
const GHOSTNET_MODE = process.env.GHOSTNET_MODE || 'development';
// After
const GHOSTNET_MODE = process.env.GHOSTNET_MODE || (process.env.NODE_ENV === 'production' ? 'production' : 'development');
```
Railway sets `NODE_ENV=production` by default, so this will auto-resolve without needing an extra env var.

### 4. Screenshot Overlay — `ui.js` + `screenshot-protection.js`
render_diffs(file:///c:/Users/novtw/.gemini/antigravity/ui.js)
render_diffs(file:///c:/Users/novtw/.gemini/antigravity/screenshot-protection.js)

**What changed:** Added `pointer-events: none` to both:
- `ui.js` → `#screenshot-overlay` div (created dynamically on window blur)
- `screenshot-protection.js` → `.ghost-blur-overlay` CSS class

This lets touch/click events pass through the overlay to the underlying UI on mobile.

---

## Railway Environment Variables

Copy-paste these into **Railway → Service → Variables**:

| Variable | Required | Recommended Value | Notes |
|---|---|---|---|
| `AUTH_JWT_SECRET` | ✅ **Yes** | `<random 64+ char string>` | Server refuses to start without this. Generate with `openssl rand -hex 32` |
| `BRIDGE_API_TOKEN` | ✅ **Yes** | `<random 32+ char string>` | Bridge refuses to start without this (≥32 chars). Generate with `openssl rand -hex 16` |
| `CORS_ALLOWED_ORIGINS` | No | `https://ghostnet-ji.vercel.app` | Already defaulted in code. Set this if you have additional frontend origins |
| `ETH_RPC_URL` | No | `https://rpc.sepolia.org` | Already defaulted. Use `https://eth-sepolia.g.alchemy.com/v2/<KEY>` for production |
| `ETH_PRIVATE_KEY` | No | `0x<64 hex chars>` | Only if you need wallet write operations. Omit for read-only mode |
| `GHOSTNET_MODE` | No | *(auto-detected)* | Auto-detects `production` from Railway's `NODE_ENV=production`. Override with `production`, `development`, or `cloud` |
| `GHOSTNET_SERVER_PORT` | No | `$PORT` | Railway injects `PORT` automatically. Code reads `PORT` as fallback |
| `GHOSTNET_BRIDGE_PORT` | No | `3001` | Only needed if bridge runs as a separate service |
| `SOL_ADDRESS` | No | `<base58 Solana address>` | For Solana wallet display |
| `NODE_ENV` | No | `production` | Railway sets this automatically |

> [!IMPORTANT]
> **Before deploying:** You must click **"Generate Domain"** in Railway → Service → Settings → Networking to get a `*.up.railway.app` public URL. Without this, the backend has no public endpoint.

> [!TIP]
> After generating the Railway domain, update your Vercel frontend's API base URL environment variable to point to the new `https://<service>.up.railway.app` URL.
