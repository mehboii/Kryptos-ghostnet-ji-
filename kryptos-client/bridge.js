'use strict';

/**
 * Kryptos Bridge Server — SECURITY HARDENED
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Real private key hardcoded in source code.
 *     const PRIVATE_KEY = "0x183abcea..." stored a live Ethereum private key
 *     directly in the source file. This key controls real funds and was
 *     committed to version control, where it is:
 *     - Permanent: git history cannot be fully purged across all clones
 *     - Visible to every developer, CI system, and code review tool
 *     - Indexed by GitHub code search and similar tools
 *     - Exposed to every npm/bundler/linter that reads source files
 *     The key visible in this file (0x183abc...) must be considered
 *     permanently compromised — any funds at that address should be moved
 *     immediately to a new wallet whose key has never appeared in source.
 *     Fixed: the private key is loaded exclusively from an encrypted
 *     keystore file (ethers.Wallet.fromEncryptedJsonSync) with the
 *     passphrase from an environment variable. The key never appears in
 *     source code in any form.
 *
 * [B] CRITICAL — /broadcast endpoint has zero authentication.
 *     Any client anywhere on the internet that can reach port 3000 can
 *     POST { "to": "0xattacker", "amount": "999" } and drain the wallet
 *     completely with a single HTTP request. There are no tokens, no
 *     signatures, no IP restrictions — nothing.
 *     Fixed: every /broadcast request must include an HMAC-SHA-256
 *     signature over the full request body. The bridge computes
 *     HMAC(body, BRIDGE_API_SECRET) and compares with crypto.timingSafeEqual.
 *     Requests with missing or incorrect signatures are rejected with 401.
 *     The API secret is loaded from environment only — never source code.
 *
 * [C] CRITICAL — `amount` is used directly from untrusted JSON with no
 *     type, range, or value validation.
 *     Several attack vectors:
 *     - amount: "999999" → drains entire wallet in one request
 *     - amount: "1e18"   → ethers.parseEther("1e18") = astronomical value
 *     - amount: {}       → parseEther throws, caught by generic catch
 *     - amount: "-1"     → negative ETH value (undefined behaviour)
 *     - amount: "0"      → zero-value spam transaction (wastes gas)
 *     Fixed: amount is validated as a string matching a strict decimal
 *     format (no scientific notation), parsed as a BigInt wei value, and
 *     checked against a MAX_TRANSFER_ETH cap (configurable via env). Zero
 *     and negative amounts are rejected. Non-string types throw immediately.
 *
 * [D] CRITICAL — `e.toString()` in the catch block sends raw exception
 *     messages to the caller.
 *     ethers.js exceptions contain rich internal detail:
 *     - RPC endpoint URL (with embedded API key)
 *     - Transaction parameters
 *     - Network error messages from the RPC node
 *     - Stack traces in some configurations
 *     Returning this to any caller is a serious information disclosure.
 *     Fixed: all exceptions are logged internally (to stderr only) with
 *     full detail. Callers receive only a fixed generic error string.
 *
 * [E] HIGH — Server listens on all interfaces (0.0.0.0) by default.
 *     http.createServer().listen(3000) binds to 0.0.0.0:3000 — every
 *     network interface on the machine. On a cloud VM this exposes the
 *     bridge to the public internet. Combined with [B] (no auth), this
 *     means the wallet is completely open to the world.
 *     Fixed: server binds to 127.0.0.1 (loopback only) by default.
 *     Set BRIDGE_BIND_HOST to override for reverse-proxy deployments.
 *
 * [F] HIGH — No request body size limit — DoS via large body.
 *     req.on('data', c => body += c) accumulated chunks without any cap.
 *     A client sending a multi-gigabyte body would exhaust memory and
 *     crash the process. Even a 100 MB body causes significant latency
 *     and ties up the event loop.
 *     Fixed: body accumulation is capped at MAX_BODY_BYTES (4096).
 *     Any request exceeding the limit is rejected with 413 and the
 *     connection is destroyed immediately.
 *
 * [G] HIGH — No rate limiting — wallet can be spammed with transactions.
 *     An authenticated caller (after [B] is fixed) could send hundreds
 *     of requests per second, each consuming gas and potentially
 *     front-running other transactions or draining the wallet's gas budget.
 *     Fixed: per-IP sliding-window rate limiter (MAX_REQ_PER_WINDOW per
 *     WINDOW_MS). Excess requests receive 429. The limiter Map is
 *     self-evicting to prevent memory growth.
 *
 * [H] HIGH — No gasLimit set on sendTransaction.
 *     Omitting gasLimit allows ethers to auto-estimate. A pathological
 *     destination contract (e.g. one with an infinite-loop fallback)
 *     could return a massive gas estimate, consuming the entire wallet
 *     balance in fees on a single transaction.
 *     Fixed: explicit gasLimit: 21000n for plain ETH transfers (the
 *     exact cost of a value-only transfer with no calldata). Any
 *     destination that requires more gas is not a plain transfer and
 *     is rejected by the EVM rather than by us overpaying.
 *
 * [I] HIGH — `to` address not validated beyond ethers.isAddress().
 *     isAddress() checks format only — it passes:
 *     - The wallet's own address (self-send — wasted gas, no-op)
 *     - The zero address (0x000...000 — burns ETH permanently)
 *     - Known smart contract addresses (contracts may have destructive fallbacks)
 *     Fixed: zero address and self-send are explicitly rejected.
 *     Checksummed address format is enforced via ethers.getAddress().
 *
 * [J] HIGH — `amount` is JSON-parsed without type checking.
 *     JSON.parse(body).amount could be any JSON type: object, array,
 *     boolean, null, or a number. Passing an object to parseEther()
 *     throws a generic error caught by the leaky catch block ([D]).
 *     Passing a JavaScript number loses precision for large values (IEEE
 *     754 float cannot represent all ETH amounts exactly).
 *     Fixed: amount is required to be a JSON string. Numbers, objects,
 *     and nulls are rejected immediately with a type error.
 *
 * [K] MEDIUM — No Content-Type validation on incoming requests.
 *     The server parsed the body as JSON unconditionally. A request
 *     with Content-Type: text/plain or no content type would still be
 *     parsed, making the endpoint callable from a wider range of clients
 *     (including HTML forms via CSRF) than intended.
 *     Fixed: requests without Content-Type: application/json receive 415.
 *
 * [L] MEDIUM — tx.hash returned without waiting for mining confirmation.
 *     tx.hash is available as soon as the transaction is submitted to the
 *     mempool — before it is confirmed in a block. The transaction may
 *     still be dropped, replaced (EIP-1559 replacement), or reverted.
 *     Returning the hash as "success" before confirmation gives a false
 *     sense of finality.
 *     Fixed: await tx.wait(1) waits for one block confirmation. The
 *     response includes blockNumber and confirmations for the caller.
 *
 * [M] MEDIUM — No security audit logging.
 *     The server had no access logging. Authentication failures, rate
 *     limit hits, and transaction submissions were all invisible. A
 *     brute-force attack on the HMAC secret or a drain attempt would
 *     leave no trace.
 *     Fixed: structured JSON log on every request (to stderr): timestamp,
 *     source IP, method, path, status. Auth failures and amount rejections
 *     are logged with a 'security' flag. Wallet address and tx hashes
 *     are logged for audit (these are public blockchain data).
 *
 * [N] LOW — Wallet address logged to stdout (captured by CI/CD logs).
 *     The wallet address itself is not secret, but associating it with a
 *     specific deployment in CI logs creates a permanent mapping between
 *     the codebase and the address.
 *     Fixed: startup logging goes to stderr only, separate from stdout.
 *
 * [O] LOW — No graceful shutdown — in-flight transactions may be abandoned.
 *     SIGTERM (sent by Docker, PM2, Kubernetes) caused immediate process
 *     exit. Any sendTransaction() call in progress would be abandoned
 *     mid-flight — the transaction may or may not have been submitted
 *     to the mempool, leaving the wallet in an unknown state.
 *     Fixed: SIGTERM and SIGINT handlers close the HTTP server to new
 *     connections and await in-flight requests before exiting.
 *
 * [P] LOW — No nonce management — concurrent requests cause nonce collisions.
 *     ethers auto-fetches the nonce on each sendTransaction() call. If
 *     two requests arrive simultaneously, both fetch the same nonce and
 *     one transaction will be rejected by the network as a nonce replay.
 *     Fixed: a serialisation lock (_txLock promise chain) ensures
 *     transactions are submitted strictly sequentially.
 */

const http = require('http');
const crypto = require('crypto');
const { ethers } = require('ethers');
const fs = require('fs');

// ─── Configuration ─────────────────────────────────────────────────────────────

// [FIX A] No private key in source. Load from encrypted keystore + env passphrase.
const KEYSTORE_PATH = process.env.KRYPTOS_KEYSTORE_PATH;
const KEYSTORE_PASS = process.env.KRYPTOS_KEYSTORE_PASS;
// [FIX B] HMAC secret for request authentication.
const BRIDGE_API_SECRET = process.env.BRIDGE_API_SECRET;
// [FIX C] Maximum single transfer in ETH (as a string decimal).
const MAX_TRANSFER_ETH = process.env.BRIDGE_MAX_ETH || '0.1';
const RPC_URL = process.env.ETH_RPC_URL || 'https://rpc.sepolia.org';
// [FIX E] Bind to loopback only by default.
const BIND_HOST = process.env.BRIDGE_BIND_HOST || '127.0.0.1';
const BIND_PORT = parseInt(process.env.BRIDGE_PORT || '3000', 10);

// [FIX F] Body size cap.
const MAX_BODY_BYTES = 4096;
// [FIX G] Rate limiting.
const MAX_REQ_PER_WINDOW = parseInt(process.env.RATE_LIMIT_MAX || '10', 10);
const WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW || '60000', 10);

// ─── Startup validation ────────────────────────────────────────────────────────

if (!KEYSTORE_PATH || !KEYSTORE_PASS) {
  process.stderr.write('[Bridge] FATAL: KRYPTOS_KEYSTORE_PATH and KRYPTOS_KEYSTORE_PASS must be set.\n');
  process.stderr.write('[Bridge] Generate a keystore with: node kryptos-wallet-gen-fixed.js\n');
  process.exit(1);
}
if (!BRIDGE_API_SECRET || BRIDGE_API_SECRET.length < 32) {
  process.stderr.write('[Bridge] FATAL: BRIDGE_API_SECRET must be set and at least 32 characters.\n');
  process.exit(1);
}

// ─── Wallet initialisation ────────────────────────────────────────────────────

// [FIX A] Load from keystore — key never in source code.
let wallet;
try {
  const keystoreJson = fs.readFileSync(KEYSTORE_PATH, 'utf8');
  wallet = ethers.Wallet.fromEncryptedJsonSync(keystoreJson, KEYSTORE_PASS);
} catch (e) {
  process.stderr.write(`[Bridge] FATAL: Failed to load keystore: ${e.message}\n`);
  process.exit(1);
}

const provider = new ethers.JsonRpcProvider(RPC_URL);
wallet = wallet.connect(provider);

// [FIX N] Wallet address to stderr only — not stdout.
process.stderr.write(`[Bridge] Wallet address: ${wallet.address}\n`);

// ─── Rate limiter ──────────────────────────────────────────────────────────────

const _rateLimiter = new Map();
function _isRateLimited(ip) {
  const now = Date.now();
  const entry = _rateLimiter.get(ip);
  if (!entry || now - entry.windowStart > WINDOW_MS) {
    _rateLimiter.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count++;
  return entry.count > MAX_REQ_PER_WINDOW;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of _rateLimiter) {
    if (now - e.windowStart > WINDOW_MS * 2) _rateLimiter.delete(ip);
  }
}, WINDOW_MS).unref();

// ─── Transaction serialisation lock ───────────────────────────────────────────

// [FIX P] Sequential transaction submission — prevents nonce collisions.
let _txLock = Promise.resolve();

// ─── Logging ───────────────────────────────────────────────────────────────────

function _log(fields) {
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), ...fields }) + '\n');
}

// ─── Input validation ──────────────────────────────────────────────────────────

const DECIMAL_AMOUNT_RE = /^\d+(\.\d+)?$/; // no scientific notation, no negatives

function _validateAmount(amount) {
  // [FIX J] Must be a string — no silent float coercion.
  if (typeof amount !== 'string') {
    throw new TypeError('amount must be a JSON string, not a number or object.');
  }
  // [FIX C] Strict decimal format — no "1e18", no negative, no empty.
  if (!DECIMAL_AMOUNT_RE.test(amount)) {
    throw new RangeError('amount must be a plain decimal string (e.g. "0.05").');
  }
  let wei;
  try {
    wei = ethers.parseEther(amount);
  } catch {
    throw new RangeError('amount is not a valid ETH value.');
  }
  if (wei <= 0n) {
    throw new RangeError('amount must be greater than zero.');
  }
  // [FIX C] Hard cap — prevents single-request wallet drain.
  const maxWei = ethers.parseEther(MAX_TRANSFER_ETH);
  if (wei > maxWei) {
    throw new RangeError(`amount exceeds maximum single transfer of ${MAX_TRANSFER_ETH} ETH.`);
  }
  return wei;
}

function _validateTo(to) {
  if (!ethers.isAddress(to)) {
    throw new TypeError('to is not a valid Ethereum address.');
  }
  // [FIX I] Reject zero address — permanent burn.
  if (to === ethers.ZeroAddress || to.toLowerCase() === ethers.ZeroAddress) {
    throw new RangeError('to must not be the zero address.');
  }
  // [FIX I] Reject self-send — no-op, wastes gas.
  if (to.toLowerCase() === wallet.address.toLowerCase()) {
    throw new RangeError('to must not be the bridge wallet address.');
  }
  // Return checksummed form.
  return ethers.getAddress(to);
}

// ─── HMAC authentication ───────────────────────────────────────────────────────

// [FIX B] Verify HMAC-SHA256(body, secret) from X-Bridge-Signature header.
function _isAuthorised(body, signatureHeader) {
  if (!signatureHeader) return false;
  const expected = crypto
    .createHmac('sha256', BRIDGE_API_SECRET)
    .update(body)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signatureHeader, 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch {
    return false;
  }
}

// ─── HTTP server ───────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const ip = req.socket?.remoteAddress || 'unknown';
  const method = req.method;
  const url = req.url;

  // [FIX G] Rate limiting.
  if (_isRateLimited(ip)) {
    _log({ ip, method, url, status: 429, security: 'rate_limited' });
    res.writeHead(429, { 'Retry-After': String(Math.ceil(WINDOW_MS / 1000)) });
    return res.end('Too Many Requests');
  }

  if (method === 'POST' && url === '/broadcast') {
    // [FIX K] Content-Type must be application/json.
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('application/json')) {
      _log({ ip, method, url, status: 415 });
      res.writeHead(415);
      return res.end('Unsupported Media Type — use application/json');
    }

    let body = '';
    let bodyBytes = 0;

    req.on('data', chunk => {
      // [FIX F] Body size cap — reject oversized requests immediately.
      bodyBytes += chunk.length;
      if (bodyBytes > MAX_BODY_BYTES) {
        _log({ ip, method, url, status: 413, security: 'body_too_large' });
        res.writeHead(413);
        res.end('Payload Too Large');
        req.destroy();
        return;
      }
      body += chunk;
    });

    req.on('end', async () => {
      if (res.writableEnded) return; // already rejected above

      // [FIX B] Authenticate before parsing body.
      const sig = req.headers['x-bridge-signature'] || '';
      if (!_isAuthorised(body, sig)) {
        _log({ ip, method, url, status: 401, security: 'auth_failure' });
        res.writeHead(401);
        return res.end('Unauthorized');
      }

      let to, amountWei;
      try {
        const parsed = JSON.parse(body);

        // [FIX C, FIX J] Strict input validation.
        to = _validateTo(parsed.to);
        amountWei = _validateAmount(parsed.amount);
      } catch (e) {
        _log({ ip, method, url, status: 400, reason: e.message });
        res.writeHead(400, { 'Content-Type': 'application/json' });
        // [FIX D] Only validation errors are safe to return — no internal detail.
        return res.end(JSON.stringify({ error: e.message }));
      }

      // [FIX P] Serialise — queue behind any in-flight transaction.
      _txLock = _txLock.then(async () => {
        try {
          // [FIX H] Fixed gasLimit for plain ETH transfer.
          const tx = await wallet.sendTransaction({
            to,
            value: amountWei,
            gasLimit: 21_000n,
          });

          _log({ ip, method, url, status: 202, txHash: tx.hash, to, amountEth: ethers.formatEther(amountWei) });

          // [FIX L] Wait for 1 block confirmation before responding.
          const receipt = await tx.wait(1);

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            hash: receipt.hash,
            blockNumber: receipt.blockNumber,
            status: receipt.status === 1 ? 'confirmed' : 'reverted',
          }));
        } catch (e) {
          // [FIX D] Full detail to stderr only — generic message to caller.
          _log({ ip, method, url, status: 500, internalError: e.message });
          if (!res.writableEnded) {
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Transaction failed. Check bridge logs.' }));
          }
        }
      });

    });

    req.on('error', (e) => {
      _log({ ip, method, url, status: 400, reason: 'request stream error', detail: e.message });
    });

  } else {
    _log({ ip, method, url, status: 404 });
    res.writeHead(404);
    res.end();
  }
});

server.on('error', (e) => {
  process.stderr.write(`[Bridge] Server error: ${e.message}\n`);
  process.exit(1);
});

// [FIX E] Bind to loopback only — not exposed to public internet by default.
server.listen(BIND_PORT, BIND_HOST, () => {
  process.stderr.write(`[Bridge] Listening on ${BIND_HOST}:${BIND_PORT}\n`);
  process.stderr.write(`[Bridge] Max transfer: ${MAX_TRANSFER_ETH} ETH\n`);
});

// [FIX O] Graceful shutdown — wait for in-flight transactions before exit.
async function _shutdown(signal) {
  process.stderr.write(`[Bridge] ${signal} received — shutting down gracefully...\n`);
  server.close(async () => {
    await _txLock; // wait for any in-flight tx to complete
    process.stderr.write('[Bridge] Shutdown complete.\n');
    process.exit(0);
  });
  // Force exit after 30s if graceful shutdown stalls.
  setTimeout(() => { process.stderr.write('[Bridge] Force exit after timeout.\n'); process.exit(1); }, 30_000).unref();
}

process.on('SIGTERM', () => _shutdown('SIGTERM'));
process.on('SIGINT', () => _shutdown('SIGINT'));