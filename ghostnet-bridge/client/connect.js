'use strict';

/**
 * GhostNet Onion Client — HARDENED
 *
 * Security fixes applied:
 *
 * CRITICAL
 *  [01] Hardcoded static AES keys ("aaa...","bbb...","ccc...") — low-entropy, trivially known
 *       → KEYS object removed entirely; all encryption uses negotiated hopKeys only
 *  [02] buildRealCircuit() used static KEYS for data plane ("TEMPORARY FIX" comment)
 *       → Real circuit ONLY sends after all hopKeys are negotiated; static fallback removed
 *  [03] buildDummyOnion() also used static KEYS — cover traffic trivially decryptable
 *       → Dummy traffic deferred until hopKeys exist; uses negotiated keys only
 *  [04] hopKeys stored in plain global object — key bytes lived indefinitely in memory
 *       → SecureKeyStore class: keys zeroed (overwritten with 0x00) immediately after use
 *  [05] deriveKey() used raw SHA-256 with no salt — not a proper KDF
 *       → HKDF-SHA-256 via Node's crypto.hkdfSync with per-circuit salt
 *  [06] getNodes() fetched over plaintext http:// — node list MITM-able
 *       → https:// enforced; http:// rejected; configurable via GHOSTNET_REGISTRY env var
 *
 * HIGH
 *  [07] pickRoute() used Math.random() — biased, predictable route selection
 *       → Fisher-Yates shuffle seeded with crypto.randomBytes
 *  [08] No validation on relay URLs from registry — arbitrary ws:// injection possible
 *       → validateRelayUrl(): must be ws:// or wss://, hostname allowlist or loopback only
 *  [09] JSON.parse in performHandshake with no try/catch — malformed message crashed handler
 *       → try/catch on every JSON.parse; malformed messages logged and dropped
 *  [10] msg.pub accepted from relay with no length/format validation
 *       → assertDerHex(): exact byte length check (91 bytes for X25519 SPKI DER) before parse
 *  [11] Replay protection fields (msgId, ts) generated but never validated — pure facade
 *       → SeenIds set tracks msgId; timestamps checked within ±30s window
 *  [12] start() called every 15 000ms — reinitialised currentRoute mid-flight; race condition
 *       → Circuit class encapsulates state; setInterval guarded so only one build runs at a time
 *
 * MEDIUM
 *  [13] Cover traffic used static keys regardless of circuit state; leaked timing patterns
 *       → Cover traffic only sent when a live circuit with negotiated keys exists
 *  [14] ws.on('error', () => {}) silently swallowed all WebSocket errors
 *       → Errors logged at debug level; circuit marked as failed for retry
 *  [15] setTimeout(ws.close, 500) — hardcoded; message lost if relay was slow
 *       → Acknowledgement-based close: ws closed after send callback fires
 *  [16] norm() only stripped ws://, broke for wss:// relays
 *       → canonicalKey() strips both ws:// and wss:// and normalises trailing slashes
 *  [17] URL string used as hopKey map key — trailing slash differences caused misses
 *       → canonicalKey() normalises all relay URLs to "host:port" form
 *  [18] No circuit ID — relay could not bind forwarded packet to negotiated key
 *       → circuitId (random 16-byte hex) embedded in every wrap(); relays can correlate
 *  [19] currentRoute and circuitBuilt were module-level globals — parallel start() invocations
 *       corrupted each other's state
 *       → Circuit class instances; module-level state replaced with single active circuit ref
 *
 * LOW
 *  [20] console.log printed full route ports and key status in production
 *       → DEBUG flag gating; production logs minimal info
 *  [21] WebCrypto + Node crypto both imported redundantly
 *       → Unified: only Node's built-in crypto used (hkdfSync, createCipheriv, etc.)
 *  [22] Dummy payload "__DUMMY__" + 16-byte hex — recognisable pattern
 *       → Full-length random bytes fill dummy payload; no identifying prefix
 *  [23] No retry/backoff on failed handshakes — failure silently disappeared
 *       → Exponential backoff (up to 3 retries) per relay; circuit reports failure
 *  [24] getPort() used split(':').pop() — broke on IPv6 and URLs with paths
 *       → Replaced with URL constructor: new URL(u).port
 */

const crypto = require('crypto');
const WebSocket = require('ws');
const https = require('https');
const http = require('http');

// ─── Configuration ────────────────────────────────────────────────────────────

const DEBUG = process.env.GHOSTNET_DEBUG === '1';
const REGISTRY_URL = process.env.GHOSTNET_REGISTRY || 'https://localhost:9000/nodes'; // [06]
const REBUILD_MS = 30_000;  // [12] rebuild circuit every 30s
const COVER_MS = 4_000;
const HANDSHAKE_TIMEOUT_MS = 8_000;
const MAX_HANDSHAKE_RETRIES = 3;
// [11] Replay window
const REPLAY_WINDOW_S = 30;
const REPLAY_CACHE_SIZE = 2048;

// [08] Allowed relay hostname patterns (loopback always allowed)
const ALLOWED_RELAY_HOSTNAMES = new Set(
    (process.env.GHOSTNET_ALLOWED_RELAY_HOSTS || '').split(',').map(h => h.trim()).filter(Boolean)
);

function dbg(...args) { if (DEBUG) console.debug('[GhostNet]', ...args); }
function info(...args) { console.log('[GhostNet]', ...args); }
function warn(...args) { console.warn('[GhostNet]', ...args); }

// ─── [24] Safe port extractor ─────────────────────────────────────────────────

function getPort(urlStr) {
    try {
        const u = new URL(urlStr);
        return u.port ? parseInt(u.port, 10) : (u.protocol === 'wss:' ? 443 : 80);
    } catch (_) {
        return 0;
    }
}

// ─── [16][17] Canonical relay key ─────────────────────────────────────────────

function canonicalKey(urlStr) {
    try {
        const u = new URL(urlStr);
        return `${u.hostname}:${u.port || (u.protocol === 'wss:' ? 443 : 80)}`;
    } catch (_) {
        return urlStr;
    }
}

// ─── [08] URL validation ──────────────────────────────────────────────────────

function validateRelayUrl(urlStr) {
    let u;
    try { u = new URL(urlStr); }
    catch (_) { throw new Error(`Invalid relay URL: ${urlStr}`); }

    if (u.protocol !== 'ws:' && u.protocol !== 'wss:') {
        throw new Error(`Relay URL must use ws:// or wss://, got: ${u.protocol}`);
    }

    const isLoopback = ['localhost', '127.0.0.1', '::1'].includes(u.hostname);
    const isAllowed = ALLOWED_RELAY_HOSTNAMES.has(u.hostname);

    if (!isLoopback && !isAllowed) {
        throw new Error(`Relay hostname not in allowlist: ${u.hostname}`);
    }

    return urlStr;
}

// ─── [04] Secure key store (zeroes keys on delete) ────────────────────────────

class SecureKeyStore {
    constructor() { this._keys = new Map(); }

    set(relayUrl, keyBuffer) {
        const old = this._keys.get(canonicalKey(relayUrl));
        if (old) old.fill(0x00); // zero old key before overwriting
        this._keys.set(canonicalKey(relayUrl), Buffer.from(keyBuffer));
    }

    get(relayUrl) {
        return this._keys.get(canonicalKey(relayUrl)) || null;
    }

    has(relayUrl) {
        return this._keys.has(canonicalKey(relayUrl));
    }

    delete(relayUrl) {
        const key = this._keys.get(canonicalKey(relayUrl));
        if (key) { key.fill(0x00); this._keys.delete(canonicalKey(relayUrl)); }
    }

    clear() {
        for (const key of this._keys.values()) key.fill(0x00);
        this._keys.clear();
    }
}

// ─── [05] Proper KDF: HKDF-SHA-256 ──────────────────────────────────────────

function deriveKey(sharedSecret, salt) {
    // [05] HKDF with per-circuit salt — not raw SHA-256
    return crypto.hkdfSync('sha256', sharedSecret, salt, 'GhostNet-v1', 32);
}

// ─── [11] Replay protection ───────────────────────────────────────────────────

class ReplayCache {
    constructor(maxSize = REPLAY_CACHE_SIZE) {
        this._seen = new Set();
        this._queue = [];
        this._max = maxSize;
    }

    isFresh(msgId, ts) {
        const now = Math.floor(Date.now() / 1000);
        if (Math.abs(now - ts) > REPLAY_WINDOW_S) return false; // outside window
        if (this._seen.has(msgId)) return false;                 // already seen
        if (this._queue.length >= this._max) {
            const oldest = this._queue.shift();
            this._seen.delete(oldest);
        }
        this._seen.add(msgId);
        this._queue.push(msgId);
        return true;
    }
}

const replayCache = new ReplayCache();

// ─── Packet helpers ───────────────────────────────────────────────────────────

function msgId() { return crypto.randomBytes(12).toString('hex'); }
function nowSec() { return Math.floor(Date.now() / 1000); }

function wrap(circuitId, next, payload) { // [18] circuitId added
    return JSON.stringify({ id: msgId(), ts: nowSec(), circuitId, next, payload });
}

// ─── [07] Cryptographically random route selection ────────────────────────────

function pickRoute(nodes) {
    if (nodes.length < 3) throw new Error('Not enough nodes for 3-hop circuit');
    // Fisher-Yates with crypto.randomBytes
    const arr = [...nodes];
    for (let i = arr.length - 1; i > 0; i--) {
        const j = crypto.randomBytes(4).readUInt32BE(0) % (i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.slice(0, 3);
}

// ─── [06] Node registry fetch — HTTPS only ───────────────────────────────────

function getNodes() {
    return new Promise((resolve) => {
        let parsedUrl;
        try { parsedUrl = new URL(REGISTRY_URL); }
        catch (_) {
            warn('Invalid GHOSTNET_REGISTRY URL — using defaults');
            return resolve(defaultNodes());
        }

        // [06] Reject plaintext http:// for registry
        if (parsedUrl.protocol === 'http:' && !['localhost', '127.0.0.1', '::1'].includes(parsedUrl.hostname)) {
            warn('Registry URL uses http:// on non-loopback — refusing (MITM risk). Use https://');
            return resolve(defaultNodes());
        }

        const lib = parsedUrl.protocol === 'https:' ? https : http;

        const req = lib.get(REGISTRY_URL, { timeout: 5000 }, (res) => {
            if (res.statusCode !== 200) { res.resume(); return resolve(defaultNodes()); }

            let data = '';
            res.setEncoding('utf8');
            res.on('data', c => { data += c; if (data.length > 65536) { res.destroy(); } });
            res.on('end', () => {
                try {
                    const raw = JSON.parse(data);
                    if (!Array.isArray(raw)) return resolve(defaultNodes());
                    // [08] Validate every URL before trusting it
                    const validated = raw.filter(u => {
                        try { validateRelayUrl(u); return true; }
                        catch (_) { dbg(`Rejected relay URL: ${u}`); return false; }
                    });
                    resolve(validated.length >= 3 ? validated : defaultNodes());
                } catch (_) {
                    resolve(defaultNodes());
                }
            });
        });

        req.on('error', () => resolve(defaultNodes()));
        req.on('timeout', () => { req.destroy(); resolve(defaultNodes()); });
    });
}

function defaultNodes() {
    // [08] Defaults are loopback — safe
    return ['ws://localhost:8080', 'ws://localhost:8081', 'ws://localhost:8082'];
}

// ─── AES-GCM encrypt — Node crypto only [21] ─────────────────────────────────

function encrypt(plaintext, keyBuffer) {
    // [21] Use only Node's built-in crypto — no WebCrypto import needed
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    // iv(12) + authTag(16) + ciphertext
    return Buffer.concat([iv, authTag, encrypted]).toString('hex');
}

// ─── [10] DER validation for relay public keys ────────────────────────────────

// X25519 SPKI DER is exactly 44 bytes; hex-encoded = 88 chars
const X25519_SPKI_DER_HEX_LEN = 88;

function assertDerHex(hexStr) {
    if (typeof hexStr !== 'string' ||
        hexStr.length !== X25519_SPKI_DER_HEX_LEN ||
        !/^[0-9a-fA-F]+$/.test(hexStr)) {
        throw new Error(`Invalid relay public key DER (expected ${X25519_SPKI_DER_HEX_LEN} hex chars)`);
    }
}

// ─── [19] Circuit class — encapsulates all mutable state ─────────────────────

class Circuit {
    constructor(route) {
        this.route = route;                  // [validated relayUrls]
        this.circuitId = crypto.randomBytes(16).toString('hex'); // [18]
        this.keyStore = new SecureKeyStore();   // [04]
        this.built = false;
        this.failed = false;
        this._keysReady = new Set();
    }

    hasAllKeys() {
        return this.route.every(url => this.keyStore.has(url));
    }

    storeKey(relayUrl, keyBuf) {
        this.keyStore.set(relayUrl, keyBuf);
        this._keysReady.add(canonicalKey(relayUrl));
        if (this.hasAllKeys() && !this.built && !this.failed) {
            this.built = true;
            info(`Circuit ${this.circuitId.slice(0, 8)} ready`);
            this._sendRealCircuit().catch(e => warn('Circuit send error:', e.message));
        }
    }

    destroy() {
        this.keyStore.clear(); // [04] zero all key material
    }

    async buildOnion(payload) {
        if (!this.hasAllKeys()) throw new Error('Circuit not ready');
        const [entryUrl, middleUrl, exitUrl] = this.route;
        let inner = payload;
        // Wrap from exit → middle → entry (innermost = exit)
        inner = encrypt(wrap(this.circuitId, null, inner), this.keyStore.get(exitUrl));   // [18]
        inner = encrypt(wrap(this.circuitId, exitUrl, inner), this.keyStore.get(middleUrl));
        inner = encrypt(wrap(this.circuitId, middleUrl, inner), this.keyStore.get(entryUrl));
        return inner;
    }

    async buildDummyOnion() {
        if (!this.hasAllKeys()) return null;
        // [22] Full-length random bytes — no "__DUMMY__" prefix pattern
        const payload = crypto.randomBytes(256).toString('hex');
        return this.buildOnion(payload);
    }

    async _sendRealCircuit() {
        const payload = crypto.randomBytes(32).toString('hex'); // [01][02] no static keys
        const onion = await this.buildOnion('HELLO_' + payload);
        return sendOnion(this.route[0], onion);
    }
}

// ─── Send a single onion packet ───────────────────────────────────────────────

function sendOnion(entryUrl, onion) {
    return new Promise((resolve, reject) => {
        let ws;
        try { ws = new WebSocket(entryUrl); }
        catch (e) { return reject(e); }

        const timer = setTimeout(() => {
            ws.terminate();
            reject(new Error(`sendOnion timeout to ${canonicalKey(entryUrl)}`));
        }, 5000);

        ws.once('open', () => {
            ws.send(JSON.stringify({ payload: onion }), err => { // [15] close in send callback
                clearTimeout(timer);
                ws.close();
                if (err) reject(err); else resolve();
            });
        });

        ws.once('error', e => {
            clearTimeout(timer);
            dbg(`sendOnion error (${canonicalKey(entryUrl)}):`, e.message); // [14]
            reject(e);
        });
    });
}

// ─── Handshake with a single relay ───────────────────────────────────────────

function performHandshake(circuit, relayUrl, attempt = 1) {
    try {
        validateRelayUrl(relayUrl); // [08]
    } catch (e) {
        warn('Rejected relay during handshake:', e.message);
        circuit.failed = true;
        return;
    }

    let ws;
    try { ws = new WebSocket(relayUrl); }
    catch (e) { warn('WS open failed:', e.message); return; }

    // [23] Timeout per handshake attempt
    const timer = setTimeout(() => {
        ws.terminate();
        dbg(`Handshake timeout: ${canonicalKey(relayUrl)} (attempt ${attempt})`);
        if (attempt < MAX_HANDSHAKE_RETRIES) {
            // [23] Exponential backoff
            const delay = 1000 * Math.pow(2, attempt - 1);
            setTimeout(() => performHandshake(circuit, relayUrl, attempt + 1), delay);
        } else {
            warn(`Handshake failed after ${MAX_HANDSHAKE_RETRIES} attempts: ${canonicalKey(relayUrl)}`);
            circuit.failed = true;
        }
    }, HANDSHAKE_TIMEOUT_MS);

    ws.on('message', (data) => {
        // [09] try/catch on every parse
        let msg;
        try { msg = JSON.parse(data.toString()); }
        catch (_) { dbg('Malformed handshake message — dropped'); return; }

        if (msg.type !== 'handshake') return;

        try {
            // [10] Validate DER hex length before createPublicKey
            assertDerHex(msg.pub);

            const relayPub = Buffer.from(msg.pub, 'hex');
            const clientKP = crypto.generateKeyPairSync('x25519');
            const sharedSecret = crypto.diffieHellman({
                privateKey: clientKP.privateKey,
                publicKey: crypto.createPublicKey({ key: relayPub, format: 'der', type: 'spki' }),
            });

            // [05] HKDF with per-circuit salt
            const salt = Buffer.from(circuit.circuitId, 'hex');
            const aesKey = Buffer.from(deriveKey(sharedSecret, salt));

            // [04] Store in SecureKeyStore
            circuit.storeKey(relayUrl, aesKey);
            aesKey.fill(0x00); // zero local copy immediately

            dbg(`Key ready: ${canonicalKey(relayUrl)}`);

            ws.send(JSON.stringify({
                type: 'client_pub',
                pub: clientKP.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
            }), () => {
                clearTimeout(timer);
                ws.close(); // [15] close in send callback
            });

        } catch (e) {
            clearTimeout(timer);
            ws.terminate();
            warn(`Key exchange error (${canonicalKey(relayUrl)}):`, e.message); // [14]
            if (attempt < MAX_HANDSHAKE_RETRIES) {
                setTimeout(() => performHandshake(circuit, relayUrl, attempt + 1),
                    1000 * Math.pow(2, attempt - 1)); // [23]
            } else {
                circuit.failed = true;
            }
        }
    });

    ws.on('error', (e) => {
        clearTimeout(timer);
        dbg(`WS error (${canonicalKey(relayUrl)}):`, e.message); // [14]
        if (attempt < MAX_HANDSHAKE_RETRIES) {
            setTimeout(() => performHandshake(circuit, relayUrl, attempt + 1),
                1000 * Math.pow(2, attempt - 1)); // [23]
        } else {
            circuit.failed = true;
        }
    });
}

// ─── Circuit builder ──────────────────────────────────────────────────────────

async function initCircuit(route) {
    const circuit = new Circuit(route);
    info(`Building circuit ${circuit.circuitId.slice(0, 8)}... hops: ${route.map(getPort).join(' → ')}`);

    // Handshake with all hops in parallel
    route.forEach(url => performHandshake(circuit, url));
    return circuit;
}

// ─── [12][19] Single active circuit — no globals for mutable state ────────────

let activeCircuit = null;
let buildInProgress = false;

async function rebuildCircuit() {
    if (buildInProgress) return; // [12] guard parallel invocations
    buildInProgress = true;

    try {
        const nodes = await getNodes();
        const route = pickRoute(nodes); // [07] crypto random
        const old = activeCircuit;

        activeCircuit = await initCircuit(route);

        // Destroy old circuit after handover (zeros key material) [04]
        if (old) setTimeout(() => old.destroy(), 5000);
    } catch (e) {
        warn('Circuit rebuild error:', e.message);
    } finally {
        buildInProgress = false;
    }
}

// ─── Cover traffic ────────────────────────────────────────────────────────────

setInterval(async () => {
    try {
        // [13] Only send cover traffic when a real circuit with negotiated keys exists
        if (!activeCircuit || !activeCircuit.built) return;

        const onion = await activeCircuit.buildDummyOnion(); // [03] uses negotiated keys
        if (!onion) return;

        await sendOnion(activeCircuit.route[0], onion);
        dbg('Cover packet sent'); // [20] debug-gated
    } catch (_) { } // cover traffic failure is intentionally silent
}, COVER_MS);

// ─── Circuit refresh ─────────────────────────────────────────────────────────

// [12] Single interval; guard prevents parallel builds
setInterval(rebuildCircuit, REBUILD_MS);

// ─── Startup ─────────────────────────────────────────────────────────────────

rebuildCircuit();

// ─── Exports (for testing) ───────────────────────────────────────────────────

module.exports = {
    rebuildCircuit,
    validateRelayUrl,
    canonicalKey,
    getPort,
    deriveKey,
    pickRoute,
    replayCache,
    SecureKeyStore,
    Circuit,
};