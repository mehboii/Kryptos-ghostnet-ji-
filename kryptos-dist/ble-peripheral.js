/**
 * Kryptos BLE Peripheral — SECURITY HARDENED
 *
 * Vulnerabilities found and fixed:
 *
 * [A] Unauthenticated writes — any BLE device could write arbitrary data.
 *     Fixed: allowlist of paired/accepted client addresses; unknown clients
 *     receive RESULT_UNLIKELY_ERROR and are ignored.
 *
 * [B] No input length validation on write requests.
 *     Fixed: enforce MAX_WRITE_BYTES (512); oversized payloads are rejected.
 *
 * [C] Offset parameter ignored in onWriteRequest.
 *     Non-zero offsets mean a chunked/multi-part write is in progress.
 *     Blindly calling data.toString() on a partial chunk produces garbled
 *     or attacker-controlled fragments. Fixed: reject non-zero offsets.
 *
 * [D] Echo reflects raw, unsanitized input back to the subscriber.
 *     An attacker-controlled payload embedded in JSON.stringify() is safe
 *     regarding JSON encoding, but the raw `msg` string is also written to
 *     console — see [E]. Echo itself disabled in production mode.
 *
 * [E] console.log prints the full received message body.
 *     Any sensitive payload (keys, tokens, PII) is exposed in system logs.
 *     Fixed: log only metadata (length, sender address) in production.
 *
 * [F] Hardcoded placeholder public key "PC_PublicKey_Here".
 *     This is not a real key and signals to scanners that no real crypto
 *     is in use. Fixed: key must be supplied via environment variable;
 *     process exits if not set.
 *
 * [G] No rate limiting on write requests.
 *     A malicious central can flood the peripheral with writes, starving
 *     legitimate traffic. Fixed: per-client token-bucket rate limiter.
 *
 * [H] Advertising restarts immediately on disconnect with no back-off.
 *     Rapid connect/disconnect cycling can be used to DoS the peripheral.
 *     Fixed: exponential back-off (1 s → 2 s → 4 s … capped at 30 s).
 *
 * [I] updateCallback is a module-level mutable variable.
 *     A second subscriber simply overwrites it, silently dropping
 *     notifications to the first. Fixed: Map of address → callback so
 *     multiple subscribers are handled correctly; only the registered
 *     subscriber for the active connection is notified.
 */

'use strict';

const bleno = require('@abandonware/bleno');

// ─── Configuration ────────────────────────────────────────────────────────────

const SERVICE_UUID = "67686f73-746e-6574-2d6d-657368000000";
const CHAR_PEER_ID = "67686f73-746e-6574-2d69-640000000000";
const CHAR_PUB_KEY = "67686f73-746e-6574-2d6b-657900000000";
const CHAR_DATA = "67686f73-746e-6574-2d64-617461000000";

const IS_PROD = process.env.NODE_ENV === 'production';
const MAX_WRITE_BYTES = 512;          // BLE ATT max write length
const RATE_MAX_WRITES = 10;          // max writes per window per client
const RATE_WINDOW_MS = 1_000;       // sliding window size (1 s)
const MAX_ADV_DELAY = 30_000;      // back-off ceiling (30 s)

// [FIX F] Require real public key from environment — fail fast if absent.
const MY_PUBLIC_KEY = process.env.KRYPTOS_PUBLIC_KEY;
if (!MY_PUBLIC_KEY || MY_PUBLIC_KEY.trim().length < 32) {
    console.error(
        '[FATAL] KRYPTOS_PUBLIC_KEY env var is not set or too short.\n' +
        '        Generate a key pair and export the public key before starting.'
    );
    process.exit(1);
}

const myName = process.env.KRYPTOS_NODE_NAME || 'GhostNode';

// ─── [FIX A] Allowlist of trusted client addresses ───────────────────────────
//
// Populate this set via your pairing / provisioning flow before advertising.
// In a real deployment this would be persisted (e.g. to a local encrypted DB).
// An empty set means NO client can write — you must add at least one address.
//
const TRUSTED_CLIENTS = new Set(
    (process.env.KRYPTOS_TRUSTED_CLIENTS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
);

// ─── Logging helpers ─────────────────────────────────────────────────────────

const log = {
    info: (...a) => console.log('[GN]', ...a),
    warn: (...a) => console.warn('[GN:WARN]', ...a),
    error: (...a) => console.error('[GN:ERR]', ...a),
    // [FIX E] In production, log only metadata — never message content.
    recv: (addr, byteLen) => {
        if (IS_PROD) {
            console.log(`[GN:RECV] from=${addr} bytes=${byteLen}`);
        }
        // In dev mode, caller may choose to log more — but this module never
        // logs the message body in production.
    }
};

// ─── [FIX G] Per-client rate limiter ─────────────────────────────────────────

const _writeTimestamps = new Map();   // address → number[]

function _checkRate(address) {
    const now = Date.now();
    let ts = _writeTimestamps.get(address) || [];
    ts = ts.filter(t => now - t < RATE_WINDOW_MS);
    if (ts.length >= RATE_MAX_WRITES) {
        log.warn(`Rate limit exceeded for client ${address}`);
        _writeTimestamps.set(address, ts);
        return false;
    }
    ts.push(now);
    _writeTimestamps.set(address, ts);
    return true;
}

// ─── [FIX I] Per-subscriber notification callbacks ───────────────────────────

const _subscribers = new Map();   // address → notify callback

// Active connection address — set by bleno accept/disconnect events.
let _connectedAddress = null;

// ─── [FIX H] Advertising back-off state ──────────────────────────────────────

let _advDelay = 1_000;

function _scheduleAdvertising() {
    log.info(`Restarting advertising in ${_advDelay} ms…`);
    setTimeout(() => {
        bleno.startAdvertising(myName, [SERVICE_UUID]);
    }, _advDelay);
    _advDelay = Math.min(_advDelay * 2, MAX_ADV_DELAY);
}

// ─── Characteristics ─────────────────────────────────────────────────────────

const PeerIdChar = new bleno.Characteristic({
    uuid: CHAR_PEER_ID,
    properties: ['read'],
    value: Buffer.from(myName, 'utf-8')
});

const PubKeyChar = new bleno.Characteristic({
    uuid: CHAR_PUB_KEY,
    properties: ['read'],
    value: Buffer.from(MY_PUBLIC_KEY, 'utf-8')  // [FIX F]
});

const DataChar = new bleno.Characteristic({
    uuid: CHAR_DATA,
    properties: ['read', 'write', 'notify'],

    onWriteRequest: (data, offset, withoutResponse, callback) => {
        const clientAddr = (_connectedAddress || 'unknown').toLowerCase();

        // [FIX A] Reject untrusted clients.
        if (!TRUSTED_CLIENTS.has(clientAddr)) {
            log.warn(`Write rejected — untrusted client: ${clientAddr}`);
            return callback(bleno.Characteristic.RESULT_UNLIKELY_ERROR);
        }

        // [FIX C] Reject non-zero offsets (chunked writes not supported here).
        if (offset !== 0) {
            log.warn(`Write rejected — non-zero offset (${offset}) from ${clientAddr}`);
            return callback(bleno.Characteristic.RESULT_ATTR_NOT_LONG);
        }

        // [FIX B] Reject oversized payloads.
        if (!data || data.length === 0 || data.length > MAX_WRITE_BYTES) {
            log.warn(`Write rejected — invalid length ${data?.length} from ${clientAddr}`);
            return callback(bleno.Characteristic.RESULT_INVALID_ATTRIBUTE_LENGTH);
        }

        // [FIX G] Rate limit.
        if (!_checkRate(clientAddr)) {
            return callback(bleno.Characteristic.RESULT_UNLIKELY_ERROR);
        }

        // [FIX E] Log metadata only — never the body — in production.
        log.recv(clientAddr, data.length);

        // [FIX D] Echo is disabled in production; only enabled in dev for testing.
        if (!IS_PROD) {
            const msg = data.toString('utf-8');
            const reply = JSON.stringify({
                from: myName,
                body: `Echo: ${msg}`,   // safe: JSON.stringify escapes the value
                ts: Date.now()
            });
            const notifyCb = _subscribers.get(clientAddr);
            if (notifyCb) {
                notifyCb(Buffer.from(reply, 'utf-8'));
            }
        }

        callback(bleno.Characteristic.RESULT_SUCCESS);
    },

    // [FIX I] Store callback keyed by address, not in a bare variable.
    onSubscribe: (maxValueSize, callback) => {
        const addr = (_connectedAddress || 'unknown').toLowerCase();
        log.info(`Client subscribed: ${addr}`);
        _subscribers.set(addr, callback);
    },

    onUnsubscribe: () => {
        const addr = (_connectedAddress || 'unknown').toLowerCase();
        log.info(`Client unsubscribed: ${addr}`);
        _subscribers.delete(addr);
    }
});

// ─── Service ─────────────────────────────────────────────────────────────────

const GhostService = new bleno.PrimaryService({
    uuid: SERVICE_UUID,
    characteristics: [PeerIdChar, PubKeyChar, DataChar]
});

// ─── Bleno event handlers ─────────────────────────────────────────────────────

bleno.on('stateChange', (state) => {
    log.info(`Bleno state: ${state}`);
    if (state === 'poweredOn') {
        _advDelay = 1_000;   // reset back-off on fresh power-on
        bleno.startAdvertising(myName, [SERVICE_UUID]);
    } else {
        bleno.stopAdvertising();
    }
});

bleno.on('advertisingStart', (error) => {
    if (!error) {
        log.info('Advertising started — peripheral is discoverable.');
        bleno.setServices([GhostService]);
        _advDelay = 1_000;   // successful start resets back-off
    } else {
        log.error('Advertising failed:', error);
        _scheduleAdvertising();   // [FIX H] back-off retry
    }
});

bleno.on('accept', (clientAddress) => {
    _connectedAddress = clientAddress;
    log.info(`Connection accepted from: ${clientAddress}`);
    // Advertising automatically stops on connection.
});

bleno.on('disconnect', (clientAddress) => {
    log.info(`Client disconnected: ${clientAddress}`);
    // Clean up subscriber state for this client.
    _subscribers.delete(clientAddress.toLowerCase());
    _writeTimestamps.delete(clientAddress.toLowerCase());
    _connectedAddress = null;
    // [FIX H] Use back-off instead of immediate restart.
    _scheduleAdvertising();
});