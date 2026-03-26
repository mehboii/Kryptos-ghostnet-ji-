/**
 * firewallLogger.js — Encrypted Audit Trail for the GhostNet Firewall
 * =====================================================================
 *
 * Every firewall event — blocked connections, detected attacks, rule
 * changes, integrity alerts — is recorded here. Logs are AES-256-GCM
 * encrypted in local storage so that even if the device is compromised,
 * the audit trail cannot be read without the session-derived key.
 *
 * Storage: Capacitor Preferences (falls back to localStorage in browser).
 * Rotation: oldest entries are evicted when total size exceeds maxLogSize.
 *
 * Event types (enum):
 *   CONNECTION_BLOCKED, PACKET_REJECTED, ANOMALY_DETECTED,
 *   QUARANTINE_ACTIVATED, INTEGRITY_ALERT, RULE_CHANGED,
 *   REPLAY_DETECTED, INJECTION_DETECTED, DDOS_DETECTED,
 *   MESH_POISON_DETECTED, SESSION_HIJACK, TIMING_ANALYSIS,
 *   FIREWALL_STARTED, FIREWALL_STOPPED, SELF_DEFENSE_ALERT
 */

import { LOGGER } from './firewallConfig.js';

// ─── Event Type Constants ────────────────────────────────────────────────────

export const EVENT = Object.freeze({
    CONNECTION_BLOCKED:   'CONNECTION_BLOCKED',
    PACKET_REJECTED:      'PACKET_REJECTED',
    ANOMALY_DETECTED:     'ANOMALY_DETECTED',
    QUARANTINE_ACTIVATED: 'QUARANTINE_ACTIVATED',
    QUARANTINE_RELEASED:  'QUARANTINE_RELEASED',
    INTEGRITY_ALERT:      'INTEGRITY_ALERT',
    RULE_CHANGED:         'RULE_CHANGED',
    REPLAY_DETECTED:      'REPLAY_DETECTED',
    INJECTION_DETECTED:   'INJECTION_DETECTED',
    DDOS_DETECTED:        'DDOS_DETECTED',
    MESH_POISON_DETECTED: 'MESH_POISON_DETECTED',
    SESSION_HIJACK:       'SESSION_HIJACK',
    TIMING_ANALYSIS:      'TIMING_ANALYSIS',
    FIREWALL_STARTED:     'FIREWALL_STARTED',
    FIREWALL_STOPPED:     'FIREWALL_STOPPED',
    SELF_DEFENSE_ALERT:   'SELF_DEFENSE_ALERT',
    EMERGENCY_MODE:       'EMERGENCY_MODE',
    REPUTATION_CHANGE:    'REPUTATION_CHANGE',
});

// ─── Crypto helpers (browser-native SubtleCrypto) ────────────────────────────

/**
 * Derive an AES-256-GCM key from a passphrase using PBKDF2.
 * The passphrase is the user's session token so logs are bound to
 * the current authenticated session.
 */
async function _deriveKey(passphrase) {
    const enc = new TextEncoder();
    // Generate a per-installation random salt, persisted to storage.
    // This prevents rainbow-table attacks across installations.
    let saltBytes;
    try {
        const store = await _getStore();
        const { value: storedSalt } = await store.get({ key: LOGGER.storagePrefix + 'kdf_salt' });
        if (storedSalt) {
            saltBytes = _base64ToBuf(storedSalt);
        } else {
            // First init: generate random 32-byte salt and persist it
            saltBytes = crypto.getRandomValues(new Uint8Array(32));
            await store.set({ key: LOGGER.storagePrefix + 'kdf_salt', value: _bufToBase64(saltBytes) });
        }
    } catch {
        // Fallback: deterministic salt if storage is unavailable
        saltBytes = enc.encode(LOGGER.storagePrefix + 'salt_fallback_v2');
    }
    const keyMaterial = await crypto.subtle.importKey(
        'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBytes, iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/** Encrypt a UTF-8 string → base64(iv + ciphertext) */
async function _encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(plaintext)
    );
    // Prepend IV to ciphertext
    const merged = new Uint8Array(iv.length + ct.byteLength);
    merged.set(iv);
    merged.set(new Uint8Array(ct), iv.length);
    return _bufToBase64(merged);
}

/** Decrypt base64(iv + ciphertext) → UTF-8 string */
async function _decrypt(b64, key) {
    const data = _base64ToBuf(b64);
    const iv = data.slice(0, 12);
    const ct = data.slice(12);
    const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ct
    );
    return new TextDecoder().decode(plain);
}

function _bufToBase64(buf) {
    let str = '';
    for (let i = 0; i < buf.length; i++) str += String.fromCharCode(buf[i]);
    return btoa(str);
}

function _base64ToBuf(b64) {
    const str = atob(b64);
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
    return buf;
}

// ─── Storage abstraction (Capacitor Preferences → localStorage fallback) ────

let _Preferences = null;

/** Attempt to load @capacitor/preferences at runtime */
async function _getStore() {
    if (_Preferences) return _Preferences;
    try {
        const mod = await import('@capacitor/preferences');
        _Preferences = mod.Preferences;
        return _Preferences;
    } catch {
        // Fallback: wrap localStorage in the same interface
        _Preferences = {
            async get({ key }) { return { value: localStorage.getItem(key) }; },
            async set({ key, value }) { localStorage.setItem(key, value); },
            async remove({ key }) { localStorage.removeItem(key); },
        };
        return _Preferences;
    }
}

// ─── Logger Class ────────────────────────────────────────────────────────────

class FirewallLogger {
    constructor() {
        /** @type {Array<object>} in-memory log buffer */
        this._entries = [];
        /** @type {CryptoKey|null} derived encryption key */
        this._key = null;
        /** Whether the logger is ready to write */
        this._ready = false;
        /** Tracks approximate byte size of current log */
        this._currentSize = 0;
        /** Flush timer handle */
        this._flushTimer = null;
        /** Counts for today's stats */
        this._dayCounts = {};
    }

    // ── Lifecycle ────────────────────────────────────────────────

    /**
     * Initialize the logger. Must be called once on app startup.
     * @param {string} sessionKey — user's session token or a derived secret
     */
    async init(sessionKey) {
        try {
            // Generate a per-device fallback key if no session key is provided.
            // Never use a hardcoded default — that's equivalent to no encryption.
            let passphrase = sessionKey;
            if (!passphrase) {
                try {
                    const store = await _getStore();
                    const { value: deviceKey } = await store.get({ key: LOGGER.storagePrefix + 'device_key' });
                    if (deviceKey) {
                        passphrase = deviceKey;
                    } else {
                        // First boot: generate a random device-bound key
                        const rnd = crypto.getRandomValues(new Uint8Array(32));
                        passphrase = Array.from(rnd).map(b => b.toString(16).padStart(2, '0')).join('');
                        await store.set({ key: LOGGER.storagePrefix + 'device_key', value: passphrase });
                    }
                } catch {
                    // Last resort: still better than a static string
                    passphrase = 'gn_' + Date.now().toString(36) + '_' + Math.random().toString(36);
                }
            }
            this._key = await _deriveKey(passphrase);
            await this._loadFromStorage();
            this._ready = true;
            // Auto-flush every 30 seconds
            this._flushTimer = setInterval(() => this._flush(), 30000);
            this.log(EVENT.FIREWALL_STARTED, null, 'allow', 'Firewall logger initialized');
        } catch (err) {
            console.error('[FW-Logger] Init failed:', err.message);
            // Fail open — logger broken should not block the firewall
            this._ready = true;
        }
    }

    /** Stop the logger and flush remaining entries */
    async shutdown() {
        if (this._flushTimer) clearInterval(this._flushTimer);
        this._flushTimer = null;
        this.log(EVENT.FIREWALL_STOPPED, null, 'allow', 'Firewall logger shutting down');
        await this._flush();
        this._ready = false;
    }

    // ── Public API ───────────────────────────────────────────────

    /**
     * Record a firewall event.
     * @param {string} eventType — one of the EVENT constants
     * @param {string|null} sourceNodeId — the node that caused the event
     * @param {'block'|'allow'|'flag'|'quarantine'|'alert'} action — what the firewall did
     * @param {string} reason — human-readable explanation
     * @param {object} [details] — extra data (severity, matched pattern, etc.)
     */
    log(eventType, sourceNodeId, action, reason, details = {}) {
        const entry = {
            timestamp: Date.now(),
            eventType,
            sourceNodeId: sourceNodeId ? String(sourceNodeId).slice(0, 128) : null,
            action,
            reason: String(reason).slice(0, 512),
            details: _sanitizeDetails(details),
        };

        this._entries.push(entry);
        this._currentSize += _estimateSize(entry);

        // Track daily counter for status dashboard
        this._dayCounts[eventType] = (this._dayCounts[eventType] || 0) + 1;

        // If buffer is getting large, flush eagerly
        if (this._entries.length > 500) {
            this._flush();
        }
    }

    /**
     * Get recent log entries (decrypted).
     * @param {number} [limit=100] — max entries to return
     * @returns {Array<object>}
     */
    getRecent(limit = 100) {
        return this._entries.slice(-limit);
    }

    /**
     * Get today's event counts grouped by type.
     * @returns {object}
     */
    getDayCounts() {
        return { ...this._dayCounts };
    }

    /**
     * Get total blocked events today.
     * @returns {number}
     */
    getBlockedToday() {
        return this._entries.filter(e =>
            e.action === 'block' &&
            _isToday(e.timestamp)
        ).length;
    }

    /**
     * Export all logs as a JSON string (for user export).
     * @returns {string} JSON array of log entries
     */
    exportLogs() {
        return JSON.stringify(this._entries, null, 2);
    }

    /**
     * Clear all logs (user action, requires authentication upstream).
     */
    async clearLogs() {
        this._entries = [];
        this._currentSize = 0;
        this._dayCounts = {};
        const store = await _getStore();
        await store.remove({ key: LOGGER.storagePrefix + 'log_0' });
        await store.remove({ key: LOGGER.storagePrefix + 'log_1' });
    }

    // ── Internal ─────────────────────────────────────────────────

    /** Load persisted (encrypted) logs from storage */
    async _loadFromStorage() {
        try {
            const store = await _getStore();
            const { value } = await store.get({ key: LOGGER.storagePrefix + 'log_0' });
            if (value && this._key) {
                const json = await _decrypt(value, this._key);
                this._entries = JSON.parse(json);
                this._currentSize = _estimateSize(this._entries);
            }
        } catch (err) {
            // Decryption failure (key changed, corrupted data) — start fresh
            console.warn('[FW-Logger] Could not load persisted logs:', err.message);
            this._entries = [];
            this._currentSize = 0;
        }
    }

    /** Persist current log buffer to encrypted storage */
    async _flush() {
        if (!this._key || this._entries.length === 0) return;
        try {
            // Enforce max size — evict oldest entries
            while (this._currentSize > LOGGER.maxLogSize && this._entries.length > 0) {
                const removed = this._entries.shift();
                this._currentSize -= _estimateSize(removed);
            }

            const json = JSON.stringify(this._entries);
            const encrypted = await _encrypt(json, this._key);
            const store = await _getStore();

            // Rotate: if current log file is too large, move to slot 1 and start fresh in slot 0
            if (encrypted.length > LOGGER.maxLogSize) {
                const { value: existing } = await store.get({ key: LOGGER.storagePrefix + 'log_0' });
                if (existing) {
                    await store.set({ key: LOGGER.storagePrefix + 'log_1', value: existing });
                }
                // Keep only the most recent half
                const half = Math.floor(this._entries.length / 2);
                this._entries = this._entries.slice(half);
                const freshJson = JSON.stringify(this._entries);
                const freshEncrypted = await _encrypt(freshJson, this._key);
                await store.set({ key: LOGGER.storagePrefix + 'log_0', value: freshEncrypted });
            } else {
                await store.set({ key: LOGGER.storagePrefix + 'log_0', value: encrypted });
            }
        } catch (err) {
            console.error('[FW-Logger] Flush error:', err.message);
        }
    }
}

// ─── Utility helpers ─────────────────────────────────────────────────────────

/** Rough byte-size estimate of an object (for quota tracking) */
function _estimateSize(obj) {
    try {
        return JSON.stringify(obj).length * 2; // UTF-16 approximation
    } catch {
        return 256;
    }
}

/** Sanitize details object — prevent prototype pollution / huge payloads */
function _sanitizeDetails(details) {
    if (!details || typeof details !== 'object') return {};
    const safe = {};
    const keys = Object.keys(details).slice(0, 20); // max 20 keys
    for (const k of keys) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
        const v = details[k];
        safe[k] = typeof v === 'string' ? v.slice(0, 1024) :
                   typeof v === 'number' || typeof v === 'boolean' ? v :
                   String(v).slice(0, 256);
    }
    return safe;
}

/** Check if a timestamp is from today */
function _isToday(ts) {
    const d = new Date(ts);
    const now = new Date();
    return d.getFullYear() === now.getFullYear() &&
           d.getMonth() === now.getMonth() &&
           d.getDate() === now.getDate();
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const firewallLogger = new FirewallLogger();
export default firewallLogger;
