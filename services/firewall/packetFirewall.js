/**
 * packetFirewall.js — Layer 2: Packet Inspection
 * =================================================
 *
 * Second line of defense. After a connection is allowed by Layer 1,
 * every packet (message, file transfer, control signal) passes through
 * here for deep inspection. Responsible for:
 *
 *   5. Payload validation (size, structure, schema)
 *   6. Encryption verification
 *   7. Injection detection (SQL, XSS, command injection, path traversal)
 *   8. Replay attack prevention (nonce + timestamp cache)
 *   9. Deep packet inspection (encoding anomalies, type mismatch)
 *
 * All decisions are logged via firewallLogger.
 */

import { PACKET, INJECTION_PATTERNS } from './firewallConfig.js';
import { firewallLogger, EVENT } from './firewallLogger.js';
import { reputationEngine } from './reputationEngine.js';

// ─── PacketFirewall ──────────────────────────────────────────────────────────

class PacketFirewall {
    constructor() {
        /**
         * Rolling nonce cache for replay detection.
         * Map: nonce → timestamp (when it was first seen)
         * @type {Map<string, number>}
         */
        this._nonceCache = new Map();

        /** Config (can be overridden by shield level) */
        this._config = { ...PACKET };

        /** Compiled injection patterns (cached for performance) */
        this._injectionPatterns = INJECTION_PATTERNS.map(p => ({
            ...p,
            compiled: p.regex,
        }));

        /** Cleanup timer for nonce cache */
        this._cleanupTimer = null;

        /** Packet inspection stats */
        this._stats = {
            inspected: 0,
            passed: 0,
            rejected: 0,
            injectionBlocks: 0,
            replayBlocks: 0,
        };
    }

    // ── Lifecycle ────────────────────────────────────────────────

    init() {
        // Purge expired nonces every 60 seconds
        this._cleanupTimer = setInterval(() => this._purgeNonces(), 60000);
    }

    shutdown() {
        if (this._cleanupTimer) clearInterval(this._cleanupTimer);
        this._cleanupTimer = null;
    }

    /**
     * Update config values when shield level changes.
     * @param {object} packetConfig
     */
    updateConfig(packetConfig) {
        this._config = { ...PACKET, ...packetConfig };
    }

    // ── Main entry point ─────────────────────────────────────────

    /**
     * Inspect an incoming packet. Returns a verdict with details.
     *
     * @param {object} packet — the raw incoming packet/message
     * @param {string} sourceNodeId — who sent it
     * @param {'message'|'file'|'control'} packetType — what kind of payload
     * @returns {{ allowed: boolean, reason: string, details?: object }}
     */
    inspect(packet, sourceNodeId, packetType = 'message') {
        this._stats.inspected++;

        try {
            // 5. Payload size validation
            const sizeResult = this._checkPayloadSize(packet, packetType);
            if (!sizeResult.allowed) {
                this._stats.rejected++;
                reputationEngine.applyDelta(sourceNodeId, -PACKET.malformedPenalty, 'oversized_payload');
                firewallLogger.log(EVENT.PACKET_REJECTED, sourceNodeId, 'block',
                    sizeResult.reason, { packetType, size: sizeResult.size });
                return sizeResult;
            }

            // 5b. Schema validation
            const schemaResult = this._validateSchema(packet);
            if (!schemaResult.allowed) {
                this._stats.rejected++;
                reputationEngine.applyDelta(sourceNodeId, -PACKET.malformedPenalty, 'invalid_schema');
                firewallLogger.log(EVENT.PACKET_REJECTED, sourceNodeId, 'block',
                    schemaResult.reason, { missingFields: schemaResult.missingFields });
                return schemaResult;
            }

            // 6. Encryption verification
            const encResult = this._verifyEncryption(packet, sourceNodeId);
            if (!encResult.allowed) {
                this._stats.rejected++;
                firewallLogger.log(EVENT.PACKET_REJECTED, sourceNodeId, 'block',
                    encResult.reason);
                return encResult;
            }

            // 8. Replay attack prevention (check before content inspection)
            const replayResult = this._checkReplay(packet, sourceNodeId);
            if (!replayResult.allowed) {
                this._stats.rejected++;
                this._stats.replayBlocks++;
                firewallLogger.log(EVENT.REPLAY_DETECTED, sourceNodeId, 'block',
                    replayResult.reason, { nonce: packet.nonce });
                return replayResult;
            }

            // 7. Injection detection (scan text content)
            if (this._config.enableInjectionDetection) {
                const injResult = this._scanForInjection(packet, sourceNodeId);
                if (!injResult.allowed) {
                    this._stats.rejected++;
                    this._stats.injectionBlocks++;
                    return injResult;
                }
            }

            // 9. Deep packet inspection (encoding anomalies)
            const dpiResult = this._deepInspect(packet, sourceNodeId, packetType);
            if (!dpiResult.allowed) {
                this._stats.rejected++;
                firewallLogger.log(EVENT.PACKET_REJECTED, sourceNodeId, 'flag',
                    dpiResult.reason, dpiResult.details);
                return dpiResult;
            }

            // All checks passed
            this._stats.passed++;
            return { allowed: true, reason: 'packet_clean' };

        } catch (err) {
            // Fail open — don't crash the app on inspection error
            console.error('[FW-L2] inspect error:', err.message);
            this._stats.passed++;
            return { allowed: true, reason: 'inspection_error_failopen' };
        }
    }

    // ── 5. Payload Size Validation ───────────────────────────────

    /**
     * Check if the packet exceeds the size limit for its type.
     */
    _checkPayloadSize(packet, packetType) {
        let payloadStr;
        try {
            payloadStr = typeof packet === 'string' ? packet : JSON.stringify(packet);
        } catch {
            return { allowed: false, reason: 'unserializable_payload', size: 0 };
        }

        const size = new Blob([payloadStr]).size;
        const limit = packetType === 'file'
            ? this._config.maxFileSize
            : this._config.maxMessageSize;

        if (size > limit) {
            return {
                allowed: false,
                reason: `Payload exceeds ${packetType} size limit (${_formatBytes(size)} > ${_formatBytes(limit)})`,
                size,
            };
        }
        return { allowed: true, reason: 'size_ok', size };
    }

    // ── 5b. Schema Validation ────────────────────────────────────

    /**
     * Validate that the packet conforms to the GhostNet protocol schema.
     * Expected: { type: string, payload: object, timestamp: number,
     *             nonce: string, signature: string }
     */
    _validateSchema(packet) {
        if (!packet || typeof packet !== 'object') {
            return { allowed: false, reason: 'Packet is not an object', missingFields: ['*'] };
        }

        const required = ['type', 'payload', 'timestamp', 'nonce', 'signature'];
        const missing = required.filter(f => !(f in packet));

        if (missing.length > 0) {
            return {
                allowed: false,
                reason: `Missing required fields: ${missing.join(', ')}`,
                missingFields: missing,
            };
        }

        // Type checks
        if (typeof packet.type !== 'string' || packet.type.length === 0 || packet.type.length > 64) {
            return { allowed: false, reason: 'Invalid packet type field', missingFields: [] };
        }
        if (typeof packet.payload !== 'object' || packet.payload === null) {
            return { allowed: false, reason: 'Payload must be a non-null object', missingFields: [] };
        }
        if (typeof packet.timestamp !== 'number' || !Number.isFinite(packet.timestamp)) {
            return { allowed: false, reason: 'Timestamp must be a finite number', missingFields: [] };
        }
        if (typeof packet.nonce !== 'string' || packet.nonce.length < 16 || packet.nonce.length > 128) {
            return { allowed: false, reason: 'Nonce must be 16-128 chars', missingFields: [] };
        }
        if (typeof packet.signature !== 'string' || packet.signature.length < 16) {
            return { allowed: false, reason: 'Invalid signature field', missingFields: [] };
        }

        return { allowed: true, reason: 'schema_valid', missingFields: [] };
    }

    // ── 6. Encryption Verification ───────────────────────────────

    /**
     * Verify that the packet's payload is properly encrypted.
     * Checks for indicators of AES-256-GCM encryption (IV, authTag).
     */
    _verifyEncryption(packet, sourceNodeId) {
        // If payload contains raw plaintext indicators, it's unencrypted
        const payload = packet.payload;

        if (typeof payload === 'string') {
            // Check for base64 encoding (encrypted payloads should be base64)
            if (!_isLikelyEncrypted(payload)) {
                // Track unencrypted packet count
                const record = reputationEngine.getRecord(sourceNodeId);
                const unencCount = (record?._unencryptedCount || 0) + 1;
                if (record) record._unencryptedCount = unencCount;

                if (unencCount >= 3) {
                    reputationEngine.recordAttackPattern(sourceNodeId, 'unencrypted_traffic');
                    return {
                        allowed: false,
                        reason: 'Repeated unencrypted packets — auto-blacklisting',
                    };
                }
                return {
                    allowed: false,
                    reason: 'Payload does not appear to be encrypted',
                };
            }
        }

        // Object payloads: check for encryption metadata fields
        if (typeof payload === 'object' && payload !== null) {
            // Encrypted payloads should have iv/nonce and ciphertext or encryptedData
            const hasEncryptionFields = payload.iv || payload.nonce ||
                payload.ciphertext || payload.encryptedData || payload.encrypted;
            if (!hasEncryptionFields && payload.content && typeof payload.content === 'string') {
                // This looks like a plaintext message object
                // Allow it if it's an internal control message
                if (['PING', 'PONG', 'HELLO', 'ACK'].includes(packet.type)) {
                    return { allowed: true, reason: 'control_message_exempt' };
                }
                // Flag but don't block — might be a legitimate plaintext field
                firewallLogger.log(EVENT.PACKET_REJECTED, sourceNodeId, 'flag',
                    'Payload may be unencrypted — flagged for review');
            }
        }

        return { allowed: true, reason: 'encryption_ok' };
    }

    // ── 7. Injection Detection ───────────────────────────────────

    /**
     * Scan all text content in the packet for injection patterns.
     * Recursively inspects nested objects up to 5 levels deep.
     */
    _scanForInjection(packet, sourceNodeId) {
        const textContent = _extractTextContent(packet, 5);

        for (const text of textContent) {
            for (const pattern of this._injectionPatterns) {
                if (pattern.compiled.test(text)) {
                    // Match found
                    reputationEngine.recordAttackPattern(sourceNodeId, pattern.name);

                    firewallLogger.log(EVENT.INJECTION_DETECTED, sourceNodeId, 'block',
                        `Injection pattern detected: ${pattern.name}`, {
                            severity: pattern.severity,
                            pattern: pattern.name,
                            matchedText: text.slice(0, 100), // truncate for log
                        });

                    if (pattern.severity === 'critical' || pattern.severity === 'high') {
                        return {
                            allowed: false,
                            reason: `Injection detected: ${pattern.name} (${pattern.severity})`,
                            details: { pattern: pattern.name, severity: pattern.severity },
                        };
                    }
                    // Medium severity: flag but don't block
                    // Continue checking for more severe patterns
                }
            }
        }

        return { allowed: true, reason: 'no_injection' };
    }

    // ── 8. Replay Attack Prevention ──────────────────────────────

    /**
     * Check if this packet's nonce has been seen before (replay)
     * and if its timestamp is within the acceptable window.
     */
    _checkReplay(packet, sourceNodeId) {
        const { nonce, timestamp } = packet;

        // Timestamp freshness check
        const age = Math.abs(Date.now() - timestamp);
        if (age > this._config.maxTimestampAge) {
            reputationEngine.applyDelta(sourceNodeId, -5, 'stale_timestamp');
            return {
                allowed: false,
                reason: `Stale packet: timestamp is ${Math.round(age / 1000)}s old (max ${this._config.maxTimestampAge / 1000}s)`,
            };
        }

        // Nonce uniqueness check
        if (this._nonceCache.has(nonce)) {
            reputationEngine.recordAttackPattern(sourceNodeId, 'replay');
            return {
                allowed: false,
                reason: 'Replay attack detected: duplicate nonce',
            };
        }

        // Record this nonce
        this._nonceCache.set(nonce, Date.now());

        // Enforce cache size limit (LRU eviction)
        if (this._nonceCache.size > this._config.nonceCacheSize) {
            const oldest = this._nonceCache.keys().next().value;
            this._nonceCache.delete(oldest);
        }

        return { allowed: true, reason: 'nonce_unique' };
    }

    // ── 9. Deep Packet Inspection ────────────────────────────────

    /**
     * Inspect packet content for anomalies that passed basic validation:
     *   - Unexpected base64 layers (double encoding)
     *   - Embedded binary in text messages
     *   - Type/payload mismatch
     */
    _deepInspect(packet, sourceNodeId, packetType) {
        const payload = packet.payload;

        // Check for double encoding (base64 inside base64)
        if (typeof payload === 'string' && _isBase64(payload)) {
            try {
                const decoded = atob(payload);
                if (_isBase64(decoded)) {
                    reputationEngine.applyDelta(sourceNodeId, -PACKET.suspiciousPenalty, 'double_encoding');
                    firewallLogger.log(EVENT.PACKET_REJECTED, sourceNodeId, 'flag',
                        'Double base64 encoding detected — possible evasion attempt');
                    return {
                        allowed: false,
                        reason: 'Suspicious double encoding detected',
                        details: { type: 'double_base64' },
                    };
                }
            } catch {
                // Not valid base64 — that's fine
            }
        }

        // Check for binary content in text messages
        if (packetType === 'message' && typeof payload === 'object' && payload.content) {
            const content = String(payload.content);
            const binaryRatio = _binaryCharRatio(content);
            if (binaryRatio > 0.3) {
                reputationEngine.applyDelta(sourceNodeId, -PACKET.suspiciousPenalty, 'binary_in_text');
                firewallLogger.log(EVENT.PACKET_REJECTED, sourceNodeId, 'flag',
                    'Binary content detected in text message', {
                        binaryRatio: Math.round(binaryRatio * 100) + '%',
                    });
                // Flag but allow — could be a legitimate emoji-heavy message
            }
        }

        // Type mismatch detection
        if (packet.type === 'text' && typeof payload === 'object' &&
            payload.data && typeof payload.data !== 'string') {
            reputationEngine.applyDelta(sourceNodeId, -PACKET.suspiciousPenalty, 'type_mismatch');
            firewallLogger.log(EVENT.PACKET_REJECTED, sourceNodeId, 'flag',
                'Packet type "text" but payload.data is not a string');
        }

        return { allowed: true, reason: 'dpi_clean', details: {} };
    }

    // ── Nonce cache maintenance ──────────────────────────────────

    /** Purge expired nonces from the cache */
    _purgeNonces() {
        const now = Date.now();
        const ttl = this._config.nonceCacheTTL;
        for (const [nonce, ts] of this._nonceCache) {
            if (now - ts > ttl) this._nonceCache.delete(nonce);
        }
    }

    // ── Stats ────────────────────────────────────────────────────

    /** Get packet inspection statistics */
    getStats() {
        return { ...this._stats, nonceCacheSize: this._nonceCache.size };
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Check if a string looks like it could be encrypted (base64 with high entropy) */
function _isLikelyEncrypted(str) {
    if (typeof str !== 'string' || str.length < 32) return false;
    // Encrypted data is typically base64 with high character diversity
    if (_isBase64(str)) return true;
    // Check for hex-encoded data
    if (/^[0-9a-fA-F]+$/.test(str) && str.length >= 64) return true;
    return false;
}

/** Check if a string is valid base64 */
function _isBase64(str) {
    if (typeof str !== 'string' || str.length < 4) return false;
    return /^[A-Za-z0-9+/]+=*$/.test(str) && str.length % 4 === 0;
}

/**
 * Recursively extract all string values from a nested object.
 * Used to scan for injection patterns in any text field.
 * @param {*} obj
 * @param {number} maxDepth
 * @returns {string[]}
 */
function _extractTextContent(obj, maxDepth = 5) {
    const texts = [];
    if (maxDepth <= 0) return texts;

    if (typeof obj === 'string') {
        texts.push(obj);
    } else if (Array.isArray(obj)) {
        for (const item of obj.slice(0, 100)) { // cap array traversal
            texts.push(..._extractTextContent(item, maxDepth - 1));
        }
    } else if (obj && typeof obj === 'object') {
        for (const key of Object.keys(obj).slice(0, 50)) { // cap key traversal
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
            texts.push(..._extractTextContent(obj[key], maxDepth - 1));
        }
    }
    return texts;
}

/** Calculate the ratio of non-printable characters in a string */
function _binaryCharRatio(str) {
    if (!str || str.length === 0) return 0;
    let binaryCount = 0;
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        // Non-printable ASCII (excluding common whitespace)
        if (code < 32 && code !== 9 && code !== 10 && code !== 13) binaryCount++;
        if (code > 126 && code < 160) binaryCount++;
    }
    return binaryCount / str.length;
}

/** Format bytes for human-readable output */
function _formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ─── Singleton Export ────────────────────────────────────────────────────────

export const packetFirewall = new PacketFirewall();
export default packetFirewall;
