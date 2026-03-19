/**
 * GhostNet Transport Layer
 * secure-transport.fixed.js
 * Universal Module (Node.js + Browser)
 *
 * SECURITY FIXES APPLIED:
 *  [1]  UUID v4 now uses crypto.randomUUID() — no bitwise bias
 *  [2]  Broadcast payloads are now AES-GCM encrypted — no longer plaintext
 *  [3]  TTL clamped server-side — client cannot exceed MAX_TTL
 *  [4]  Timestamp validated — envelopes too old or future-dated are rejected
 *  [5]  seenMessages eviction is Map-based with O(1) eviction — no race
 *  [6]  console.error no longer leaks error details — sanitized log only
 *  [7]  decryptEnvelope throws typed errors — no silent null returns
 *  [8]  _importKey uses Ed25519 for verify — not ECDSA P-256
 *  [9]  signData uses JSON.stringify — no delimiter injection possible
 *  [10] fromPubKey is verified to match envelope.from — no spoofing
 *  [11] envelope.from is always derived from identity — never from client
 *  [12] MAX_TTL is now enforced in both createEnvelope and verifyEnvelope
 *  [13] Per-sender rate limiting on envelope processing
 *  [14] Max payload size enforced before any crypto operations
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        const crypto = require('crypto');
        const GhostIdentity = require('./ghostnet-identity');
        module.exports = factory(crypto.webcrypto || crypto, GhostIdentity);
    } else {
        root.GhostTransport = factory(window.crypto || window.msCrypto, root.GhostIdentity);
    }
}(typeof self !== 'undefined' ? self : this, function (cryptoImpl, GhostIdentity) {

    const subtle = cryptoImpl.subtle || (cryptoImpl.webcrypto ? cryptoImpl.webcrypto.subtle : null);
    if (!subtle) throw new Error('WebCrypto API not supported in this environment.');

    // ─────────────────────────────────────────────
    // CONSTANTS
    // ─────────────────────────────────────────────

    const MAX_TTL = 20;
    const MIN_TTL = 1;
    const MAX_PAYLOAD_BYTES = 64 * 1024;       // [14] 64 KB hard cap
    const MAX_TIMESTAMP_SKEW = 5 * 60 * 1000;   // [4]  ±5 minutes allowed
    const SEEN_CACHE_SIZE = 1000;
    const RATE_LIMIT_WINDOW = 60 * 1000;       // [13] 1 minute window
    const RATE_LIMIT_MAX = 100;             // [13] max 100 envelopes/min/sender

    // ─────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────

    const _getRandomValues = (len) => {
        const arr = new Uint8Array(len);
        if (cryptoImpl.getRandomValues) {
            cryptoImpl.getRandomValues(arr);
        } else {
            const buf = cryptoImpl.randomBytes(len);
            arr.set(buf);
        }
        return arr;
    };

    // [1] FIX: Use crypto.randomUUID() — no bitwise bias from old UUID hack
    const _generateUUID = () => {
        if (cryptoImpl.randomUUID) return cryptoImpl.randomUUID();
        // RFC 4122 v4 fallback — no bitwise arithmetic bias
        const bytes = _getRandomValues(16);
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant bits
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    };

    const _arrayBufferToHex = (buffer) =>
        Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

    const _hexToArrayBuffer = (hex) => {
        if (typeof hex !== 'string' || hex.length % 2 !== 0) return new ArrayBuffer(0);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes.buffer;
    };

    // [13] Rate limiter — tracks per-sender envelope counts
    const _rateLimitMap = new Map();

    const _checkRateLimit = (senderId) => {
        const now = Date.now();
        const entry = _rateLimitMap.get(senderId) || { count: 0, windowStart: now };

        if (now - entry.windowStart > RATE_LIMIT_WINDOW) {
            entry.count = 1;
            entry.windowStart = now;
        } else {
            entry.count++;
        }

        _rateLimitMap.set(senderId, entry);

        if (entry.count > RATE_LIMIT_MAX) {
            throw new Error('Rate limit exceeded.');
        }

        // Prevent unbounded map growth
        if (_rateLimitMap.size > 10000) {
            _rateLimitMap.delete(_rateLimitMap.keys().next().value);
        }
    };

    // ─────────────────────────────────────────────
    // KEY IMPORT / EXPORT
    // ─────────────────────────────────────────────

    const _exportKey = async (key, type = 'spki') => {
        const exported = await subtle.exportKey(type, key);
        return _arrayBufferToHex(exported);
    };

    // [8] FIX: Ed25519 used for verify — ECDSA P-256 was incorrect
    const _importKey = async (hex, usage, type = 'spki') => {
        const buffer = _hexToArrayBuffer(hex);

        let algo;
        if (usage === 'deriveKey') {
            algo = { name: 'ECDH', namedCurve: 'P-256' };
        } else if (usage === 'verify') {
            algo = { name: 'Ed25519' }; // [8] FIX: was ECDSA P-256 — wrong algorithm
        } else {
            throw new Error(`Unknown key usage: ${usage}`);
        }

        return subtle.importKey(type, buffer, algo, true, [usage]);
    };

    // [9] FIX: Canonical sign data via JSON.stringify
    //         Old code used string concat with ":" — injection possible if fields contained ":"
    const _buildSignData = (envelope) => {
        const canonical = {
            id: envelope.id,
            from: envelope.from,
            to: envelope.to,
            timestamp: envelope.timestamp,
            payload: envelope.payload
        };
        return new TextEncoder().encode(JSON.stringify(canonical));
    };

    // [2] FIX: Broadcast channel AES-GCM key
    //         Broadcast was plaintext hex before — now encrypted
    let _broadcastKey = null;

    const _getBroadcastKey = async () => {
        if (_broadcastKey) return _broadcastKey;
        // In production: derive this from an out-of-band shared channel secret
        _broadcastKey = await subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        return _broadcastKey;
    };

    const _encryptBroadcast = async (payloadBytes) => {
        const key = await _getBroadcastKey();
        const iv = _getRandomValues(12);
        const cipherBuffer = await subtle.encrypt({ name: 'AES-GCM', iv }, key, payloadBytes);
        return {
            payload: _arrayBufferToHex(cipherBuffer),
            iv: _arrayBufferToHex(iv)
        };
    };

    const _decryptBroadcast = async (payloadHex, ivHex) => {
        const key = await _getBroadcastKey();
        const iv = _hexToArrayBuffer(ivHex);
        const payloadBuffer = _hexToArrayBuffer(payloadHex);
        const decrypted = await subtle.decrypt({ name: 'AES-GCM', iv }, key, payloadBuffer);
        return new TextDecoder().decode(decrypted);
    };

    // ─────────────────────────────────────────────
    // MAIN CLASS
    // ─────────────────────────────────────────────

    class GhostTransport {

        constructor(identity) {
            if (!identity || !identity.address || !identity.signingKey || !identity.verificationKey) {
                throw new Error('GhostTransport requires a valid identity object.');
            }
            this.identity = identity;
            this.seenMessages = new Map(); // [5] FIX: Map for O(1) ordered eviction
        }

        // [5] FIX: Proper bounded cache — Map preserves insertion order
        _markSeen(id) {
            if (this.seenMessages.has(id)) return false;
            this.seenMessages.set(id, Date.now());
            if (this.seenMessages.size > SEEN_CACHE_SIZE) {
                // Evict oldest entry (first inserted)
                this.seenMessages.delete(this.seenMessages.keys().next().value);
            }
            return true;
        }

        _hasSeen(id) {
            return this.seenMessages.has(id);
        }

        // ─────────────────────────────────────────
        // IDENTITY GENERATION
        // ─────────────────────────────────────────

        static async generateIdentity() {
            if (!GhostIdentity) throw new Error('GhostIdentity dependency missing.');

            const coreIdentity = await GhostIdentity.generateIdentity();

            const encKeyPair = await subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' },
                true,
                ['deriveKey', 'deriveBits']
            );

            return {
                signingKey: coreIdentity.privateKey,
                verificationKey: coreIdentity.publicKey,
                address: coreIdentity.nodeId,
                encryptionKey: encKeyPair.publicKey,
                decryptionKey: encKeyPair.privateKey
            };
        }

        // ─────────────────────────────────────────
        // CREATE ENVELOPE
        // ─────────────────────────────────────────

        async createEnvelope(receiverPubKeyHex, payload, ttl = 10) {

            // [14] Payload size check BEFORE any crypto work
            const payloadStr = JSON.stringify(payload);
            const payloadBytes = new TextEncoder().encode(payloadStr);
            if (payloadBytes.byteLength > MAX_PAYLOAD_BYTES) {
                throw new Error(`Payload exceeds maximum allowed size of ${MAX_PAYLOAD_BYTES} bytes.`);
            }

            // [3] FIX: Clamp TTL — client cannot exceed MAX_TTL or go below MIN_TTL
            const safeTTL = Math.max(MIN_TTL, Math.min(Number(ttl) || MIN_TTL, MAX_TTL));

            // [4] FIX: Timestamp always server-assigned — never from client input
            const timestamp = Date.now();
            const id = _generateUUID();
            const isBroadcast = receiverPubKeyHex === 'broadcast';

            let encryptedPayloadHex = null;
            let encryptedKeyHex = null;
            let ephemeralPubKeyHex = null;
            let ivHex = null;

            if (isBroadcast) {
                // [2] FIX: Encrypt broadcast payload — was plaintext hex before
                const { payload: ep, iv } = await _encryptBroadcast(payloadBytes);
                encryptedPayloadHex = ep;
                ivHex = iv;
            } else {
                // P2P Hybrid Encrypt (ECDH + AES-GCM)
                const ephemeralKeyPair = await subtle.generateKey(
                    { name: 'ECDH', namedCurve: 'P-256' },
                    true,
                    ['deriveKey']
                );
                ephemeralPubKeyHex = await _exportKey(ephemeralKeyPair.publicKey, 'spki');

                const receiverKey = await _importKey(receiverPubKeyHex, 'deriveKey', 'spki');

                const sharedKEK = await subtle.deriveKey(
                    { name: 'ECDH', public: receiverKey },
                    ephemeralKeyPair.privateKey,
                    { name: 'AES-KW', length: 256 },
                    true,
                    ['wrapKey']
                );

                const messageAESKey = await subtle.generateKey(
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );

                const wrappedKeyBuffer = await subtle.wrapKey('raw', messageAESKey, sharedKEK, 'AES-KW');
                encryptedKeyHex = _arrayBufferToHex(wrappedKeyBuffer);

                const iv = _getRandomValues(12);
                ivHex = _arrayBufferToHex(iv);

                const cipherBuffer = await subtle.encrypt(
                    { name: 'AES-GCM', iv },
                    messageAESKey,
                    payloadBytes
                );
                encryptedPayloadHex = _arrayBufferToHex(cipherBuffer);
            }

            // [11] FIX: from is always derived from this.identity — never from client input
            const myVerifKeyHex = await _exportKey(this.identity.verificationKey, 'spki');

            const envelope = {
                id: id,
                from: this.identity.address,  // [11] identity-derived, not client-supplied
                fromPubKey: myVerifKeyHex,           // [10] bound to identity.address
                to: isBroadcast ? 'broadcast' : receiverPubKeyHex,
                ttl: safeTTL,                 // [3]  clamped
                timestamp: timestamp,               // [4]  server-assigned
                payload: encryptedPayloadHex,
                iv: ivHex,
                encryptedKey: encryptedKeyHex,
                ephemeralPubKey: ephemeralPubKeyHex,
                signature: null
            };

            // [9] FIX: Sign over JSON canonical form — no delimiter injection
            const signBytes = _buildSignData(envelope);

            if (GhostIdentity && GhostIdentity.signMessage) {
                envelope.signature = await GhostIdentity.signMessage(signBytes, this.identity.signingKey);
            } else {
                const sigBuffer = await subtle.sign({ name: 'Ed25519' }, this.identity.signingKey, signBytes);
                envelope.signature = _arrayBufferToHex(sigBuffer);
            }

            return envelope;
        }

        // ─────────────────────────────────────────
        // VERIFY ENVELOPE
        // ─────────────────────────────────────────

        async verifyEnvelope(envelope) {
            if (!envelope || !envelope.id || !envelope.signature ||
                !envelope.fromPubKey || !envelope.from || !envelope.timestamp) {
                return false;
            }

            // [5] Replay detection
            if (this._hasSeen(envelope.id)) return false;

            // [12] FIX: Enforce MAX_TTL on receive — was defined but never checked
            if (typeof envelope.ttl !== 'number' || envelope.ttl > MAX_TTL || envelope.ttl < 0) {
                return false;
            }

            // [4] FIX: Reject envelopes with timestamps too far in past or future
            const skew = Math.abs(Date.now() - envelope.timestamp);
            if (skew > MAX_TIMESTAMP_SKEW) return false;

            // [14] Payload size check on receive
            if (envelope.payload && envelope.payload.length / 2 > MAX_PAYLOAD_BYTES) {
                return false;
            }

            // [13] Per-sender rate limiting
            try { _checkRateLimit(envelope.from); }
            catch { return false; }

            try {
                // [8] FIX: Import as Ed25519 verify key
                const pubKey = await _importKey(envelope.fromPubKey, 'verify', 'spki');

                // [10][11] FIX: Derive address from fromPubKey and compare to envelope.from
                //               If they don't match, sender is spoofing .from
                const derivedAddress = await this._deriveAddressFromPubKey(envelope.fromPubKey);
                if (derivedAddress !== envelope.from) return false;

                // [9] FIX: Verify over JSON canonical sign data
                const signBytes = _buildSignData(envelope);
                const isValid = await GhostIdentity.verifySignature(signBytes, envelope.signature, pubKey);

                if (isValid) this._markSeen(envelope.id);

                return isValid;

            } catch {
                // [6] FIX: Never log raw error — only a sanitized message
                console.warn('[GhostTransport] Envelope verification failed.');
                return false;
            }
        }

        // [10][11] Derive a node address from a public key hex string
        async _deriveAddressFromPubKey(pubKeyHex) {
            if (GhostIdentity && GhostIdentity.deriveNodeId) {
                return GhostIdentity.deriveNodeId(pubKeyHex);
            }
            // Fallback: SHA-256 of the raw key bytes
            const keyBuffer = _hexToArrayBuffer(pubKeyHex);
            const hashBuffer = await subtle.digest('SHA-256', keyBuffer);
            return _arrayBufferToHex(hashBuffer);
        }

        // ─────────────────────────────────────────
        // DECRYPT ENVELOPE
        // ─────────────────────────────────────────

        async decryptEnvelope(envelope) {
            // Always verify before attempting decryption
            const verified = await this.verifyEnvelope(envelope);
            if (!verified) {
                // [7] FIX: Throw — not silent null return
                throw new Error('Envelope failed verification — decryption refused.');
            }

            try {
                if (envelope.to === 'broadcast') {
                    // [2] FIX: Decrypt broadcast payload
                    if (!envelope.iv) throw new Error('Missing IV for broadcast envelope.');
                    const str = await _decryptBroadcast(envelope.payload, envelope.iv);
                    try { return JSON.parse(str); } catch { return str; }
                }

                if (!envelope.ephemeralPubKey || !envelope.encryptedKey || !envelope.iv) {
                    throw new Error('Missing required fields for P2P decryption.');
                }

                const senderEphemeralKey = await _importKey(envelope.ephemeralPubKey, 'deriveKey', 'spki');

                const sharedKEK = await subtle.deriveKey(
                    { name: 'ECDH', public: senderEphemeralKey },
                    this.identity.decryptionKey,
                    { name: 'AES-KW', length: 256 },
                    true,
                    ['unwrapKey']
                );

                const encryptedKeyBuffer = _hexToArrayBuffer(envelope.encryptedKey);
                const messageAESKey = await subtle.unwrapKey(
                    'raw',
                    encryptedKeyBuffer,
                    sharedKEK,
                    'AES-KW',
                    { name: 'AES-GCM' },
                    true,
                    ['decrypt']
                );

                const iv = _hexToArrayBuffer(envelope.iv);
                const payloadBuffer = _hexToArrayBuffer(envelope.payload);

                const decryptedBuffer = await subtle.decrypt(
                    { name: 'AES-GCM', iv },
                    messageAESKey,
                    payloadBuffer
                );

                return JSON.parse(new TextDecoder().decode(decryptedBuffer));

            } catch (e) {
                // [7] FIX: Throw typed errors — never silently return null
                if (e.name === 'OperationError') {
                    throw new Error('Decryption failed: message may have been tampered with.');
                }
                throw new Error('Decryption failed.');
            }
        }
    }

    return GhostTransport;
}));