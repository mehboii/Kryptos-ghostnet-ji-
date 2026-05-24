/**
 * GhostNet Transport Layer
 * secure-transport.js
 * Universal Module (Node.js + Browser)
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        // Node.js
        const crypto = require('crypto');
        const GhostIdentity = require('./ghostnet-identity');
        module.exports = factory(crypto.webcrypto || crypto, GhostIdentity);
    } else {
        // Browser
        root.GhostTransport = factory(window.crypto || window.msCrypto, root.GhostIdentity);
    }
}(typeof self !== 'undefined' ? self : this, function (cryptoImpl, GhostIdentity) {

    // Helper: Get SubtleCrypto
    const subtle = cryptoImpl.subtle || (cryptoImpl.webcrypto ? cryptoImpl.webcrypto.subtle : null);

    if (!subtle) {
        throw new Error("WebCrypto API not supported here");
    }

    // Helper: Buffer Compat
    const _getRandomValues = (len) => {
        if (cryptoImpl.getRandomValues) {
            return cryptoImpl.getRandomValues(new Uint8Array(len));
        }
        return cryptoImpl.randomBytes(len); // Node fallback
        // crypto.randomBytes returns Buffer, which is Uint8Array enough
    };

    class GhostTransport {
        constructor(identity) {
            this.identity = identity;
            this.seenMessages = new Set();
            this.processedCacheSize = 1000;
            this.MAX_TTL = 20;

            // Constants
            this.ALGO_ENCRYPT = { name: "ECDH", namedCurve: "P-256" };
            this.ALGO_AES = "AES-GCM";
            this.ALGO_WRAP = "AES-KW";
        }

        // --- UTILS ---

        async _exportKey(key, type = 'spki') {
            const exported = await subtle.exportKey(type, key);
            return this._arrayBufferToHex(exported);
        }

        async _importKey(hex, usage, type = 'spki') {
            const buffer = this._hexToArrayBuffer(hex);

            // Usage for ECDH vs ECDSA
            let algo;
            if (usage === 'deriveKey') algo = this.ALGO_ENCRYPT;
            else algo = { name: "ECDSA", namedCurve: "P-256" }; // Fallback

            // Special Check: If hex is Ed25519 (32 bytes raw), import usage is 'verify'
            // We need context. For now assuming P-256 unless explicit.

            // Because verifyEnvelope calls importKey for Ed25519 signature verification:
            if (usage === 'verify') {
                algo = { name: "ECDSA", namedCurve: "P-256" }; // Matched with GhostIdentity implementation
            }

            return subtle.importKey(type, buffer, algo, true, [usage]);
        }

        _arrayBufferToHex(buffer) {
            return Array.from(new Uint8Array(buffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }

        _hexToArrayBuffer(hex) {
            if (typeof hex !== 'string') return new ArrayBuffer(0);
            const bytes = new Uint8Array(Math.ceil(hex.length / 2));
            for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
            return bytes.buffer;
        }

        _generateUUID() {
            // Basic UUID v4
            return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c =>
                (c ^ _getRandomValues(1)[0] & 15 >> c / 4).toString(16)
            );
        }

        // --- CORE GENERATORS ---

        static async generateIdentity() {
            // 1. Core Identity (Ed25519)
            let coreIdentity;
            if (GhostIdentity) {
                coreIdentity = await GhostIdentity.generateIdentity();
            } else {
                throw new Error("GhostIdentity dependency missing");
            }

            // 2. Encryption Keys (ECDH P-256)
            // [FIX 21] extractable: false — private ECDH key cannot be exported
            const encKeyPair = await subtle.generateKey(
                { name: "ECDH", namedCurve: "P-256" },
                false,
                ["deriveKey", "deriveBits"]
            );

            // [FIX 21] Seal private keys — only expose public keys and
            // method handles. Private keys stay in closure scope.
            const _signingKey = coreIdentity.privateKey;
            const _decryptionKey = encKeyPair.privateKey;

            return {
                verificationKey: coreIdentity.publicKey,
                address: coreIdentity.nodeId,
                encryptionKey: encKeyPair.publicKey,
                // Accessor needed internally by GhostTransport — not directly
                // exposed as a plain property to prevent accidental serialization.
                get signingKey() { return _signingKey; },
                get decryptionKey() { return _decryptionKey; },
            };
        }

        // --- TRANSPORT LOGIC ---

        async createEnvelope(receiverPubKeyHex, payload, ttl = 10) {
            const timestamp = Date.now();
            const id = this._generateUUID();
            const payloadStr = JSON.stringify(payload);
            const payloadBytes = new TextEncoder().encode(payloadStr);

            let encryptedPayloadHex = null;
            let encryptedKeyHex = null;
            let ephemeralPubKeyHex = null;
            let ivHex = null;
            let isBroadcast = (receiverPubKeyHex === "broadcast");

            if (isBroadcast) {
                encryptedPayloadHex = this._arrayBufferToHex(payloadBytes);
            } else {
                // P2P Hybrid Encrypt
                const ephemeralKeyPair = await subtle.generateKey(
                    { name: "ECDH", namedCurve: "P-256" },
                    true,
                    ["deriveKey"]
                );
                ephemeralPubKeyHex = await this._exportKey(ephemeralKeyPair.publicKey, 'spki');

                const receiverKey = await this._importKey(receiverPubKeyHex, 'deriveKey', 'spki');

                const sharedKEK = await subtle.deriveKey(
                    { name: "ECDH", public: receiverKey },
                    ephemeralKeyPair.privateKey,
                    { name: "AES-KW", length: 256 },
                    true,
                    ["wrapKey"]
                );

                const messageAESKey = await subtle.generateKey(
                    { name: "AES-GCM", length: 256 },
                    true,
                    ["encrypt", "decrypt"]
                );

                const wrappedKeyBuffer = await subtle.wrapKey(
                    "raw",
                    messageAESKey,
                    sharedKEK,
                    "AES-KW"
                );
                encryptedKeyHex = this._arrayBufferToHex(wrappedKeyBuffer);

                const iv = _getRandomValues(12);
                ivHex = this._arrayBufferToHex(iv);

                const cipherBuffer = await subtle.encrypt(
                    { name: "AES-GCM", iv: iv },
                    messageAESKey,
                    payloadBytes
                );
                encryptedPayloadHex = this._arrayBufferToHex(cipherBuffer);
            }

            // Signing
            const myVerifKeyHex = await this._exportKey(this.identity.verificationKey, 'spki'); // Ed25519 PubKey

            const envelope = {
                id: id,
                from: this.identity.address,
                fromPubKey: myVerifKeyHex,
                to: isBroadcast ? "broadcast" : receiverPubKeyHex,
                ttl: ttl,
                timestamp: timestamp,
                payload: encryptedPayloadHex,
                iv: ivHex,
                encryptedKey: encryptedKeyHex,
                ephemeralPubKey: ephemeralPubKeyHex,
                signature: null
            };

            const signData = `${envelope.id}:${envelope.from}:${envelope.to}:${envelope.timestamp}:${envelope.payload}`;
            const signBytes = new TextEncoder().encode(signData);

            // Use GhostIdentity static helper if available, or raw subtle
            if (GhostIdentity && GhostIdentity.signMessage) {
                envelope.signature = await GhostIdentity.signMessage(signBytes, this.identity.signingKey);
            } else {
                const sigBuffer = await subtle.sign(
                    { name: "Ed25519" },
                    this.identity.signingKey,
                    signBytes
                );
                envelope.signature = this._arrayBufferToHex(sigBuffer);
            }

            return envelope;
        }

        async verifyEnvelope(envelope) {
            if (!envelope.id || !envelope.signature || !envelope.fromPubKey) return false;
            if (this.seenMessages.has(envelope.id)) return false;

            try {
                const pubKey = await this._importKey(envelope.fromPubKey, 'verify', 'spki');
                const signData = `${envelope.id}:${envelope.from}:${envelope.to}:${envelope.timestamp}:${envelope.payload}`;

                // Using GhostIdentity helper
                const isValid = await GhostIdentity.verifySignature(signData, envelope.signature, pubKey);

                if (isValid) {
                    this.seenMessages.add(envelope.id);
                    if (this.seenMessages.size > this.processedCacheSize) {
                        const it = this.seenMessages.values();
                        this.seenMessages.delete(it.next().value);
                    }
                }
                return isValid;
            } catch (e) {
                console.error("Verify Error", e);
                return false;
            }
        }

        async decryptEnvelope(envelope) {
            try {
                if (envelope.to === "broadcast") {
                    const bytes = this._hexToArrayBuffer(envelope.payload);
                    const str = new TextDecoder().decode(bytes);
                    try { return JSON.parse(str); } catch (e) { return str; }
                }

                if (!envelope.ephemeralPubKey || !envelope.encryptedKey || !envelope.iv) return null;

                const senderEphemeralKey = await this._importKey(envelope.ephemeralPubKey, 'deriveKey', 'spki');

                const sharedKEK = await subtle.deriveKey(
                    { name: "ECDH", public: senderEphemeralKey },
                    this.identity.decryptionKey,
                    { name: "AES-KW", length: 256 },
                    true,
                    ["unwrapKey"]
                );

                const encryptedKeyBuffer = this._hexToArrayBuffer(envelope.encryptedKey);
                const messageAESKey = await subtle.unwrapKey(
                    "raw",
                    encryptedKeyBuffer,
                    sharedKEK,
                    "AES-KW",
                    { name: "AES-GCM" },
                    true,
                    ["decrypt"]
                );

                const iv = this._hexToArrayBuffer(envelope.iv);
                const payloadBuffer = this._hexToArrayBuffer(envelope.payload);

                const decryptedBuffer = await subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    messageAESKey,
                    payloadBuffer
                );

                const str = new TextDecoder().decode(decryptedBuffer);
                return JSON.parse(str);

            } catch (e) {
                return null;
            }
        }
    }

    return GhostTransport;
}));
