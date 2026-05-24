/**
 * GhostNet Chat — SECURITY HARDENED
 * Universal Module (UMD)
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Plaintext body included alongside ciphertext in every payload.
 *     `body: body` was added to the outbound payload "to allow simple
 *     historical storage". This completely defeats encryption — the plaintext
 *     body travels over the network with the ciphertext, visible to any relay,
 *     observer, or MITM. Every message ever sent was effectively unencrypted.
 *     Fixed: `body` is stripped from all outbound payloads. Only iv + data
 *     (ciphertext) are transmitted. Plaintext is reconstructed only after
 *     successful local decryption.
 *
 * [B] CRITICAL — "Shared secret" derived from SHA-256(sort(pubA + pubB)).
 *     Both public keys are public values broadcast to the network. Any
 *     observer who knows two peers' public keys can compute their exact
 *     "session key" and decrypt every message exchanged. This is not
 *     encryption — it is obfuscation with a publicly derivable key.
 *     Fixed: _deriveSharedSecret() now uses HKDF-SHA-256 with domain
 *     separation and a per-session salt. NOTE: This is still symmetric
 *     derivation from public keys and therefore still NOT true ECDH.
 *     A production deployment MUST replace this with a real ECDH key
 *     exchange (X25519 or secp256k1 ECDH) using actual private key material.
 *     The comment in the code marks the exact integration point.
 *
 * [C] CRITICAL — Decrypted message history stored in plaintext in localStorage.
 *     `_persist()` serialized message objects including the decrypted `body`
 *     field to localStorage. localStorage is readable by any script on the
 *     page (XSS), all browser extensions, and is written to disk as plaintext.
 *     Fixed: only the original encrypted fields (iv, data, metadata) are
 *     persisted — never the decrypted body. On load, messages are restored
 *     as encrypted blobs; the UI must call receive() to decrypt them for
 *     display.
 *
 * [D] HIGH — DELETE requests are not authenticated.
 *     handleDelete() checked `target.from === packet.from`, but `packet.from`
 *     is attacker-supplied data from the network. Any peer can forge a DELETE
 *     packet claiming to be from any sender and delete any message.
 *     Fixed: DELETE packets are now HMAC-SHA-256 signed by the sender using
 *     the session key. Unsigned or incorrectly signed DELETE packets are
 *     rejected before any state is modified.
 *
 * [E] HIGH — No sender authenticity verification on received messages.
 *     receive() accepted any packet claiming any `from` identity. There was
 *     no signature check — any network participant or MITM could inject
 *     messages appearing to come from any peer.
 *     Fixed: outbound MSG packets include an HMAC over (id + from + to + ts +
 *     iv + data) computed with the session key. Incoming packets whose HMAC
 *     fails verification are silently discarded.
 *
 * [F] HIGH — myIdentity.priv (private key) stored on the chat object.
 *     The constructor comment `{ pub: "...", priv: "..." }` showed the private
 *     key was expected and stored in this.myIdentity. Any code holding a
 *     GhostChat reference could read it.
 *     Fixed: constructor accepts only { pub, nodeId }. If a full identity
 *     object with priv is passed, the private key is explicitly stripped
 *     before storage.
 *
 * [G] HIGH — EPHEMERAL messages stored in the messages Map before the timer fires.
 *     Ephemeral messages were inserted into this.messages and then removed by
 *     a setTimeout. During that window they existed in the Map and could be
 *     read by any code with access to the GhostChat instance. They were also
 *     eligible for _persist() calls on the next operation if the mode check
 *     was missed.
 *     Fixed: EPHEMERAL messages are never added to this.messages at all.
 *     They are passed directly to onMessage() and immediately discarded.
 *
 * [H] HIGH — TTL enforced only by client-side setTimeout; trivially bypassed.
 *     setTimeout can be paused (debugger), cancelled (if reference lost), or
 *     the Map can be read before expiry. Ephemeral messages were not truly
 *     ephemeral.
 *     Fixed: combined with [G] — EPHEMERAL messages never enter any persistent
 *     structure. setTimeout is kept only to notify the UI to hide the message
 *     from its render state.
 *
 * [I] MEDIUM — No validation of packet.iv length or packet.data type.
 *     new Uint8Array(packet.iv) was called on attacker-supplied data. A packet
 *     with a malformed iv (wrong length, not an array, etc.) would cause an
 *     uncaught error or, worse, attempt decryption with a broken IV in some
 *     runtime environments.
 *     Fixed: _validatePacket() checks iv is an array of exactly 12 numbers
 *     in [0,255], data is a non-empty array, and all required string fields
 *     are present and within length limits.
 *
 * [J] MEDIUM — No maximum message body length.
 *     No size limit was applied before encryption or after decryption. A
 *     malicious peer could send a 100MB payload causing memory exhaustion
 *     during JSON.parse and Uint8Array construction.
 *     Fixed: MAX_BODY_BYTES (64 KB) enforced before encryption on send, and
 *     on the ciphertext byte length on receive before attempting decryption.
 *
 * [K] MEDIUM — Duplicate message IDs accepted; existing messages overwritten.
 *     this.messages.set(packet.id, ...) replaced any existing message with
 *     the same ID. An attacker could replay an old message ID with new content
 *     to silently overwrite legitimate history.
 *     Fixed: incoming message IDs are checked against this.messages; packets
 *     whose ID already exists are discarded as replays.
 *
 * [L] LOW — UMD root assignment uses plain property — overwritable by any script.
 *     root.GhostChat = factory() allowed later scripts to overwrite the global.
 *     Fixed: Object.defineProperty with writable:false, configurable:false.
 *
 * [M] LOW — typeof onDelete check does not verify it is a function.
 *     `if (this.onDelete) this.onDelete(...)` passes if onDelete is any
 *     truthy value (string, number, object). Calling a non-function throws.
 *     Fixed: check is `typeof this.onDelete === 'function'`.
 */

(function (root, factory) {
    'use strict';
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        // [FIX L] Immutable global — cannot be overwritten by later scripts.
        Object.defineProperty(root, 'GhostChat', {
            value: factory(),
            writable: false,
            configurable: false,
            enumerable: true,
        });
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ─── Constants ────────────────────────────────────────────────────────────
    const STORAGE_KEY = 'ghost_chat_history';
    const MAX_BODY_BYTES = 65536;   // [FIX J] 64 KB hard ceiling
    const MAX_FIELD_LEN = 256;     // Max length for string fields in packets

    // ─── Crypto helpers ───────────────────────────────────────────────────────

    /**
     * [FIX B] Derive a session key using HKDF-SHA-256 with domain separation.
     *
     * ⚠ ARCHITECTURAL NOTE: This derivation is still symmetric and based on
     * public key material. It prevents trivial SHA-256(sort(pub+pub)) attacks
     * but is NOT a substitute for a real ECDH key exchange. A production
     * deployment must replace _deriveSharedSecret() with a proper X25519 or
     * secp256k1 ECDH using the peer's public key and our private key material,
     * exchanged out-of-band (e.g. via a signed DH handshake packet). The
     * integration point is marked below.
     */
    async function _deriveSharedSecret(ecdhPrivateKey, peerEcdhPubKeyHex, sessionSalt) {
        const enc = new TextEncoder();

        let ikmKey;

        if (ecdhPrivateKey && peerEcdhPubKeyHex && typeof peerEcdhPubKeyHex === 'string') {
            const peerKeyBytes = new Uint8Array(
                peerEcdhPubKeyHex.match(/.{1,2}/g).map(b => parseInt(b, 16))
            );
            const peerPubCryptoKey = await crypto.subtle.importKey(
                'raw', peerKeyBytes,
                { name: 'ECDH', namedCurve: 'P-256' },
                false, []
            );
            const sharedBits = await crypto.subtle.deriveBits(
                { name: 'ECDH', public: peerPubCryptoKey },
                ecdhPrivateKey,
                256
            );
            ikmKey = await crypto.subtle.importKey(
                'raw', sharedBits, 'HKDF', false, ['deriveKey']
            );
        } else {
            throw new Error('ECDH key exchange requires both private key and peer public key');
        }

        const sessionKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: sessionSalt,
                info: enc.encode('GhostChat-v1-session'),
            },
            ikmKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        const hmacKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: sessionSalt,
                info: enc.encode('GhostChat-v1-hmac'),
            },
            ikmKey,
            { name: 'HMAC', hash: 'SHA-256', length: 256 },
            false,
            ['sign', 'verify']
        );

        return { sessionKey, hmacKey };
    }

    /** Compute HMAC over a canonical string representation of packet fields. */
    async function _signPacket(hmacKey, packet) {
        const enc = new TextEncoder();
        const canonical = `${packet.id}|${packet.from}|${packet.to}|${packet.ts}|` +
            `${JSON.stringify(packet.iv)}|${JSON.stringify(packet.data)}`;
        const sig = await crypto.subtle.sign('HMAC', hmacKey, enc.encode(canonical));
        return Array.from(new Uint8Array(sig));
    }

    /** Verify an HMAC; returns true only on a valid match. */
    async function _verifyPacket(hmacKey, packet) {
        if (!Array.isArray(packet.hmac) || packet.hmac.length === 0) return false;
        const enc = new TextEncoder();
        const canonical = `${packet.id}|${packet.from}|${packet.to}|${packet.ts}|` +
            `${JSON.stringify(packet.iv)}|${JSON.stringify(packet.data)}`;
        try {
            return await crypto.subtle.verify(
                'HMAC',
                hmacKey,
                new Uint8Array(packet.hmac),
                enc.encode(canonical)
            );
        } catch {
            return false;
        }
    }

    /** Compute HMAC for a DELETE request. */
    async function _signDelete(hmacKey, packet) {
        const enc = new TextEncoder();
        const canonical = `DELETE|${packet.id}|${packet.targetId}|${packet.from}|${packet.ts}`;
        const sig = await crypto.subtle.sign('HMAC', hmacKey, enc.encode(canonical));
        return Array.from(new Uint8Array(sig));
    }

    /** Verify a DELETE request HMAC. */
    async function _verifyDelete(hmacKey, packet) {
        if (!Array.isArray(packet.hmac) || packet.hmac.length === 0) return false;
        const enc = new TextEncoder();
        const canonical = `DELETE|${packet.id}|${packet.targetId}|${packet.from}|${packet.ts}`;
        try {
            return await crypto.subtle.verify(
                'HMAC',
                hmacKey,
                new Uint8Array(packet.hmac),
                enc.encode(canonical)
            );
        } catch {
            return false;
        }
    }

    // ─── Packet validation ────────────────────────────────────────────────────

    /**
     * [FIX I] Validate all required fields of an incoming packet before
     * any crypto or state operation is performed.
     */
    function _validatePacket(packet) {
        if (!packet || typeof packet !== 'object') return false;
        if (typeof packet.id !== 'string' || packet.id.length > MAX_FIELD_LEN) return false;
        if (typeof packet.from !== 'string' || packet.from.length > MAX_FIELD_LEN) return false;
        if (typeof packet.to !== 'string' || packet.to.length > MAX_FIELD_LEN) return false;
        if (typeof packet.ts !== 'number' || packet.ts <= 0) return false;
        if (typeof packet.type !== 'string') return false;

        if (packet.type === 'MSG') {
            // iv must be exactly 12 bytes in [0,255]
            if (!Array.isArray(packet.iv) || packet.iv.length !== 12) return false;
            if (!packet.iv.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) return false;
            // data must be a non-empty array, capped at MAX_BODY_BYTES
            if (!Array.isArray(packet.data) || packet.data.length === 0) return false;
            if (packet.data.length > MAX_BODY_BYTES + 16) return false; // +16 for GCM tag
            if (!packet.data.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) return false;
            // salt must be present (16 bytes)
            if (!Array.isArray(packet.salt) || packet.salt.length !== 16) return false;
            if (!packet.salt.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) return false;
        }

        if (packet.type === 'DELETE') {
            if (typeof packet.targetId !== 'string' || packet.targetId.length > MAX_FIELD_LEN) return false;
        }

        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────

    class GhostChat {
        constructor(myIdentity, transportSender) {
            const { pub, nodeId } = myIdentity || {};
            this.myIdentity = { pub, nodeId };

            this.sendToNetwork = transportSender;

            this.sessions = new Map();
            this.messages = new Map();
            this.peerEcdhKeys = new Map();

            this._ecdhKeyPair = null;
            this._ecdhPubHex = null;
            this._initPromise = this._initEcdh();

            this.onMessage = () => { };
            this.onDelete = null;

            this._loadPersistedMessages();
        }

        async _initEcdh() {
            this._ecdhKeyPair = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' },
                false,
                ['deriveBits']
            );
            const rawPub = await crypto.subtle.exportKey('raw', this._ecdhKeyPair.publicKey);
            this._ecdhPubHex = Array.from(new Uint8Array(rawPub))
                .map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async getSession(peerIdentityKey, salt, peerEcdhPubHex) {
            await this._initPromise;

            if (peerEcdhPubHex) {
                this.peerEcdhKeys.set(peerIdentityKey, peerEcdhPubHex);
            }
            const resolvedPeerEcdh = this.peerEcdhKeys.get(peerIdentityKey) || peerEcdhPubHex;

            const cacheKey = `${peerIdentityKey}:${salt ? salt.join(',') : 'default'}:${resolvedPeerEcdh || 'no-ecdh'}`;
            if (this.sessions.has(cacheKey)) return this.sessions.get(cacheKey);

            const saltBytes = salt
                ? new Uint8Array(salt)
                : crypto.getRandomValues(new Uint8Array(16));

            if (!resolvedPeerEcdh) {
                throw new Error('Peer ECDH public key required for session establishment');
            }

            const session = await _deriveSharedSecret(
                this._ecdhKeyPair.privateKey, resolvedPeerEcdh, saltBytes
            );
            this.sessions.set(cacheKey, { ...session, salt: Array.from(saltBytes) });
            return this.sessions.get(cacheKey);
        }

        // ── Sending Messages ────────────────────────────────────────────────

        async sendMessage(body, toPubKey, mode = 'PERSIST', ttl = 0) {
            await this._initPromise;

            if (typeof body !== 'string' || body.length === 0) {
                throw new Error('Message body must be a non-empty string.');
            }

            const encodedBody = new TextEncoder().encode(body);
            if (encodedBody.length > MAX_BODY_BYTES) {
                throw new Error(`Message too large (max ${MAX_BODY_BYTES} bytes).`);
            }

            const msgId = crypto.randomUUID();
            const ts = Date.now();
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const salt = crypto.getRandomValues(new Uint8Array(16));
            const session = await this.getSession(toPubKey, Array.from(salt));

            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                session.sessionKey,
                encodedBody
            );

            const payload = {
                id: msgId,
                type: 'MSG',
                from: this.myIdentity.pub,
                to: toPubKey,
                ts,
                mode,
                ttl,
                iv: Array.from(iv),
                data: Array.from(new Uint8Array(ciphertext)),
                salt: Array.from(salt),
                dhPub: this._ecdhPubHex,
            };

            payload.hmac = await _signPacket(session.hmacKey, payload);

            this.sendToNetwork(JSON.stringify(payload));

            // [FIX G] EPHEMERAL messages never enter the messages Map.
            if (mode !== 'EPHEMERAL') {
                // [FIX C] Store only the encrypted packet — no plaintext body.
                this.messages.set(msgId, { ...payload, status: 'sent' });
                this._persist();
            }

            return { id: msgId, from: this.myIdentity.pub, to: toPubKey, ts, mode, status: 'sent' };
        }

        async sendDeleteRequest(targetMsgId, toPubKey) {
            // Verify we own the message we're deleting.
            if (this.messages.has(targetMsgId)) {
                const target = this.messages.get(targetMsgId);
                if (target.from !== this.myIdentity.pub) {
                    throw new Error('Cannot delete a message you did not send.');
                }
            }

            const packet = {
                id: crypto.randomUUID(),
                type: 'DELETE',
                targetId: targetMsgId,
                from: this.myIdentity.pub,
                to: toPubKey,
                ts: Date.now(),
            };

            // [FIX D] Sign the DELETE request.
            const salt = this.messages.get(targetMsgId)?.salt;
            const session = await this.getSession(toPubKey, salt);
            packet.hmac = await _signDelete(session.hmacKey, packet);

            this.sendToNetwork(JSON.stringify(packet));
        }

        // ── Receiving Messages ──────────────────────────────────────────────

        async receive(rawJson) {
            let packet;
            try {
                packet = JSON.parse(rawJson);
            } catch {
                // Malformed JSON — discard silently.
                return;
            }

            // [FIX I] Structural validation before any processing.
            if (!_validatePacket(packet)) return;

            // Only process packets addressed to us or broadcast.
            if (packet.to !== this.myIdentity.pub && packet.to !== 'broadcast') return;

            if (packet.type === 'DELETE') {
                await this._handleDelete(packet);
            } else if (packet.type === 'MSG') {
                await this._handleMessage(packet);
            }
        }

        async _handleMessage(packet) {
            if (this.messages.has(packet.id)) return;

            const peerEcdh = (typeof packet.dhPub === 'string' && packet.dhPub.length > 0) ? packet.dhPub : undefined;
            const session = await this.getSession(packet.from, packet.salt, peerEcdh);

            // [FIX E] Verify HMAC before attempting decryption.
            const valid = await _verifyPacket(session.hmacKey, packet);
            if (!valid) {
                console.warn('[GhostChat] HMAC verification failed — packet discarded.');
                return;
            }

            let body;
            try {
                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: new Uint8Array(packet.iv) },
                    session.sessionKey,
                    new Uint8Array(packet.data)
                );
                body = new TextDecoder().decode(decryptedBuffer);
            } catch {
                console.warn('[GhostChat] Decryption failed — packet discarded.');
                return;
            }

            // [FIX J] Verify decrypted body length.
            if (new TextEncoder().encode(body).length > MAX_BODY_BYTES) {
                console.warn('[GhostChat] Decrypted body exceeds size limit — discarded.');
                return;
            }

            const msgObj = { ...packet, body };

            if (packet.mode === 'EPHEMERAL') {
                // [FIX G] + [FIX H] EPHEMERAL messages never stored anywhere.
                msgObj.ephemeral = true;
                this.onMessage(msgObj);
                // Notify UI to hide after TTL — this is UI-only, not a security control.
                setTimeout(() => {
                    if (typeof this.onDelete === 'function') this.onDelete(packet.id);
                }, (packet.ttl || 30) * 1000);
            } else {
                // [FIX C] Persist only the encrypted packet — not the plaintext body.
                this.messages.set(packet.id, { ...packet, status: 'received' });
                this._persist();
                this.onMessage(msgObj);
            }
        }

        async _handleDelete(packet) {
            if (!this.messages.has(packet.targetId)) return;

            const target = this.messages.get(packet.targetId);
            // Use the salt from the stored message to reconstruct the session.
            const session = await this.getSession(packet.from, target.salt);

            // [FIX D] Verify DELETE is signed by the session key of the sender.
            const valid = await _verifyDelete(session.hmacKey, packet);
            if (!valid) {
                console.warn('[GhostChat] DELETE HMAC invalid — request discarded.');
                return;
            }

            // [FIX D] Only the original sender of the message may delete it.
            if (target.from !== packet.from) {
                console.warn('[GhostChat] DELETE sender mismatch — request discarded.');
                return;
            }

            this.messages.delete(packet.targetId);
            this._persist();

            // [FIX M] Verified to be a function before calling.
            if (typeof this.onDelete === 'function') this.onDelete(packet.targetId);
        }

        // ── Persistence ─────────────────────────────────────────────────────

        _persist() {
            // [FIX C] Save only encrypted blobs — the body field is deliberately
            //         absent. Any message object that somehow contains a body
            //         field is stripped here as a defence-in-depth measure.
            const toSave = Array.from(this.messages.values())
                .filter(m => m.mode === 'PERSIST' || m.mode === 'DELETE')
                .map(({ body: _stripped, ...rest }) => rest);  // explicitly drop body

            try {
                localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
            } catch (e) {
                console.error('[GhostChat] Failed to persist messages:', e.message);
            }
        }

        _loadPersistedMessages() {
            try {
                const stored = localStorage.getItem(STORAGE_KEY);
                if (!stored) return;
                const parsed = JSON.parse(stored);
                if (!Array.isArray(parsed)) return;
                for (const msg of parsed) {
                    // [FIX I] Validate before restoring to state.
                    if (_validatePacket(msg) && typeof msg.id === 'string') {
                        // [FIX C] Confirm no plaintext body slipped through.
                        const { body: _dropped, ...safe } = msg;
                        this.messages.set(safe.id, safe);
                    }
                }
            } catch (e) {
                console.error('[GhostChat] Failed to load chat history:', e.message);
            }
        }

        /** Return all stored message IDs so the UI can request decryption. */
        getMessageIds() {
            return Array.from(this.messages.keys());
        }

        /**
         * Decrypt a single stored message for UI display.
         * Callers should discard the returned body after rendering — never
         * store the decrypted string.
         */
        async decryptStored(msgId) {
            const packet = this.messages.get(msgId);
            if (!packet) return null;
            const session = await this.getSession(
                packet.from === this.myIdentity.pub ? packet.to : packet.from,
                packet.salt
            );
            try {
                const buf = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: new Uint8Array(packet.iv) },
                    session.sessionKey,
                    new Uint8Array(packet.data)
                );
                return new TextDecoder().decode(buf);
            } catch {
                return null;
            }
        }
    }

    return GhostChat;
}));