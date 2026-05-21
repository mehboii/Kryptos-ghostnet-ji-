(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        Object.defineProperty(root, 'GhostNAT', {
            value: factory(),
            writable: false,
            configurable: false,
            enumerable: true,
        });
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    if (typeof window === 'undefined' || !window.crypto?.subtle) {
        return null;
    }

    const subtle = window.crypto.subtle;
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    const STORAGE = {
        IDENTITY: 'ghostnet_nat_identity_v1',
        DHT: 'ghostnet_nat_dht_v1',
    };

    const DEFAULT_STUN_SERVERS = [
        'stun:stun.l.google.com:19302',
        'stun:stun.cloudflare.com:3478',
        'stun:global.stun.twilio.com:3478',
    ];

    const ANNOUNCEMENT_TTL_MS = 60_000;
    const PUNCH_TIMEOUT_MS = 30_000;
    const NONCE_FRESHNESS_MS = 5 * 60 * 1000;

    function toHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    function fromHex(hex) {
        if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
            throw new TypeError('Invalid hex input');
        }
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) {
            out[i] = parseInt(hex.slice(i * 2, (i * 2) + 2), 16);
        }
        return out;
    }

    function randomHex(bytes = 32) {
        const out = new Uint8Array(bytes);
        crypto.getRandomValues(out);
        return toHex(out);
    }

    function stableStringify(value) {
        if (Array.isArray(value)) {
            return `[${value.map(stableStringify).join(',')}]`;
        }
        if (value && typeof value === 'object') {
            return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
        }
        return JSON.stringify(value);
    }

    async function sha256Hex(text) {
        const digest = await subtle.digest('SHA-256', enc.encode(text));
        return toHex(digest);
    }

    async function importVerifyKey(spkiHex) {
        return subtle.importKey('spki', fromHex(spkiHex), { name: 'Ed25519' }, false, ['verify']);
    }

    async function importSignKey(pkcs8Hex) {
        return subtle.importKey('pkcs8', fromHex(pkcs8Hex), { name: 'Ed25519' }, false, ['sign']);
    }

    async function importEcdhPublicKey(spkiHex) {
        return subtle.importKey('spki', fromHex(spkiHex), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    }

    async function importEcdhPrivateKey(pkcs8Hex) {
        return subtle.importKey('pkcs8', fromHex(pkcs8Hex), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    }

    function parseCandidate(candidateLine) {
        const candidate = typeof candidateLine === 'string' ? candidateLine : String(candidateLine?.candidate || '');
        const parts = candidate.trim().split(/\s+/);
        if (parts.length < 8) return null;
        const typeIndex = parts.indexOf('typ');
        if (typeIndex === -1 || parts[typeIndex + 1] !== 'srflx') return null;
        return {
            ip: parts[4],
            port: Number(parts[5]),
            protocol: (parts[2] || '').toLowerCase(),
            type: parts[typeIndex + 1],
        };
    }

    class GhostNATManager {
        constructor() {
            this.identity = null;
            this.ownerNodeId = null;
            this.sequence = 0;
            this.mesh = null;
            this.lastStunConsensus = null;
            this.pendingPunches = new Map();
            this.pendingAnnouncementQueries = new Map();
            this.seenNonces = new Map();
            this.ready = this._restoreIdentity();
        }

        async _restoreIdentity() {
            const raw = localStorage.getItem(STORAGE.IDENTITY);
            if (!raw) return null;
            try {
                const stored = JSON.parse(raw);
                this.identity = await this._hydrateIdentity(stored);
                return this.identity;
            } catch {
                this.identity = null;
                return null;
            }
        }

        async _hydrateIdentity(stored) {
            const signingPrivateKey = await importSignKey(stored.signingPrivateKeyPkcs8);
            const signingPublicKey = await importVerifyKey(stored.signingPublicKeySpki);
            const decryptionKey = await importEcdhPrivateKey(stored.decryptionKeyPkcs8);
            const encryptionKey = await importEcdhPublicKey(stored.encryptionPublicKeySpki);
            return {
                ...stored,
                signingPrivateKey,
                signingPublicKey,
                decryptionKey,
                encryptionKey,
            };
        }

        async _createIdentity() {
            const signKeys = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
            const encKeys = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            const signingPublicKeySpki = toHex(await subtle.exportKey('spki', signKeys.publicKey));
            const signingPrivateKeyPkcs8 = toHex(await subtle.exportKey('pkcs8', signKeys.privateKey));
            const encryptionPublicKeySpki = toHex(await subtle.exportKey('spki', encKeys.publicKey));
            const decryptionKeyPkcs8 = toHex(await subtle.exportKey('pkcs8', encKeys.privateKey));
            const keyId = await sha256Hex(signingPublicKeySpki);
            const stored = {
                version: 1,
                keyId,
                signingPublicKeySpki,
                signingPrivateKeyPkcs8,
                encryptionPublicKeySpki,
                decryptionKeyPkcs8,
                createdAt: Date.now(),
            };
            localStorage.setItem(STORAGE.IDENTITY, JSON.stringify(stored));
            this.identity = await this._hydrateIdentity(stored);
            return this.identity;
        }

        async initialize(options = {}) {
            await this.ready;
            if (!this.identity) {
                await this._createIdentity();
            }
            this.ownerNodeId = typeof options.nodeId === 'string' ? options.nodeId : this.ownerNodeId;
            return this.getPublicBundle();
        }

        getPublicBundle() {
            if (!this.identity) return null;
            return {
                keyId: this.identity.keyId,
                signingPublicKey: this.identity.signingPublicKeySpki,
                encryptionPublicKey: this.identity.encryptionPublicKeySpki,
                ownerNodeId: this.ownerNodeId,
            };
        }

        async _signObject(payload) {
            const bytes = enc.encode(stableStringify(payload));
            const sig = await subtle.sign('Ed25519', this.identity.signingPrivateKey, bytes);
            return toHex(sig);
        }

        async _verifyObject(payload, signatureHex, publicKeyHex) {
            const bytes = enc.encode(stableStringify(payload));
            const key = await importVerifyKey(publicKeyHex);
            return subtle.verify('Ed25519', key, fromHex(signatureHex), bytes);
        }

        _reportInboundAnomaly(source, reason, details = {}) {
            if (window.SignalIntelligence?.flagInboundAnomaly) {
                window.SignalIntelligence.flagInboundAnomaly(source, reason, details);
            }
        }

        _rememberNonce(scope, nonce, ts = Date.now()) {
            const key = `${scope}:${nonce}`;
            const now = Date.now();
            for (const [existingKey, existingTs] of this.seenNonces) {
                if (now - existingTs > NONCE_FRESHNESS_MS) {
                    this.seenNonces.delete(existingKey);
                }
            }
            if (this.seenNonces.has(key)) {
                return false;
            }
            this.seenNonces.set(key, ts);
            return true;
        }

        _validatePunchSchema(plaintext) {
            return !!(
                plaintext &&
                typeof plaintext === 'object' &&
                typeof plaintext.nonce === 'string' &&
                /^[0-9a-f]{64}$/i.test(plaintext.nonce) &&
                typeof plaintext.nodeId === 'string' &&
                typeof plaintext.keyId === 'string' &&
                typeof plaintext.signingPublicKey === 'string' &&
                typeof plaintext.encryptionPublicKey === 'string' &&
                typeof plaintext.timestamp === 'number'
            );
        }

        _validateChallengeSchema(payload) {
            return !!(
                payload &&
                typeof payload === 'object' &&
                typeof payload.nonce === 'string' &&
                /^[0-9a-f]{64}$/i.test(payload.nonce) &&
                typeof payload.responderNodeId === 'string' &&
                typeof payload.responderKeyId === 'string' &&
                typeof payload.responderSigningPublicKey === 'string' &&
                typeof payload.timestamp === 'number'
            );
        }

        _loadDht() {
            try {
                const raw = localStorage.getItem(STORAGE.DHT);
                const parsed = raw ? JSON.parse(raw) : {};
                return parsed && typeof parsed === 'object' ? parsed : {};
            } catch {
                return {};
            }
        }

        _saveDht(records) {
            localStorage.setItem(STORAGE.DHT, JSON.stringify(records));
        }

        async multiStunProbe(servers = DEFAULT_STUN_SERVERS) {
            const probes = servers.slice(0, 3).map(url => this._probeSingleStun(url));
            const results = (await Promise.allSettled(probes))
                .filter(r => r.status === 'fulfilled' && r.value)
                .map(r => r.value);

            const tally = new Map();
            for (const result of results) {
                const key = `${result.ip}:${result.port}`;
                tally.set(key, (tally.get(key) || 0) + 1);
            }

            let consensus = null;
            for (const [endpoint, count] of tally) {
                if (count >= 2) {
                    consensus = { endpoint, count };
                    break;
                }
            }

            this.lastStunConsensus = {
                observations: results,
                consensus,
                checkedAt: Date.now(),
            };
            return this.lastStunConsensus;
        }

        async _probeSingleStun(url) {
            return new Promise(async (resolve) => {
                const pc = new RTCPeerConnection({ iceServers: [{ urls: url }] });
                let settled = false;
                const finish = (value) => {
                    if (settled) return;
                    settled = true;
                    try { pc.close(); } catch (_) {}
                    resolve(value);
                };

                pc.createDataChannel('ghostnet-nat-probe');
                pc.onicecandidate = (event) => {
                    if (!event.candidate) return;
                    const parsed = parseCandidate(event.candidate.candidate);
                    if (parsed) {
                        finish({ server: url, ...parsed });
                    }
                };

                try {
                    const offer = await pc.createOffer();
                    await pc.setLocalDescription(offer);
                } catch {
                    finish(null);
                    return;
                }

                setTimeout(() => finish(null), 3500);
            });
        }

        async createSignedAnnouncement(endpoint) {
            await this.initialize();
            if (typeof endpoint !== 'string' || endpoint.length === 0) {
                return null;
            }
            const now = Date.now();
            const payload = {
                nodeId: this.ownerNodeId,
                keyId: this.identity.keyId,
                signingPublicKey: this.identity.signingPublicKeySpki,
                encryptionPublicKey: this.identity.encryptionPublicKeySpki,
                endpoint,
                timestamp: now,
                expiresAt: now + ANNOUNCEMENT_TTL_MS,
                seq: ++this.sequence,
                stun: this.lastStunConsensus,
            };
            const signature = await this._signObject(payload);
            return { ...payload, signature };
        }

        async verifyAnnouncement(record) {
            if (!record || typeof record !== 'object') return false;
            if (!record.signature || !record.signingPublicKey || !record.nodeId) return false;
            if (typeof record.endpoint !== 'string' || record.endpoint.length === 0) return false;
            if (typeof record.expiresAt !== 'number' || record.expiresAt < Date.now()) return false;
            const { signature, ...payload } = record;
            return this._verifyObject(payload, signature, record.signingPublicKey);
        }

        async publishAnnouncement(mesh, endpoint) {
            const record = await this.createSignedAnnouncement(endpoint);
            if (!record) return null;
            const records = this._loadDht();
            const existing = records[record.nodeId];
            if (!existing || (existing.seq || 0) <= record.seq) {
                records[record.nodeId] = record;
                this._saveDht(records);
            }
            if (mesh?.sendControl) {
                mesh.sendControl({ type: 'SECURE_ENDPOINT_ANNOUNCE', record });
            }
            return record;
        }

        async queryAnnouncement(mesh, nodeId) {
            const localRecord = this.getAnnouncement(nodeId);
            if (localRecord) {
                return localRecord;
            }
            if (mesh?.sendControl) {
                mesh.sendControl({ type: 'SECURE_ENDPOINT_QUERY', nodeId, requester: this.ownerNodeId });
            }
            if (!mesh?.sendControl) {
                return null;
            }
            return new Promise((resolve) => {
                const timeout = setTimeout(() => {
                    const waiters = this.pendingAnnouncementQueries.get(nodeId) || [];
                    const filtered = waiters.filter(entry => entry.resolve !== resolve);
                    if (filtered.length > 0) {
                        this.pendingAnnouncementQueries.set(nodeId, filtered);
                    } else {
                        this.pendingAnnouncementQueries.delete(nodeId);
                    }
                    resolve(null);
                }, 5000);

                const entry = { resolve, timeout };
                const waiters = this.pendingAnnouncementQueries.get(nodeId) || [];
                waiters.push(entry);
                this.pendingAnnouncementQueries.set(nodeId, waiters);
            });
        }

        getAnnouncement(nodeId) {
            const record = this._loadDht()[nodeId];
            if (!record || record.expiresAt < Date.now()) return null;
            if (typeof record.endpoint !== 'string' || record.endpoint.length === 0) return null;
            return record;
        }

        async ingestAnnouncement(record) {
            if (!(await this.verifyAnnouncement(record))) return false;
            const records = this._loadDht();
            const existing = records[record.nodeId];
            if (!existing || (existing.seq || 0) <= record.seq) {
                records[record.nodeId] = record;
                this._saveDht(records);
            }
            const waiters = this.pendingAnnouncementQueries.get(record.nodeId) || [];
            for (const waiter of waiters) {
                clearTimeout(waiter.timeout);
                waiter.resolve(record);
            }
            if (waiters.length > 0) {
                this.pendingAnnouncementQueries.delete(record.nodeId);
            }
            return true;
        }

        async createEncryptedPunch(peerRecord) {
            await this.initialize();
            const nonceHex = randomHex(32);
            const plaintext = {
                nonce: nonceHex,
                nodeId: this.ownerNodeId,
                keyId: this.identity.keyId,
                signingPublicKey: this.identity.signingPublicKeySpki,
                encryptionPublicKey: this.identity.encryptionPublicKeySpki,
                timestamp: Date.now(),
            };

            const ephemeral = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            const peerPublicKey = await importEcdhPublicKey(peerRecord.encryptionPublicKey);
            const sharedBits = await subtle.deriveBits(
                { name: 'ECDH', public: peerPublicKey },
                ephemeral.privateKey,
                256
            );
            const sharedKeyMaterial = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const aesKey = await subtle.deriveKey(
                { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('GhostNet-NAT-Punch-v1') },
                sharedKeyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt']
            );
            const ciphertext = await subtle.encrypt(
                { name: 'AES-GCM', iv },
                aesKey,
                enc.encode(JSON.stringify(plaintext))
            );
            const ephPub = await subtle.exportKey('spki', ephemeral.publicKey);

            this.pendingPunches.set(peerRecord.nodeId, {
                nonce: nonceHex,
                record: peerRecord,
                createdAt: Date.now(),
                verified: false,
            });

            const signedEnvelope = {
                type: 'SECURE_PUNCH',
                from: this.ownerNodeId,
                to: peerRecord.nodeId,
                senderKeyId: this.identity.keyId,
                signingPublicKey: this.identity.signingPublicKeySpki,
                ephemeralPublicKey: toHex(ephPub),
                salt: toHex(salt),
                iv: toHex(iv),
                ciphertext: toHex(ciphertext),
                timestamp: Date.now(),
            };
            signedEnvelope.signature = await this._signObject(signedEnvelope);
            return signedEnvelope;
        }

        async decryptPunch(packet) {
            const ephPublic = await importEcdhPublicKey(packet.ephemeralPublicKey);
            const sharedBits = await subtle.deriveBits(
                { name: 'ECDH', public: ephPublic },
                this.identity.decryptionKey,
                256
            );
            const sharedKeyMaterial = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
            const aesKey = await subtle.deriveKey(
                {
                    name: 'HKDF',
                    hash: 'SHA-256',
                    salt: fromHex(packet.salt),
                    info: enc.encode('GhostNet-NAT-Punch-v1')
                },
                sharedKeyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
            const plaintext = await subtle.decrypt(
                { name: 'AES-GCM', iv: fromHex(packet.iv) },
                aesKey,
                fromHex(packet.ciphertext)
            );
            return JSON.parse(dec.decode(plaintext));
        }

        async createChallengeResponse(plaintext, packet) {
            const payload = {
                nonce: plaintext.nonce,
                responderNodeId: this.ownerNodeId,
                responderKeyId: this.identity.keyId,
                responderSigningPublicKey: this.identity.signingPublicKeySpki,
                timestamp: Date.now(),
                requestTimestamp: packet.timestamp,
            };
            const signature = await this._signObject(payload);
            return {
                type: 'SECURE_CHALLENGE_RESPONSE',
                to: plaintext.nodeId,
                from: this.ownerNodeId,
                nonce: plaintext.nonce,
                signingPublicKey: this.identity.signingPublicKeySpki,
                payload,
                signature,
            };
        }

        async verifyChallengeResponse(message) {
            if (!message?.payload || !message.signature || !message.from) return false;
            const pending = this.pendingPunches.get(message.from);
            if (!pending) return false;
            if (Date.now() - pending.createdAt > PUNCH_TIMEOUT_MS) {
                this.pendingPunches.delete(message.from);
                return false;
            }
            if (pending.verified) {
                this._reportInboundAnomaly('handshake', 'replay_detected', { from: message.from, type: message.type });
                return false;
            }
            if (message.payload.nonce !== pending.nonce) {
                this._reportInboundAnomaly('handshake', 'nonce_mismatch', { from: message.from });
                return false;
            }
            const record = pending.record;
            if (!this._validateChallengeSchema(message.payload)) {
                this._reportInboundAnomaly('handshake', 'schema_invalid', { from: message.from, type: message.type });
                return false;
            }
            if (!this._rememberNonce(`challenge:${message.from}`, message.payload.nonce, message.payload.timestamp)) {
                this._reportInboundAnomaly('handshake', 'replay_detected', { from: message.from, type: message.type });
                return false;
            }
            const ok = await this._verifyObject(message.payload, message.signature, record.signingPublicKey);
            if (ok) {
                pending.verified = true;
                pending.verifiedAt = Date.now();
                this.pendingPunches.set(message.from, pending);
            } else {
                this._reportInboundAnomaly('handshake', 'signature_invalid', { from: message.from, type: message.type });
            }
            return ok;
        }

        async handleMeshMessage(message, mesh) {
            if (!message || typeof message !== 'object') return false;

            if (message.type === 'SECURE_ENDPOINT_ANNOUNCE') {
                return this.ingestAnnouncement(message.record);
            }

            if (message.type === 'SECURE_ENDPOINT_QUERY') {
                if (message.nodeId === this.ownerNodeId) {
                    const record = await this.createSignedAnnouncement(
                        this.lastStunConsensus?.consensus?.endpoint || null
                    );
                    if (record) {
                        mesh?.sendControl?.({ type: 'SECURE_ENDPOINT_ANNOUNCE', record });
                    }
                    return true;
                }
                return false;
            }

            if (message.type === 'SECURE_PUNCH' && message.to === this.ownerNodeId) {
                try {
                    if (!message.signature || !message.signingPublicKey) {
                        this._reportInboundAnomaly('socket', 'signature_missing', { type: message.type });
                        return false;
                    }
                    const signed = { ...message };
                    delete signed.signature;
                    const outerVerified = await this._verifyObject(
                        signed,
                        message.signature,
                        message.signingPublicKey
                    );
                    if (!outerVerified) {
                        this._reportInboundAnomaly('socket', 'signature_invalid', { type: message.type, from: message.from });
                        return false;
                    }
                    const plaintext = await this.decryptPunch(message);
                    if (!this._validatePunchSchema(plaintext)) {
                        this._reportInboundAnomaly('socket', 'schema_invalid', { type: message.type, from: message.from });
                        return false;
                    }
                    if (Math.abs(Date.now() - plaintext.timestamp) > NONCE_FRESHNESS_MS) {
                        this._reportInboundAnomaly('socket', 'stale_nonce', { from: plaintext.nodeId, type: message.type });
                        return false;
                    }
                    const knownRecord = this.getAnnouncement(plaintext.nodeId);
                    if (!knownRecord || knownRecord.signingPublicKey !== plaintext.signingPublicKey) {
                        this._reportInboundAnomaly('socket', 'unknown_sender_binding', { from: plaintext.nodeId });
                        return false;
                    }
                    if (!this._rememberNonce(`punch:${plaintext.nodeId}`, plaintext.nonce, plaintext.timestamp)) {
                        this._reportInboundAnomaly('socket', 'replay_detected', { from: plaintext.nodeId, type: message.type });
                        return false;
                    }
                    const response = await this.createChallengeResponse(plaintext, message);
                    mesh?.sendControl?.(response);
                    return true;
                } catch {
                    this._reportInboundAnomaly('socket', 'decrypt_failed', { type: message.type, from: message.from });
                    return false;
                }
            }

            if (message.type === 'SECURE_CHALLENGE_RESPONSE' && message.to === this.ownerNodeId) {
                return this.verifyChallengeResponse(message);
            }

            return false;
        }

        async attachMesh(mesh) {
            await this.initialize({ nodeId: mesh?.identity?.nodeId || mesh?.identity?.id || this.ownerNodeId });
            this.mesh = mesh;
            if (!mesh.__ghostNatAttached) {
                const previousSecureMessage = mesh.onSecureMessage;
                mesh.onSecureMessage = async (msg, transport) => {
                    await this.handleMeshMessage(msg, mesh);
                    if (typeof previousSecureMessage === 'function') {
                        previousSecureMessage(msg, transport);
                    }
                };
                mesh.__ghostNatAttached = true;
            }

            try {
                await this.multiStunProbe();
            } catch (_) {}

            if (this.lastStunConsensus?.consensus?.endpoint) {
                await this.publishAnnouncement(mesh, this.lastStunConsensus.consensus.endpoint);
            }
            return this.getPublicBundle();
        }

        async startSecurePunch(mesh, targetNodeId) {
            const record = await this.queryAnnouncement(mesh, targetNodeId);
            if (!record) {
                throw new Error(`No signed endpoint announcement available for ${targetNodeId}`);
            }
            const packet = await this.createEncryptedPunch(record);
            const sent = mesh?.sendControl?.(packet);
            if (!sent) {
                throw new Error('Secure punch could not be sent');
            }
            return packet;
        }

        getPunchStatus(nodeId) {
            return this.pendingPunches.get(nodeId) || null;
        }
    }

    return new GhostNATManager();
}));
