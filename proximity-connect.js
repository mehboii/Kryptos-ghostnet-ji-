/**
 * Proximity Connect — Offline BLE Discovery + Handshake + Key Exchange
 *
 * Two nearby GhostNet devices discover each other over BLE without internet.
 * Protocol:
 *   1. Device A advertises GhostNet service UUID via Capacitor BLE
 *   2. Device B scans and finds A
 *   3. B reads A's peerId + ephemeral public key from characteristics
 *   4. B writes its own identity + ephemeral public key to A's DATA char
 *   5. Both derive a shared secret via ECDH (P-256)
 *   6. Challenge-response: A sends a nonce encrypted with the shared key,
 *      B decrypts and echoes it back → mutual proof of key agreement
 *   7. Session established — both devices can now exchange encrypted messages
 *
 * Security properties:
 *   - Ephemeral keys per session → forward secrecy
 *   - ECDH P-256 via Web Crypto → no private key leaves the device
 *   - Challenge-response → mutual authentication
 *   - 6-digit verification code displayed on both devices → anti-MITM
 *   - No internet, no server, no location — fully offline
 */

'use strict';

class ProximityConnect {
    constructor() {
        this.state = 'idle'; // idle | advertising | scanning | handshaking | connected | failed
        this.sessionKeys = null;
        this.localEphemeral = null; // { publicKey, privateKey } CryptoKeyPair
        this.localIdentity = null;  // { nodeId, publicKeyHex }
        this.remotePeer = null;     // { peerId, publicKeyHex, ephemeralKeyHex }
        this.verificationCode = null;
        this.bleClient = null;
        this._listeners = {};
        this._scanDevices = [];
    }

    // ── Events ──────────────────────────────────────────────────

    on(event, fn) {
        if (!this._listeners[event]) this._listeners[event] = [];
        this._listeners[event].push(fn);
    }

    _emit(event, data) {
        (this._listeners[event] || []).forEach(fn => fn(data));
    }

    _setState(s) {
        this.state = s;
        this._emit('stateChange', s);
    }

    // ── Init ────────────────────────────────────────────────────

    async init(identity) {
        if (!identity || !identity.nodeId) throw new Error('Identity required');
        this.localIdentity = {
            nodeId: identity.nodeId,
            publicKeyHex: identity.publicKeyHex || identity.publicKey || ''
        };

        // Generate ephemeral ECDH keypair (P-256) — private key never leaves this device
        this.localEphemeral = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            false, // non-extractable private key
            ['deriveKey', 'deriveBits']
        );

        // Export ephemeral public key for transmission
        const pubRaw = await crypto.subtle.exportKey('raw', this.localEphemeral.publicKey);
        this._ephemeralPubHex = this._bufToHex(pubRaw);

        this._log('Initialized with ephemeral ECDH keypair');
        return true;
    }

    // ── Scan for nearby devices ─────────────────────────────────

    async startScan() {
        this._setState('scanning');
        this._scanDevices = [];

        try {
            const { BleClient } = await import('@capacitor-community/bluetooth-le');
            this.bleClient = BleClient;
            await BleClient.initialize();

            const SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';

            // scanMode 1 = LOW_LATENCY — continuous scan window for fastest discovery at range
            await BleClient.requestLEScan(
                { services: [SERVICE_UUID], allowDuplicates: false, scanMode: 1 },
                (result) => {
                    // Deduplicate by deviceId
                    if (this._scanDevices.find(d => d.deviceId === result.device.deviceId)) return;

                    const device = {
                        deviceId: result.device.deviceId,
                        name: result.device.name || 'GhostNet Device',
                        rssi: result.rssi,
                        timestamp: Date.now()
                    };
                    this._scanDevices.push(device);
                    this._emit('deviceFound', device);
                    this._log(`Found: ${device.name} (${device.deviceId}) RSSI: ${device.rssi}`);
                }
            );

            // Scan for 10 seconds then stop
            await new Promise(r => setTimeout(r, 10000));
            await BleClient.stopLEScan();

            if (this._scanDevices.length === 0) {
                this._setState('idle');
                this._emit('scanComplete', { devices: [], count: 0 });
            } else {
                this._emit('scanComplete', { devices: this._scanDevices, count: this._scanDevices.length });
            }

            return this._scanDevices;
        } catch (e) {
            this._log('Scan failed: ' + e.message);
            this._setState('failed');
            this._emit('error', { phase: 'scan', message: e.message });
            return [];
        }
    }

    stopScan() {
        if (this.bleClient) {
            try { this.bleClient.stopLEScan(); } catch (_) {}
        }
        if (this.state === 'scanning') this._setState('idle');
    }

    // ── Connect + Handshake ─────────────────────────────────────

    async connectTo(deviceId) {
        if (!this.localEphemeral) throw new Error('Call init() first');
        this._setState('handshaking');

        const SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';
        const CHAR_PEER_ID = '67686f73-746e-6574-2d69-640000000000';
        const CHAR_PUB_KEY = '67686f73-746e-6574-2d6b-657900000000';
        const CHAR_DATA    = '67686f73-746e-6574-2d64-617461000000';

        try {
            const BLE = this.bleClient;
            if (!BLE) throw new Error('BLE not initialized');

            // 1. Connect to the device
            await BLE.connect(deviceId, () => {
                this._log('Peer disconnected');
                this._setState('idle');
                this._emit('disconnected', { deviceId });
            });
            this._log('Connected to ' + deviceId);

            // 2. Read peer identity (with retry for range reliability)
            const peerIdBuf = await this._bleRetry(
                () => BLE.read(deviceId, SERVICE_UUID, CHAR_PEER_ID), 'Read peerId');
            const peerId = new TextDecoder().decode(peerIdBuf);

            // 3. Read peer's public key (with retry)
            const peerKeyBuf = await this._bleRetry(
                () => BLE.read(deviceId, SERVICE_UUID, CHAR_PUB_KEY), 'Read pubKey');
            const peerKeyHex = this._bufToHex(peerKeyBuf);

            this._log(`Peer: ${peerId}, key: ${peerKeyHex.slice(0, 16)}...`);

            // 4. Send our identity + ephemeral public key via DATA characteristic (with retry)
            const handshakePayload = JSON.stringify({
                type: 'HANDSHAKE_INIT',
                nodeId: this.localIdentity.nodeId,
                ephemeralPub: this._ephemeralPubHex,
                ts: Date.now()
            });
            const payloadBytes = new TextEncoder().encode(handshakePayload);
            await this._bleRetry(
                () => BLE.write(deviceId, SERVICE_UUID, CHAR_DATA, payloadBytes), 'Write handshake');
            this._log('Sent handshake init');

            // 5. Wait for handshake response (peer's ephemeral key)
            const response = await this._waitForNotification(deviceId, SERVICE_UUID, CHAR_DATA, 15000);
            const respData = JSON.parse(new TextDecoder().decode(response));

            if (respData.type !== 'HANDSHAKE_ACCEPT' || !respData.ephemeralPub) {
                throw new Error('Invalid handshake response');
            }

            // 6. Import peer's ephemeral public key and derive shared secret
            const peerEphemeralKey = await this._importEphemeralPub(respData.ephemeralPub);
            const sharedBits = await crypto.subtle.deriveBits(
                { name: 'ECDH', public: peerEphemeralKey },
                this.localEphemeral.privateKey,
                256
            );

            // 7. Derive session keys via HKDF
            const sessionSalt = crypto.getRandomValues(new Uint8Array(16));
            this.sessionKeys = await this._deriveSessionKeys(sharedBits, sessionSalt);

            // 8. Generate verification code from shared secret (anti-MITM)
            this.verificationCode = await this._deriveVerificationCode(sharedBits);

            // 9. Challenge-response: encrypt a nonce and send it
            const nonce = crypto.getRandomValues(new Uint8Array(16));
            const challengeIv = crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: challengeIv },
                this.sessionKeys.encKey,
                nonce
            );

            const challenge = JSON.stringify({
                type: 'CHALLENGE',
                iv: this._bufToHex(challengeIv),
                data: this._bufToHex(encrypted),
                salt: this._bufToHex(sessionSalt)
            });
            await this._bleRetry(
                () => BLE.write(deviceId, SERVICE_UUID, CHAR_DATA, new TextEncoder().encode(challenge)), 'Write challenge');
            this._log('Sent challenge');

            // 10. Wait for challenge response
            const chalResp = await this._waitForNotification(deviceId, SERVICE_UUID, CHAR_DATA, 10000);
            const chalRespData = JSON.parse(new TextDecoder().decode(chalResp));

            if (chalRespData.type !== 'CHALLENGE_RESPONSE') {
                throw new Error('Invalid challenge response');
            }

            // Verify the echoed nonce
            const respIv = this._hexToBuf(chalRespData.iv);
            const respCipher = this._hexToBuf(chalRespData.data);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: respIv },
                this.sessionKeys.encKey,
                respCipher
            );
            const echoedNonce = new Uint8Array(decrypted);

            if (!this._constantTimeEqual(nonce, echoedNonce)) {
                throw new Error('Challenge verification failed — possible MITM');
            }

            // Handshake complete
            this.remotePeer = {
                deviceId,
                peerId,
                publicKeyHex: peerKeyHex,
                ephemeralKeyHex: respData.ephemeralPub
            };

            this._setState('connected');
            this._emit('connected', {
                peer: this.remotePeer,
                verificationCode: this.verificationCode
            });

            this._log(`Handshake complete with ${peerId} — code: ${this.verificationCode}`);
            return this.remotePeer;

        } catch (e) {
            this._log('Handshake failed: ' + e.message);
            this._setState('failed');
            this._emit('error', { phase: 'handshake', message: e.message });
            // Disconnect on failure
            try { await this.bleClient.disconnect(deviceId); } catch (_) {}
            return null;
        }
    }

    // ── Respond to incoming handshake (peripheral side) ─────────

    async handleIncomingHandshake(initData, writeBack) {
        if (!this.localEphemeral) throw new Error('Call init() first');

        try {
            // 1. Send our ephemeral key back
            const accept = JSON.stringify({
                type: 'HANDSHAKE_ACCEPT',
                nodeId: this.localIdentity.nodeId,
                ephemeralPub: this._ephemeralPubHex,
                ts: Date.now()
            });
            await writeBack(accept);

            // 2. Import initiator's ephemeral key
            const peerEphemeralKey = await this._importEphemeralPub(initData.ephemeralPub);

            // 3. Derive shared secret
            const sharedBits = await crypto.subtle.deriveBits(
                { name: 'ECDH', public: peerEphemeralKey },
                this.localEphemeral.privateKey,
                256
            );

            // 4. Verification code (both devices compute the same code)
            this.verificationCode = await this._deriveVerificationCode(sharedBits);

            this.remotePeer = {
                peerId: initData.nodeId,
                ephemeralKeyHex: initData.ephemeralPub
            };

            // Store shared bits for session key derivation when challenge arrives
            this._pendingSharedBits = sharedBits;

            this._setState('handshaking');
            this._emit('pairingRequest', {
                peerId: initData.nodeId,
                verificationCode: this.verificationCode
            });

            this._log(`Incoming handshake from ${initData.nodeId} — code: ${this.verificationCode}`);
        } catch (e) {
            this._log('Incoming handshake failed: ' + e.message);
            this._emit('error', { phase: 'incoming-handshake', message: e.message });
        }
    }

    async handleChallenge(challengeData, writeBack) {
        try {
            // Derive session keys with the salt from the challenger
            const salt = this._hexToBuf(challengeData.salt);
            this.sessionKeys = await this._deriveSessionKeys(this._pendingSharedBits, salt);
            this._pendingSharedBits = null;

            // Decrypt the challenge nonce
            const iv = this._hexToBuf(challengeData.iv);
            const cipher = this._hexToBuf(challengeData.data);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                this.sessionKeys.encKey,
                cipher
            );

            // Re-encrypt with a fresh IV and send back
            const respIv = crypto.getRandomValues(new Uint8Array(12));
            const reEncrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: respIv },
                this.sessionKeys.encKey,
                decrypted
            );

            const response = JSON.stringify({
                type: 'CHALLENGE_RESPONSE',
                iv: this._bufToHex(respIv),
                data: this._bufToHex(reEncrypted)
            });
            await writeBack(response);

            this._setState('connected');
            this._emit('connected', {
                peer: this.remotePeer,
                verificationCode: this.verificationCode
            });

            this._log('Challenge-response complete — session established');
        } catch (e) {
            this._log('Challenge-response failed: ' + e.message);
            this._setState('failed');
            this._emit('error', { phase: 'challenge', message: e.message });
        }
    }

    // ── Encrypted messaging over established session ────────────

    async sendEncrypted(deviceId, plaintext) {
        if (!this.sessionKeys) throw new Error('No session — handshake first');

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.sessionKeys.encKey,
            data
        );

        return {
            type: 'ENCRYPTED_MSG',
            iv: this._bufToHex(iv),
            data: this._bufToHex(encrypted)
        };
    }

    async decryptMessage(msg) {
        if (!this.sessionKeys) throw new Error('No session');

        const iv = this._hexToBuf(msg.iv);
        const cipher = this._hexToBuf(msg.data);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.sessionKeys.encKey,
            cipher
        );

        return new TextDecoder().decode(decrypted);
    }

    // ── Crypto internals ────────────────────────────────────────

    async _importEphemeralPub(hex) {
        const raw = this._hexToBuf(hex);
        return crypto.subtle.importKey(
            'raw', raw,
            { name: 'ECDH', namedCurve: 'P-256' },
            false, []
        );
    }

    async _deriveSessionKeys(sharedBits, salt) {
        const ikm = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
        const enc = new TextEncoder();

        const encKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('GhostNet-Proximity-v1-enc') },
            ikm,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        const macKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('GhostNet-Proximity-v1-mac') },
            ikm,
            { name: 'HMAC', hash: 'SHA-256', length: 256 },
            false,
            ['sign', 'verify']
        );

        return { encKey, macKey };
    }

    async _deriveVerificationCode(sharedBits) {
        // SHA-256 the shared bits, take first 3 bytes → 6-digit code
        const hash = await crypto.subtle.digest('SHA-256', sharedBits);
        const bytes = new Uint8Array(hash);
        const num = (bytes[0] << 16 | bytes[1] << 8 | bytes[2]) % 1000000;
        return String(num).padStart(6, '0');
    }

    _constantTimeEqual(a, b) {
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    async _waitForNotification(deviceId, serviceUUID, charUUID, timeoutMs) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error('Notification timeout'));
            }, timeoutMs);

            this.bleClient.startNotifications(deviceId, serviceUUID, charUUID, (value) => {
                clearTimeout(timer);
                resolve(value);
            });
        });
    }

    // ── GATT retry — BLE reads/writes can fail at range ────────

    async _bleRetry(fn, label, maxAttempts = 3) {
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return await fn();
            } catch (e) {
                this._log(`${label} attempt ${attempt}/${maxAttempts} failed: ${e.message}`);
                if (attempt === maxAttempts) throw e;
                // Brief pause before retry — BLE stack needs recovery time
                await new Promise(r => setTimeout(r, 300 * attempt));
            }
        }
    }

    // ── Utilities ────────────────────────────────────────────────

    _bufToHex(buf) {
        return Array.from(new Uint8Array(buf.buffer || buf))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    _hexToBuf(hex) {
        const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
        const bytes = new Uint8Array(clean.match(/.{1,2}/g).map(b => parseInt(b, 16)));
        return bytes.buffer;
    }

    _log(msg) {
        console.log(`[ProximityConnect] ${msg}`);
    }

    disconnect() {
        if (this.remotePeer?.deviceId && this.bleClient) {
            try { this.bleClient.disconnect(this.remotePeer.deviceId); } catch (_) {}
        }
        this.sessionKeys = null;
        this.remotePeer = null;
        this.verificationCode = null;
        this.localEphemeral = null;
        this._pendingSharedBits = null;
        this._setState('idle');
    }
}

window.ProximityConnect = new ProximityConnect();
