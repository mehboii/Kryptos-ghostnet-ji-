/**
 * Proximity Connect — Offline BLE Discovery + Mutual Identity Auth + Session
 *
 * Runs in the WebView, but the radio lives in React Native. All BLE I/O goes
 * through `window.GhostNetBLE` (injected by App.js, backed by ProximityBLE.js:
 * react-native-ble-plx for the central role + the ghostnet-ble-peripheral native
 * module for advertising + GATT server). The previous version imported
 * `@capacitor-community/bluetooth-le`, which does not exist in this runtime — so
 * it threw on first use and discovery silently failed. It also only ever scanned
 * (never advertised), so two phones could never see each other.
 *
 * What this version does, symmetrically on every device:
 *   1. ADVERTISE + SCAN concurrently. Advertise the shared rendezvous Service
 *      UUID + a rotating ephemeral pseudonym (never a stable id); scan for the
 *      same UUID, dedupe, sort by RSSI, expose a live nearby list.
 *   2. CONNECT (central) on selection; negotiate MTU up.
 *   3. AUTHENTICATE (mutual). Ephemeral ECDH (P-256) → shared session key, THEN
 *      a challenge–response where each side signs a FRESH random nonce with its
 *      long-term GhostNet identity key (secp256k1 / ethers) and verifies the
 *      peer's signature against the peer's identity public key. The signed
 *      transcript is bound to BOTH ephemeral public keys, so a man-in-the-middle
 *      who substitutes its own ECDH keys cannot forge a victim's signature.
 *      Fail closed on any mismatch or timeout.
 *   4. SESSION. Derive AES-256-GCM keys via HKDF; all further data is encrypted.
 *   5. MESH. Register the authenticated peer with GhostMesh as a BLE neighbor.
 *
 * Crypto notes (see the README "Assumptions / missing APIs" section):
 *   - The repo has NO Ed25519/X25519 (the original spec's wording). The real
 *     GhostNet identity is secp256k1 (ethers wallet, crypto-identity.js), so the
 *     identity proof signs with that. Ephemeral key agreement stays P-256 ECDH
 *     via Web Crypto, exactly as the prior version did.
 */

'use strict';

const PROX_SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';
const PROX_CHAR_PEER_ID = '67686f73-746e-6574-2d69-640000000000';
const PROX_CHAR_PUB_KEY = '67686f73-746e-6574-2d6b-657900000000';
const PROX_CHAR_DATA    = '67686f73-746e-6574-2d64-617461000000';

const PSEUDONYM_ROTATION_MS = 15 * 60 * 1000;
const AUTH_TRANSCRIPT_TAG = 'GHOSTNET-PROX-AUTHv1';
const SCAN_REPORT_MS = 8000; // first "scanComplete" for the UI; scanning continues

// BLE notifications are capped at MTU-3 bytes and the stack does NOT chunk them,
// so handshake frames (identity pubkey + ephemeral pubkey + signature ≈ 400 B)
// must be fragmented and reassembled by us. We base64 the JSON first (so every
// fragment is JSON-string-safe) then wrap each slice in a tiny envelope that fits
// the smallest target MTU (iOS ≈ 185 → ~182 usable). 120 keeps envelopes well
// under that even after the {"_g":..,"i":..,"n":..,"d":".."} overhead.
const FRAME_CHUNK = 120;

class ProximityConnect {
    constructor() {
        this.state = 'idle'; // idle | advertising_scanning | peer_found | connecting | authenticating | session_ready | mesh_registered | failed
        this.sessionKeys = null;
        this.localEphemeral = null; // CryptoKeyPair (P-256 ECDH)
        this._ephemeralPubHex = null;
        this.localIdentity = null;  // { nodeId, publicKeyHex }
        this.remotePeer = null;
        this.verificationCode = null;
        this._listeners = {};
        this._scanDevices = new Map(); // deviceId -> { deviceId, name, rssi, timestamp }
        this._advertising = false;
        this._scanning = false;
        this._pseudonymSecret = null;
        this._pseudonymTimer = null;
        this._scanReportTimer = null;
        this._bridgeWired = false;
        // Per-connection responder state (peripheral side).
        this._responder = null; // { deviceId, sharedBits, peerIdentityPub, peerNodeId, peerDisplayName, ephA, ephB, nonceB }
        this._pendingSession = null;   // authed session awaiting user confirmation
        this._registeredPeerId = null; // mesh peer created by confirmSession()
    }

    // ── Events ──────────────────────────────────────────────────
    on(event, fn) {
        (this._listeners[event] = this._listeners[event] || []).push(fn);
    }
    _emit(event, data) {
        (this._listeners[event] || []).forEach(fn => { try { fn(data); } catch (_) {} });
    }
    _setState(s) {
        this.state = s;
        this._emit('stateChange', s);
    }

    get _ble() {
        return (typeof window !== 'undefined') ? window.GhostNetBLE : null;
    }

    // ── Init ────────────────────────────────────────────────────
    async init(identity) {
        if (!identity || !identity.nodeId) throw new Error('Identity required');
        if (!this._ble) {
            throw new Error('Native BLE bridge unavailable. Proximity Connect needs the GhostNet dev/EAS build (not Expo Go / browser).');
        }

        this.localIdentity = {
            nodeId: identity.nodeId,
            displayName: this._resolveDisplayName(identity),
            publicKeyHex: await this._resolveIdentityPublicKey(identity)
        };
        if (!this._isRealPublicKey(this.localIdentity.publicKeyHex)) {
            // Identity auth signs/verifies against a real secp256k1 key. Without one
            // we'd fall back to unauthenticated key-agreement — refuse instead.
            throw new Error('Could not resolve your GhostNet public key — unlock your identity before pairing.');
        }

        // Ephemeral ECDH (P-256). Private key non-extractable → never leaves device.
        this.localEphemeral = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']
        );
        const pubRaw = await crypto.subtle.exportKey('raw', this.localEphemeral.publicKey);
        this._ephemeralPubHex = this._bufToHex(pubRaw);

        await this._initPseudonymSecret();
        this._wireBridge();

        this._log('Initialized (ephemeral ECDH + identity ' + (this.localIdentity.publicKeyHex ? 'present' : 'MISSING') + ')');
        return true;
    }

    /**
     * Concurrent ADVERTISE + SCAN. This is the fix: a phone is discoverable while
     * it scans, so discovery is mutual. UI calls this `startScan` for back-compat.
     */
    async startScan() {
        if (!this.localEphemeral) throw new Error('Call init() first');
        const ble = this._ble;

        // Permissions + radio readiness (degrade gracefully, never crash).
        try {
            const granted = await ble.requestPermissions();
            if (granted === false) {
                this._emit('error', { phase: 'permission', message: 'Bluetooth permission denied' });
                return [];
            }
        } catch (_) {}

        const state = await ble.adapterState().catch(() => 'Unknown');
        if (state && state !== 'PoweredOn') {
            this._emit('error', { phase: 'adapter', message: 'Bluetooth is off or unavailable (' + state + ')' });
            return [];
        }

        this._setState('advertising_scanning');
        this._scanDevices.clear();

        // 1) ADVERTISE (best-effort — degrade to scan-only if unsupported).
        await this._startAdvertising();

        // 2) SCAN (continuous). deviceFound/deviceUpdated come via the bridge.
        try {
            this._scanning = true;
            await ble.startScan();
            this._log('Advertising + scanning for rendezvous ' + PROX_SERVICE_UUID);
        } catch (e) {
            this._emit('error', { phase: 'scan', message: e.message });
        }

        // Emit a "scanComplete" snapshot for the existing UI after a short window,
        // WITHOUT stopping the radio (discovery stays live in the background).
        clearTimeout(this._scanReportTimer);
        this._scanReportTimer = setTimeout(() => {
            const devices = this._sortedDevices();
            this._emit('scanComplete', { devices, count: devices.length });
        }, SCAN_REPORT_MS);

        return this._sortedDevices();
    }

    // Adaptive scan kept as an alias so the UI's optional call still works.
    startAdaptiveScan() { return this.startScan(); }

    stopScan() {
        const ble = this._ble;
        clearTimeout(this._scanReportTimer);
        if (ble) { try { ble.stopScan(); } catch (_) {} }
        this._scanning = false;
        if (this.state === 'advertising_scanning') this._setState('idle');
    }

    async stop() {
        this.stopScan();
        clearInterval(this._pseudonymTimer);
        this._pseudonymTimer = null;
        if (this._ble && this._advertising) { try { await this._ble.stopAdvertising(); } catch (_) {} }
        this._advertising = false;
        this._setState('idle');
    }

    _sortedDevices() {
        return [...this._scanDevices.values()].sort((a, b) => (b.rssi || -999) - (a.rssi || -999));
    }

    // ── Advertising + rotating pseudonym ────────────────────────
    async _startAdvertising() {
        const ble = this._ble;
        try {
            const supported = await ble.isPeripheralSupported();
            if (!supported) {
                this._advertising = false;
                this._emit('error', { phase: 'advertise', message: 'This device cannot advertise — running scan-only. The other phone must be advertise-capable for discovery.' });
                return;
            }
            const pseudonymHex = await this._currentPseudonymHex();
            // peerId/publicKeyHex are deliberately BLANK: CHAR_PEER_ID/CHAR_PUB_KEY
            // were readable by ANY connecting central before authentication, leaking
            // a stable nodeId + identity key and defeating the rotating pseudonym.
            // Identity is now exchanged only inside the handshake frames.
            const ok = await ble.startAdvertising({
                peerId: '',
                publicKeyHex: '',
                pseudonymHex
            });
            this._advertising = !!ok;
            if (ok) this._schedulePseudonymRotation();
        } catch (e) {
            this._advertising = false;
            this._emit('error', { phase: 'advertise', message: e.message });
        }
    }

    _schedulePseudonymRotation() {
        clearInterval(this._pseudonymTimer);
        this._pseudonymTimer = setInterval(async () => {
            if (!this._advertising) return;
            try { await this._ble.updatePseudonym(await this._currentPseudonymHex()); }
            catch (_) {}
        }, PSEUDONYM_ROTATION_MS);
    }

    async _initPseudonymSecret() {
        // Prefer a secret DERIVED from the identity private key (stable across
        // restarts, unforgeable by others). If the key is locked/unavailable,
        // fall back to a fresh random secret — still unlinkable, just not stable.
        let basis = null;
        try {
            if (window.GhostIdentity && window.GhostIdentity.getSessionPrivateKey) {
                basis = await window.GhostIdentity.getSessionPrivateKey();
            }
        } catch (_) {}
        if (basis && /^0x[0-9a-fA-F]{64}$/.test(basis)) {
            const seed = new TextEncoder().encode('ghostnet-pseudonym|' + basis);
            const digest = await crypto.subtle.digest('SHA-256', seed);
            this._pseudonymSecret = new Uint8Array(digest);
        } else {
            this._pseudonymSecret = crypto.getRandomValues(new Uint8Array(32));
        }
    }

    /** pseudonym = HMAC-SHA256(secret, windowCounter)[0..4) — rotates every 15 min. */
    async _currentPseudonymHex() {
        if (!this._pseudonymSecret) await this._initPseudonymSecret();
        const win = Math.floor(Date.now() / PSEUDONYM_ROTATION_MS);
        const winBytes = new Uint8Array(8);
        const dv = new DataView(winBytes.buffer);
        dv.setUint32(0, Math.floor(win / 2 ** 32) >>> 0);
        dv.setUint32(4, win >>> 0);
        const key = await crypto.subtle.importKey(
            'raw', this._pseudonymSecret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );
        const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, winBytes));
        return this._bufToHex(mac.slice(0, 4));
    }

    // ── Bridge wiring (central notifications + peripheral writes) ─
    _wireBridge() {
        if (this._bridgeWired || !this._ble) return;
        this._bridgeWired = true;

        // CENTRAL: track scan results.
        const upsert = (d) => {
            if (!d || !d.deviceId) return;
            const known = this._scanDevices.has(d.deviceId);
            this._scanDevices.set(d.deviceId, d);
            if (!known) {
                this._emit('deviceFound', d);
            } else {
                this._emit('deviceUpdated', d); // RSSI refresh for re-sorting
            }
        };
        this._ble.on('deviceFound', upsert);
        this._ble.on('deviceUpdated', upsert);

        // CENTRAL: notifications from the peer's GATT server land here. Fragments
        // are reassembled before dispatch.
        this._ble.on('notification', (e) => {
            if (!e || !e.base64) return;
            const frame = this._ingest(e.deviceId, this._b64ToStr(e.base64));
            if (frame) this._onCentralFrame(e.deviceId, frame);
        });

        // PERIPHERAL: a connecting central wrote a (possibly fragmented) frame.
        this._ble.on('centralWrite', (e) => {
            if (!e || !e.base64) return;
            const frame = this._ingest(e.deviceId, this._b64ToStr(e.base64));
            if (frame) this._onResponderFrame(e.deviceId, frame);
        });

        this._ble.on('disconnected', (e) => {
            if (this.remotePeer && this.remotePeer.deviceId === (e && e.deviceId)) {
                // Link dropped — revoke any mesh trust granted for this session.
                this._unregisterMeshPeer();
                this._pendingSession = null;
                this._emit('disconnected', { deviceId: e.deviceId });
                if (this.state !== 'session_ready' && this.state !== 'mesh_registered') {
                    this._setState('advertising_scanning');
                }
            }
        });

        this._ble.on('error', (e) => this._emit('error', e));
    }

    // ── Central handshake (initiator) ───────────────────────────
    async connectTo(deviceId) {
        if (!this.localEphemeral) throw new Error('Call init() first');
        const ble = this._ble;
        this._setState('connecting');

        try {
            await ble.connect(deviceId);
            await ble.startNotifications(deviceId, PROX_CHAR_DATA);
            this._log('Connected to ' + deviceId.slice(0, 12));

            // No GATT identity reads: CHAR_PEER_ID/CHAR_PUB_KEY are blank by design
            // (pre-auth identity leak). Identity arrives in HANDSHAKE_ACCEPT instead.
            this._setState('authenticating');

            // 1. HANDSHAKE_INIT → peer (our identity + ephemeral pub). Central
            //    writes go to the peer's CHAR_DATA (useNotify=false).
            await this._sendData(deviceId, {
                type: 'HANDSHAKE_INIT',
                nodeId: this.localIdentity.nodeId,
                displayName: this.localIdentity.displayName,
                identityPub: this.localIdentity.publicKeyHex,
                ephemeralPub: this._ephemeralPubHex,
                ts: Date.now()
            }, false);

            // 2. Wait for HANDSHAKE_ACCEPT (peer ephemeral pub).
            const accept = await this._awaitFrame(12000);
            if (accept.type !== 'HANDSHAKE_ACCEPT' || !accept.ephemeralPub) {
                throw new Error('Invalid handshake response');
            }
            const ephA = this._ephemeralPubHex;        // initiator ephemeral (us)
            const ephB = accept.ephemeralPub;          // responder ephemeral (peer)
            const peerNodeId = String(accept.nodeId || '').trim();
            const acceptIdentityPub = this._normalizePub(accept.identityPub || '');
            if (!peerNodeId || !acceptIdentityPub) {
                throw new Error('Peer did not present an identity in the handshake');
            }
            this._log('Peer ' + peerNodeId.slice(0, 12) + ' id-key ' + acceptIdentityPub.slice(0, 16) + '…');

            // 3. Derive ECDH shared secret + session keys + visual code.
            const sharedBits = await this._deriveShared(ephB);
            const salt = crypto.getRandomValues(new Uint8Array(16));
            this.sessionKeys = await this._deriveSessionKeys(sharedBits, salt);
            this.verificationCode = await this._deriveVerificationCode(sharedBits);

            // 4. CHALLENGE: our fresh nonce; peer must sign it with its identity key.
            const nonceA = this._bufToHex(crypto.getRandomValues(new Uint8Array(16)));
            await this._sendData(deviceId, {
                type: 'CHALLENGE',
                nonce: nonceA,
                salt: this._bufToHex(salt),
                identityPub: this.localIdentity.publicKeyHex
            }, false);

            // 5. CHALLENGE_RESPONSE: peer's signature over nonceA + peer's nonceB.
            const chalResp = await this._awaitFrame(12000);
            if (chalResp.type !== 'CHALLENGE_RESPONSE' || !chalResp.signature || !chalResp.nonce) {
                throw new Error('Invalid challenge response');
            }
            const okPeer = await this._verifyIdentitySig(
                acceptIdentityPub, nonceA, ephA, ephB, chalResp.signature
            );
            if (!okPeer) throw new Error('Peer identity signature INVALID — possible MITM/impersonation');

            // The signature proves the peer owns acceptIdentityPub; this proves the
            // claimed nodeId actually DERIVES from that key (anti-GhostTag-spoofing).
            this._assertNodeIdBinding(peerNodeId, acceptIdentityPub, accept.displayName);

            // 6. AUTH_FINAL: prove OUR identity by signing peer's nonceB.
            const sigA = await this._signIdentity(chalResp.nonce, ephA, ephB);
            await this._sendData(deviceId, { type: 'AUTH_FINAL', signature: sigA }, false);

            // Mutual identity auth complete.
            this.remotePeer = { deviceId, peerId: peerNodeId, publicKeyHex: acceptIdentityPub, ephemeralKeyHex: ephB };
            this._sessionRole = 'central';
            await this._onSessionReady(deviceId, 'ble');
            return this.remotePeer;

        } catch (e) {
            this._log('Handshake failed: ' + e.message);
            this._setState('failed');
            this._emit('error', { phase: 'handshake', message: e.message });
            try { await ble.disconnect(deviceId); } catch (_) {}
            // Return to discovery so the user can retry.
            setTimeout(() => { if (this.state === 'failed') this._setState('advertising_scanning'); }, 50);
            return null;
        }
    }

    // ── Peripheral handshake (responder) ────────────────────────
    async _onResponderFrame(deviceId, frame) {
        try {
            if (frame.type === 'HANDSHAKE_INIT') {
                const ephA = frame.ephemeralPub;       // initiator ephemeral (peer)
                const ephB = this._ephemeralPubHex;    // responder ephemeral (us)
                const sharedBits = await this._deriveShared(ephA);
                this.verificationCode = await this._deriveVerificationCode(sharedBits);
                this._responder = {
                    deviceId,
                    sharedBits,
                    ephA, ephB,
                    peerIdentityPub: this._normalizePub(frame.identityPub || ''),
                    peerNodeId: frame.nodeId,
                    peerDisplayName: frame.displayName
                };
                this._setState('authenticating');
                this._emit('pairingRequest', { peerId: frame.nodeId, verificationCode: this.verificationCode });

                await this._sendData(deviceId, {
                    type: 'HANDSHAKE_ACCEPT',
                    nodeId: this.localIdentity.nodeId,
                    displayName: this.localIdentity.displayName,
                    identityPub: this.localIdentity.publicKeyHex,
                    ephemeralPub: this._ephemeralPubHex,
                    ts: Date.now()
                }, true);
                return;
            }

            if (frame.type === 'CHALLENGE') {
                const r = this._responder;
                if (!r) throw new Error('CHALLENGE before HANDSHAKE_INIT');
                if (frame.identityPub) r.peerIdentityPub = this._normalizePub(frame.identityPub);
                this.sessionKeys = await this._deriveSessionKeys(r.sharedBits, this._hexToBytes(frame.salt));

                // Sign the initiator's nonce (prove OUR identity), and challenge back.
                const sigB = await this._signIdentity(frame.nonce, r.ephA, r.ephB);
                r.nonceB = this._bufToHex(crypto.getRandomValues(new Uint8Array(16)));
                await this._sendData(deviceId, { type: 'CHALLENGE_RESPONSE', signature: sigB, nonce: r.nonceB }, true);
                return;
            }

            if (frame.type === 'AUTH_FINAL') {
                const r = this._responder;
                if (!r || !r.nonceB) throw new Error('AUTH_FINAL out of order');
                const okPeer = await this._verifyIdentitySig(
                    r.peerIdentityPub, r.nonceB, r.ephA, r.ephB, frame.signature
                );
                if (!okPeer) throw new Error('Initiator identity signature INVALID — possible MITM/impersonation');

                // Bind the claimed nodeId to the key that just signed (anti-spoofing).
                this._assertNodeIdBinding(r.peerNodeId, r.peerIdentityPub, r.peerDisplayName);

                this.remotePeer = {
                    deviceId,
                    peerId: r.peerNodeId,
                    publicKeyHex: r.peerIdentityPub,
                    ephemeralKeyHex: r.ephA
                };
                this._responder = null;
                this._sessionRole = 'peripheral';
                await this._onSessionReady(deviceId, 'ble');
                return;
            }

            if (frame.type === 'ENCRYPTED_MSG') {
                const text = await this.decryptMessage(frame);
                this._emit('message', { deviceId, text });
                return;
            }
        } catch (e) {
            this._log('Responder error: ' + e.message);
            this._setState('failed');
            this._emit('error', { phase: 'responder', message: e.message });
            this._responder = null;
            setTimeout(() => { if (this.state === 'failed') this._setState('advertising_scanning'); }, 50);
        }
    }

    // ── nodeId ↔ identity-key binding ───────────────────────────
    /**
     * nodeId is deterministically derived from the peer's public key under one of:
     *   v2 (CURRENT): "gn_" + BLAKE3(uncompressed pubkey bytes)        — pubkey-only
     *   v1 (LEGACY):  ethers.id("<len>:<pubkey>|<len>:<displayName>")  — keccak256
     * (crypto-identity.js generateNodeId / nodeIdMatches). A valid signature only
     * proves the peer owns SOME key — without this check it could pair that key with
     * a victim's nodeId/GhostTag. Recompute under BOTH schemes and fail closed on
     * mismatch so v1 and v2 nodes interoperate.
     */
    _assertNodeIdBinding(claimedNodeId, identityPubHex, displayName) {
        const gi = (typeof window !== 'undefined') ? window.GhostIdentity : null;
        if (!gi || typeof gi.generateNodeId !== 'function') {
            throw new Error('Identity module unavailable — cannot verify peer nodeId binding');
        }
        let canonicalPub;
        try {
            // Creation always uses the uncompressed lowercase 0x04… form
            // (wallet.signingKey.publicKey); expand whatever the peer sent to match.
            canonicalPub = ethers.SigningKey.computePublicKey(
                '0x' + String(identityPubHex || '').replace(/^0x/, ''), false
            );
        } catch (_) {
            throw new Error('Peer identity key is not a valid secp256k1 key');
        }
        // Accept BOTH derivations so v2 (BLAKE3, "gn_") and v1 (keccak, "0x") nodes
        // interoperate. nodeIdMatches dispatches on the claimed id's prefix.
        const ok = (typeof gi.nodeIdMatches === 'function')
            ? gi.nodeIdMatches(claimedNodeId, canonicalPub, displayName)
            // Fallback for older identity module: v1-only check.
            : (claimedNodeId && String(gi.generateNodeId(canonicalPub, displayName)).toLowerCase()
                 === String(claimedNodeId).toLowerCase());
        if (!ok) {
            throw new Error('Peer nodeId does not derive from its identity key — impersonation blocked');
        }
    }

    // ── Identity public-key resolution ─────────────────────────
    /** A real secp256k1 pubkey: 33-byte compressed (02/03) or 65-byte uncompressed (04). */
    _isRealPublicKey(hex) {
        if (!hex) return false;
        const h = hex.replace(/^0x/, '').toLowerCase();
        return (h.length === 66 && (h.startsWith('02') || h.startsWith('03'))) ||
               (h.length === 130 && h.startsWith('04'));
    }

    /**
     * Our displayName as used at nodeId creation time. It is part of the
     * canonical nodeId derivation, so the peer needs it to verify our binding.
     */
    _resolveDisplayName(identity) {
        if (identity && identity.displayName !== undefined && identity.displayName !== null) {
            return String(identity.displayName);
        }
        try {
            const stored = window.GhostIdentity && window.GhostIdentity.getStoredIdentity
                ? window.GhostIdentity.getStoredIdentity() : null;
            if (stored && stored.displayName !== undefined && stored.displayName !== null) {
                return String(stored.displayName);
            }
        } catch (_) {}
        return '';
    }

    /**
     * Resolve OUR real identity public key. The app's `identity.pub` is often the
     * nodeId (a keccak hash), NOT a key — so prefer the stored identity, then derive
     * from the in-memory private key, before giving up.
     */
    async _resolveIdentityPublicKey(identity) {
        const candidates = [identity.publicKeyHex, identity.publicKey, identity.pub];
        for (const c of candidates) {
            const n = this._normalizePub(c);
            if (this._isRealPublicKey(n)) return n;
        }
        try {
            const stored = window.GhostIdentity && window.GhostIdentity.getStoredIdentity
                ? window.GhostIdentity.getStoredIdentity() : null;
            if (stored && this._isRealPublicKey(this._normalizePub(stored.publicKey))) {
                return this._normalizePub(stored.publicKey);
            }
        } catch (_) {}
        try {
            const pk = window.GhostIdentity && await window.GhostIdentity.getSessionPrivateKey();
            if (pk && typeof ethers !== 'undefined') {
                const pub = new ethers.SigningKey(pk).publicKey; // uncompressed 0x04…
                return this._normalizePub(pub);
            }
        } catch (_) {}
        return '';
    }

    // ── Identity signature (secp256k1 / ethers), bound to ECDH ──
    _authTranscript(nonceHex, ephAHex, ephBHex) {
        return `${AUTH_TRANSCRIPT_TAG}|${nonceHex}|${ephAHex}|${ephBHex}`;
    }

    async _signIdentity(nonceHex, ephAHex, ephBHex) {
        const pk = window.GhostIdentity && await window.GhostIdentity.getSessionPrivateKey();
        if (!pk) throw new Error('Identity locked — unlock GhostNet before pairing');
        const wallet = new ethers.Wallet(pk);
        return wallet.signMessage(this._authTranscript(nonceHex, ephAHex, ephBHex));
    }

    async _verifyIdentitySig(peerIdentityPubHex, nonceHex, ephAHex, ephBHex, signature) {
        try {
            if (!peerIdentityPubHex) return false;
            const recovered = ethers.verifyMessage(this._authTranscript(nonceHex, ephAHex, ephBHex), signature);
            const expected = ethers.computeAddress('0x' + peerIdentityPubHex.replace(/^0x/, ''));
            return recovered.toLowerCase() === expected.toLowerCase();
        } catch (_) {
            return false;
        }
    }

    // ── Session ready + mesh registration ───────────────────────
    /**
     * Cryptographic auth is complete, but the peer is NOT trusted yet: mesh
     * registration is deferred until the user compares the 6-digit verification
     * code and calls confirmSession(). This applies to BOTH roles.
     */
    async _onSessionReady(deviceId, transport) {
        this._pendingSession = { deviceId };
        this._setState('session_ready');
        this._emit('connected', { peer: this.remotePeer, verificationCode: this.verificationCode });
        this._log('SESSION_READY with ' + (this.remotePeer.peerId || deviceId).slice(0, 12) + ' code ' + this.verificationCode + ' — awaiting user confirmation');
    }

    /** User confirmed the verification code matches — NOW grant mesh trust. */
    confirmSession() {
        const pending = this._pendingSession;
        if (!pending || !this.remotePeer || this.state !== 'session_ready') {
            this._log('confirmSession ignored — no session awaiting confirmation');
            return false;
        }
        const deviceId = pending.deviceId;
        try {
            if (window.app && window.app.mesh && typeof window.app.mesh.registerProximityPeer === 'function') {
                window.app.mesh.registerProximityPeer({
                    id: this.remotePeer.peerId || deviceId,
                    deviceId,
                    name: 'Proximity ' + (this.remotePeer.peerId || deviceId).slice(-6),
                    publicKey: this.remotePeer.publicKeyHex,
                    transport: 'ble',
                    send: (payload) => this.sendEncryptedTo(deviceId, payload)
                });
                this._registeredPeerId = this.remotePeer.peerId || deviceId;
                this._setState('mesh_registered');
                this._log('User confirmed pairing — registered authenticated peer in mesh');
            }
            this._pendingSession = null;
            return true;
        } catch (e) {
            this._emit('error', { phase: 'mesh', message: e.message });
            return false;
        }
    }

    /** Remove the mesh peer created by confirmSession(), if any. */
    _unregisterMeshPeer() {
        const peerId = this._registeredPeerId;
        this._registeredPeerId = null;
        if (!peerId) return;
        try {
            if (window.app && window.app.mesh && typeof window.app.mesh.unregisterProximityPeer === 'function') {
                window.app.mesh.unregisterProximityPeer(peerId);
                this._log('Unregistered proximity peer ' + String(peerId).slice(0, 12) + ' from mesh');
            }
        } catch (_) {}
    }

    // ── Encrypted messaging over the session ────────────────────
    async sendEncrypted(plaintext) {
        if (!this.sessionKeys) throw new Error('No session — handshake first');
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const data = new TextEncoder().encode(typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.sessionKeys.encKey, data);
        return { type: 'ENCRYPTED_MSG', iv: this._bufToHex(iv), data: this._bufToHex(encrypted) };
    }

    /** Encrypt + push to a connected peer. Central writes; peripheral notifies. */
    async sendEncryptedTo(deviceId, plaintext) {
        const msg = await this.sendEncrypted(plaintext);
        const useNotify = this._sessionRole === 'peripheral';
        await this._sendData(deviceId, msg, useNotify);
        return true;
    }

    async decryptMessage(msg) {
        if (!this.sessionKeys) throw new Error('No session');
        const iv = this._hexToBytes(msg.iv);
        const cipher = this._hexToBytes(msg.data);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.sessionKeys.encKey, cipher);
        return new TextDecoder().decode(decrypted);
    }

    // ── BLE frame helpers (fragmented DATA channel) ─────────────
    /**
     * Serialize → base64 → fragment → send. useNotify=true uses the peripheral
     * notify path (responder → central); false uses the central write path
     * (central → peripheral's GATT server).
     */
    async _sendData(deviceId, obj, useNotify) {
        const b64 = this._strToB64(JSON.stringify(obj));
        const fid = (Date.now() % 1e6).toString(36) + Math.floor(Math.random() * 1e6).toString(36);
        const total = Math.max(1, Math.ceil(b64.length / FRAME_CHUNK));
        for (let i = 0; i < total; i++) {
            const env = JSON.stringify({ _g: fid, i, n: total, d: b64.slice(i * FRAME_CHUNK, (i + 1) * FRAME_CHUNK) });
            const wire = this._strToB64(env);
            if (useNotify) await this._ble.notifyData(wire);
            else await this._ble.write(deviceId, PROX_CHAR_DATA, wire);
        }
    }

    /** Reassemble a fragment; returns the parsed frame once complete, else null. */
    _ingest(deviceId, rawStr) {
        let env;
        try { env = JSON.parse(rawStr); } catch (_) { return null; }
        if (!env || env._g === undefined || env.d === undefined) return null;
        if (!this._reasm) this._reasm = new Map();
        const key = deviceId + ':' + env._g;
        let slot = this._reasm.get(key);
        if (!slot) { slot = { n: env.n, parts: new Array(env.n), got: 0, at: Date.now() }; this._reasm.set(key, slot); }
        if (slot.parts[env.i] === undefined) { slot.parts[env.i] = env.d; slot.got++; }
        if (slot.got < slot.n) {
            this._gcReasm();
            return null;
        }
        this._reasm.delete(key);
        try { return JSON.parse(this._b64ToStr(slot.parts.join(''))); }
        catch (_) { return null; }
    }

    _gcReasm() {
        // Drop partial frames older than 30s so a dropped fragment can't leak memory.
        const now = Date.now();
        for (const [k, v] of this._reasm) if (now - v.at > 30000) this._reasm.delete(k);
    }

    /** Central side: a fully reassembled notification frame. */
    _onCentralFrame(deviceId, frame) {
        if (this._frameResolver) {
            const r = this._frameResolver;
            this._frameResolver = null;
            r(frame);
            return;
        }
        if (frame && frame.type === 'ENCRYPTED_MSG') {
            this.decryptMessage(frame).then((text) => this._emit('message', { deviceId, text })).catch(() => {});
        }
    }

    /** Central side: await the next reassembled frame (handshake step). */
    _awaitFrame(timeoutMs) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => { this._frameResolver = null; reject(new Error('Notification timeout')); }, timeoutMs);
            this._frameResolver = (frame) => { clearTimeout(timer); resolve(frame); };
        });
    }

    // ── Crypto internals ────────────────────────────────────────
    async _deriveShared(peerEphemeralPubHex) {
        const peerKey = await crypto.subtle.importKey(
            'raw', this._hexToBytes(peerEphemeralPubHex), { name: 'ECDH', namedCurve: 'P-256' }, false, []
        );
        return crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, this.localEphemeral.privateKey, 256);
    }
    async _deriveSessionKeys(sharedBits, salt) {
        const ikm = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
        const enc = new TextEncoder();
        const encKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('GhostNet-Proximity-v1-enc') },
            ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );
        return { encKey };
    }
    async _deriveVerificationCode(sharedBits) {
        const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', sharedBits));
        const num = (hash[0] << 16 | hash[1] << 8 | hash[2]) % 1000000;
        return String(num).padStart(6, '0');
    }

    // ── Utilities ───────────────────────────────────────────────
    _normalizePub(p) {
        if (!p) return '';
        return String(p).replace(/^0x/, '').toLowerCase();
    }
    _bufToHex(buf) {
        return Array.from(new Uint8Array(buf.buffer || buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    _hexToBytes(hex) {
        const clean = String(hex).replace(/^0x/, '');
        const out = new Uint8Array(clean.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
        return out;
    }
    _strToB64(str) {
        return btoa(unescape(encodeURIComponent(str)));
    }
    _b64ToStr(b64) {
        return decodeURIComponent(escape(atob(b64)));
    }
    _b64ToHex(b64) {
        const bin = atob(b64);
        let hex = '';
        for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, '0');
        return hex;
    }
    _log(msg) { console.log('[ProximityConnect] ' + msg); }

    async disconnect() {
        this._unregisterMeshPeer();
        this._pendingSession = null;
        const deviceId = this.remotePeer && this.remotePeer.deviceId;
        if (deviceId && this._ble) { try { await this._ble.disconnect(deviceId); } catch (_) {} }
        this.sessionKeys = null;
        this.remotePeer = null;
        this.verificationCode = null;
        this._responder = null;
        this._setState(this._advertising || this._scanning ? 'advertising_scanning' : 'idle');
    }
}

if (typeof window !== 'undefined') window.ProximityConnect = new ProximityConnect();
