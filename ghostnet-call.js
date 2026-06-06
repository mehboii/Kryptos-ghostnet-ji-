/**
 * GhostNet 1:1 Encrypted Voice Call
 * =================================
 *
 * Phase 1: identity-authenticated 1:1 audio calls between two GhostTag
 * identities. Reuses existing infrastructure — NOTHING new is stood up:
 *
 *   • Signaling  → the existing encrypted mesh channel (GhostMesh.sendToPeer /
 *                  onMessage). No new server, no new socket.
 *   • iceServers → the existing STUN consensus + TURN relay (GhostNATManager).
 *   • Identity   → the app's GhostTag identity key (secp256k1) signs the local
 *                  DTLS fingerprint; the remote fingerprint is verified against
 *                  the resolved GhostTag identity BEFORE any SDP is applied.
 *
 * Media transport is WebRTC. Both the React web client and the React Native
 * Expo client run inside a WebView, so a single browser-`RTCPeerConnection`
 * adapter serves both today; a native `react-native-webrtc` adapter can be
 * dropped in behind the same injection points (see EXTENSION POINTS below).
 *
 * EXTENSION POINTS (intentionally NOT implemented in Phase 1):
 *   • Group calls / SFU — `_call` is a single 1:1 session by design. A future
 *     multi-party layer would manage a map of peer connections.
 *   • Insertable streams (per-frame E2EE on top of DTLS) — left out; the
 *     security guarantee here is the identity-bound DTLS fingerprint.
 *   • Native `react-native-webrtc` — inject `RTCPeerConnection` / `getUserMedia`
 *     via the constructor to swap the media engine without changing call logic.
 *
 * @module ghostnet-call
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory(
            require('./ghostnet-call-signaling.js'),
            require('./ghostnet-call-fingerprint.js')
        );
    } else {
        root.GhostCall = factory(root.GhostCallSignaling, root.GhostCallFingerprint);
    }
}(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this), function (Signaling, Fingerprint) {
    'use strict';

    // ─── CONSTANTS ──────────────────────────────────────

    const STATES = Object.freeze({
        IDLE: 'idle',
        RINGING: 'ringing',
        CONNECTING: 'connecting',
        ACTIVE: 'active',
        ENDED: 'ended',
    });

    const DEFAULT_RING_TIMEOUT_MS = 30000;
    /** Opus, tuned for mobile data — DTX on, modest average bitrate. */
    const DEFAULT_MAX_AVG_BITRATE = 24000; // bits/s
    const OPUS_RTPMAP_REGEX = /^a=rtpmap:(\d+)\s+opus\/48000(?:\/2)?\s*$/im;

    const DEFAULT_ICE_SERVERS = [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
    ];

    // ─── small helpers ──────────────────────────────────

    function _now() { return Date.now(); }

    function _uuid() {
        if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
        const b = (typeof crypto !== 'undefined' && crypto.getRandomValues)
            ? crypto.getRandomValues(new Uint8Array(16))
            : Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
        return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    }

    /**
     * Munge an SDP to: keep Opus, enable DTX, and cap the average bitrate so the
     * call stays friendly on mobile data. Returns a new SDP string.
     */
    function shapeOpusSdp(sdp, maxAvgBitrate) {
        const m = OPUS_RTPMAP_REGEX.exec(sdp);
        if (!m) return sdp; // no opus line — leave untouched
        const pt = m[1];
        const params = `usedtx=1;useinbandfec=1;maxaveragebitrate=${maxAvgBitrate}`;
        const fmtpRe = new RegExp(`^a=fmtp:${pt} (.*)$`, 'im');
        if (fmtpRe.test(sdp)) {
            return sdp.replace(fmtpRe, (line, existing) => {
                // Append our params if not already present.
                const has = /usedtx=/.test(existing);
                return has ? line : `a=fmtp:${pt} ${existing};${params}`;
            });
        }
        // No fmtp line for opus — insert one right after its rtpmap.
        return sdp.replace(m[0], `${m[0]}\r\na=fmtp:${pt} ${params}`);
    }

    // ─── tiny event emitter (matches the app's lightweight style) ──

    function createEmitter() {
        const handlers = new Map(); // event -> Set<fn>
        return {
            on(event, fn) {
                if (!handlers.has(event)) handlers.set(event, new Set());
                handlers.get(event).add(fn);
                return () => handlers.get(event) && handlers.get(event).delete(fn);
            },
            off(event, fn) { if (handlers.has(event)) handlers.get(event).delete(fn); },
            emit(event, payload) {
                if (!handlers.has(event)) return;
                for (const fn of handlers.get(event)) {
                    try { fn(payload); } catch (e) { /* never let a listener break call logic */ }
                }
            },
        };
    }

    // ─── MAIN CLASS ─────────────────────────────────────

    class GhostCall {
        /**
         * @param {Object} opts
         * @param {Object} opts.mesh   GhostMesh-like: sendToPeer(peerId,msg) + onMessage hook.
         * @param {Object} [opts.nat]  GhostNATManager-like (used for iceServers).
         * @param {Object} opts.identity  { id, publicKey, privateKey } — the local GhostTag identity.
         * @param {Object} [opts.signer]   DI signer; defaults to secp256k1 from identity.privateKey.
         * @param {Object} [opts.verifier] DI verifier; defaults to secp256k1.
         * @param {Function} [opts.resolveGhostTag]    async (tag) => { routeId, publicKey }.
         * @param {Function} [opts.resolveIdentityKey] async (peerId, msg) => publicKey|null (verify incoming).
         * @param {Function} [opts.getIceServers]      async () => RTCIceServer[].
         * @param {Array}    [opts.iceServers]          static iceServers (overrides getIceServers).
         * @param {Function} [opts.RTCPeerConnection]   constructor injection (native adapter / tests).
         * @param {Function} [opts.getUserMedia]        async (constraints) => MediaStream (injection).
         * @param {number}   [opts.ringTimeoutMs]
         * @param {number}   [opts.maxAverageBitrate]
         */
        constructor(opts) {
            opts = opts || {};
            if (!opts.mesh || typeof opts.mesh.sendToPeer !== 'function') {
                throw new Error('[GhostCall] opts.mesh with sendToPeer() is required');
            }
            if (!opts.identity || typeof opts.identity.id !== 'string') {
                throw new Error('[GhostCall] opts.identity.id is required');
            }

            this.mesh = opts.mesh;
            this.nat = opts.nat || null;
            this.identity = opts.identity;

            this.signer = opts.signer
                || Fingerprint.createSecp256k1Signer({
                    privateKey: opts.identity.privateKey,
                    publicKey: opts.identity.publicKey,
                });
            this.verifier = opts.verifier || Fingerprint.secp256k1Verifier;

            this.resolveGhostTag = opts.resolveGhostTag || _defaultResolveGhostTag;
            this.resolveIdentityKey = opts.resolveIdentityKey || _defaultResolveIdentityKey;
            this._getIceServers = opts.getIceServers || null;
            this._staticIceServers = opts.iceServers || null;

            this._PC = opts.RTCPeerConnection
                || (typeof RTCPeerConnection !== 'undefined' ? RTCPeerConnection : null)
                || (typeof window !== 'undefined' && window.RTCPeerConnection) || null;
            this._getUserMedia = opts.getUserMedia
                || ((typeof navigator !== 'undefined' && navigator.mediaDevices)
                    ? (c) => navigator.mediaDevices.getUserMedia(c)
                    : null);

            this.ringTimeoutMs = opts.ringTimeoutMs || DEFAULT_RING_TIMEOUT_MS;
            this.maxAverageBitrate = opts.maxAverageBitrate || DEFAULT_MAX_AVG_BITRATE;

            this._emitter = createEmitter();
            this._call = null; // single 1:1 session (see EXTENSION POINTS)

            this._wireMesh();
        }

        // ── events ──────────────────────────────────────
        /** Events: 'incoming' | 'ringing' | 'connected' | 'ended' | 'error'. */
        on(event, fn) { return this._emitter.on(event, fn); }
        off(event, fn) { this._emitter.off(event, fn); }

        get state() { return this._call ? this._call.state : STATES.IDLE; }

        // ── public API ──────────────────────────────────

        /**
         * Place a call to a GhostTag. Resolves the tag → identity key + route,
         * builds an SDP offer with an identity-bound fingerprint proof, and sends
         * it over the mesh. Verifies the answer's fingerprint before connecting.
         */
        async startCall(ghostTag) {
            if (this._call) throw new Error('[GhostCall] already in a call');
            let resolved;
            try {
                resolved = await this.resolveGhostTag(ghostTag);
            } catch (e) {
                this._fail('resolve', `could not resolve ${ghostTag}: ${e.message}`);
                return;
            }
            if (!resolved || !resolved.publicKey || !resolved.routeId) {
                this._fail('resolve', `GhostTag ${ghostTag} did not resolve to an identity`);
                return;
            }

            const call = this._newCall({
                id: _uuid(),
                role: 'caller',
                peerId: resolved.routeId,
                peerTag: ghostTag,
                peerKey: resolved.publicKey,
            });

            const pc = await this._createPeerConnection(call);
            if (!pc) return; // _fail already emitted

            const stream = await this._acquireMic(call);
            if (!stream) return; // mic error already surfaced

            try {
                stream.getTracks().forEach(t => pc.addTrack(t, stream));
                let offer = await pc.createOffer({ offerToReceiveAudio: true });
                offer = { type: 'offer', sdp: shapeOpusSdp(offer.sdp, this.maxAverageBitrate) };
                await pc.setLocalDescription(offer);
                this._applySenderBitrate(pc);

                const fp = await Fingerprint.buildProof({
                    kind: 'offer', callId: call.id, from: this.identity.id, to: call.peerId,
                    sdp: pc.localDescription || offer,
                }, this.signer);

                this._send(Signaling.buildOffer({
                    callId: call.id, from: this.identity.id, to: call.peerId,
                    sdp: { type: 'offer', sdp: (pc.localDescription || offer).sdp }, fp,
                }));

                this._setState(call, STATES.RINGING);
                this._emit('ringing', { callId: call.id, peer: ghostTag, direction: 'outgoing' });
                this._armRingTimeout(call);
            } catch (e) {
                this._fail('offer', `failed to create offer: ${e.message}`);
            }
        }

        /**
         * Accept the current incoming (ringing) call. The offer's fingerprint
         * proof was already verified at receipt, so it's safe to apply here.
         */
        async acceptCall() {
            const call = this._call;
            if (!call || call.role !== 'callee' || call.state !== STATES.RINGING) {
                throw new Error('[GhostCall] no incoming call to accept');
            }
            this._clearRingTimeout(call);
            this._setState(call, STATES.CONNECTING);

            const pc = await this._createPeerConnection(call);
            if (!pc) return;

            const stream = await this._acquireMic(call);
            if (!stream) return;

            try {
                stream.getTracks().forEach(t => pc.addTrack(t, stream));
                await pc.setRemoteDescription({ type: 'offer', sdp: call.pendingOffer.sdp.sdp });
                this._drainRemoteCandidates(call);

                let answer = await pc.createAnswer();
                answer = { type: 'answer', sdp: shapeOpusSdp(answer.sdp, this.maxAverageBitrate) };
                await pc.setLocalDescription(answer);
                this._applySenderBitrate(pc);

                const fp = await Fingerprint.buildProof({
                    kind: 'answer', callId: call.id, from: this.identity.id, to: call.peerId,
                    sdp: pc.localDescription || answer,
                }, this.signer);

                this._send(Signaling.buildAnswer({
                    callId: call.id, from: this.identity.id, to: call.peerId,
                    sdp: { type: 'answer', sdp: (pc.localDescription || answer).sdp }, fp,
                }));
                call.pendingOffer = null;
            } catch (e) {
                this._fail('answer', `failed to answer: ${e.message}`);
            }
        }

        /** Decline a ringing incoming call. */
        rejectCall() {
            const call = this._call;
            if (!call || call.role !== 'callee' || call.state !== STATES.RINGING) return;
            this._send(Signaling.buildHangup({
                callId: call.id, from: this.identity.id, to: call.peerId, reason: 'rejected',
            }));
            this._teardown('rejected');
        }

        /** End the current call (ringing/connecting/active) from either side. */
        endCall() {
            const call = this._call;
            if (!call) return;
            const reason = call.role === 'caller' && call.state === STATES.RINGING ? 'cancelled' : 'normal';
            try {
                this._send(Signaling.buildHangup({
                    callId: call.id, from: this.identity.id, to: call.peerId, reason,
                }));
            } catch (_) { /* best-effort notify */ }
            this._teardown(reason);
        }

        /** Tear down everything and release the mesh hook. */
        destroy() {
            if (this._call) this._teardown('normal');
            if (this._restoreMeshOnMessage) {
                this.mesh.onMessage = this._prevOnMessage;
                this._restoreMeshOnMessage = false;
            }
        }

        // ── mesh wiring (non-invasive: preserves the app's handler) ──

        _wireMesh() {
            if (typeof this.mesh.onMessage !== 'undefined') {
                this._prevOnMessage = typeof this.mesh.onMessage === 'function' ? this.mesh.onMessage : null;
                this._restoreMeshOnMessage = true;
                const self = this;
                this.mesh.onMessage = function (data, fromId, transport) {
                    self._onMeshMessage(data, fromId);
                    if (self._prevOnMessage) {
                        try { self._prevOnMessage(data, fromId, transport); } catch (_) { /* isolate */ }
                    }
                };
            }
        }

        _onMeshMessage(data, fromId) {
            // Only handle our call.* envelopes; everything else flows to the app.
            if (!data || typeof data !== 'object' || typeof data.t !== 'string' || data.t.indexOf('call.') !== 0) {
                return;
            }
            const v = Signaling.validateMessage(data);
            if (!v.ok) return; // drop malformed signaling silently

            switch (data.t) {
                case Signaling.TYPES.OFFER: return this._onOffer(data, fromId);
                case Signaling.TYPES.ANSWER: return this._onAnswer(data);
                case Signaling.TYPES.ICE: return this._onIce(data);
                case Signaling.TYPES.HANGUP: return this._onHangup(data);
                default: return;
            }
        }

        async _onOffer(msg, fromId) {
            if (this._call) {
                // Busy — politely decline without disturbing the active call.
                this._send(Signaling.buildHangup({
                    callId: msg.callId, from: this.identity.id, to: msg.from, reason: 'busy',
                }));
                return;
            }
            // Resolve the caller's identity key INDEPENDENTLY (trust the GhostTag,
            // not the proof) and verify the fingerprint BEFORE we even ring.
            let peerKey = null;
            try {
                peerKey = await this.resolveIdentityKey(msg.from, msg);
            } catch (_) { peerKey = null; }
            if (!peerKey) {
                this._emit('error', { code: 'peer-unresolved', message: `cannot resolve identity for ${msg.from}` });
                this._send(Signaling.buildHangup({
                    callId: msg.callId, from: this.identity.id, to: msg.from, reason: 'error',
                }));
                return;
            }

            const check = Fingerprint.verifyProof(msg.fp, {
                kind: 'offer', callId: msg.callId, from: msg.from, to: this.identity.id, sdp: msg.sdp,
            }, peerKey, this.verifier);
            if (!check.ok) {
                // SECURITY: fingerprint not bound to the claimed identity ⇒ abort.
                this._emit('error', { code: 'fingerprint', message: `offer fingerprint rejected: ${check.error}` });
                this._send(Signaling.buildHangup({
                    callId: msg.callId, from: this.identity.id, to: msg.from, reason: 'fingerprint',
                }));
                return;
            }

            const call = this._newCall({
                id: msg.callId, role: 'callee', peerId: msg.from, peerTag: msg.from, peerKey,
            });
            call.pendingOffer = msg;
            this._setState(call, STATES.RINGING);
            this._emit('incoming', { callId: call.id, from: msg.from, direction: 'incoming' });
            this._armRingTimeout(call);
        }

        async _onAnswer(msg) {
            const call = this._call;
            if (!call || call.role !== 'caller' || call.id !== msg.callId) return;

            // Verify the answer's fingerprint against the GhostTag we dialed.
            const check = Fingerprint.verifyProof(msg.fp, {
                kind: 'answer', callId: msg.callId, from: msg.from, to: this.identity.id, sdp: msg.sdp,
            }, call.peerKey, this.verifier);
            if (!check.ok) {
                this._emit('error', { code: 'fingerprint', message: `answer fingerprint rejected: ${check.error}` });
                this.endCall();
                return;
            }

            this._clearRingTimeout(call);
            this._setState(call, STATES.CONNECTING);
            try {
                await call.pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp.sdp });
                this._drainRemoteCandidates(call);
            } catch (e) {
                this._fail('answer', `failed to apply answer: ${e.message}`);
            }
        }

        async _onIce(msg) {
            const call = this._call;
            if (!call || call.id !== msg.callId) return;
            const cand = msg.candidate;
            // Buffer until remoteDescription exists, else addIceCandidate throws.
            if (!call.pc || !call.pc.remoteDescription) {
                call.remoteCandidates.push(cand);
                return;
            }
            try { await call.pc.addIceCandidate(cand); } catch (_) { /* ignore bad candidate */ }
        }

        _onHangup(msg) {
            const call = this._call;
            if (!call || call.id !== msg.callId) return;
            this._teardown(msg.reason || 'normal');
        }

        // ── peer connection / media ─────────────────────

        async _iceServers() {
            if (this._staticIceServers) return this._staticIceServers;
            // A configured ICE provider (e.g. Cloudflare TURN) is authoritative.
            // It is FAIL CLOSED: if it throws or returns nothing we propagate the
            // error so the caller aborts — never start a call with no relay.
            if (this._getIceServers) {
                const s = await this._getIceServers();
                if (!Array.isArray(s) || !s.length) throw new Error('ICE provider returned no servers');
                return s;
            }
            // Best-effort reuse of the NAT manager's STUN consensus if present.
            if (this.nat && typeof this.nat.getIceServers === 'function') {
                try { const s = await this.nat.getIceServers(); if (Array.isArray(s) && s.length) return s; } catch (_) { /* fall through */ }
            }
            return DEFAULT_ICE_SERVERS;
        }

        async _createPeerConnection(call) {
            if (!this._PC) {
                this._fail('webrtc', 'RTCPeerConnection is unavailable in this environment');
                return null;
            }
            let iceServers;
            try {
                iceServers = await this._iceServers();
            } catch (e) {
                // FAIL CLOSED: no TURN/ICE config ⇒ abort rather than risk a call
                // that can't traverse NAT (or runs with no relay fallback).
                this._fail('ice', `could not obtain TURN/ICE servers — call aborted: ${e.message}`);
                return null;
            }
            let pc;
            try {
                pc = new this._PC({ iceServers, iceTransportPolicy: 'all' });
            } catch (e) {
                this._fail('webrtc', `failed to create RTCPeerConnection: ${e.message}`);
                return null;
            }
            call.pc = pc;

            pc.onicecandidate = (ev) => {
                if (!ev.candidate || !this._call || this._call.id !== call.id) return;
                this._send(Signaling.buildIce({
                    callId: call.id, from: this.identity.id, to: call.peerId,
                    candidate: ev.candidate.toJSON ? ev.candidate.toJSON() : ev.candidate,
                }));
            };
            pc.ontrack = (ev) => {
                call.remoteStream = ev.streams && ev.streams[0] ? ev.streams[0] : null;
            };
            pc.oniceconnectionstatechange = () => {
                const s = pc.iceConnectionState;
                if ((s === 'connected' || s === 'completed') && call.state !== STATES.ACTIVE) {
                    this._setState(call, STATES.ACTIVE);
                    this._emit('connected', { callId: call.id, remoteStream: call.remoteStream });
                } else if (s === 'failed' || s === 'closed' || s === 'disconnected') {
                    if (this._call && this._call.id === call.id) this._teardown('error');
                }
            };
            return pc;
        }

        async _acquireMic(call) {
            if (!this._getUserMedia) {
                this._fail('mic-permission', 'microphone access is unavailable in this environment');
                return null;
            }
            try {
                const stream = await this._getUserMedia({ audio: true, video: false });
                call.localStream = stream;
                return stream;
            } catch (e) {
                // In the Expo WebView, getUserMedia needs native permission plumbing
                // (Android onPermissionRequest + RECORD_AUDIO; iOS Info.plist mic key).
                // Surface a clear, actionable error rather than failing opaquely.
                const name = e && e.name ? e.name : 'Error';
                this._fail('mic-permission',
                    `microphone access denied or unavailable (${name}). ` +
                    'In the Expo WebView this requires native mic permission plumbing — see VOICE_CALLS.md.');
                this._teardown('error');
                return null;
            }
        }

        _applySenderBitrate(pc) {
            try {
                const sender = pc.getSenders && pc.getSenders().find(s => s.track && s.track.kind === 'audio');
                if (!sender || !sender.getParameters) return;
                const params = sender.getParameters();
                params.encodings = params.encodings && params.encodings.length ? params.encodings : [{}];
                params.encodings[0].maxBitrate = this.maxAverageBitrate;
                params.encodings[0].dtx = 'enabled';
                if (sender.setParameters) sender.setParameters(params).catch(() => {});
            } catch (_) { /* setParameters is best-effort */ }
        }

        _drainRemoteCandidates(call) {
            if (!call.pc || !call.remoteCandidates.length) return;
            const pending = call.remoteCandidates.splice(0);
            for (const c of pending) {
                try { call.pc.addIceCandidate(c); } catch (_) { /* ignore */ }
            }
        }

        // ── state / lifecycle ───────────────────────────

        _newCall(fields) {
            this._call = Object.assign({
                pc: null,
                state: STATES.IDLE,
                localStream: null,
                remoteStream: null,
                remoteCandidates: [],
                pendingOffer: null,
                ringTimer: null,
                startedAt: _now(),
            }, fields);
            return this._call;
        }

        _setState(call, state) {
            if (!call) return;
            call.state = state;
        }

        _armRingTimeout(call) {
            this._clearRingTimeout(call);
            call.ringTimer = setTimeout(() => {
                if (!this._call || this._call.id !== call.id) return;
                if (call.state === STATES.RINGING) {
                    try {
                        this._send(Signaling.buildHangup({
                            callId: call.id, from: this.identity.id, to: call.peerId, reason: 'timeout',
                        }));
                    } catch (_) { /* best effort */ }
                    this._teardown('timeout');
                }
            }, this.ringTimeoutMs);
        }

        _clearRingTimeout(call) {
            if (call && call.ringTimer) { clearTimeout(call.ringTimer); call.ringTimer = null; }
        }

        _teardown(reason) {
            const call = this._call;
            if (!call) return;
            this._clearRingTimeout(call);
            if (call.localStream) {
                try { call.localStream.getTracks().forEach(t => t.stop()); } catch (_) { /* */ }
            }
            if (call.pc) {
                try {
                    call.pc.onicecandidate = null;
                    call.pc.ontrack = null;
                    call.pc.oniceconnectionstatechange = null;
                    call.pc.close();
                } catch (_) { /* */ }
            }
            this._setState(call, STATES.ENDED);
            this._call = null;
            this._emit('ended', { callId: call.id, reason });
        }

        _send(envelope) {
            // The mesh message is delivered E2EE + identity-authenticated by the
            // existing channel; we simply hand it the routing id + payload.
            try {
                this.mesh.sendToPeer(envelope.to, envelope);
            } catch (e) {
                this._emit('error', { code: 'transport', message: `mesh send failed: ${e.message}` });
            }
        }

        _emit(event, payload) { this._emitter.emit(event, payload); }

        _fail(code, message) {
            this._emit('error', { code, message });
            if (this._call) this._teardown('error');
        }
    }

    // ─── default resolvers (browser/WebView) ────────────

    /** Resolve a GhostTag via the app's GhostTag module → { routeId, publicKey }. */
    async function _defaultResolveGhostTag(tag) {
        if (typeof window === 'undefined' || !window.GhostTag || !window.GhostTag.resolveTag) {
            throw new Error('GhostTag module unavailable');
        }
        const r = await window.GhostTag.resolveTag(tag);
        if (!r || r.error) throw new Error(r && r.error ? r.error : 'resolve failed');
        return { routeId: r.nodeId || r.id || tag, publicKey: r.publicKey };
    }

    /**
     * Resolve the identity key for an INCOMING peer id. Defaults to GhostTag
     * resolution; integrators with a node registry can inject a stronger lookup.
     * Returns null ⇒ the call is rejected (fail closed) — we never trust the
     * key embedded in the proof.
     */
    async function _defaultResolveIdentityKey(peerId /*, msg */) {
        try {
            const r = await _defaultResolveGhostTag(peerId);
            return r.publicKey || null;
        } catch (_) {
            return null;
        }
    }

    GhostCall.STATES = STATES;
    GhostCall.shapeOpusSdp = shapeOpusSdp;
    return GhostCall;
}));
