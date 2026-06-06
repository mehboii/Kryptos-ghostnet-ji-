/**
 * GhostNet Call Signaling — Schema & Validation
 * =============================================
 *
 * Typed message schema + fail-closed runtime validators for 1:1 voice-call
 * signaling. These messages ride over the EXISTING encrypted mesh channel
 * (GhostMesh.sendToPeer / onMessage) — there is NO new signaling server or
 * socket. This module is pure (no DOM, no crypto, no network) so it loads and
 * runs identically in the browser/WebView and under Node for unit tests.
 *
 * Message types (Phase 1 — 1:1 only):
 *   call.offer   caller → callee   SDP offer  + identity-bound fingerprint proof
 *   call.answer  callee → caller   SDP answer + identity-bound fingerprint proof
 *   call.ice     either → either   trickled ICE candidate
 *   call.hangup  either → either   teardown (reason)
 *
 * SECURITY NOTE: structural validation only. The cryptographic verification of
 * the DTLS-fingerprint proof (binding the media keys to a GhostTag identity)
 * lives in ghostnet-call-fingerprint.js and is enforced by ghostnet-call.js
 * BEFORE any remote SDP is applied. A malformed message is dropped silently by
 * the caller; an invalid proof aborts the call.
 *
 * @module ghostnet-call-signaling
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostCallSignaling = factory();
    }
}(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this), function () {
    'use strict';

    // ─── CONSTANTS ──────────────────────────────────────

    /** Bump when the wire format changes incompatibly. */
    const PROTOCOL_VERSION = 1;

    const TYPES = Object.freeze({
        OFFER: 'call.offer',
        ANSWER: 'call.answer',
        ICE: 'call.ice',
        HANGUP: 'call.hangup',
    });

    const VALID_TYPES = new Set(Object.values(TYPES));

    /** Realistic audio-only SDPs are < 4 KB; cap well above that, reject abuse. */
    const MAX_SDP_LENGTH = 16384;
    /** A single trickled ICE candidate line is tiny. */
    const MAX_CANDIDATE_LENGTH = 1024;
    /** GhostTag / nodeId routing identifiers. */
    const MAX_PEER_ID_LENGTH = 256;

    /** callId is a UUID v4 minted by the caller (crypto.randomUUID). */
    const CALL_ID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    /** Hangup reasons surfaced to the state machine / UI. */
    const HANGUP_REASONS = new Set([
        'normal',       // user ended an active call
        'rejected',     // callee declined a ringing call
        'busy',         // callee already in a call
        'timeout',      // unanswered within the ring window
        'cancelled',    // caller aborted before answer
        'fingerprint',  // SECURITY: remote fingerprint proof failed verification
        'error',        // internal/transport failure
    ]);

    // ─── TYPEDEFS (JSDoc) ───────────────────────────────

    /**
     * @typedef {Object} FingerprintProof
     * @property {number} v          Proof format version.
     * @property {'offer'|'answer'} kind  Which SDP this proof binds.
     * @property {string} alg        Identity signature algorithm (e.g. 'secp256k1').
     * @property {string} fingerprint  Canonical DTLS fingerprint ("sha-256 AB:CD:...").
     * @property {string} sig        Identity signature over the canonical proof message.
     * @property {string} pub        Signer public key (informational; trust comes from the
     *                               resolved GhostTag key, not this field).
     */

    /**
     * @typedef {Object} CallEnvelope
     * @property {number} v          PROTOCOL_VERSION.
     * @property {string} t          One of TYPES.*
     * @property {string} callId     UUID v4 shared across one call's messages.
     * @property {string} from       Sender GhostTag / nodeId.
     * @property {string} to         Recipient GhostTag / nodeId.
     * @property {number} ts         Sender unix-ms timestamp.
     * @property {Object} [sdp]      RTCSessionDescriptionInit ({type, sdp}) for offer/answer.
     * @property {FingerprintProof} [fp]  Identity-bound fingerprint proof for offer/answer.
     * @property {Object} [candidate]  RTCIceCandidateInit for call.ice.
     * @property {string} [reason]   Hangup reason for call.hangup.
     */

    // ─── INTERNAL GUARDS ────────────────────────────────

    function isPlainObject(v) {
        return !!v && typeof v === 'object' && !Array.isArray(v);
    }

    function isPeerId(v) {
        return typeof v === 'string' && v.length > 0 && v.length <= MAX_PEER_ID_LENGTH;
    }

    function isCallId(v) {
        return typeof v === 'string' && CALL_ID_REGEX.test(v);
    }

    /** Accepts either an RTCSessionDescriptionInit-like object or a raw SDP string. */
    function validateSdp(sdp, expectedType) {
        if (!isPlainObject(sdp)) return 'sdp must be an object';
        if (sdp.type !== expectedType) return `sdp.type must be "${expectedType}"`;
        if (typeof sdp.sdp !== 'string') return 'sdp.sdp must be a string';
        if (sdp.sdp.length === 0 || sdp.sdp.length > MAX_SDP_LENGTH) return 'sdp.sdp length out of range';
        if (!sdp.sdp.trim().startsWith('v=')) return 'sdp.sdp failed structural check';
        return null;
    }

    function validateFingerprintProof(fp, expectedKind) {
        if (!isPlainObject(fp)) return 'fp must be an object';
        if (typeof fp.alg !== 'string' || fp.alg.length === 0) return 'fp.alg required';
        if (fp.kind !== expectedKind) return `fp.kind must be "${expectedKind}"`;
        if (typeof fp.fingerprint !== 'string' || fp.fingerprint.length === 0) return 'fp.fingerprint required';
        if (fp.fingerprint.length > 512) return 'fp.fingerprint too long';
        if (typeof fp.sig !== 'string' || fp.sig.length === 0) return 'fp.sig required';
        if (typeof fp.pub !== 'string' || fp.pub.length === 0) return 'fp.pub required';
        return null;
    }

    function validateCandidate(candidate) {
        if (!isPlainObject(candidate)) return 'candidate must be an object';
        if (typeof candidate.candidate !== 'string') return 'candidate.candidate must be a string';
        if (candidate.candidate.length > MAX_CANDIDATE_LENGTH) return 'candidate.candidate too long';
        const hasMid = typeof candidate.sdpMid === 'string';
        const hasIdx = Number.isInteger(candidate.sdpMLineIndex);
        if (!hasMid && !hasIdx) return 'candidate needs sdpMid or sdpMLineIndex';
        return null;
    }

    // ─── PUBLIC: VALIDATION ─────────────────────────────

    /**
     * Validate an incoming signaling message. Returns a result object rather
     * than throwing so the mesh handler can drop bad input silently.
     *
     * @param {*} msg
     * @returns {{ ok: boolean, error?: string }}
     */
    function validateMessage(msg) {
        if (!isPlainObject(msg)) return { ok: false, error: 'message must be an object' };
        if (msg.v !== PROTOCOL_VERSION) return { ok: false, error: `unsupported version: ${msg.v}` };
        if (!VALID_TYPES.has(msg.t)) return { ok: false, error: `invalid type: ${msg.t}` };
        if (!isCallId(msg.callId)) return { ok: false, error: 'invalid callId' };
        if (!isPeerId(msg.from)) return { ok: false, error: 'invalid from' };
        if (!isPeerId(msg.to)) return { ok: false, error: 'invalid to' };
        if (typeof msg.ts !== 'number' || !Number.isFinite(msg.ts)) return { ok: false, error: 'invalid ts' };

        switch (msg.t) {
            case TYPES.OFFER: {
                const e = validateSdp(msg.sdp, 'offer') || validateFingerprintProof(msg.fp, 'offer');
                if (e) return { ok: false, error: e };
                break;
            }
            case TYPES.ANSWER: {
                const e = validateSdp(msg.sdp, 'answer') || validateFingerprintProof(msg.fp, 'answer');
                if (e) return { ok: false, error: e };
                break;
            }
            case TYPES.ICE: {
                const e = validateCandidate(msg.candidate);
                if (e) return { ok: false, error: e };
                break;
            }
            case TYPES.HANGUP: {
                if (typeof msg.reason !== 'string' || !HANGUP_REASONS.has(msg.reason)) {
                    return { ok: false, error: 'invalid hangup reason' };
                }
                break;
            }
            default:
                return { ok: false, error: `unhandled type: ${msg.t}` };
        }
        return { ok: true };
    }

    /** Throwing variant for call sites that prefer exceptions. */
    function assertValid(msg) {
        const r = validateMessage(msg);
        if (!r.ok) throw new Error(`[GhostCallSignaling] invalid message: ${r.error}`);
        return msg;
    }

    // ─── PUBLIC: BUILDERS ───────────────────────────────

    function _base(type, { callId, from, to }) {
        return { v: PROTOCOL_VERSION, t: type, callId, from, to, ts: Date.now() };
    }

    /**
     * @param {{callId:string, from:string, to:string, sdp:Object, fp:FingerprintProof}} p
     * @returns {CallEnvelope}
     */
    function buildOffer(p) {
        return assertValid({ ..._base(TYPES.OFFER, p), sdp: p.sdp, fp: p.fp });
    }

    function buildAnswer(p) {
        return assertValid({ ..._base(TYPES.ANSWER, p), sdp: p.sdp, fp: p.fp });
    }

    function buildIce(p) {
        return assertValid({ ..._base(TYPES.ICE, p), candidate: p.candidate });
    }

    function buildHangup(p) {
        const reason = HANGUP_REASONS.has(p.reason) ? p.reason : 'normal';
        return assertValid({ ..._base(TYPES.HANGUP, p), reason });
    }

    // ─── EXPORTS ────────────────────────────────────────

    return {
        PROTOCOL_VERSION,
        TYPES,
        HANGUP_REASONS,
        MAX_SDP_LENGTH,
        CALL_ID_REGEX,
        validateMessage,
        assertValid,
        buildOffer,
        buildAnswer,
        buildIce,
        buildHangup,
    };
}));
