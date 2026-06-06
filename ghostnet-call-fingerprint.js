/**
 * GhostNet Call Fingerprint — Identity-Bound DTLS Verification
 * ===========================================================
 *
 * "Privacy by mathematics." The signaling relay (the mesh) must never be able
 * to MITM the media keys. WebRTC already encrypts media under DTLS-SRTP, where
 * the DTLS handshake is authenticated by the certificate fingerprints carried
 * in the SDP. The weak point is SDP delivery: a relay could swap an SDP and its
 * fingerprint to insert itself. We close that by binding the local DTLS
 * fingerprint to the caller's GhostTag identity key with a signature, and
 * verifying the remote fingerprint against the *resolved* GhostTag identity
 * BEFORE the SDP is ever applied. Mismatch ⇒ fail closed (abort the call).
 *
 * The cryptographic core is dependency-injected (signer / verifier) so the
 * algorithm can change without touching call logic. The LIVE implementation is
 * secp256k1 — the same identity key the app already uses for GhostTag / node
 * auth (ethers wallet: personal-sign + address recovery). An Ed25519 signer can
 * be dropped in later via the same interface.
 *
 * Pure except for the secp256k1 default impl, which resolves `ethers` from
 * `window.ethers` (browser/WebView, v6) or `require('ethers')` (Node tests, v5).
 * Both versions interoperate for personal-sign + computeAddress.
 *
 * @module ghostnet-call-fingerprint
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostCallFingerprint = factory();
    }
}(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this), function () {
    'use strict';

    const PROOF_VERSION = 1;
    const DOMAIN = 'GhostNet.CallFingerprint.v1';
    /** Matches `a=fingerprint:<hash-func> <hex:colon:bytes>` in an SDP blob. */
    const SDP_FINGERPRINT_REGEX = /^a=fingerprint:(\S+)\s+([0-9A-Fa-f:]+)\s*$/m;

    // ─── ethers resolver + v5/v6 API adapter ────────────

    let _ethers = null;
    function _getEthers() {
        if (_ethers) return _ethers;
        if (typeof window !== 'undefined' && window.ethers) {
            _ethers = window.ethers;
        } else if (typeof globalThis !== 'undefined' && globalThis.ethers) {
            _ethers = globalThis.ethers;
        } else if (typeof require === 'function') {
            try { _ethers = require('ethers'); } catch (_) { _ethers = null; }
        }
        if (!_ethers) throw new Error('[GhostCallFingerprint] ethers is not available');
        return _ethers;
    }

    /**
     * ethers v5 exposes helpers under `ethers.utils`; v6 hoists them to the top
     * level. Normalise so the same code path works in browser (v6) and Node (v5).
     */
    function _utils() {
        const e = _getEthers();
        return e.utils ? e.utils : e;
    }

    // ─── canonical proof message ────────────────────────

    function _lp(field, value) {
        const s = String(value);
        return `${field}=${s.length}:${s}`;
    }

    /**
     * Deterministic, length-prefixed message that BOTH sides sign/verify. Binding
     * callId + from + to + kind + fingerprint prevents replay across calls,
     * directions, and offer/answer roles.
     *
     * @param {{kind:'offer'|'answer', callId:string, from:string, to:string, fingerprint:string}} ctx
     * @returns {string}
     */
    function canonicalMessage(ctx) {
        return [
            DOMAIN,
            _lp('kind', ctx.kind),
            _lp('callId', ctx.callId),
            _lp('from', ctx.from),
            _lp('to', ctx.to),
            _lp('fp', ctx.fingerprint),
        ].join('|');
    }

    // ─── SDP fingerprint extraction ─────────────────────

    /**
     * Extract the DTLS fingerprint from an SDP string or RTCSessionDescription.
     *
     * @param {string|{sdp:string}} sdp
     * @returns {{ algorithm: string, value: string, canonical: string }}
     * @throws if no fingerprint line is present
     */
    function extractFingerprint(sdp) {
        const text = typeof sdp === 'string' ? sdp : (sdp && sdp.sdp);
        if (typeof text !== 'string' || text.length === 0) {
            throw new Error('[GhostCallFingerprint] cannot extract fingerprint: empty SDP');
        }
        const m = SDP_FINGERPRINT_REGEX.exec(text);
        if (!m) throw new Error('[GhostCallFingerprint] no a=fingerprint line in SDP');
        const algorithm = m[1].toLowerCase();
        const value = m[2].toUpperCase();
        return { algorithm, value, canonical: `${algorithm} ${value}` };
    }

    // ─── LIVE secp256k1 signer / verifier ───────────────

    /**
     * Build a signer bound to a secp256k1 private key (the app's GhostTag key).
     *
     * @param {{ privateKey: string, publicKey?: string }} opts
     * @returns {{ alg:string, sign:(msg:string)=>Promise<string>, getPublicKey:()=>string }}
     */
    function createSecp256k1Signer(opts) {
        const ethers = _getEthers();
        if (!opts || typeof opts.privateKey !== 'string') {
            throw new Error('[GhostCallFingerprint] secp256k1 signer requires a privateKey');
        }
        const wallet = new ethers.Wallet(opts.privateKey);
        // v6: wallet.signingKey.publicKey ; v5: wallet._signingKey().publicKey.
        const publicKey = opts.publicKey
            || (wallet.signingKey ? wallet.signingKey.publicKey : wallet._signingKey().publicKey);
        return {
            alg: 'secp256k1',
            getPublicKey() { return publicKey; },
            async sign(message) { return wallet.signMessage(message); },
        };
    }

    /**
     * Verify a personal-sign signature against the public key the GhostTag
     * resolves to. Trust comes from `expectedPublicKey` (resolved from GhostTag),
     * NOT from any key embedded in the proof. Returns boolean; never throws on a
     * bad signature — it FAILS CLOSED (returns false).
     *
     * @param {string} message
     * @param {string} signature
     * @param {string} expectedPublicKey  secp256k1 public key bound to the GhostTag
     * @returns {boolean}
     */
    function secp256k1Verify(message, signature, expectedPublicKey) {
        try {
            const u = _utils();
            const recovered = u.verifyMessage(message, signature).toLowerCase();
            const expected = u.computeAddress(expectedPublicKey).toLowerCase();
            return recovered === expected;
        } catch (_) {
            return false; // malformed signature / key ⇒ fail closed
        }
    }

    /** Default verifier object (DI-compatible). */
    const secp256k1Verifier = {
        alg: 'secp256k1',
        verify: secp256k1Verify,
    };

    // ─── proof build / verify (DI core) ─────────────────

    /**
     * Build a fingerprint proof for a local SDP. Signs the canonical message
     * with the injected identity signer.
     *
     * @param {{ kind:'offer'|'answer', callId:string, from:string, to:string, sdp:(string|{sdp:string}) }} ctx
     * @param {{ alg:string, sign:Function, getPublicKey:Function }} signer
     * @returns {Promise<import('./ghostnet-call-signaling.js').FingerprintProof>}
     */
    async function buildProof(ctx, signer) {
        if (!signer || typeof signer.sign !== 'function') {
            throw new Error('[GhostCallFingerprint] buildProof requires a signer');
        }
        const fp = extractFingerprint(ctx.sdp);
        const message = canonicalMessage({
            kind: ctx.kind, callId: ctx.callId, from: ctx.from, to: ctx.to, fingerprint: fp.canonical,
        });
        const sig = await signer.sign(message);
        return {
            v: PROOF_VERSION,
            kind: ctx.kind,
            alg: signer.alg || 'secp256k1',
            fingerprint: fp.canonical,
            sig,
            pub: typeof signer.getPublicKey === 'function' ? signer.getPublicKey() : '',
        };
    }

    /**
     * Verify a remote fingerprint proof against the SDP that carried it AND the
     * GhostTag-resolved identity key. FAILS CLOSED: returns {ok:false,...} on any
     * mismatch — the caller MUST abort before applying the remote SDP.
     *
     *   1. The proof's fingerprint must exactly equal the SDP's fingerprint
     *      (a relay can't sign one fingerprint and ship a different SDP).
     *   2. The signature must verify against `expectedPublicKey` (resolved from
     *      the callee/caller's GhostTag), over the canonical message.
     *
     * @param {Object} proof  FingerprintProof from the remote message.
     * @param {{ kind:'offer'|'answer', callId:string, from:string, to:string, sdp:(string|{sdp:string}) }} ctx
     * @param {string} expectedPublicKey  Identity key resolved from the peer's GhostTag.
     * @param {{ verify:Function }} [verifier]  Defaults to secp256k1.
     * @returns {{ ok: boolean, error?: string }}
     */
    function verifyProof(proof, ctx, expectedPublicKey, verifier) {
        const v = verifier || secp256k1Verifier;
        if (!proof || typeof proof !== 'object') return { ok: false, error: 'missing proof' };
        if (typeof expectedPublicKey !== 'string' || expectedPublicKey.length === 0) {
            return { ok: false, error: 'missing expected public key' };
        }
        if (proof.kind !== ctx.kind) return { ok: false, error: 'proof kind mismatch' };

        let sdpFp;
        try {
            sdpFp = extractFingerprint(ctx.sdp);
        } catch (e) {
            return { ok: false, error: `sdp fingerprint: ${e.message}` };
        }
        // (1) Proof must describe the SAME fingerprint the SDP actually carries.
        if (proof.fingerprint !== sdpFp.canonical) {
            return { ok: false, error: 'fingerprint does not match SDP' };
        }

        // (2) Signature must verify against the GhostTag-resolved identity key.
        const message = canonicalMessage({
            kind: ctx.kind, callId: ctx.callId, from: ctx.from, to: ctx.to, fingerprint: sdpFp.canonical,
        });
        let ok = false;
        try {
            ok = !!v.verify(message, proof.sig, expectedPublicKey);
        } catch (_) {
            ok = false; // verifier threw ⇒ fail closed
        }
        if (!ok) return { ok: false, error: 'signature does not match GhostTag identity' };
        return { ok: true };
    }

    // ─── EXPORTS ────────────────────────────────────────

    return {
        PROOF_VERSION,
        DOMAIN,
        canonicalMessage,
        extractFingerprint,
        buildProof,
        verifyProof,
        // live secp256k1 impl (DI defaults)
        createSecp256k1Signer,
        secp256k1Verify,
        secp256k1Verifier,
    };
}));
