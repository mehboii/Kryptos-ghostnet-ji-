'use strict';

/**
 * Kryptos Identity System — SECURITY HARDENED
 * kryptos-identity.js
 *
 * Implements Ed25519 Cryptographic Identity.
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Private key returned in plain object to every caller.
 *     generateIdentity() and rotateKey() both returned
 *     { privateKey: keyPair.privateKey, ... } in the object handed to callers.
 *     Any code that receives the identity object — transport layers, UI
 *     components, loggers, or a JSON.stringify() call — has direct access to
 *     the private key CryptoKey. A single careless assignment or console.log
 *     leaks the key. This was identified in GhostIdentity.js (browser) as
 *     fix [A] and [F] in previous audits and recurs here.
 *     Fixed: the private key is NEVER returned. It is sealed inside a closure
 *     and exposed only through a sign() method on the identity object.
 *     Callers can request signatures but cannot read or export the key.
 *
 * [B] CRITICAL — Private key generated as extractable (exportable).
 *     generateKey() was called with extractable: true (the second argument).
 *     Any code holding the CryptoKey object can call
 *     crypto.subtle.exportKey('pkcs8', privateKey) to dump the raw private
 *     key bytes. Combined with [A], the key was both reachable AND exportable.
 *     Fixed: private key generated with extractable: false. It cannot be
 *     exported by any code path.
 *
 * [C] HIGH — nodeId derived from only the first 16 hex characters of
 *     SHA-256(pubKey) — 64 bits of collision space.
 *     hashHex.substring(0, 16) keeps 8 bytes = 64 bits. A birthday collision
 *     is expected after ~4 billion nodes (2^32) — not theoretical in a large
 *     network. An attacker who can generate many keys offline can find a
 *     collision with a target nodeId in ~2^32 attempts (feasible on GPU
 *     hardware). Any system using nodeId for routing, lookup, or trust
 *     decisions is vulnerable to impersonation.
 *     Fixed: nodeId is the full 64-character SHA-256 hex string (256-bit
 *     collision resistance). A "short" display ID for UIs can be derived from
 *     the first 16 characters of nodeId separately, never used for identity.
 *
 * [D] HIGH — rotateKey() link payload uses string concatenation with
 *     no field length encoding — susceptible to field-boundary confusion.
 *     `LINK:${oldId}:${newId}:${timestamp}` separates fields with colons.
 *     If nodeIds can contain colons, or if the timestamp is substituted by
 *     an attacker-controlled value, the fields run together. Even without
 *     colons in nodeIds, a crafted oldId of "A:B:123:LINK" could produce a
 *     payload that is valid for a different "old" node than intended.
 *     Fixed: length-prefixed canonical encoding:
 *     "KRYPTOS_LINK_V1:<len>:<oldId>:<len>:<newId>:<timestamp>"
 *     This makes field boundaries unambiguous regardless of field content.
 *
 * [E] HIGH — rotateKey() rotation proof does not include the new public key,
 *     only the new nodeId.
 *     The link payload binds oldId → newId (the short hash), but not the
 *     actual new public key bytes. An attacker who finds a second public key
 *     that hashes to the same newId (possible given [C]'s 64-bit space) can
 *     substitute their own key and present a valid rotation proof that was
 *     signed by the old identity but certifies a different key.
 *     Fixed: the link payload includes the hex-encoded new public key (SPKI
 *     export), not just the nodeId. Verification must check the full key.
 *
 * [F] HIGH — verifySignature() has no error handling.
 *     crypto.subtle.verify() throws on malformed signature buffers, wrong
 *     key type, or mismatched algorithm. The raw exception propagates to the
 *     caller with no context. As with the previous audit [FIX F on
 *     GhostIdentity.js], a blanket catch returning false masks programming
 *     errors, but no catch at all is worse — it crashes callers.
 *     Fixed: DOMException (expected: bad signature format) is caught and
 *     returned as false. All other exception types are re-thrown.
 *
 * [G] HIGH — _hexToBuf() does not validate input.
 *     Math.ceil(hex.length / 2) on an odd-length string silently reads one
 *     character past the end in the last iteration, producing NaN for the
 *     last byte. A non-hex string produces NaN bytes throughout. Both cases
 *     result in a corrupted Uint8Array used as a signature buffer, with no
 *     error raised.
 *     Fixed: _hexToBuf() validates non-empty, even length, and
 *     [0-9a-fA-F]-only input; throws clearly on invalid data.
 *
 * [H] MEDIUM — signMessage() accepts any type for the message parameter.
 *     Passing null, an object, or a number causes TextEncoder.encode() to
 *     coerce the value to a string ("null", "[object Object]", "42") and
 *     sign that instead of rejecting the call. A caller that accidentally
 *     passes msg.body when body is undefined signs the string "undefined".
 *     Fixed: explicit type guard — accepts only string or Uint8Array/
 *     ArrayBuffer; throws TypeError on anything else.
 *
 * [I] MEDIUM — verifySignature() accepts any type for publicKey.
 *     Passing null, a string, or undefined causes crypto.subtle.verify()
 *     to throw a DOMException which was silently caught and returned as
 *     false. A caller that passes the wrong variable as publicKey gets
 *     false back and cannot distinguish "bad signature" from "programming
 *     error".
 *     Fixed: publicKey is type-checked at entry. Strings are treated as
 *     hex-encoded SPKI and imported automatically. null/undefined throws.
 *
 * [J] MEDIUM — verifyRotationProof() does not exist.
 *     rotateKey() creates a rotation proof with a signature, but there is
 *     no corresponding verification function. Without a verifier, any code
 *     that accepts rotation proofs must roll its own verification, which
 *     is likely to be incorrect.
 *     Fixed: static verifyRotationProof(proof, oldPublicKey) added.
 *     It reconstructs the canonical payload, verifies the signature, and
 *     confirms the proof binds the correct new public key.
 *
 * [K] MEDIUM — identity.created uses Date.now() (milliseconds since epoch).
 *     In a P2P network, clocks are not synchronised. A created timestamp from
 *     Date.now() can be spoofed or skewed. It is also unnecessary for any
 *     cryptographic purpose.
 *     Fixed: created is retained for logging/display but is explicitly
 *     documented as untrusted and not used in any cryptographic binding.
 *
 * [L] LOW — Dual export: both window.GhostIdentity and module.exports are set.
 *     window.GhostIdentity = GhostIdentity allows any later script to overwrite
 *     the class. In Node.js, module.exports is fine; in the browser, the
 *     global should be immutable.
 *     Fixed: browser global uses Object.defineProperty with writable:false,
 *     configurable:false. Node.js export unchanged.
 *
 * [M] LOW — No check that the runtime actually supports Ed25519 before
 *     attempting key generation.
 *     If Ed25519 is not supported (Chrome <113, Firefox <122, Safari <17),
 *     generateKey() throws an opaque DOMException: "Algorithm: Unrecognized
 *     name". The caller gets no actionable message.
 *     Fixed: _checkSupport() probes for Ed25519 support once on first use
 *     and throws a clear, descriptive error naming the required browser
 *     versions if unsupported.
 */

// ─── Runtime ──────────────────────────────────────────────────────────────────
const _subtle = (typeof window !== 'undefined' ? window.crypto : globalThis.crypto)?.subtle;

// ─── Validation helpers ───────────────────────────────────────────────────────

// [FIX G] Strict hex validation.
function _hexToBuf(hex) {
    if (typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0) {
        throw new TypeError(`_hexToBuf: expected a non-empty even-length hex string, got "${String(hex).slice(0, 32)}".`);
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
        throw new TypeError('_hexToBuf: input contains non-hex characters.');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function _bufToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// [FIX M] Probe for Ed25519 support exactly once.
let _ed25519Supported = null;
async function _checkSupport() {
    if (_ed25519Supported === true) return;
    if (_ed25519Supported === false) {
        throw new Error(
            'Ed25519 is not supported in this environment. ' +
            'Requires Chrome 113+, Firefox 122+, or Safari 17+.'
        );
    }
    try {
        await _subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
        _ed25519Supported = true;
    } catch {
        _ed25519Supported = false;
        throw new Error(
            'Ed25519 is not supported in this environment. ' +
            'Requires Chrome 113+, Firefox 122+, or Safari 17+.'
        );
    }
}

// [FIX I] Import a public key from its SPKI hex string for verification.
async function _importPublicKey(spkiHex) {
    const raw = _hexToBuf(spkiHex);
    return _subtle.importKey(
        'spki',
        raw,
        { name: 'Ed25519' },
        false,        // non-extractable — verify only
        ['verify']
    );
}

// ─────────────────────────────────────────────────────────────────────────────

class GhostIdentity {

    // ── 1. Core Generators ────────────────────────────────────────────────────

    /**
     * Generate a new Ed25519 identity.
     *
     * Returns:
     *   {
     *     nodeId:       string    — full SHA-256(pubKey) hex (256-bit)
     *     publicKeyHex: string    — SPKI-encoded public key as hex
     *     publicKey:    CryptoKey — live public key for in-session verification
     *     sign:         async (message: string|Uint8Array) => signatureHex
     *     created:      number    — Date.now() at generation (untrusted display only)
     *   }
     *
     * The private key is NEVER returned. It is sealed in the sign() closure.
     */
    static async generateIdentity() {
        await _checkSupport();  // [FIX M]

        // [FIX B] extractable: false — private key cannot be exported.
        const keyPair = await _subtle.generateKey(
            { name: 'Ed25519' },
            false,          // [FIX B]
            ['sign', 'verify']
        );

        const rawPub = await _subtle.exportKey('raw', keyPair.publicKey);
        const spkiPub = await _subtle.exportKey('spki', keyPair.publicKey);
        const nodeId = await GhostIdentity._deriveNodeId(rawPub);   // [FIX C] full hash
        const pubKeyHex = _bufToHex(spkiPub);

        // [FIX A] Private key sealed in closure — never returned directly.
        const _privateKey = keyPair.privateKey;

        return {
            nodeId,
            publicKeyHex: pubKeyHex,
            publicKey: keyPair.publicKey,
            // [FIX A] Only way to use the private key.
            sign: (message) => GhostIdentity.signMessage(message, _privateKey),
            // [FIX K] Documented as untrusted display value, not used cryptographically.
            created: Date.now(),
            // privateKey intentionally absent.
        };
    }

    /**
     * [FIX C] Full SHA-256(pubKey) hex — 256-bit collision resistance.
     * A short display ID can be obtained as nodeId.slice(0, 16) in UI code
     * but must NEVER be used for identity decisions.
     */
    static async _deriveNodeId(rawPubBuffer) {
        const hashBuffer = await _subtle.digest('SHA-256', rawPubBuffer);
        return _bufToHex(hashBuffer); // full 64-char hex — 256 bits
    }

    // ── 2. Signing & Verification ─────────────────────────────────────────────

    /**
     * Sign a message with the given private key.
     * [FIX H] Only accepts string or Uint8Array/ArrayBuffer — no silent coercion.
     * Returns the Ed25519 signature as a hex string.
     */
    static async signMessage(message, privateKey) {
        // [FIX H] Strict input guard.
        if (typeof message !== 'string' && !(message instanceof Uint8Array) && !(message instanceof ArrayBuffer)) {
            throw new TypeError('signMessage: message must be a string, Uint8Array, or ArrayBuffer.');
        }
        if (!privateKey || typeof privateKey !== 'object') {
            throw new TypeError('signMessage: privateKey must be a CryptoKey object.');
        }

        const data = typeof message === 'string' ? new TextEncoder().encode(message) : message;
        const sigBuffer = await _subtle.sign({ name: 'Ed25519' }, privateKey, data);
        return _bufToHex(sigBuffer);
    }

    /**
     * Verify a signature.
     * publicKey may be a live CryptoKey or a SPKI hex string.
     * Returns true if valid, false if the signature does not match.
     * Throws on programming errors (wrong argument types, unsupported algorithm).
     */
    static async verifySignature(message, signatureHex, publicKey) {
        // [FIX H] Input guards.
        if (typeof message !== 'string' && !(message instanceof Uint8Array) && !(message instanceof ArrayBuffer)) {
            throw new TypeError('verifySignature: message must be a string, Uint8Array, or ArrayBuffer.');
        }
        if (typeof signatureHex !== 'string') {
            throw new TypeError('verifySignature: signatureHex must be a string.');
        }
        // [FIX I] null/undefined throws immediately.
        if (!publicKey) {
            throw new TypeError('verifySignature: publicKey is required.');
        }

        const data = typeof message === 'string' ? new TextEncoder().encode(message) : message;
        // [FIX G] Validated hex parsing.
        const sigBytes = _hexToBuf(signatureHex);

        // [FIX I] Accept SPKI hex string — import automatically.
        let key = publicKey;
        if (typeof publicKey === 'string') {
            key = await _importPublicKey(publicKey);
        }

        // [FIX F] Catch only the expected DOMException from a bad signature.
        //         Any other error type is re-thrown so bugs surface clearly.
        try {
            return await _subtle.verify({ name: 'Ed25519' }, key, sigBytes, data);
        } catch (e) {
            if (e instanceof DOMException) {
                // Expected: malformed signature bytes, key/algo mismatch.
                return false;
            }
            // Unexpected: programming error — surface it.
            throw e;
        }
    }

    // ── 3. Key Rotation ───────────────────────────────────────────────────────

    /**
     * Rotate keys: generate a new identity and sign a link certificate with
     * the old private key to prove continuity.
     *
     * [FIX D] Link payload uses length-prefixed canonical encoding.
     * [FIX E] Payload binds the full new public key, not just the nodeId.
     *
     * The rotation proof contains everything a verifier needs:
     *   previousNodeId, newNodeId, newPublicKeyHex, timestamp, signature
     */
    static async rotateKey(oldIdentity) {
        if (!oldIdentity?.sign || typeof oldIdentity.sign !== 'function') {
            throw new TypeError('rotateKey: oldIdentity must expose a sign() function.');
        }
        if (!oldIdentity.nodeId || typeof oldIdentity.nodeId !== 'string') {
            throw new TypeError('rotateKey: oldIdentity must have a nodeId string.');
        }

        const newIdentity = await GhostIdentity.generateIdentity();
        const timestamp = Date.now();

        // [FIX D] Length-prefixed canonical payload — field boundaries unambiguous.
        // [FIX E] Binds newPublicKeyHex, not just newId, so key substitution is detectable.
        const linkPayload = GhostIdentity._buildLinkPayload(
            oldIdentity.nodeId,
            newIdentity.nodeId,
            newIdentity.publicKeyHex,
            timestamp
        );

        // Sign with OLD key via the sealed closure.
        const proofSig = await oldIdentity.sign(linkPayload);

        newIdentity.rotationProof = {
            previousNodeId: oldIdentity.nodeId,
            timestamp,
            newPublicKeyHex: newIdentity.publicKeyHex,
            signature: proofSig,
        };

        return newIdentity;
    }

    /**
     * Verify a rotation proof.
     * [FIX J] Provides the missing verifier for rotateKey().
     *
     * @param {object}    proof           - The rotationProof object from rotateKey().
     * @param {CryptoKey|string} oldPublicKey - The old identity's public key (CryptoKey or SPKI hex).
     * @returns {boolean} true if the proof is valid.
     */
    static async verifyRotationProof(proof, oldPublicKey) {
        if (!proof || typeof proof !== 'object') {
            throw new TypeError('verifyRotationProof: proof must be an object.');
        }
        const { previousNodeId, timestamp, newPublicKeyHex, signature } = proof;

        if (!previousNodeId || !timestamp || !newPublicKeyHex || !signature) {
            throw new TypeError('verifyRotationProof: proof is missing required fields.');
        }

        // Reconstruct the exact canonical payload that was signed.
        // Note: we derive newNodeId from newPublicKeyHex for the payload.
        // The verifier should separately confirm that newIdentity.nodeId ===
        // SHA-256(importedNewPublicKey) to close the binding loop.
        const newPubKeyBytes = _hexToBuf(newPublicKeyHex);
        const newPubKey = await _subtle.importKey(
            'spki',
            newPubKeyBytes,
            { name: 'Ed25519' },
            true,
            ['verify']
        );
        const newRawPub = await _subtle.exportKey('raw', newPubKey);
        const newNodeId = await GhostIdentity._deriveNodeId(newRawPub);

        const linkPayload = GhostIdentity._buildLinkPayload(
            previousNodeId,
            newNodeId,
            newPublicKeyHex,
            timestamp
        );

        return GhostIdentity.verifySignature(linkPayload, signature, oldPublicKey);
    }

    /**
     * [FIX D] Canonical link payload with length-prefixed fields.
     * Format: "KRYPTOS_LINK_V1:<oldLen>:<oldId>:<newLen>:<newId>:<pkLen>:<pkHex>:<ts>"
     */
    static _buildLinkPayload(oldNodeId, newNodeId, newPublicKeyHex, timestamp) {
        return [
            'KRYPTOS_LINK_V1',
            `${oldNodeId.length}:${oldNodeId}`,
            `${newNodeId.length}:${newNodeId}`,
            `${newPublicKeyHex.length}:${newPublicKeyHex}`,
            String(timestamp),
        ].join(':');
    }

    // ── Utils ─────────────────────────────────────────────────────────────────

    static _bufToHex(buffer) { return _bufToHex(buffer); }
    static _hexToBuf(hex) { return _hexToBuf(hex); }

    // Expose importPublicKey for callers reconstructing keys from storage.
    static importPublicKey(spkiHex) { return _importPublicKey(spkiHex); }
}

// ─── Export ───────────────────────────────────────────────────────────────────

if (typeof window !== 'undefined') {
    // [FIX L] Immutable global — cannot be overwritten by later scripts.
    Object.defineProperty(window, 'GhostIdentity', {
        value: GhostIdentity,
        writable: false,
        configurable: false,
        enumerable: true,
    });
}

if (typeof module !== 'undefined') {
    module.exports = GhostIdentity;
}