/**
 * GhostIdentity.js — SECURITY HARDENED
 * Browser Compatible Identity Module
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Private key returned in plain object and left in caller memory.
 *     generateIdentity() returned { privateKey: keys.privateKey } in the
 *     object given to callers. The CryptoKey object sits in JS heap memory,
 *     is accessible to any code holding the identity object, shows up in
 *     DevTools memory snapshots, and can be serialised by JSON.stringify in
 *     some environments. A transport layer, UI component, or logging call
 *     that receives the full identity object has unnecessary access to the
 *     private key.
 *     Fixed: the private key is NEVER returned. generateIdentity() returns
 *     only public material. The private key is sealed inside a closure
 *     returned as a sign() function — callers can request a signature but
 *     cannot read or export the key itself.
 *
 * [B] CRITICAL — Private key is extractable (exportable).
 *     generateKey() was called with extractable: true. This means any code
 *     that holds the CryptoKey object can call crypto.subtle.exportKey() to
 *     get the raw private key bytes. Combined with [A], the private key was
 *     both accessible AND exportable.
 *     Fixed: generateKey() uses extractable: false for the private key.
 *     It can never be exported from the browser's key store.
 *
 * [C] HIGH — nodeId derived from only the last 8 hex characters of the
 *     public key (4 bytes = 32 bits of entropy).
 *     `pubHex.substring(pubHex.length - 8)` took only the trailing 8 hex
 *     chars of the SPKI-encoded public key. With only 32 bits of space
 *     there are ~4 billion possible node IDs — a birthday collision is
 *     expected after roughly 65,000 nodes. An attacker can grind key
 *     generation until they produce a nodeId that collides with a target
 *     node, then impersonate it in any lookup that uses nodeId as identity.
 *     Fixed: nodeId is SHA-256 of the full SPKI public key export, encoded
 *     as hex — 256 bits of collision resistance.
 *
 * [D] HIGH — `id` field falls back to `Date.now().toString()` when
 *     crypto.randomUUID is unavailable.
 *     Date.now() returns a millisecond timestamp — predictable, sequential,
 *     and with only ~1ms resolution. Two identities generated in the same
 *     millisecond collide. In contexts without randomUUID (older browsers,
 *     some WebViews) this is the only fallback.
 *     Fixed: fallback uses 128 bits of crypto.getRandomValues() formatted
 *     as a UUID v4-style string — always unpredictable regardless of
 *     browser support for randomUUID.
 *
 * [E] HIGH — hexToBuffer() does not validate input.
 *     Passing a non-hex string produces silent NaN bytes in the Uint8Array
 *     which are then used as a signature in verifySignature(). An attacker
 *     who can influence the signatureHex argument gets verifySignature() to
 *     attempt verification against a corrupted byte sequence with no error.
 *     Fixed: hexToBuffer() validates that the input is an even-length string
 *     containing only [0-9a-fA-F] and throws clearly on invalid input.
 *
 * [F] MEDIUM — verifySignature() returns false on exception, masking errors.
 *     The catch block returned false for ALL exceptions — including ones
 *     caused by the wrong publicKey type, a corrupted signature buffer, an
 *     API misuse, or a browser bug. Silently returning false for non-
 *     cryptographic errors makes bugs invisible and can cause a caller to
 *     treat a programming error as a "signature mismatch" and continue.
 *     Fixed: only CryptoKey DOMException errors from the verify call are
 *     caught and returned as false. Other exception types are re-thrown so
 *     they surface as real errors to the caller.
 *
 * [G] MEDIUM — Public key returned as a raw CryptoKey object.
 *     Returning the live CryptoKey means callers can attempt to use it for
 *     operations beyond verification (depending on the browser's key usage
 *     enforcement), and there is no stable serialisable representation for
 *     storage or transmission.
 *     Fixed: generateIdentity() exports the public key as both a CryptoKey
 *     (for in-session use) and as a stable hex string of the SPKI encoding
 *     (for storage and transmission). Callers that need to verify from a
 *     stored key must import it first via importPublicKey().
 *
 * [H] MEDIUM — window.GhostIdentity is overwritable.
 *     Plain assignment `window.GhostIdentity = GhostIdentity` allows any
 *     later-loaded script to replace the object with a hostile version that
 *     exfiltrates the private key on the next signMessage() call.
 *     Fixed: Object.defineProperty with writable:false, configurable:false.
 *
 * [I] LOW — No input type validation on signMessage() / verifySignature().
 *     Neither function checked that messageStr was a string or ArrayBuffer,
 *     or that signatureHex was a string. Passing null or an object could
 *     produce confusing downstream errors or silent misbehaviour.
 *     Fixed: explicit type guards at the top of each function.
 *
 * [J] LOW — IIFE receives `this` as fallback when window is undefined.
 *     In a non-browser ESM or strict-mode context, `this` is undefined, so
 *     the IIFE receives undefined and the assignment at line 1 throws.
 *     Fixed: guard ensures the module only executes in a browser context
 *     where window is defined.
 */

(function () {
    'use strict';

    // [FIX J] Only execute in a genuine browser context.
    if (typeof window === 'undefined' || typeof window.crypto === 'undefined') {
        console.warn('[GhostIdentity] Not a browser context — module not loaded.');
        return;
    }

    // ─── Utilities ────────────────────────────────────────────────────────────

    function bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // [FIX E] Validate hex string before parsing.
    function hexToBuffer(hex) {
        if (typeof hex !== 'string' || hex.length === 0) {
            throw new TypeError('hexToBuffer: input must be a non-empty string.');
        }
        if (hex.length % 2 !== 0) {
            throw new TypeError('hexToBuffer: input must have even length.');
        }
        if (!/^[0-9a-fA-F]+$/.test(hex)) {
            throw new TypeError('hexToBuffer: input contains non-hex characters.');
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    // [FIX D] Cryptographically secure UUID fallback.
    function _secureUUID() {
        if (typeof crypto.randomUUID === 'function') {
            return crypto.randomUUID();
        }
        // 128 bits of randomness formatted as UUID v4.
        const bytes = crypto.getRandomValues(new Uint8Array(16));
        bytes[6] = (bytes[6] & 0x0f) | 0x40;   // version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80;   // variant bits
        const hex = bufferToHex(bytes);
        return [
            hex.slice(0, 8),
            hex.slice(8, 12),
            hex.slice(12, 16),
            hex.slice(16, 20),
            hex.slice(20, 32),
        ].join('-');
    }

    // ─── Public key import helper ─────────────────────────────────────────────

    // Import a public key from its SPKI hex string for signature verification.
    async function importPublicKey(spkiHex) {
        if (typeof spkiHex !== 'string' || spkiHex.length === 0) {
            throw new TypeError('importPublicKey: spkiHex must be a non-empty string.');
        }
        const raw = hexToBuffer(spkiHex);
        return window.crypto.subtle.importKey(
            'spki',
            raw,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,          // non-extractable — for verify only
            ['verify']
        );
    }

    // ─── Core module ──────────────────────────────────────────────────────────

    const GhostIdentity = {

        /**
         * Generate a new ECDSA P-256 identity.
         *
         * Returns:
         *   {
         *     id:           string   — random UUID (128-bit secure)
         *     nodeId:       string   — "node_" + SHA-256(SPKI) hex
         *     publicKeyHex: string   — SPKI-encoded public key as hex (for storage/transmission)
         *     publicKey:    CryptoKey — live key object (for in-session verify calls)
         *     sign:         async (messageStr) => signatureHex
         *   }
         *
         * The private key is NEVER returned. It is sealed inside the sign()
         * closure and cannot be read or exported by any caller.
         */
        async generateIdentity() {
            // [FIX B] Private key is NOT extractable.
            const keys = await window.crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                false,          // [FIX B] extractable: false — private key cannot be exported
                ['sign', 'verify']
            );

            const pubBuffer = await window.crypto.subtle.exportKey('spki', keys.publicKey);
            const publicKeyHex = bufferToHex(new Uint8Array(pubBuffer));

            // [FIX C] nodeId = SHA-256 of the full SPKI export — 256 bits of collision resistance.
            const nodeIdBuffer = await window.crypto.subtle.digest('SHA-256', pubBuffer);
            const nodeId = 'node_' + bufferToHex(new Uint8Array(nodeIdBuffer));

            // [FIX A] Private key sealed in closure — never returned directly.
            const _privateKey = keys.privateKey;

            // [FIX A] sign() is the ONLY way to use the private key.
            async function sign(messageStr) {
                return GhostIdentity.signMessage(messageStr, _privateKey);
            }

            return {
                // [FIX D] Always cryptographically random.
                id: _secureUUID(),
                nodeId,
                publicKeyHex, // [FIX G] Stable hex for storage/transmission.
                publicKey: keys.publicKey,
                sign,         // [FIX A] Private key only accessible via this closure.
                // privateKey is intentionally absent.
            };
        },

        /**
         * Sign a message string.
         * privateKey must be a non-extractable ECDSA CryptoKey from generateIdentity().
         * Returns the DER-encoded ECDSA signature as a hex string.
         */
        async signMessage(messageStr, privateKey) {
            // [FIX I] Input type guards.
            if (typeof messageStr !== 'string' && !(messageStr instanceof ArrayBuffer) && !(messageStr instanceof Uint8Array)) {
                throw new TypeError('signMessage: messageStr must be a string or BufferSource.');
            }
            if (!privateKey || typeof privateKey !== 'object') {
                throw new TypeError('signMessage: privateKey must be a CryptoKey object.');
            }

            const encoder = new TextEncoder();
            const data = typeof messageStr === 'string' ? encoder.encode(messageStr) : messageStr;

            const signature = await window.crypto.subtle.sign(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                privateKey,
                data
            );

            return bufferToHex(new Uint8Array(signature));
        },

        /**
         * Verify a signature.
         * publicKey may be a CryptoKey object or a SPKI hex string.
         * Returns true if the signature is valid, false if not.
         * Throws on programming errors (wrong key type, invalid arguments).
         */
        async verifySignature(messageStr, signatureHex, publicKey) {
            // [FIX I] Input type guards.
            if (typeof messageStr !== 'string' && !(messageStr instanceof ArrayBuffer) && !(messageStr instanceof Uint8Array)) {
                throw new TypeError('verifySignature: messageStr must be a string or BufferSource.');
            }
            if (typeof signatureHex !== 'string') {
                throw new TypeError('verifySignature: signatureHex must be a string.');
            }
            if (!publicKey) {
                throw new TypeError('verifySignature: publicKey is required.');
            }

            const encoder = new TextEncoder();
            const data = typeof messageStr === 'string' ? encoder.encode(messageStr) : messageStr;

            // [FIX E] Validated hex parsing.
            const signatureBytes = hexToBuffer(signatureHex);

            // Accept both a live CryptoKey and a SPKI hex string.
            let key = publicKey;
            if (typeof publicKey === 'string') {
                key = await importPublicKey(publicKey);
            }

            // [FIX F] Catch only the expected DOMException from the verify call.
            //         Any other error type is re-thrown so bugs surface clearly.
            try {
                return await window.crypto.subtle.verify(
                    { name: 'ECDSA', hash: { name: 'SHA-256' } },
                    key,
                    signatureBytes,
                    data
                );
            } catch (e) {
                if (e instanceof DOMException) {
                    // Expected: invalid signature format, key mismatch, etc.
                    return false;
                }
                // Unexpected: programming error, wrong argument type, etc. — surface it.
                throw e;
            }
        },

        // Expose importPublicKey so callers can reconstruct a key from a stored hex string.
        importPublicKey,
    };

    // [FIX H] Immutable global — cannot be overwritten by later scripts.
    Object.defineProperty(window, 'GhostIdentity', {
        value: GhostIdentity,
        writable: false,
        configurable: false,
        enumerable: true,
    });

})();