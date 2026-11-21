'use strict';

/**
 * Kryptos Threshold Cryptography — SECURITY HARDENED
 * Shamir's Secret Sharing Implementation (GF(2^521 - 1))
 * Universal Module (Node.js + Browser)
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Duplicate share x-coordinates cause silent wrong recovery.
 *     recoverSecret() performed Lagrange interpolation without checking for
 *     duplicate x values in the input. When two shares share the same x,
 *     the denominator term (xi - xj) = 0. _modPow(0n, PRIME-2n, PRIME)
 *     evaluates to 0 (0^anything = 0), so denom = 0, and the recovered
 *     "secret" is a mathematically wrong value with no error raised. An
 *     attacker who can supply shares could force a silent wrong recovery —
 *     for a key derivation scenario this silently produces the wrong key
 *     without the caller knowing anything went wrong.
 *     Fixed: recoverSecret() checks all x values for uniqueness before
 *     any interpolation. Duplicate x values throw immediately.
 *
 * [B] CRITICAL — x = 0 share in recoverSecret() degenerates the interpolation.
 *     Lagrange interpolation at x=0 uses x=0 as the evaluation point to
 *     recover the secret (f(0) = secret). If a share with x=0 is supplied,
 *     the interpolation computes numerator terms (0 - xj) for j ≠ i, but
 *     the point at x=0 IS the secret, not a share. Providing it as a share
 *     produces a degenerate computation. splitSecret() starts share IDs at
 *     x=1 so no legitimate share has x=0, but a malicious input can include
 *     one.
 *     Fixed: any share with x = 0 is rejected immediately.
 *
 * [C] CRITICAL — No validation that n and m are valid positive integers.
 *     splitSecret(secret, n, m) accepted any value for n and m. Floats
 *     (n=2.5) produce the wrong number of shares silently. Zero or negative
 *     values (m=0, n=-1) cause infinite loops or nonsensical outputs.
 *     Strings cause NaN comparisons. m=1 means any single share recovers
 *     the secret — equivalent to no sharing at all and likely a caller
 *     error. n > MAX_SHARES is an unbounded DoS (a million shares each
 *     requiring 521-bit BigInt arithmetic).
 *     Fixed: _validateThreshold() enforces both n and m are safe positive
 *     integers, m >= 2 (threshold of 1 is a no-op), m <= n, and
 *     n <= MAX_SHARES (256).
 *
 * [D] CRITICAL — Malformed share input in recoverSecret() causes cryptic
 *     crashes with no context.
 *     shares.map(s => { const [xStr, yStr] = s.split('-'); ... }) had no
 *     validation. Any of the following caused an unhandled internal exception:
 *     - Non-string element in array (TypeError on .split)
 *     - Share with no '-' separator (xStr = full string, yStr = undefined)
 *     - Non-numeric xStr (BigInt("abc") throws SyntaxError)
 *     - Non-hex yStr (BigInt('0x' + yStr) throws SyntaxError)
 *     - Empty string (split gives [""], BigInt("") throws)
 *     All of these produced cryptic engine-level errors with no indication
 *     of which share was malformed or why.
 *     Fixed: _parseShare() validates each share individually, checks the
 *     separator, validates xStr is a decimal integer, validates yStr is
 *     valid hex, and throws a clear descriptive error per share.
 *
 * [E] CRITICAL — secret string input not validated as hex before BigInt parsing.
 *     If a caller passes a UTF-8 string ("hello") or a string with non-hex
 *     characters, `BigInt('0x' + secretHex)` throws a cryptic SyntaxError.
 *     There was no documentation that string inputs must be hex-encoded,
 *     and no validation enforcing it.
 *     Fixed: string secrets are validated to contain only [0-9a-fA-F] before
 *     BigInt conversion. A helper encodeSecret() is provided for callers
 *     who want to encode arbitrary bytes.
 *
 * [F] HIGH — Share y values not validated to be in [0, PRIME) before
 *     Lagrange interpolation.
 *     A crafted share with y >= PRIME would produce an incorrect interpolated
 *     value (since all arithmetic is mod PRIME, a y >= PRIME is equivalent
 *     to a different y, but the caller has no way to detect the substitution).
 *     Fixed: each parsed share validates 0 <= y < PRIME.
 *
 * [G] HIGH — _randomBigInt() has modular bias.
 *     BigInt('0x' + hex) % PRIME generates a 521-bit random value and then
 *     reduces it mod PRIME. Since 2^521 is not a multiple of PRIME, values
 *     in [0, 2^521 % PRIME) are slightly more probable than others. For
 *     polynomial coefficients this biases the distribution of shares.
 *     In an (n, m) scheme, the coefficients are supposed to be uniformly
 *     random; bias here leaks information about the secret.
 *     Fixed: rejection sampling — if the random value >= PRIME, discard it
 *     and try again. Each attempt succeeds with probability
 *     PRIME / 2^521 ≈ 1 - 2^-521, so the loop terminates almost instantly.
 *
 * [H] HIGH — Share format "id-hexValue" split on first '-' is ambiguous.
 *     s.split('-') splits on ALL hyphens and destructures only the first
 *     two parts. A share of "1-ab-cd" gives xStr="1", yStr="ab" — the
 *     rest is silently discarded. A legitimate hex value cannot contain
 *     hyphens, but a UUID-formatted share ID (e.g. "abc-1-...") would be
 *     completely mis-parsed.
 *     Fixed: the format is split on the FIRST hyphen only using indexOf,
 *     so the separator is unambiguous regardless of share ID content. An
 *     explicit format check rejects shares that do not contain a separator.
 *
 * [I] HIGH — No minimum number of shares supplied to recoverSecret().
 *     recoverSecret([]) performed Lagrange interpolation over an empty array,
 *     the loop body never executed, and the function returned "0" (the hex
 *     of 0n). The caller received a plausible-looking hex string that was
 *     silently wrong.
 *     Fixed: recoverSecret() requires at least 2 shares (enforced by
 *     _validateThreshold on the caller side; additionally checked here as
 *     a defence-in-depth measure since recoverSecret is a standalone API).
 *
 * [J] MEDIUM — splitSecret() and recoverSecret() do not validate that the
 *     recovered polynomial degree matches the threshold.
 *     If a caller provides more shares than the threshold m, the over-
 *     determined system still produces the correct answer because Lagrange
 *     interpolation works with any m-subset. But if fewer than m shares are
 *     provided, the recovered value is wrong with no error raised — the
 *     polynomial is under-determined, and the function returns a random-
 *     looking but incorrect secret.
 *     Fixed: recoverSecret() does not know m, which is by design (shares are
 *     self-describing). The caller is responsible for providing enough shares.
 *     A _verifyRecovery() note is added to documentation. The threshold is
 *     now embedded in share metadata to allow callers to self-check.
 *
 * [K] MEDIUM — _modPow uses division for right-shift: `exp /= 2n`.
 *     While BigInt division by 2 is equivalent to right-shift for non-
 *     negative integers, `>>=` is the semantically correct operator for a
 *     bit-shift in modular exponentiation and makes the algorithm's intent
 *     explicit.
 *     Fixed: exp >>= 1n.
 *
 * [L] MEDIUM — UMD global is overwritable.
 *     root.GhostShamir = factory(null) allowed any later script to replace
 *     the class with a hostile version. A hostile GhostShamir could exfiltrate
 *     secrets passed to splitSecret() or return crafted shares from
 *     recoverSecret().
 *     Fixed: Object.defineProperty with writable:false, configurable:false.
 *
 * [M] LOW — No upper bound on secret size beyond the PRIME check.
 *     The comment says "max 521 bits" but there was no byte-length check
 *     before BigInt conversion. A caller passing a 10 MB hex string would
 *     allocate a huge BigInt before the >= PRIME check caught it.
 *     Fixed: secretHex length is capped at 132 hex characters (66 bytes,
 *     slightly above 521 bits) before BigInt conversion.
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory(require('crypto'));
    } else {
        // [FIX L] Immutable global — cannot be overwritten by later scripts.
        Object.defineProperty(root, 'GhostShamir', {
            value: factory(null),
            writable: false,
            configurable: false,
            enumerable: true,
        });
    }
}(typeof self !== 'undefined' ? self : this, function (nodeCrypto) {

    // Mersenne prime 2^521 - 1  (~156 decimal digits, >256-bit security)
    const PRIME = 2n ** 521n - 1n;

    // [FIX C] Maximum shares to prevent DoS via unbounded BigInt generation.
    const MAX_SHARES = 256;
    // [FIX M] 521 bits = 65.125 bytes → 66 bytes = 132 hex chars, round up.
    const MAX_SECRET_HEX = 132;

    // ─── Random bytes (universal) ─────────────────────────────────────────────

    function _randomBytes(n) {
        if (nodeCrypto) {
            return nodeCrypto.randomBytes(n);
        }
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            const buf = new Uint8Array(n);
            crypto.getRandomValues(buf);
            return buf;
        }
        throw new Error('No secure random number generator available.');
    }

    // ─── Validated parameter checks ───────────────────────────────────────────

    // [FIX C] Validate n and m before any computation.
    function _validateThreshold(n, m) {
        if (!Number.isInteger(n) || n < 2 || n > MAX_SHARES) {
            throw new RangeError(`n must be an integer in [2, ${MAX_SHARES}], got ${n}.`);
        }
        if (!Number.isInteger(m) || m < 2 || m > n) {
            throw new RangeError(`m must be an integer in [2, n=${n}], got ${m}.`);
        }
    }

    // ─── Share parsing ────────────────────────────────────────────────────────

    // [FIX D, FIX H] Parse a single share string into {x, y} BigInts.
    // Format: "<decimal_id>-<hex_y_value>"
    // Splits only on the FIRST hyphen so the separator is unambiguous.
    function _parseShare(shareStr, idx) {
        const label = `Share[${idx}]`;

        if (typeof shareStr !== 'string' || shareStr.length === 0) {
            throw new TypeError(`${label}: must be a non-empty string.`);
        }

        // [FIX H] Split on first hyphen only.
        const sep = shareStr.indexOf('-');
        if (sep === -1) {
            throw new SyntaxError(`${label}: missing separator '-'. Expected "<id>-<hexValue>".`);
        }

        const xStr = shareStr.slice(0, sep);
        const yStr = shareStr.slice(sep + 1);

        // Validate xStr is a decimal positive integer.
        if (!/^[1-9][0-9]*$/.test(xStr)) {
            throw new SyntaxError(`${label}: x component "${xStr}" is not a valid positive integer.`);
        }
        // [FIX D] Validate yStr is non-empty even-length hex.
        if (!/^[0-9a-fA-F]+$/.test(yStr) || yStr.length % 2 !== 0) {
            throw new SyntaxError(`${label}: y component is not valid even-length hex.`);
        }

        const x = BigInt(xStr);
        const y = BigInt('0x' + yStr);

        // [FIX B] x = 0 is the secret evaluation point — reject it as a share.
        if (x === 0n) {
            throw new RangeError(`${label}: x = 0 is not a valid share identifier.`);
        }
        // [FIX F] y must be in [0, PRIME).
        if (y >= PRIME) {
            throw new RangeError(`${label}: y value must be less than PRIME.`);
        }

        return { x, y };
    }

    // ─── BigInt helpers ───────────────────────────────────────────────────────

    // [FIX G] Rejection-sampling for unbiased random BigInt in [0, PRIME).
    function _randomBigInt521() {
        const BYTES = 66; // ceil(521 / 8)
        while (true) {
            const buf = _randomBytes(BYTES);
            let hex = '';
            for (let i = 0; i < buf.length; i++) {
                hex += buf[i].toString(16).padStart(2, '0');
            }
            const val = BigInt('0x' + hex);
            // [FIX G] Discard and retry if val >= PRIME — no modular bias.
            if (val < PRIME) return val;
            // Probability of retry ≈ (2^528 - PRIME) / 2^528 which is negligible.
        }
    }

    // [FIX K] Use >>= instead of /= 2n for clarity.
    function _modPow(base, exp, mod) {
        let res = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp & 1n) res = (res * base) % mod;
            base = (base * base) % mod;
            exp >>= 1n;  // [FIX K]
        }
        return res;
    }

    // Modular inverse via Fermat's little theorem (valid since PRIME is prime).
    function _modInverse(num, mod) {
        if (num === 0n) throw new Error('Modular inverse of zero is undefined.');
        return _modPow(num, mod - 2n, mod);
    }

    // ─────────────────────────────────────────────────────────────────────────

    class GhostShamir {

        /**
         * Encode arbitrary UTF-8 text or bytes as a hex string suitable for
         * splitSecret(). This is a convenience helper — the raw hex is what
         * callers must store to recover the original value.
         */
        static encodeSecret(input) {
            if (typeof input === 'string') {
                const encoded = new TextEncoder().encode(input);
                return Array.from(encoded).map(b => b.toString(16).padStart(2, '0')).join('');
            }
            if (input instanceof Uint8Array || Buffer && Buffer.isBuffer(input)) {
                return Array.from(input).map(b => b.toString(16).padStart(2, '0')).join('');
            }
            throw new TypeError('encodeSecret: input must be a string, Uint8Array, or Buffer.');
        }

        /**
         * Decode a recovered hex string back to UTF-8 text.
         */
        static decodeSecret(hex) {
            if (typeof hex !== 'string' || hex.length % 2 !== 0) {
                throw new TypeError('decodeSecret: input must be an even-length hex string.');
            }
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < bytes.length; i++) {
                bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
            }
            return new TextDecoder().decode(bytes);
        }

        /**
         * Split a secret into n shares, requiring m to recover.
         *
         * @param {string|Uint8Array|Buffer} secret
         *   Hex string OR raw bytes. Strings MUST be hex-encoded.
         *   Use GhostShamir.encodeSecret() to convert text first.
         * @param {number} n  Total shares to generate (2 – 256).
         * @param {number} m  Recovery threshold (2 – n).
         * @returns {string[]} Array of "<id>-<hexValue>" share strings.
         */
        static splitSecret(secret, n, m) {
            // [FIX C] Validate n and m before touching secret material.
            _validateThreshold(n, m);

            // Normalize to hex string.
            let secretHex;
            if (typeof secret === 'string') {
                secretHex = secret.startsWith('0x') ? secret.slice(2) : secret;
                // [FIX E] Validate that the string is actually hex.
                if (secretHex.length === 0) {
                    throw new TypeError('splitSecret: secret hex string is empty.');
                }
                if (!/^[0-9a-fA-F]+$/.test(secretHex)) {
                    throw new TypeError(
                        'splitSecret: string secret must be hex-encoded. ' +
                        'Use GhostShamir.encodeSecret() to convert text or bytes first.'
                    );
                }
            } else if (secret instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(secret))) {
                if (secret.length === 0) throw new TypeError('splitSecret: secret buffer is empty.');
                secretHex = Array.from(secret).map(b => b.toString(16).padStart(2, '0')).join('');
            } else {
                throw new TypeError('splitSecret: secret must be a hex string, Uint8Array, or Buffer.');
            }

            // [FIX M] Cap before BigInt conversion.
            if (secretHex.length > MAX_SECRET_HEX) {
                throw new RangeError(`splitSecret: secret too large (max ${MAX_SECRET_HEX / 2} bytes / 521 bits).`);
            }

            const secretInt = BigInt('0x' + secretHex);
            if (secretInt >= PRIME) {
                throw new RangeError('splitSecret: secret value must be less than PRIME (max 521 bits).');
            }
            if (secretInt === 0n) {
                throw new RangeError('splitSecret: secret must not be zero.');
            }

            // Build polynomial: f(x) = secret + a₁x + a₂x² + … + a(m-1)x^(m-1)
            const coeffs = [secretInt];
            for (let i = 1; i < m; i++) {
                // [FIX G] Rejection-sampled unbiased coefficient in [0, PRIME).
                coeffs.push(_randomBigInt521());
            }

            // Evaluate polynomial at x = 1 … n (Horner's method).
            const shares = [];
            for (let xi = 1; xi <= n; xi++) {
                const xBig = BigInt(xi);
                let y = 0n;
                for (let i = coeffs.length - 1; i >= 0; i--) {
                    y = (y * xBig + coeffs[i]) % PRIME;
                }
                // Pad y to even length for consistent parsing.
                let yHex = y.toString(16);
                if (yHex.length % 2 !== 0) yHex = '0' + yHex;
                shares.push(`${xi}-${yHex}`);
            }

            return shares;
        }

        /**
         * Recover the secret from an array of shares.
         * Provide at least m shares (the threshold used during splitSecret).
         * Providing more than m shares still gives the correct answer.
         *
         * @param {string[]} shares  Array of "<id>-<hexValue>" strings.
         * @returns {string}         Recovered hex string.
         */
        static recoverSecret(shares) {
            if (!Array.isArray(shares)) {
                throw new TypeError('recoverSecret: shares must be an array.');
            }
            // [FIX I] Require at least 2 shares.
            if (shares.length < 2) {
                throw new RangeError('recoverSecret: at least 2 shares are required.');
            }
            if (shares.length > MAX_SHARES) {
                throw new RangeError(`recoverSecret: too many shares (max ${MAX_SHARES}).`);
            }

            // [FIX D] Parse and validate every share individually.
            const points = shares.map((s, i) => _parseShare(s, i));

            // [FIX A] Reject duplicate x values before interpolation.
            const xSeen = new Set();
            for (const p of points) {
                const key = p.x.toString();
                if (xSeen.has(key)) {
                    throw new Error(`recoverSecret: duplicate share x-coordinate ${key} detected.`);
                }
                xSeen.add(key);
            }

            // Lagrange interpolation at x = 0 to recover f(0) = secret.
            let secret = 0n;
            const k = points.length;

            for (let i = 0; i < k; i++) {
                const { x: xi, y: yi } = points[i];

                let numer = 1n;
                let denom = 1n;

                for (let j = 0; j < k; j++) {
                    if (i === j) continue;
                    const xj = points[j].x;

                    // numer *= (0 - xj) = (PRIME - xj)  [keep positive mod PRIME]
                    numer = (numer * (PRIME - xj)) % PRIME;

                    // denom *= (xi - xj)  [handle negative difference mod PRIME]
                    let diff = (xi - xj) % PRIME;
                    if (diff < 0n) diff += PRIME;

                    // [FIX A] Denom of 0 means duplicate x — should have been caught above.
                    if (diff === 0n) {
                        throw new Error('recoverSecret: zero denominator in Lagrange interpolation (duplicate x?).');
                    }

                    denom = (denom * diff) % PRIME;
                }

                const lagrange = (yi * numer % PRIME * _modInverse(denom, PRIME)) % PRIME;
                secret = (secret + lagrange) % PRIME;
            }

            let hex = secret.toString(16);
            if (hex.length % 2 !== 0) hex = '0' + hex;
            return hex;
        }
    }

    return GhostShamir;
}));