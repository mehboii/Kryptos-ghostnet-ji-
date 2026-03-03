/**
 * GhostNet Threshold Cryptography
 * Shamir's Secret Sharing Implementation (GF(2^521 - 1))
 * Universal Module (Node.js + Browser)
 * 
 * Securely splits secrets (BigInt-supported) into N shares,
 * requiring M shares to recover.
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        // Node.js
        module.exports = factory(require('crypto'));
    } else {
        // Browser
        root.GhostShamir = factory(null);
    }
}(typeof self !== 'undefined' ? self : this, function (nodeCrypto) {

    // Mersenne Prime 2^521 - 1 (Standard large prime for >256-bit security)
    const PRIME = 2n ** 521n - 1n;

    class GhostShamir {

        // --- HELPER: Random Bytes (Universal) ---
        static _randomBytes(bytes) {
            if (nodeCrypto) {
                return nodeCrypto.randomBytes(bytes);
            } else if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
                const buf = new Uint8Array(bytes);
                crypto.getRandomValues(buf);
                return buf;
            } else {
                throw new Error("No secure random number generator available.");
            }
        }

        // --- HELPER: Math ---

        static _randomBigInt(bits) {
            const bytes = Math.ceil(bits / 8);
            const buf = this._randomBytes(bytes);

            // Convert buffer to hex string manually for universality
            let hex = '';
            for (let i = 0; i < buf.length; i++) {
                hex += buf[i].toString(16).padStart(2, '0');
            }

            return BigInt('0x' + hex) % PRIME;
        }

        // Modular Exponentiation: base^exp % mod
        static _modPow(base, exp, mod) {
            let res = 1n;
            base = base % mod;
            while (exp > 0n) {
                if (exp % 2n === 1n) res = (res * base) % mod;
                base = (base * base) % mod;
                exp /= 2n;
            }
            return res;
        }

        // Modular Inverse: (num)^-1 % mod
        static _modInverse(num, mod) {
            return this._modPow(num, mod - 2n, mod);
        }

        // --- CORE API ---

        /**
         * Splits a secret into N shares, requiring M to recover.
         * @param {string|Uint8Array} secret - Hex String OR Uint8Array/Buffer
         * @param {number} n - Total shares
         * @param {number} m - Threshold
         * @returns {string[]} Array of "id-hexValue"
         */
        static splitSecret(secret, n, m) {
            if (m > n) throw new Error("Threshold cannot be greater than total shares");

            // Normalize Secret to Hex
            let secretHex;
            if (typeof secret === 'string') {
                secretHex = secret.startsWith('0x') ? secret.slice(2) : secret;
            } else {
                // Buffer/Uint8Array
                secretHex = Array.from(secret)
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            }

            const secretInt = BigInt('0x' + secretHex);
            if (secretInt >= PRIME) throw new Error("Secret too large (max 521 bits)");

            // Coefficients: f(x) = secret + a1*x + ...
            const coeffs = [secretInt];
            for (let i = 1; i < m; i++) {
                coeffs.push(this._randomBigInt(521));
            }

            // Generate Shares
            const shares = [];
            for (let x = 1; x <= n; x++) {
                const xBig = BigInt(x);
                let y = 0n;

                // Horner's Method
                for (let i = coeffs.length - 1; i >= 0; i--) {
                    y = (y * xBig + coeffs[i]) % PRIME;
                }

                shares.push(`${x}-${y.toString(16)}`);
            }

            return shares;
        }

        /**
         * Recovers the secret from shares.
         * @param {string[]} shares - Array of "id-hexValue"
         * @returns {string} Reconstructed Hex Secret
         */
        static recoverSecret(shares) {
            const points = shares.map(s => {
                const [xStr, yStr] = s.split('-');
                return { x: BigInt(xStr), y: BigInt('0x' + yStr) };
            });

            // Lagrange Interpolation at x=0
            let secret = 0n;
            const k = points.length;

            for (let i = 0; i < k; i++) {
                const xi = points[i].x;
                const yi = points[i].y;

                let numer = 1n;
                let denom = 1n;

                for (let j = 0; j < k; j++) {
                    if (i === j) continue;
                    const xj = points[j].x;

                    // (0 - xj)
                    numer = (numer * (PRIME - xj)) % PRIME;
                    // (xi - xj)
                    let diff = (xi - xj) % PRIME;
                    if (diff < 0n) diff += PRIME;
                    denom = (denom * diff) % PRIME;
                }

                const lagrange = (yi * numer * this._modInverse(denom, PRIME)) % PRIME;
                secret = (secret + lagrange) % PRIME;
            }

            let hex = secret.toString(16);
            if (hex.length % 2 !== 0) hex = '0' + hex;
            return hex;
        }
    }

    return GhostShamir;
}));
