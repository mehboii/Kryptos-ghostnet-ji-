/* GhostIdentity.js - Browser Compatible Identity Module
 *
 * SECURITY FIXES:
 * [FIX 05-A] Private key generated with extractable: false
 * [FIX 05-B] Private key NOT returned in identity object — sealed in closure
 * [FIX 05-C] sign() method exposed instead of raw CryptoKey
 */
(function (root) {

    function bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
    }

    function hexToBuffer(hex) {
        if (!hex) return new Uint8Array(0);
        const tokens = hex.match(/.{1,2}/g);
        if (!tokens) return new Uint8Array(0);
        return new Uint8Array(tokens.map(byte => parseInt(byte, 16)));
    }

    const GhostIdentity = {
        async generateIdentity() {
            // [FIX 05-A] extractable: false — private key cannot be exported
            const keys = await root.crypto.subtle.generateKey(
                {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                false,
                ["sign", "verify"]
            );

            const pubBuffer = await root.crypto.subtle.exportKey("spki", keys.publicKey);
            const pubHex = bufferToHex(pubBuffer);
            const nodeId = "node_" + pubHex.substring(pubHex.length - 8);

            // [FIX 05-B] Seal private key in closure — never returned
            const _privateKey = keys.privateKey;

            return {
                id: crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString()),
                nodeId: nodeId,
                publicKey: keys.publicKey,
                publicKeyHex: pubHex,
                // [FIX 05-C] Only way to use the private key
                sign: (message) => GhostIdentity.signMessage(message, _privateKey),
                // privateKey intentionally absent
            };
        },

        async signMessage(messageStr, privateKey) {
            if (!privateKey || typeof privateKey !== 'object') {
                throw new TypeError('signMessage: privateKey must be a CryptoKey object.');
            }
            const encoder = new TextEncoder();
            const data = typeof messageStr === 'string' ? encoder.encode(messageStr) : messageStr;

            const signature = await root.crypto.subtle.sign(
                {
                    name: "ECDSA",
                    hash: { name: "SHA-256" },
                },
                privateKey,
                data
            );
            return bufferToHex(signature);
        },

        async verifySignature(messageStr, signatureHex, publicKey) {
            if (!publicKey) {
                throw new TypeError('verifySignature: publicKey is required.');
            }
            const encoder = new TextEncoder();
            const data = typeof messageStr === 'string' ? encoder.encode(messageStr) : messageStr;

            if (typeof signatureHex !== 'string' || !/^[0-9a-fA-F]+$/.test(signatureHex)) {
                return false;
            }
            const signature = hexToBuffer(signatureHex);

            try {
                const isValid = await root.crypto.subtle.verify(
                    {
                        name: "ECDSA",
                        hash: { name: "SHA-256" },
                    },
                    publicKey,
                    signature,
                    data
                );
                return isValid;
            } catch (e) {
                if (e instanceof DOMException) {
                    return false;
                }
                throw e;
            }
        }
    };

    // Immutable global — cannot be overwritten by later scripts
    if (typeof root !== 'undefined' && root !== null) {
        Object.defineProperty(root, 'GhostIdentity', {
            value: GhostIdentity,
            writable: false,
            configurable: false,
            enumerable: true,
        });
    }

})(typeof window !== 'undefined' ? window : this);
