/* GhostIdentity.js - Browser Compatible Identity Module */
(function (window) {

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
            // Using ECDSA P-256 for browser compatibility
            const keys = await window.crypto.subtle.generateKey(
                {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                true,
                ["sign", "verify"]
            );

            // Generate a deterministic Node ID from public key
            // (We export SPKI to get a consistent unique string representation)
            const pubBuffer = await window.crypto.subtle.exportKey("spki", keys.publicKey);
            const pubHex = bufferToHex(pubBuffer);
            const nodeId = "node_" + pubHex.substring(pubHex.length - 8);

            return {
                id: crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString()),
                nodeId: nodeId,
                publicKey: keys.publicKey,
                privateKey: keys.privateKey
            };
        },

        async signMessage(messageStr, privateKey) {
            const encoder = new TextEncoder();
            const data = typeof messageStr === 'string' ? encoder.encode(messageStr) : messageStr;

            const signature = await window.crypto.subtle.sign(
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
            const encoder = new TextEncoder();
            const data = typeof messageStr === 'string' ? encoder.encode(messageStr) : messageStr;
            const signature = hexToBuffer(signatureHex);

            try {
                const isValid = await window.crypto.subtle.verify(
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
                console.error("Signature Verify Failed:", e);
                return false;
            }
        }
    };

    window.GhostIdentity = GhostIdentity;

})(typeof window !== 'undefined' ? window : this);