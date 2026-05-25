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

    // [RASP-10] Constant-time buffer comparison — prevents timing attacks on signature bytes
    function constantTimeEqual(a, b) {
        if (a.length !== b.length) return false;
        let result = 0;
        for (let i = 0; i < a.length; i++) result |= a[i] ^ b[i];
        return result === 0;
    }

    const GhostIdentity = {
        async generateIdentity() {
            // [DAST-08] Generate extractable to export pubkey, then re-import private key as non-extractable
            const keys = await window.crypto.subtle.generateKey(
                {
                    name: "ECDSA",
                    namedCurve: "P-256",
                },
                true,
                ["sign", "verify"]
            );

            const pubBuffer = await window.crypto.subtle.exportKey("spki", keys.publicKey);
            const pubHex = bufferToHex(pubBuffer);
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', pubBuffer);
            const hashHex = bufferToHex(hashBuffer);
            const nodeId = "0x" + hashHex.substring(0, 40);

            // [DAST-08] Re-import private key as non-extractable so exportKey('pkcs8') is blocked
            const privBuffer = await window.crypto.subtle.exportKey("pkcs8", keys.privateKey);
            const nonExtractablePrivKey = await window.crypto.subtle.importKey(
                "pkcs8", privBuffer,
                { name: "ECDSA", namedCurve: "P-256" },
                false,
                ["sign"]
            );
            // Zero out exported private key material
            new Uint8Array(privBuffer).fill(0);

            return {
                id: crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString()),
                nodeId: nodeId,
                publicKey: keys.publicKey,
                privateKey: nonExtractablePrivKey
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
                // [RT-BREAK-14] Log only message, not full error with key material
                console.error("Signature Verify Failed:", e.message || 'unknown');
                return false;
            }
        }
    };

    window.GhostIdentity = GhostIdentity;

})(typeof window !== 'undefined' ? window : this);