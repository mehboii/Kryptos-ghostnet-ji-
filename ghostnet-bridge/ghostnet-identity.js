/**
 * GhostNet Identity System
 * ghostnet-identity.js
 * 
 * Implements Ed25519 Cryptographic Identity.
 * - Key Generation
 * - Signing / Verification
 * - Node ID Derivation (SHA-256 Hash of PubKey)
 * 
 * Note: Uses Web Crypto API 'Ed25519' (Supported in Chrome 113+, Firefox 122+, Safari 17+).
 * If not supported, throws error (or could fallback to P-256 in a real app).
 */

class GhostIdentity {

    // --- 1. CORE GENERATORS ---

    /**
     * Generates a new Ed25519 Keypair and derives Node ID.
     */
    static async generateIdentity() {
        // Generate Key Pair
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "Ed25519",
            },
            true,
            ["sign", "verify"]
        );

        // Export Public Key to derive Node ID
        const rawPub = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
        const nodeId = await this._deriveNodeId(rawPub);

        return {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey,
            nodeId: nodeId,
            created: Date.now()
        };
    }

    /**
     * Derives Node ID: SHA-256(PublicKey) -> Hex -> First 16 chars
     */
    static async _deriveNodeId(rawPubBuffer) {
        const hashBuffer = await window.crypto.subtle.digest("SHA-256", rawPubBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex.substring(0, 16); // Short ID
    }

    // --- 2. SIGNING & VERIFICATION ---

    /**
     * Signs a message (String or Buffer) with Private Key.
     * @param {string|Uint8Array} message 
     * @param {CryptoKey} privateKey 
     * @returns {string} Hex Signature
     */
    static async signMessage(message, privateKey) {
        const data = typeof message === 'string' ? new TextEncoder().encode(message) : message;

        const sigBuffer = await window.crypto.subtle.sign(
            {
                name: "Ed25519"
            },
            privateKey,
            data
        );

        return this._bufToHex(sigBuffer);
    }

    /**
     * Verifies a signature against a Public Key.
     * @param {string|Uint8Array} message 
     * @param {string} signatureHex 
     * @param {CryptoKey} publicKey 
     * @returns {boolean} Valid?
     */
    static async verifySignature(message, signatureHex, publicKey) {
        const data = typeof message === 'string' ? new TextEncoder().encode(message) : message;
        const sigBuffer = this._hexToBuf(signatureHex);

        const isValid = await window.crypto.subtle.verify(
            {
                name: "Ed25519"
            },
            publicKey,
            sigBuffer,
            data
        );

        return isValid;
    }

    // --- 3. KEY MANAGEMENT ---

    /**
     * ROTATE KEYS (Optional)
     * Generates a new identity and signs the new Public Key with the OLD Private Key
     * to prove continuity/ownership using a "Link Certificate".
     */
    static async rotateKey(oldIdentity) {
        // 1. Gen New Key
        const newIdentity = await this.generateIdentity();

        // 2. Create Link Payload
        // "I, [OldID], certify that [NewID] is my new key."
        const timestamp = Date.now();
        const linkPayload = `LINK:${oldIdentity.nodeId}:${newIdentity.nodeId}:${timestamp}`;

        // 3. Sign with OLD Key
        const proofSig = await this.signMessage(linkPayload, oldIdentity.privateKey);

        // 4. Attach Proof
        newIdentity.rotationProof = {
            previousId: oldIdentity.nodeId,
            timestamp: timestamp,
            signature: proofSig
        };

        return newIdentity;
    }

    // --- UTILS ---

    static _bufToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    static _hexToBuf(hex) {
        const bytes = new Uint8Array(Math.ceil(hex.length / 2));
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        return bytes.buffer;
    }
}

// Export
if (typeof window !== "undefined") {
    window.GhostIdentity = GhostIdentity;
}

if (typeof module !== "undefined") {
    module.exports = GhostIdentity;
}
