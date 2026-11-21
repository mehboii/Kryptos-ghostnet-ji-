const GhostTransport = require("./kryptos-transport");
const GhostIdentity = require("./kryptos-identity");

(async () => {
    try {
        console.log("--- Testing GhostTransport (Universal) ---");

        // 1. Identity
        console.log("Generating Identity A...");
        const idA = await GhostTransport.generateIdentity();
        console.log("ID A:", idA.address);

        console.log("Generating Identity B...");
        const idB = await GhostTransport.generateIdentity();
        console.log("ID B:", idB.address);

        // 2. Transport A -> B
        const transportA = new GhostTransport(idA);
        const transportB = new GhostTransport(idB); // Required for decryption

        // 3. Encrypt
        const msg = { text: "Secret Meeting at Midnight" };
        console.log("Encryp payload:", JSON.stringify(msg));

        // Use Verify Key for addressing (simulating discovery)
        const recipientPubKeyHex = await transportA._exportKey(idB.encryptionKey, 'spki'); // Use encryption key! 
        // Wait, createEnvelope expects receiverPubKeyHex to be capable of 'deriveKey' (ECDH)
        // Transport.generateIdentity returns encryptionKey (ECDH Public)

        const envelope = await transportA.createEnvelope(recipientPubKeyHex, msg);
        console.log("Envelope created. ID:", envelope.id);
        console.log("Payload Hex (first 20):", envelope.payload.substring(0, 20) + "...");

        // 4. Verify & Decrypt (B side)
        console.log("Verifying on B...");
        const valid = await transportB.verifyEnvelope(envelope);
        console.log("Signature Valid:", valid);

        if (!valid) throw new Error("Signature verification failed");

        console.log("Decrypting on B...");
        const decrypted = await transportB.decryptEnvelope(envelope);
        console.log("Decrypted:", JSON.stringify(decrypted));

        if (decrypted && decrypted.text === msg.text) {
            console.log(" TEST PASSED");
        } else {
            console.error(" DECRYPTION MISMATCH");
        }

    } catch (e) {
        console.error(" TEST FAILED:", e);
    }
})();
