const GhostIdentity = require("./kryptos-identity");
// Add this environment check so it doesn't crash the simulation if run there
if (typeof window === 'undefined') {
    // We are in Node
}

(async () => {
    console.log("--- Testing GhostIdentity (Universal) ---");

    // 1. Generate
    console.log("Generating Identity...");
    const id = await GhostIdentity.generateIdentity();
    console.log("ID Generated:", id.nodeId);
    console.log("Pub Key:", id.publicKey ? "OK" : "MISSING");

    // 2. Sign
    const msg = "Hello Kryptos";
    console.log("Signing:", msg);
    const sig = await GhostIdentity.signMessage(msg, id.privateKey);
    console.log("Signature:", sig.substring(0, 20) + "...");

    // 3. Verify
    console.log("Verifying...");
    const valid = await GhostIdentity.verifySignature(msg, sig, id.publicKey);
    console.log("Verification Result:", valid);

    if (valid && id.nodeId) {
        console.log(" TEST PASSED");
    } else {
        console.error(" TEST FAILED");
        process.exit(1);
    }
})();
