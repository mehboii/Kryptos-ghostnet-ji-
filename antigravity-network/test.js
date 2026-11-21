const identity = require("./kryptos-identity");

(async () => {
    const node = await identity.createIdentity();

    console.log("NODE ID:", node.id);
    console.log("PUBLIC KEY:\n", node.publicKey);
})();