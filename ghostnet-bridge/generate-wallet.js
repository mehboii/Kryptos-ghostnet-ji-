const { ethers } = require("ethers");
const fs = require("fs");

console.log(" Generating new GhostNet Wallet...");

const wallet = ethers.Wallet.createRandom();

console.log("\n✅ Wallet Generated Successfully!");
console.log("---------------------------------------------------");
console.log(` Address:      ${wallet.address}`);
console.log(` Private Key:  ${wallet.privateKey}`);
console.log(` Mnemonic:     ${wallet.mnemonic.phrase}`);
console.log("---------------------------------------------------");
console.log("\n⚠️ ACTION REQUIRED:");
console.log("1. Copy the 'Private Key' above.");
console.log("2. Open 'bridge.js'.");
console.log("3. Replace 'PUT_TEST_PRIVATE_KEY_HERE' with this key.");
console.log("4. Restart the bridge: 'node bridge.js'");
