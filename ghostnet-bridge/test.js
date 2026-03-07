const identity = require("./ghostnet-identity");
const transport = require("./ghostnet-transport");
const chat = require("./ghostnet-chat");
const discovery = require("./ghostnet-discovery");
const webrtc = require("./ghostnet-webrtc");
const reputation = require("./ghostnet-reputation");

console.log("\n🧠 Identity:");
console.log(identity.createIdentity());

console.log("\n📡 Transport:");
console.log(typeof transport.sendPacket);

console.log("\n💬 Chat:");
console.log(typeof chat.sendMessage);

console.log("\n🕸 Discovery:");
console.log(typeof discovery.discoverPeers);

console.log("\n📞 WebRTC:");
console.log(typeof webrtc.createPeer);

console.log("\n⭐ Reputation:");
console.log(typeof reputation.updateScore);

console.log("\n✅ ALL MODULES LOADED SUCCESSFULLY");
