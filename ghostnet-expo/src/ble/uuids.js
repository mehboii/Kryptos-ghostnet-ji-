/**
 * GhostNet Proximity Connect — shared BLE identifiers.
 *
 * SINGLE SOURCE OF TRUTH. These exact values are already used by the web layer
 * (ghostnet-mesh.js, proximity-connect.js). The native bridge, the GATT server,
 * and the existing web mesh MUST all agree on them, otherwise a device that
 * advertises will not be matched by a peer that scans.
 *
 * The service UUID is the shared *rendezvous* UUID every GhostNet client both
 * advertises and scans for. It carries NO identity — identity is only revealed
 * after a GATT connection + the authenticated handshake (see proximity-connect.js).
 *
 * The bytes spell "ghostnet-mesh" / "-id" / "-key" / "-data" in ASCII, which is
 * just a human-readable mnemonic — it is a fixed, public, non-identifying value
 * shared by every install, so it cannot be used to track a specific device.
 */
'use strict';

// "ghostnet-mesh\0\0\0"
const SERVICE_UUID = '67686f73-746e-6574-2d6d-657368000000';

// Peripheral-exposed characteristics. Layout is intentionally identical to what
// ghostnet-mesh.js already reads, so an authenticated proximity peer is a valid
// mesh BLE peer without a second GATT schema.
const CHAR_PEER_ID = '67686f73-746e-6574-2d69-640000000000'; // read  — peer's nodeId (UTF-8)
const CHAR_PUB_KEY = '67686f73-746e-6574-2d6b-657900000000'; // read  — peer's identity public key (hex)
const CHAR_DATA    = '67686f73-746e-6574-2d64-617461000000'; // write + notify — handshake + session channel

// 16-bit "service data" tag advertised alongside the service UUID on Android.
// Carries ONLY the rotating ephemeral pseudonym (see pseudonym.js) — never a
// stable identifier. iOS CoreBluetooth strips this, so it is best-effort and
// the protocol never depends on it (rich data is exchanged only post-GATT).
const PSEUDONYM_SERVICE_DATA_UUID = '67687073'; // "ghps"

// MTU targets. iOS effectively caps ATT MTU around 185; Android can negotiate
// up to 247. We request the higher value and use whatever the link grants.
const MTU_TARGET_ANDROID = 247;
const MTU_TARGET_IOS = 185;

module.exports = {
  SERVICE_UUID,
  CHAR_PEER_ID,
  CHAR_PUB_KEY,
  CHAR_DATA,
  PSEUDONYM_SERVICE_DATA_UUID,
  MTU_TARGET_ANDROID,
  MTU_TARGET_IOS,
};
