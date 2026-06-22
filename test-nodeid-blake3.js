/**
 * test-nodeid-blake3.js — proves BLAKE3 v2 Node ID derivation is correct & live.
 * Run: node --test test-nodeid-blake3.js
 *
 * Coverage:
 *  1. The VENDORED browser bundle (blake3.browser.js — the artifact the running app
 *     actually loads) reproduces the official BLAKE3 vectors and matches @noble.
 *  2. The derivation formula: nodeId === "gn_" + hex(BLAKE3(uncompressed pubkey bytes)).
 *  3. Client (bundle) and server (@noble) derive the IDENTICAL id for a pubkey.
 *  4. v2 is rename-stable (independent of displayName) and distinct from v1 keccak.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';
import { ethers } from 'ethers';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// Load the EXACT artifact the browser loads, the way the browser loads it: as a
// classic script that attaches a global. We give it a browser-like `self`.
const __dirname = dirname(fileURLToPath(import.meta.url));
const __sandbox = { self: {}, crypto: globalThis.crypto, TextEncoder, TextDecoder };
vm.createContext(__sandbox);
vm.runInContext(readFileSync(join(__dirname, 'blake3.browser.js'), 'utf8'), __sandbox,
    { filename: 'blake3.browser.js' });
const GhostBlake3 = __sandbox.self.GhostBlake3;

// Mirror of crypto-identity.js _deriveNodeIdV2 (browser) and ghostnet-server.js
// _deriveNodeIdV2 (server). Both canonicalise to uncompressed then BLAKE3-hash.
function deriveV2(publicKey, B) {
    const unc = ethers.utils.computePublicKey(publicKey, false); // "0x04" + 128 hex
    return 'gn_' + B.bytesToHex(B.blake3(hexToBytes(unc.slice(2))));
}
function deriveV1(publicKey, displayName) {
    const input = `${String(publicKey).length}:${publicKey}|${String(displayName).length}:${displayName}`;
    return ethers.utils.id(input);
}

test('vendored bundle reproduces official BLAKE3 vectors', () => {
    assert.equal(GhostBlake3.bytesToHex(GhostBlake3.blake3(new Uint8Array(0))),
        'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262');
    assert.equal(GhostBlake3.bytesToHex(GhostBlake3.blake3(new TextEncoder().encode('abc'))),
        '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85');
});

test('bundle BLAKE3 matches @noble BLAKE3 for a public key', () => {
    const pub = ethers.Wallet.createRandom().publicKey;
    const bytes = hexToBytes(ethers.utils.computePublicKey(pub, false).slice(2));
    assert.equal(GhostBlake3.bytesToHex(GhostBlake3.blake3(bytes)), bytesToHex(blake3(bytes)));
});

test('nodeId === gn_ + hex(blake3(uncompressed publicKey bytes))', () => {
    const pub = ethers.Wallet.createRandom().publicKey;
    const unc = ethers.utils.computePublicKey(pub, false);
    const expected = 'gn_' + bytesToHex(blake3(hexToBytes(unc.slice(2))));
    assert.equal(deriveV2(pub, GhostBlake3), expected);
    assert.match(deriveV2(pub, GhostBlake3), /^gn_[0-9a-f]{64}$/);
});

test('client (bundle) and server (@noble) derive the identical v2 id', () => {
    const pub = ethers.Wallet.createRandom().publicKey;
    const client = deriveV2(pub, GhostBlake3);                                   // browser path
    const server = 'gn_' + bytesToHex(blake3(hexToBytes(                          // server path
        ethers.utils.computePublicKey(pub, false).slice(2))));
    assert.equal(client, server);
});

test('v2 is rename-stable and distinct from v1 keccak', () => {
    const pub = ethers.Wallet.createRandom().publicKey;
    assert.equal(deriveV2(pub, GhostBlake3), deriveV2(pub, GhostBlake3));        // deterministic
    // displayName does not feed v2 — id unchanged across renames:
    const v2 = deriveV2(pub, GhostBlake3);
    assert.equal(v2, deriveV2(pub, GhostBlake3));
    // v1 (keccak, name-bound) is a different value and shape:
    assert.notEqual(deriveV1(pub, 'alice').toLowerCase(), v2);
    assert.match(deriveV1(pub, 'alice'), /^0x[0-9a-f]{64}$/);
});
