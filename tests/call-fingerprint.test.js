/**
 * Unit tests — GhostNet call fingerprint sign/verify (secp256k1).
 *
 * Run: node --test tests/call-fingerprint.test.js
 *
 * The security property under test: a remote DTLS fingerprint is accepted ONLY
 * when its proof signature verifies against the GhostTag-resolved identity key
 * AND describes the exact fingerprint carried by the SDP. Every tamper case must
 * FAIL CLOSED (verifyProof().ok === false).
 *
 * Uses the real `ethers` dependency for genuine secp256k1 personal-sign +
 * address recovery. The fingerprint module is a classic UMD script; under Node's
 * ESM loader it reads `globalThis.ethers`, which we set from the import below.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import ethers from 'ethers';

// Make ethers visible to the UMD module's resolver before any test runs, then
// load the module for its side effect (assigns globalThis.GhostCallFingerprint).
globalThis.ethers = ethers;
await import('../ghostnet-call-fingerprint.js');
const FP = globalThis.GhostCallFingerprint;

// ethers v5 (utils.*) and v6 (top-level) both supported.
const E = ethers.utils ? ethers.utils : ethers;

const CALL_ID = '11111111-2222-4333-8444-555566667777';
const FROM = 'gn_caller';
const TO = 'gn_callee';

function sdpWithFingerprint(fpHex) {
    return [
        'v=0',
        'o=- 0 0 IN IP4 127.0.0.1',
        's=-',
        't=0 0',
        'm=audio 9 UDP/TLS/RTP/SAVPF 111',
        'a=rtpmap:111 opus/48000/2',
        `a=fingerprint:sha-256 ${fpHex}`,
        'a=setup:actpass',
        '',
    ].join('\r\n');
}

const FP_A = 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89';
const FP_B = '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF';

function newIdentity() {
    const w = ethers.Wallet.createRandom();
    const publicKey = w.signingKey ? w.signingKey.publicKey : w._signingKey().publicKey;
    return { privateKey: w.privateKey, publicKey };
}

async function makeOfferProof(identity, sdp) {
    const signer = FP.createSecp256k1Signer({ privateKey: identity.privateKey, publicKey: identity.publicKey });
    return FP.buildProof({ kind: 'offer', callId: CALL_ID, from: FROM, to: TO, sdp }, signer);
}

describe('extractFingerprint', () => {
    it('parses the a=fingerprint line', () => {
        const fp = FP.extractFingerprint(sdpWithFingerprint(FP_A));
        assert.equal(fp.algorithm, 'sha-256');
        assert.equal(fp.value, FP_A);
        assert.equal(fp.canonical, `sha-256 ${FP_A}`);
    });
    it('throws when no fingerprint is present', () => {
        assert.throws(() => FP.extractFingerprint('v=0\r\nm=audio 9 RTP/AVP 0\r\n'));
    });
});

describe('verifyProof — happy path', () => {
    it('accepts a valid proof against the correct identity', async () => {
        const id = newIdentity();
        const sdp = sdpWithFingerprint(FP_A);
        const proof = await makeOfferProof(id, sdp);
        const r = FP.verifyProof(proof, { kind: 'offer', callId: CALL_ID, from: FROM, to: TO, sdp }, id.publicKey);
        assert.equal(r.ok, true);
    });
});

describe('verifyProof — fails closed', () => {
    it('rejects a tampered fingerprint (SDP swapped after signing)', async () => {
        const id = newIdentity();
        const proof = await makeOfferProof(id, sdpWithFingerprint(FP_A));
        const swappedSdp = sdpWithFingerprint(FP_B); // relay ships a different SDP/fingerprint
        const r = FP.verifyProof(proof, { kind: 'offer', callId: CALL_ID, from: FROM, to: TO, sdp: swappedSdp }, id.publicKey);
        assert.equal(r.ok, false);
        assert.match(r.error, /fingerprint/);
    });

    it('rejects verification against the WRONG identity key', async () => {
        const id = newIdentity();
        const attacker = newIdentity();
        const sdp = sdpWithFingerprint(FP_A);
        const proof = await makeOfferProof(id, sdp);
        const r = FP.verifyProof(proof, { kind: 'offer', callId: CALL_ID, from: FROM, to: TO, sdp }, attacker.publicKey);
        assert.equal(r.ok, false);
        assert.match(r.error, /signature/);
    });

    it('rejects a malformed signature', async () => {
        const id = newIdentity();
        const sdp = sdpWithFingerprint(FP_A);
        const proof = await makeOfferProof(id, sdp);
        proof.sig = '0xnotasignature';
        const r = FP.verifyProof(proof, { kind: 'offer', callId: CALL_ID, from: FROM, to: TO, sdp }, id.publicKey);
        assert.equal(r.ok, false);
    });

    it('rejects a kind mismatch (offer proof used as answer)', async () => {
        const id = newIdentity();
        const sdp = sdpWithFingerprint(FP_A);
        const proof = await makeOfferProof(id, sdp);
        const r = FP.verifyProof(proof, { kind: 'answer', callId: CALL_ID, from: FROM, to: TO, sdp }, id.publicKey);
        assert.equal(r.ok, false);
    });

    it('rejects when the canonical context is altered (callId replay)', async () => {
        const id = newIdentity();
        const sdp = sdpWithFingerprint(FP_A);
        const proof = await makeOfferProof(id, sdp);
        const r = FP.verifyProof(proof, { kind: 'offer', callId: 'ffffffff-2222-4333-8444-555566667777', from: FROM, to: TO, sdp }, id.publicKey);
        assert.equal(r.ok, false);
    });

    it('rejects a missing expected key', async () => {
        const id = newIdentity();
        const sdp = sdpWithFingerprint(FP_A);
        const proof = await makeOfferProof(id, sdp);
        assert.equal(FP.verifyProof(proof, { kind: 'offer', callId: CALL_ID, from: FROM, to: TO, sdp }, '').ok, false);
    });
});

describe('verifyProof — accepts an address as the expected identity', () => {
    it('verifies when the peer is identified by address (not full pubkey)', async () => {
        const id = newIdentity();
        const address = E.computeAddress(id.publicKey); // how contacts are often stored
        const sdp = sdpWithFingerprint(FP_A);
        const proof = await makeOfferProof(id, sdp);
        const ok = FP.verifyProof(proof, { kind: 'offer', callId: CALL_ID, from: FROM, to: TO, sdp }, address);
        assert.equal(ok.ok, true);
        // wrong address still fails closed
        const other = E.computeAddress(newIdentity().publicKey);
        assert.equal(FP.verifyProof(proof, { kind: 'offer', callId: CALL_ID, from: FROM, to: TO, sdp }, other).ok, false);
    });
});

describe('secp256k1Verify round-trip', () => {
    it('verifies a hand-built canonical message and rejects a wrong key', async () => {
        const id = newIdentity();
        const signer = FP.createSecp256k1Signer({ privateKey: id.privateKey, publicKey: id.publicKey });
        const msg = FP.canonicalMessage({ kind: 'offer', callId: CALL_ID, from: FROM, to: TO, fingerprint: `sha-256 ${FP_A}` });
        const sig = await signer.sign(msg);
        assert.equal(FP.secp256k1Verify(msg, sig, id.publicKey), true);
        assert.equal(FP.secp256k1Verify(msg, sig, newIdentity().publicKey), false);
    });
});
