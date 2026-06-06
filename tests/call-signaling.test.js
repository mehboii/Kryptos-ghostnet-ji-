/**
 * Unit tests — GhostNet call signaling schema & validators.
 *
 * Run: node --test tests/call-signaling.test.js
 *
 * Pure schema tests: no network, no crypto, no DOM. The module is a classic
 * UMD script (browser <script> compatible); under Node's ESM loader it assigns
 * itself to globalThis, so we import it for its side effect and read it back.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import '../ghostnet-call-signaling.js';

const Signaling = globalThis.GhostCallSignaling;

const CALL_ID = '11111111-2222-4333-8444-555566667777';
const FROM = 'gn_caller';
const TO = 'gn_callee';

const VALID_SDP_OFFER = { type: 'offer', sdp: 'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' };
const VALID_SDP_ANSWER = { type: 'answer', sdp: 'v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n' };
const VALID_FP_OFFER = {
    v: 1, kind: 'offer', alg: 'secp256k1',
    fingerprint: 'sha-256 AB:CD', sig: '0xdeadbeef', pub: '0x04abcd',
};
const VALID_FP_ANSWER = { ...VALID_FP_OFFER, kind: 'answer' };
const VALID_CANDIDATE = { candidate: 'candidate:1 1 udp 2 1.2.3.4 5 typ host', sdpMid: '0', sdpMLineIndex: 0 };

describe('builders produce valid messages', () => {
    it('buildOffer', () => {
        const m = Signaling.buildOffer({ callId: CALL_ID, from: FROM, to: TO, sdp: VALID_SDP_OFFER, fp: VALID_FP_OFFER });
        assert.equal(m.t, Signaling.TYPES.OFFER);
        assert.equal(m.v, Signaling.PROTOCOL_VERSION);
        assert.ok(Signaling.validateMessage(m).ok);
    });
    it('buildAnswer', () => {
        const m = Signaling.buildAnswer({ callId: CALL_ID, from: FROM, to: TO, sdp: VALID_SDP_ANSWER, fp: VALID_FP_ANSWER });
        assert.ok(Signaling.validateMessage(m).ok);
    });
    it('buildIce', () => {
        const m = Signaling.buildIce({ callId: CALL_ID, from: FROM, to: TO, candidate: VALID_CANDIDATE });
        assert.ok(Signaling.validateMessage(m).ok);
    });
    it('buildHangup defaults unknown reason to normal', () => {
        const m = Signaling.buildHangup({ callId: CALL_ID, from: FROM, to: TO, reason: 'not-a-reason' });
        assert.equal(m.reason, 'normal');
        assert.ok(Signaling.validateMessage(m).ok);
    });
});

describe('validateMessage rejects malformed input (fail closed)', () => {
    const base = () => Signaling.buildOffer({ callId: CALL_ID, from: FROM, to: TO, sdp: VALID_SDP_OFFER, fp: VALID_FP_OFFER });

    it('rejects non-objects', () => {
        for (const bad of [null, undefined, 'x', 42, []]) {
            assert.equal(Signaling.validateMessage(bad).ok, false);
        }
    });
    it('rejects wrong protocol version', () => {
        assert.equal(Signaling.validateMessage({ ...base(), v: 999 }).ok, false);
    });
    it('rejects unknown type', () => {
        assert.equal(Signaling.validateMessage({ ...base(), t: 'call.evil' }).ok, false);
    });
    it('rejects malformed callId', () => {
        assert.equal(Signaling.validateMessage({ ...base(), callId: 'nope' }).ok, false);
    });
    it('rejects missing from/to', () => {
        assert.equal(Signaling.validateMessage({ ...base(), from: '' }).ok, false);
        assert.equal(Signaling.validateMessage({ ...base(), to: undefined }).ok, false);
    });
    it('rejects offer without fingerprint proof', () => {
        const m = base(); delete m.fp;
        assert.equal(Signaling.validateMessage(m).ok, false);
    });
    it('rejects offer with answer-kind proof', () => {
        assert.equal(Signaling.validateMessage({ ...base(), fp: VALID_FP_ANSWER }).ok, false);
    });
    it('rejects offer without sdp', () => {
        const m = base(); delete m.sdp;
        assert.equal(Signaling.validateMessage(m).ok, false);
    });
    it('rejects sdp that does not start with v=', () => {
        assert.equal(Signaling.validateMessage({ ...base(), sdp: { type: 'offer', sdp: 'garbage' } }).ok, false);
    });
    it('rejects oversized sdp', () => {
        const huge = 'v=0\r\n' + 'a'.repeat(Signaling.MAX_SDP_LENGTH + 1);
        assert.equal(Signaling.validateMessage({ ...base(), sdp: { type: 'offer', sdp: huge } }).ok, false);
    });
    it('rejects ice without a usable candidate', () => {
        const m = Signaling.buildIce({ callId: CALL_ID, from: FROM, to: TO, candidate: VALID_CANDIDATE });
        assert.equal(Signaling.validateMessage({ ...m, candidate: { candidate: 'x' } }).ok, false); // no mid/index
    });
    it('rejects hangup with an invalid reason', () => {
        const m = Signaling.buildHangup({ callId: CALL_ID, from: FROM, to: TO, reason: 'normal' });
        assert.equal(Signaling.validateMessage({ ...m, reason: 'whatever' }).ok, false);
    });
});
