/**
 * Integration smoke tests — GhostCall mesh wiring.
 *
 * Run: node --test tests/call-integration.test.js
 *
 * Verifies the two fixes that make incoming calls work:
 *   1. GhostCall constructs WITHOUT a signing key (lazy signer) so it can wire the
 *      mesh and ring before the identity is unlocked.
 *   2. call.* messages are intercepted and NOT forwarded to the app's chat handler
 *      (otherwise they render as raw JSON in the chat).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import ethers from 'ethers';

globalThis.ethers = ethers;
await import('../ghostnet-call-signaling.js');
await import('../ghostnet-call-fingerprint.js');
await import('../ghostnet-call.js');
const GhostCall = globalThis.GhostCall;

const CALL_ID = '11111111-2222-4333-8444-555566667777';

function makeCall(meshOnMessage) {
    const mesh = { sent: [], onMessage: meshOnMessage || function () {}, sendToPeer(id, msg) { this.sent.push({ id, msg }); } };
    const call = new GhostCall({
        mesh,
        identity: { id: 'gn_me', publicKey: '0x04abcd', getPrivateKey: async () => null },
        getIceServers: async () => [],
    });
    return { mesh, call };
}

describe('GhostCall mesh wiring', () => {
    it('constructs without a private key and wraps mesh.onMessage', () => {
        const prev = function () {};
        const { mesh, call } = makeCall(prev);
        assert.notEqual(mesh.onMessage, prev, 'onMessage should be wrapped');
        assert.equal(call.state, 'idle');
    });

    it('forwards normal chat messages to the app handler', () => {
        let appGot = null;
        const { mesh } = makeCall(function (data) { appGot = data; });
        mesh.onMessage({ t: 'MESH_DIRECT', data: 'hi' }, 'peer', 'ws');
        assert.equal(appGot && appGot.t, 'MESH_DIRECT');
    });

    it('intercepts call.* messages and does NOT forward them to chat', () => {
        let appGot = null;
        const { mesh } = makeCall(function (data) { appGot = data; });
        mesh.onMessage({
            v: 1, t: 'call.hangup', callId: CALL_ID, from: 'peer', to: 'gn_me', ts: Date.now(), reason: 'normal',
        }, 'peer', 'ws');
        assert.equal(appGot, null, 'call.* must not reach the chat handler');
    });
});
