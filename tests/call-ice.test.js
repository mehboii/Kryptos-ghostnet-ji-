/**
 * Unit tests — GhostNet call ICE/TURN provider.
 *
 * Run: node --test tests/call-ice.test.js
 *
 * Locks in two properties:
 *   1. STUN/hole-punching is always kept; TURN is appended (relay fallback).
 *   2. The provider FAILS CLOSED — any credential-fetch failure rejects, so the
 *      call never proceeds with no relay.
 *
 * `fetch` and the auth helpers are injected, so this is pure (no network, no DOM).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import '../ghostnet-call-ice.js';

const ICE = globalThis.GhostCallIce;

const STUN = [{ urls: 'stun:stun.example:3478' }];
const CF_OBJECT = {
    urls: [
        'stun:stun.cloudflare.com:3478',
        'turn:turn.cloudflare.com:3478?transport=udp',
        'turn:turn.cloudflare.com:3478?transport=tcp',
        'turns:turn.cloudflare.com:5349?transport=tcp',
    ],
    username: 'temp-user',
    credential: 'temp-cred',
};

function jsonResponse(body, status = 200) {
    return Promise.resolve({ ok: status >= 200 && status < 300, status, json: async () => body });
}

const authHeaders = () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test' });
const noAuth = () => ({ 'Content-Type': 'application/json' });

describe('mergeIceServers', () => {
    it('keeps STUN first and appends a single TURN object', () => {
        const merged = ICE.mergeIceServers(STUN, { iceServers: CF_OBJECT });
        assert.equal(merged[0].urls, 'stun:stun.example:3478');
        assert.deepEqual(merged[merged.length - 1], CF_OBJECT);
        assert.equal(merged.length, 2);
    });
    it('accepts an array form too', () => {
        const merged = ICE.mergeIceServers(STUN, { iceServers: [CF_OBJECT] });
        assert.equal(merged.length, 2);
    });
    it('throws when nothing is available', () => {
        assert.throws(() => ICE.mergeIceServers([], { iceServers: null }));
    });
});

describe('provider — success', () => {
    it('returns STUN + fetched TURN credentials', async () => {
        const getIceServers = ICE.createCloudflareIceProvider({
            endpoint: 'https://x/turn/credentials',
            stunServers: STUN,
            getAuthHeaders: authHeaders,
            ensureAuth: async () => 'tok',
            fetchImpl: async () => jsonResponse({ iceServers: [CF_OBJECT], ttl: 3600 }),
        });
        const servers = await getIceServers();
        assert.equal(servers[0].urls, 'stun:stun.example:3478');
        assert.equal(servers[1].username, 'temp-user');
        assert.equal(servers[1].credential, 'temp-cred');
    });

    it('calls ensureAuth when no token is present, then succeeds', async () => {
        let ensured = 0;
        const getIceServers = ICE.createCloudflareIceProvider({
            endpoint: 'https://x/turn/credentials', stunServers: STUN,
            getAuthHeaders: noAuth,
            ensureAuth: async () => { ensured++; return 'tok'; },
            fetchImpl: async () => jsonResponse({ iceServers: [CF_OBJECT] }),
        });
        const servers = await getIceServers();
        assert.equal(ensured >= 1, true);
        assert.equal(servers.length, 2);
    });

    it('re-auths once on 401 then retries', async () => {
        let calls = 0;
        const getIceServers = ICE.createCloudflareIceProvider({
            endpoint: 'https://x/turn/credentials', stunServers: STUN,
            getAuthHeaders: authHeaders,
            ensureAuth: async () => 'tok',
            fetchImpl: async () => {
                calls++;
                return calls === 1 ? jsonResponse({}, 401) : jsonResponse({ iceServers: [CF_OBJECT] });
            },
        });
        const servers = await getIceServers();
        assert.equal(calls, 2);
        assert.equal(servers.length, 2);
    });
});

describe('provider — fails closed', () => {
    const base = (over) => ICE.createCloudflareIceProvider(Object.assign({
        endpoint: 'https://x/turn/credentials', stunServers: STUN,
        getAuthHeaders: authHeaders, ensureAuth: async () => 'tok',
    }, over));

    it('rejects on non-OK HTTP status', async () => {
        const getIceServers = base({ fetchImpl: async () => jsonResponse({ error: 'nope' }, 500) });
        await assert.rejects(getIceServers(), /HTTP 500/);
    });

    it('rejects when fetch throws (network error)', async () => {
        const getIceServers = base({ fetchImpl: async () => { throw new Error('ECONNREFUSED'); } });
        await assert.rejects(getIceServers(), /failed/);
    });

    it('rejects when the body has no iceServers', async () => {
        const getIceServers = base({ fetchImpl: async () => jsonResponse({ ttl: 3600 }) });
        await assert.rejects(getIceServers(), /missing iceServers/);
    });

    it('rejects when the body is not JSON', async () => {
        const getIceServers = base({
            fetchImpl: async () => ({ ok: true, status: 200, json: async () => { throw new Error('bad json'); } }),
        });
        await assert.rejects(getIceServers(), /not valid JSON/);
    });

    it('never returns a STUN-only list on failure', async () => {
        const getIceServers = base({ fetchImpl: async () => jsonResponse({ error: 'x' }, 502) });
        await assert.rejects(getIceServers()); // must throw, NOT resolve to [STUN]
    });
});
