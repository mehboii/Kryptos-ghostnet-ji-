/**
 * GhostNet Call — ICE / TURN credential provider
 * ==============================================
 *
 * Supplies the `iceServers` array for a voice call's RTCPeerConnection. It does
 * NOT touch call signaling, the state machine, or the DTLS-fingerprint flow — it
 * only assembles ICE configuration:
 *
 *   • Keeps the existing STUN / hole-punching servers (primary, direct P2P).
 *   • Appends SHORT-LIVED Cloudflare Realtime TURN credentials (relay fallback),
 *     minted server-side at `${BACKEND}/turn/credentials`. The Cloudflare API
 *     token / key ID NEVER reach the client — only the ephemeral username +
 *     credential do.
 *
 * Wire it into GhostCall via the `getIceServers` hook:
 *
 *     const provider = GhostCallIce.createCloudflareIceProvider({ stunServers });
 *     const call = new GhostCall({ ..., getIceServers: provider });
 *
 * GhostCall calls `getIceServers()` at peer-connection creation — i.e. fresh per
 * call, on BOTH startCall and acceptCall. FAIL CLOSED: if the fetch fails this
 * REJECTS, and GhostCall aborts the call rather than proceeding with no relay.
 *
 * @module ghostnet-call-ice
 */

(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.GhostCallIce = factory();
    }
}(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this), function () {
    'use strict';

    const DEFAULT_BACKEND = 'https://ghostnet-ji-production.up.railway.app';
    const DEFAULT_PATH = '/turn/credentials';
    /** STUN kept in the list so direct P2P is tried before relay. */
    const DEFAULT_STUN_SERVERS = [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' },
    ];

    // ─── helpers ────────────────────────────────────────

    function _defaultBackend() {
        if (typeof window !== 'undefined' && window.BACKEND && window.BACKEND.http) return window.BACKEND.http;
        return DEFAULT_BACKEND;
    }

    /** Read the app's JWT (unwraps the {token,expiresAt} envelope) — no external deps. */
    function _defaultReadToken() {
        if (typeof sessionStorage === 'undefined' && typeof localStorage === 'undefined') return '';
        const sources = [];
        try { sources.push(sessionStorage.getItem('ghostnet_token')); } catch (_) { /* */ }
        try { sources.push(localStorage.getItem('ghostnet_token')); } catch (_) { /* */ }
        for (const raw of sources) {
            if (!raw) continue;
            try {
                const p = JSON.parse(raw);
                if (p && typeof p.token === 'string') {
                    if (p.expiresAt && Date.now() > p.expiresAt) continue;
                    return p.token;
                }
            } catch (_) { /* not JSON */ }
            if (typeof raw === 'string' && raw.length > 10) return raw;
        }
        return '';
    }

    function _defaultAuthHeaders() {
        const token = _defaultReadToken();
        const h = { 'Content-Type': 'application/json' };
        if (token) h.Authorization = `Bearer ${token}`;
        return h;
    }

    function _defaultEnsureAuth() {
        if (typeof window !== 'undefined' && typeof window.ghostnetEnsureAuth === 'function') {
            return window.ghostnetEnsureAuth();
        }
        return Promise.resolve(null);
    }

    function _hasAuth(headers) {
        return !!(headers && (headers.Authorization || headers.authorization));
    }

    /**
     * Merge the local STUN/hole-punch servers with the fetched TURN credentials.
     * STUN first (direct P2P preferred), TURN appended as fallback. Accepts the
     * server response in either `{ iceServers: [...] }` (array) or
     * `{ iceServers: { urls, username, credential } }` (single object) form.
     *
     * @param {Array} stunServers
     * @param {Object} fetched  Parsed server response.
     * @returns {Array<RTCIceServer>}
     */
    function mergeIceServers(stunServers, fetched) {
        const stun = Array.isArray(stunServers) ? stunServers.slice() : [];
        let turn = [];
        const ice = fetched && fetched.iceServers;
        if (Array.isArray(ice)) {
            turn = ice;
        } else if (ice && (ice.urls || ice.url)) {
            turn = [ice];
        }
        const merged = stun.concat(turn);
        if (!merged.length) throw new Error('no ICE servers available after merge');
        return merged;
    }

    // ─── provider ───────────────────────────────────────

    /**
     * Build a `getIceServers()` function that fetches fresh Cloudflare TURN
     * credentials and merges them with STUN. Throws (fail closed) on any failure.
     *
     * @param {Object} [opts]
     * @param {string}   [opts.endpoint]      Full URL to the credential endpoint.
     * @param {Array}    [opts.stunServers]   STUN/hole-punch servers to keep (primary).
     * @param {Function} [opts.getAuthHeaders] () => headers object (default reads JWT).
     * @param {Function} [opts.ensureAuth]    async () => token|null (default window.ghostnetEnsureAuth).
     * @param {Function} [opts.fetchImpl]     fetch implementation (default global fetch; injectable for tests).
     * @returns {() => Promise<Array<RTCIceServer>>}
     */
    function createCloudflareIceProvider(opts) {
        opts = opts || {};
        const endpoint = opts.endpoint || (_defaultBackend() + DEFAULT_PATH);
        const stunServers = opts.stunServers || DEFAULT_STUN_SERVERS;
        const getAuthHeaders = opts.getAuthHeaders || _defaultAuthHeaders;
        const ensureAuth = opts.ensureAuth || _defaultEnsureAuth;
        const fetchImpl = opts.fetchImpl
            || (typeof fetch === 'function' ? fetch.bind(typeof globalThis !== 'undefined' ? globalThis : null) : null);

        if (!fetchImpl) {
            return async function getIceServers() {
                throw new Error('[GhostCallIce] no fetch implementation available');
            };
        }

        async function _doFetch(headers) {
            return fetchImpl(endpoint, { method: 'POST', headers, body: JSON.stringify({}) });
        }

        return async function getIceServers() {
            let headers = getAuthHeaders();
            // Ensure we have a token before the first attempt (mirrors the app pattern).
            if (!_hasAuth(headers) && ensureAuth) {
                try { await ensureAuth(); } catch (_) { /* surfaced below if still 401 */ }
                headers = getAuthHeaders();
            }

            let res;
            try {
                res = await _doFetch(headers);
            } catch (e) {
                throw new Error(`TURN credential request failed: ${e && e.message ? e.message : 'network error'}`);
            }

            // Token expired/invalid → re-auth once and retry (no relay if it still fails).
            if (res && res.status === 401 && ensureAuth) {
                try { await ensureAuth(); } catch (_) { /* */ }
                try { res = await _doFetch(getAuthHeaders()); } catch (e) {
                    throw new Error(`TURN credential retry failed: ${e && e.message ? e.message : 'network error'}`);
                }
            }

            if (!res || !res.ok) {
                throw new Error(`TURN credential fetch failed: HTTP ${res ? res.status : 'no response'}`);
            }

            let body;
            try {
                body = await res.json();
            } catch (e) {
                throw new Error('TURN credential response was not valid JSON');
            }
            if (!body || !body.iceServers) {
                throw new Error('TURN credential response missing iceServers');
            }
            return mergeIceServers(stunServers, body);
        };
    }

    // ─── EXPORTS ────────────────────────────────────────

    return {
        DEFAULT_STUN_SERVERS,
        DEFAULT_PATH,
        mergeIceServers,
        createCloudflareIceProvider,
    };
}));
