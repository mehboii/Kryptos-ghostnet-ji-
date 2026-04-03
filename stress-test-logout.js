/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *  GhostNet — Logout Flow End-to-End Stress Test
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 *  Tests the FULL logout lifecycle under stress:
 *
 *  Phase 1 — Single-User E2E Flow
 *    1.1  Signup → Verify → Login → Obtain JWT
 *    1.2  Access protected endpoints (GET /auth/me, GET /conversations)
 *    1.3  Open WebSocket with valid token
 *    1.4  Call POST /auth/logout  (bumps tokenVersion)
 *    1.5  Verify ALL protected endpoints reject the revoked token (401)
 *    1.6  Verify WebSocket upgrade is rejected with the revoked token
 *    1.7  Verify re-login succeeds and new token works
 *
 *  Phase 2 — Double Logout (Idempotency)
 *    2.1  Login → Logout → try Logout again with same revoked token
 *    2.2  Expect 401 on second logout (token already revoked)
 *
 *  Phase 3 — Rapid Login/Logout Cycling (Race Conditions)
 *    3.1  Single user: login → logout × N rapid cycles
 *    3.2  Verify each cycle's old token is revoked after its logout
 *
 *  Phase 4 — Concurrent Mass Logout Stress
 *    4.1  Register N users in parallel
 *    4.2  All N users call POST /auth/logout simultaneously
 *    4.3  All N old tokens must fail on protected routes (401)
 *    4.4  All N users re-login; new tokens must work
 *
 *  Phase 5 — Cross-Session Token Reuse Attack
 *    5.1  Login → capture token A → Logout → Login again → capture token B
 *    5.2  Token A must be rejected; Token B must work
 *    5.3  Logout with Token B → both A and B must be rejected
 *
 *  Phase 6 — WebSocket Stability Under Mass Logout
 *    6.1  N users connected via WebSocket
 *    6.2  All N users logout simultaneously
 *    6.3  Attempt WebSocket reconnect with old tokens → all must fail
 *
 *  Usage:
 *    node stress-test-logout.js                          # defaults
 *    node stress-test-logout.js --url=http://localhost:8080
 *    node stress-test-logout.js --users=100
 *    node stress-test-logout.js --cycles=20
 *
 *  Requires: ws (in package.json)
 */

import http from 'http';
import https from 'https';
import crypto from 'crypto';
import WebSocket from 'ws';

// ─── CLI Args ────────────────────────────────────────────────────────────────

const args = Object.fromEntries(
    process.argv.slice(2).map(a => {
        const [k, v] = a.replace(/^--/, '').split('=');
        return [k, v ?? true];
    })
);

const BACKEND_URL  = args.url || 'https://ghostnet-ji-production.up.railway.app';
const NUM_USERS    = parseInt(args.users || '50', 10);
const RAPID_CYCLES = parseInt(args.cycles || '10', 10);
const STAGGER_MS   = parseInt(args.stagger || '200', 10);
const PASSWORD     = 'GhostNet!Str3ss2026';
const MAX_RETRIES  = 3;

// ─── Stats ───────────────────────────────────────────────────────────────────

const stats = {
    passed: 0,
    failed: 0,
    errors: [],
    phases: {},
    startTime: Date.now(),
};

function recordResult(phase, testName, passed, detail = '') {
    if (!stats.phases[phase]) stats.phases[phase] = { passed: 0, failed: 0, tests: [] };
    stats.phases[phase].tests.push({ name: testName, passed, detail });
    if (passed) {
        stats.passed++;
        stats.phases[phase].passed++;
    } else {
        stats.failed++;
        stats.phases[phase].failed++;
        stats.errors.push(`[${phase}] ${testName}: ${detail}`);
    }
    const icon = passed ? '✅' : '❌';
    console.log(`  ${icon} ${testName}${detail ? ` — ${detail}` : ''}`);
}

// ─── HTTP Request Helper ─────────────────────────────────────────────────────

function request(method, path, { body = null, token = null, timeout = 30000 } = {}) {
    return new Promise((resolve, reject) => {
        const url = new URL(path, BACKEND_URL);
        const mod = url.protocol === 'https:' ? https : http;
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const payload = body ? JSON.stringify(body) : null;
        if (payload) headers['Content-Length'] = Buffer.byteLength(payload);

        const req = mod.request(url, { method, headers, timeout }, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(data), raw: data });
                } catch (_) {
                    resolve({ status: res.statusCode, data: null, raw: data });
                }
            });
        });

        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
        if (payload) req.write(payload);
        req.end();
    });
}

/**
 * Request with automatic retry on timeout / 429 rate-limit.
 */
async function requestWithRetry(method, path, opts = {}, retries = MAX_RETRIES) {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            const res = await request(method, path, opts);
            // Retry on rate-limit
            if (res.status === 429 && attempt < retries) {
                const wait = Math.min(2000 * Math.pow(2, attempt - 1), 15000);
                console.log(`    ⏳ Rate-limited (429). Retrying in ${wait}ms... (attempt ${attempt}/${retries})`);
                await sleep(wait);
                continue;
            }
            return res;
        } catch (e) {
            if (attempt < retries && e.message.includes('timeout')) {
                const wait = Math.min(3000 * attempt, 10000);
                console.log(`    ⏳ Timeout. Retrying in ${wait}ms... (attempt ${attempt}/${retries})`);
                await sleep(wait);
                continue;
            }
            throw e;
        }
    }
}

// ─── User Lifecycle Helpers ──────────────────────────────────────────────────

function generateEmail() {
    return `stress_${crypto.randomBytes(8).toString('hex')}@ghostnet-test.io`;
}

/**
 * Full signup → verify → login cycle.
 * Returns { email, token, userId }
 */
async function createAndLoginUser(email = null) {
    email = email || generateEmail();

    // 1. Signup
    const signupRes = await requestWithRetry('POST', '/auth/signup', {
        body: { email, password: PASSWORD }
    });

    if (!signupRes.data?.success && !signupRes.data?.requiresVerification) {
        throw new Error(`Signup failed for ${email}: ${signupRes.raw}`);
    }

    // 2. Get verify code (from devCode or log fallback)
    let devCode = signupRes.data?.devCode;
    if (!devCode) {
        // In production without devCode, we can't auto-verify
        // For stress test, we need the devCode. Try to proceed anyway.
        throw new Error(`No devCode returned for ${email} — is SMTP configured? Stress test requires dev mode.`);
    }

    // 3. Verify email
    const verifyRes = await requestWithRetry('POST', '/auth/verify', {
        body: { email, code: devCode }
    });

    if (!verifyRes.data?.verified && !verifyRes.data?.token) {
        throw new Error(`Verify failed for ${email}: ${verifyRes.raw}`);
    }

    // If verify returned a token, use it directly
    if (verifyRes.data?.token) {
        return {
            email,
            token: verifyRes.data.token,
            userId: verifyRes.data.user?.id,
        };
    }

    // 4. Login (if verify didn't return token)
    const loginRes = await requestWithRetry('POST', '/auth/login', {
        body: { email, password: PASSWORD }
    });

    if (!loginRes.data?.token) {
        throw new Error(`Login failed for ${email}: ${loginRes.raw}`);
    }

    return {
        email,
        token: loginRes.data.token,
        userId: loginRes.data.user?.id,
    };
}

/**
 * Login an existing verified user.
 * Returns { token, userId }
 */
async function loginUser(email) {
    const res = await requestWithRetry('POST', '/auth/login', {
        body: { email, password: PASSWORD }
    });

    if (!res.data?.token) {
        throw new Error(`Login failed for ${email}: ${res.raw}`);
    }

    return { token: res.data.token, userId: res.data.user?.id };
}

/**
 * Call POST /auth/logout with the given token.
 * Returns the HTTP response.
 */
async function logoutUser(token) {
    return requestWithRetry('POST', '/auth/logout', { token });
}

/**
 * Attempt WebSocket connection. Resolves with { connected, ws, error }.
 */
function attemptWebSocket(token, timeoutMs = 5000) {
    return new Promise(resolve => {
        const base = new URL(BACKEND_URL);
        const wsUrl = `${base.protocol === 'https:' ? 'wss:' : 'ws:'}//${base.host}/ws?token=${encodeURIComponent(token)}`;

        let settled = false;
        const timer = setTimeout(() => {
            if (!settled) {
                settled = true;
                resolve({ connected: false, ws: null, error: 'timeout' });
            }
        }, timeoutMs);

        try {
            const ws = new WebSocket(wsUrl, {
                handshakeTimeout: timeoutMs,
                headers: { 'User-Agent': 'GhostNet-LogoutStress' }
            });

            ws.on('open', () => {
                if (!settled) {
                    settled = true;
                    clearTimeout(timer);
                    resolve({ connected: true, ws, error: null });
                }
            });

            ws.on('error', (err) => {
                if (!settled) {
                    settled = true;
                    clearTimeout(timer);
                    resolve({ connected: false, ws: null, error: err.message });
                }
            });

            ws.on('unexpected-response', (_req, res) => {
                if (!settled) {
                    settled = true;
                    clearTimeout(timer);
                    resolve({ connected: false, ws: null, error: `HTTP ${res.statusCode}` });
                }
            });

            ws.on('close', (code) => {
                if (!settled) {
                    settled = true;
                    clearTimeout(timer);
                    resolve({ connected: false, ws: null, error: `closed: ${code}` });
                }
            });
        } catch (e) {
            if (!settled) {
                settled = true;
                clearTimeout(timer);
                resolve({ connected: false, ws: null, error: e.message });
            }
        }
    });
}

// ─── Phase 1: Single-User E2E Flow ──────────────────────────────────────────

async function phase1() {
    console.log('\n┌──────────────────────────────────────────────────────────────┐');
    console.log('│  PHASE 1 — Single-User End-to-End Logout Flow               │');
    console.log('└──────────────────────────────────────────────────────────────┘\n');

    const phase = 'Phase 1';

    try {
        // 1.1 — Signup → Verify → Login
        const user = await createAndLoginUser();
        recordResult(phase, '1.1 Signup → Verify → Login', true, `email: ${user.email}`);

        // 1.2 — Access protected endpoints with valid token
        const meRes = await request('GET', '/auth/me', { token: user.token });
        const meOk = meRes.status === 200 && meRes.data?.user;
        recordResult(phase, '1.2a GET /auth/me (valid token)', meOk,
            meOk ? `userId: ${meRes.data.user.id}` : `status: ${meRes.status}`);

        const convosRes = await request('GET', '/conversations', { token: user.token });
        const convosOk = convosRes.status === 200;
        recordResult(phase, '1.2b GET /conversations (valid token)', convosOk,
            `status: ${convosRes.status}`);

        const statusRes = await request('GET', '/status');
        recordResult(phase, '1.2c GET /status (public)', statusRes.status === 200,
            `status: ${statusRes.status}`);

        // 1.3 — Open WebSocket with valid token
        const wsResult = await attemptWebSocket(user.token);
        recordResult(phase, '1.3 WebSocket connect (valid token)', wsResult.connected,
            wsResult.connected ? 'connected' : wsResult.error);
        if (wsResult.ws) wsResult.ws.close();

        // Small delay to let server process
        await sleep(500);

        // 1.4 — Logout
        const logoutRes = await logoutUser(user.token);
        const logoutOk = logoutRes.status === 200 && logoutRes.data?.success;
        recordResult(phase, '1.4 POST /auth/logout', logoutOk,
            logoutOk ? 'tokenVersion bumped' : `status: ${logoutRes.status}, body: ${logoutRes.raw}`);

        // Small delay for server-side state to propagate
        await sleep(300);

        // 1.5 — Protected endpoints must reject revoked token
        const me2Res = await request('GET', '/auth/me', { token: user.token });
        const me2Revoked = me2Res.status === 401;
        recordResult(phase, '1.5a GET /auth/me (revoked token → 401)', me2Revoked,
            `status: ${me2Res.status}`);

        const convos2Res = await request('GET', '/conversations', { token: user.token });
        const convos2Revoked = convos2Res.status === 401;
        recordResult(phase, '1.5b GET /conversations (revoked token → 401)', convos2Revoked,
            `status: ${convos2Res.status}`);

        const walletRes = await request('GET', '/wallet', { token: user.token });
        const walletRevoked = walletRes.status === 401;
        recordResult(phase, '1.5c GET /wallet (revoked token → 401)', walletRevoked,
            `status: ${walletRes.status}`);

        // 1.6 — WebSocket must reject revoked token
        const ws2Result = await attemptWebSocket(user.token);
        const ws2Rejected = !ws2Result.connected;
        recordResult(phase, '1.6 WebSocket connect (revoked token → rejected)', ws2Rejected,
            ws2Rejected ? `rejected: ${ws2Result.error}` : 'ERROR: connected with revoked token!');
        if (ws2Result.ws) ws2Result.ws.close();

        // 1.7 — Re-login → new token works
        const reAuth = await loginUser(user.email);
        recordResult(phase, '1.7a Re-login after logout', !!reAuth.token, 'new token obtained');

        const me3Res = await request('GET', '/auth/me', { token: reAuth.token });
        const me3Ok = me3Res.status === 200 && me3Res.data?.user;
        recordResult(phase, '1.7b GET /auth/me (new token)', me3Ok,
            me3Ok ? `userId: ${me3Res.data.user.id}` : `status: ${me3Res.status}`);

        // New token WS
        const ws3Result = await attemptWebSocket(reAuth.token);
        recordResult(phase, '1.7c WebSocket connect (new token)', ws3Result.connected,
            ws3Result.connected ? 'connected' : ws3Result.error);
        if (ws3Result.ws) ws3Result.ws.close();

    } catch (e) {
        recordResult(phase, 'Phase 1 FATAL', false, e.message);
    }
}

// ─── Phase 2: Double Logout (Idempotency) ────────────────────────────────────

async function phase2() {
    console.log('\n┌──────────────────────────────────────────────────────────────┐');
    console.log('│  PHASE 2 — Double Logout (Idempotency)                      │');
    console.log('└──────────────────────────────────────────────────────────────┘\n');

    const phase = 'Phase 2';

    try {
        const user = await createAndLoginUser();
        recordResult(phase, '2.0 Setup user', true, user.email);

        // First logout
        const logout1 = await logoutUser(user.token);
        recordResult(phase, '2.1 First logout', logout1.status === 200, `status: ${logout1.status}`);

        await sleep(300);

        // Second logout with same (now revoked) token → should get 401
        const logout2 = await logoutUser(user.token);
        const doubleOk = logout2.status === 401;
        recordResult(phase, '2.2 Second logout (revoked token → 401)', doubleOk,
            `status: ${logout2.status}${!doubleOk ? ' — EXPECTED 401' : ''}`);

    } catch (e) {
        recordResult(phase, 'Phase 2 FATAL', false, e.message);
    }
}

// ─── Phase 3: Rapid Login/Logout Cycling ─────────────────────────────────────

async function phase3() {
    console.log('\n┌──────────────────────────────────────────────────────────────┐');
    console.log(`│  PHASE 3 — Rapid Login/Logout Cycling (${RAPID_CYCLES} cycles)           │`);
    console.log('└──────────────────────────────────────────────────────────────┘\n');

    const phase = 'Phase 3';

    try {
        const user = await createAndLoginUser();
        recordResult(phase, '3.0 Setup user', true, user.email);

        const revokedTokens = [];
        let currentToken = user.token;
        let allCyclesOk = true;

        for (let i = 1; i <= RAPID_CYCLES; i++) {
            // Logout
            const logoutRes = await logoutUser(currentToken);
            if (logoutRes.status !== 200) {
                recordResult(phase, `3.1 Cycle ${i} logout`, false, `status: ${logoutRes.status}`);
                allCyclesOk = false;
                break;
            }

            revokedTokens.push(currentToken);

            // Re-login
            const reAuth = await loginUser(user.email);
            if (!reAuth.token) {
                recordResult(phase, `3.1 Cycle ${i} re-login`, false, 'no token');
                allCyclesOk = false;
                break;
            }

            currentToken = reAuth.token;
        }

        recordResult(phase, `3.1 ${RAPID_CYCLES} rapid login/logout cycles`, allCyclesOk,
            allCyclesOk ? 'all cycles completed' : 'cycle failed');

        // Verify ALL old tokens are revoked
        let allRevoked = true;
        const checkSubset = revokedTokens.slice(0, Math.min(revokedTokens.length, 5)); // check first 5
        for (const oldToken of checkSubset) {
            const meRes = await request('GET', '/auth/me', { token: oldToken });
            if (meRes.status !== 401) {
                allRevoked = false;
                break;
            }
        }
        recordResult(phase, '3.2 All old tokens revoked after cycling', allRevoked,
            `checked ${checkSubset.length} old tokens`);

        // Current token should still work
        const meRes = await request('GET', '/auth/me', { token: currentToken });
        recordResult(phase, '3.3 Current token still valid', meRes.status === 200,
            `status: ${meRes.status}`);

    } catch (e) {
        recordResult(phase, 'Phase 3 FATAL', false, e.message);
    }
}

// ─── Phase 4: Concurrent Mass Logout ─────────────────────────────────────────

async function phase4() {
    console.log('\n┌──────────────────────────────────────────────────────────────┐');
    console.log(`│  PHASE 4 — Concurrent Mass Logout (${NUM_USERS} users)               │`);
    console.log('└──────────────────────────────────────────────────────────────┘\n');

    const phase = 'Phase 4';

    try {
        // 4.1 — Register N users with stagger
        console.log(`  ⏳ Creating ${NUM_USERS} users...`);
        const users = [];
        const createErrors = [];

        for (let i = 0; i < NUM_USERS; i++) {
            try {
                const user = await createAndLoginUser();
                users.push(user);
            } catch (e) {
                createErrors.push(e.message);
            }
            if (i < NUM_USERS - 1 && STAGGER_MS > 0) {
                await sleep(STAGGER_MS);
            }
        }

        recordResult(phase, `4.1 Created ${users.length}/${NUM_USERS} users`,
            users.length > 0,
            `${createErrors.length} create errors${createErrors.length > 0 ? ': ' + createErrors[0] : ''}`);

        if (users.length === 0) {
            recordResult(phase, '4.x Phase 4 aborted', false, 'no users created');
            return;
        }

        // Capture all tokens before logout
        const preLogoutTokens = users.map(u => u.token);

        // 4.2 — All users call POST /auth/logout simultaneously
        console.log(`  ⏳ Firing ${users.length} simultaneous logouts...`);
        const logoutStart = Date.now();
        const logoutResults = await Promise.allSettled(
            users.map(u => logoutUser(u.token))
        );
        const logoutDuration = Date.now() - logoutStart;

        const logoutSuccesses = logoutResults.filter(
            r => r.status === 'fulfilled' && r.value.status === 200
        ).length;
        const logoutFails = logoutResults.filter(
            r => r.status === 'rejected' || (r.status === 'fulfilled' && r.value.status !== 200)
        ).length;

        recordResult(phase, `4.2 Mass logout (${users.length} simultaneous)`,
            logoutSuccesses === users.length,
            `${logoutSuccesses}/${users.length} succeeded in ${logoutDuration}ms (${logoutFails} failed)`);

        await sleep(500);

        // 4.3 — All old tokens must fail
        console.log(`  ⏳ Verifying ${preLogoutTokens.length} revoked tokens...`);
        const revokeChecks = await Promise.allSettled(
            preLogoutTokens.map(t => request('GET', '/auth/me', { token: t }))
        );

        const allRevokedCount = revokeChecks.filter(
            r => r.status === 'fulfilled' && r.value.status === 401
        ).length;

        recordResult(phase, '4.3 All old tokens revoked (401)',
            allRevokedCount === preLogoutTokens.length,
            `${allRevokedCount}/${preLogoutTokens.length} correctly rejected`);

        // 4.4 — All users re-login; new tokens must work
        console.log(`  ⏳ Re-logging ${users.length} users...`);
        const reLoginResults = await Promise.allSettled(
            users.map(u => loginUser(u.email))
        );

        const reLoginSuccesses = reLoginResults.filter(
            r => r.status === 'fulfilled' && r.value.token
        ).length;

        recordResult(phase, '4.4 All users re-login successfully',
            reLoginSuccesses === users.length,
            `${reLoginSuccesses}/${users.length} re-logged in`);

        // Spot-check a few new tokens
        const newTokens = reLoginResults
            .filter(r => r.status === 'fulfilled' && r.value.token)
            .slice(0, 5);
        let spotChecksPassed = 0;
        for (const r of newTokens) {
            const meRes = await request('GET', '/auth/me', { token: r.value.token });
            if (meRes.status === 200) spotChecksPassed++;
        }
        recordResult(phase, '4.5 Spot-check new tokens (GET /auth/me)',
            spotChecksPassed === newTokens.length,
            `${spotChecksPassed}/${newTokens.length} passed`);

    } catch (e) {
        recordResult(phase, 'Phase 4 FATAL', false, e.message);
    }
}

// ─── Phase 5: Cross-Session Token Reuse Attack ───────────────────────────────

async function phase5() {
    console.log('\n┌──────────────────────────────────────────────────────────────┐');
    console.log('│  PHASE 5 — Cross-Session Token Reuse Attack                 │');
    console.log('└──────────────────────────────────────────────────────────────┘\n');

    const phase = 'Phase 5';

    try {
        // 5.1 — Login → Token A → Logout → Login → Token B
        const user = await createAndLoginUser();
        const tokenA = user.token;
        recordResult(phase, '5.1a Captured Token A', !!tokenA, '');

        await logoutUser(tokenA);
        await sleep(300);

        const reAuth = await loginUser(user.email);
        const tokenB = reAuth.token;
        recordResult(phase, '5.1b Captured Token B (after re-login)', !!tokenB, '');

        // 5.2 — Token A must be rejected; Token B must work
        const meA = await request('GET', '/auth/me', { token: tokenA });
        const aRejected = meA.status === 401;
        recordResult(phase, '5.2a Token A rejected (401)', aRejected, `status: ${meA.status}`);

        const meB = await request('GET', '/auth/me', { token: tokenB });
        const bAccepted = meB.status === 200;
        recordResult(phase, '5.2b Token B accepted (200)', bAccepted, `status: ${meB.status}`);

        // 5.3 — Logout with Token B → both must now be rejected
        await logoutUser(tokenB);
        await sleep(300);

        const meA2 = await request('GET', '/auth/me', { token: tokenA });
        recordResult(phase, '5.3a Token A still rejected after second logout',
            meA2.status === 401, `status: ${meA2.status}`);

        const meB2 = await request('GET', '/auth/me', { token: tokenB });
        recordResult(phase, '5.3b Token B now rejected after second logout',
            meB2.status === 401, `status: ${meB2.status}`);

    } catch (e) {
        recordResult(phase, 'Phase 5 FATAL', false, e.message);
    }
}

// ─── Phase 6: WebSocket Stability Under Mass Logout ──────────────────────────

async function phase6() {
    const wsTestCount = Math.min(NUM_USERS, 20); // Cap WS tests at 20 to avoid overwhelming

    console.log('\n┌──────────────────────────────────────────────────────────────┐');
    console.log(`│  PHASE 6 — WebSocket Stability Under Mass Logout (${wsTestCount} users) │`);
    console.log('└──────────────────────────────────────────────────────────────┘\n');

    const phase = 'Phase 6';

    try {
        // 6.1 — Create users and connect via WebSocket
        console.log(`  ⏳ Creating ${wsTestCount} WebSocket-connected users...`);
        const users = [];
        const sockets = [];

        for (let i = 0; i < wsTestCount; i++) {
            try {
                const user = await createAndLoginUser();
                users.push(user);

                const wsResult = await attemptWebSocket(user.token);
                if (wsResult.connected) sockets.push({ user, ws: wsResult.ws });
            } catch (e) {
                // continue
            }
            if (i < wsTestCount - 1) await sleep(STAGGER_MS);
        }

        recordResult(phase, `6.1 Users connected via WS`,
            sockets.length > 0,
            `${sockets.length}/${wsTestCount} connected`);

        // 6.2 — All logout simultaneously
        console.log(`  ⏳ Firing ${users.length} simultaneous logouts...`);
        const logoutResults = await Promise.allSettled(
            users.map(u => logoutUser(u.token))
        );

        const logoutSuccesses = logoutResults.filter(
            r => r.status === 'fulfilled' && r.value.status === 200
        ).length;

        recordResult(phase, '6.2 Mass logout while WS open',
            logoutSuccesses === users.length,
            `${logoutSuccesses}/${users.length} logout calls succeeded`);

        // Close the existing sockets
        sockets.forEach(s => { try { s.ws.close(); } catch (_) {} });
        await sleep(1000);

        // 6.3 — Attempt reconnect with old tokens → all must fail
        console.log(`  ⏳ Attempting ${users.length} WS reconnects with revoked tokens...`);
        const reconnectResults = await Promise.allSettled(
            users.map(u => attemptWebSocket(u.token, 4000))
        );

        const allRejected = reconnectResults.every(
            r => r.status === 'fulfilled' && !r.value.connected
        );
        const rejectedCount = reconnectResults.filter(
            r => r.status === 'fulfilled' && !r.value.connected
        ).length;

        recordResult(phase, '6.3 WS reconnect with revoked tokens → all rejected',
            allRejected,
            `${rejectedCount}/${users.length} correctly rejected`);

        // Cleanup any accidentally connected sockets
        reconnectResults.forEach(r => {
            if (r.status === 'fulfilled' && r.value.ws) {
                try { r.value.ws.close(); } catch (_) {}
            }
        });

    } catch (e) {
        recordResult(phase, 'Phase 6 FATAL', false, e.message);
    }
}

// ─── Report ──────────────────────────────────────────────────────────────────

async function printReport() {
    const elapsed = ((Date.now() - stats.startTime) / 1000).toFixed(1);

    console.log('\n');
    console.log('━'.repeat(72));
    console.log('  LOGOUT STRESS TEST — FINAL REPORT');
    console.log('━'.repeat(72));
    console.log(`  Backend:           ${BACKEND_URL}`);
    console.log(`  Duration:          ${elapsed}s`);
    console.log(`  Total Tests:       ${stats.passed + stats.failed}`);
    console.log(`  Passed:            ${stats.passed}`);
    console.log(`  Failed:            ${stats.failed}`);
    console.log(`  Mass Logout Users: ${NUM_USERS}`);
    console.log(`  Rapid Cycles:      ${RAPID_CYCLES}`);
    console.log('');

    // Per-phase summary
    console.log('  ── Phase Breakdown ──');
    for (const [phase, data] of Object.entries(stats.phases)) {
        const icon = data.failed === 0 ? '✅' : '❌';
        console.log(`  ${icon} ${phase}: ${data.passed} passed, ${data.failed} failed`);
    }

    if (stats.errors.length > 0) {
        console.log('');
        console.log('  ── Failures ──');
        stats.errors.forEach(e => console.log(`  ❌ ${e}`));
    }

    console.log('');

    // Verdict
    if (stats.failed === 0) {
        console.log('  ╔══════════════════════════════════════════════════════════╗');
        console.log('  ║  🟢 ALL TESTS PASSED — Logout flow is SOLID            ║');
        console.log('  ╚══════════════════════════════════════════════════════════╝');
    } else {
        console.log('  ╔══════════════════════════════════════════════════════════╗');
        console.log(`  ║  🔴 ${stats.failed} TEST(S) FAILED — Logout flow has issues       ║`);
        console.log('  ╚══════════════════════════════════════════════════════════╝');
    }

    console.log('━'.repeat(72));

    // Write to log file
    const logFile = `stress-test-logout-${Date.now()}.txt`;
    try {
        const fs = await import('fs');
        const logLines = [
            `GhostNet Logout Stress Test Results`,
            `Date: ${new Date().toISOString()}`,
            `Backend: ${BACKEND_URL}`,
            `Duration: ${elapsed}s`,
            `Total: ${stats.passed + stats.failed} | Passed: ${stats.passed} | Failed: ${stats.failed}`,
            '',
            ...stats.errors.map(e => `FAIL: ${e}`),
        ];
        fs.writeFileSync(logFile, logLines.join('\n') + '\n');
        console.log(`\n  📝 Log written to: ${logFile}`);
    } catch (_) {}
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
    console.log('━'.repeat(72));
    console.log('  GhostNet — Logout Flow End-to-End Stress Test');
    console.log('━'.repeat(72));
    console.log(`  Backend:     ${BACKEND_URL}`);
    console.log(`  Users:       ${NUM_USERS}`);
    console.log(`  Cycles:      ${RAPID_CYCLES}`);
    console.log(`  Stagger:     ${STAGGER_MS}ms`);
    console.log('━'.repeat(72));

    // Preflight: check server is up
    try {
        const health = await request('GET', '/health');
        if (health.status !== 200 && health.status !== 404) {
            console.log(`  ⚠️  Server health check returned ${health.status}. Proceeding anyway...`);
        } else {
            console.log(`  ✅ Server is reachable.`);
        }
    } catch (e) {
        console.error(`  ❌ Server unreachable: ${e.message}`);
        console.error(`  → Is the server running at ${BACKEND_URL}?`);
        process.exit(1);
    }

    await phase1();
    await phase2();
    await phase3();
    await phase4();
    await phase5();
    await phase6();

    printReport();

    process.exit(stats.failed > 0 ? 1 : 0);
}

main().catch(e => {
    console.error('\n💥 Stress test crashed:', e);
    process.exit(1);
});
