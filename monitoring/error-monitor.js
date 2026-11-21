/**
 * Kryptos Error Monitor
 * ══════════════════════
 *
 * Lightweight, dependency-free error monitoring with Sentry-compatible API.
 * Tracks crash rate, API error rate, and WebSocket disconnect spikes over a
 * rolling 5-minute window and fires alerts via webhook when thresholds are
 * exceeded.
 *
 * THRESHOLDS:
 *   - Crash rate         > 1%   of process events (uncaught/unhandled)
 *   - API error rate     > 5%   of HTTP responses (5xx)
 *   - WS disconnect rate > 3x   baseline disconnects/min
 *
 * SWAP TO SENTRY:
 *   To replace with real Sentry, set env SENTRY_DSN and the captureException
 *   function will forward to Sentry.captureException() if @sentry/node is
 *   installed. Otherwise events go to the local rolling window + webhook.
 *
 * ENV:
 *   MONITOR_WEBHOOK_URL    — POST target for alerts (Slack/Discord/PagerDuty)
 *   MONITOR_ALERT_COOLDOWN — Min seconds between alerts of the same kind (default 300)
 *   SENTRY_DSN             — Optional, forwards to Sentry if installed
 *
 * @module monitoring/error-monitor
 */

const WINDOW_MS = 5 * 60 * 1000;          // 5-minute rolling window
const CRASH_RATE_THRESHOLD = 0.01;         // 1%
const API_ERROR_RATE_THRESHOLD = 0.05;     // 5%
const WS_DISCONNECT_SPIKE_MULTIPLIER = 3;  // 3x baseline
const MIN_SAMPLES_FOR_RATE = 20;           // Avoid divide-by-zero noise

const cooldownSec = parseInt(process.env.MONITOR_ALERT_COOLDOWN, 10) || 300;
const webhookUrl = process.env.MONITOR_WEBHOOK_URL || null;

// ─── Rolling window storage ─────────────────────────────────────────────────
// Each bucket is { ts, kind } where kind ∈ {'crash','request','api_error','ws_connect','ws_disconnect'}
const events = [];
const lastAlertAt = new Map(); // alertKey → timestamp(ms)

let _sentry = null;
async function _trySentry() {
    if (_sentry !== null) return _sentry;
    if (!process.env.SENTRY_DSN) { _sentry = false; return false; }
    try {
        const mod = await import('@sentry/node');
        mod.init({ dsn: process.env.SENTRY_DSN, tracesSampleRate: 0.1 });
        _sentry = mod;
        console.log('[Monitor] Sentry initialised');
        return mod;
    } catch (_) {
        _sentry = false;
        return false;
    }
}

function _prune(now) {
    const cutoff = now - WINDOW_MS;
    while (events.length && events[0].ts < cutoff) events.shift();
}

function _record(kind, meta = null) {
    const now = Date.now();
    events.push({ ts: now, kind, meta });
    _prune(now);
}

function _countByKind(kind) {
    return events.reduce((n, e) => n + (e.kind === kind ? 1 : 0), 0);
}

// ─── PUBLIC API (Sentry-compatible) ─────────────────────────────────────────

/**
 * Capture an exception. Forwards to Sentry if available, otherwise records
 * a crash event in the rolling window.
 */
export function captureException(err, context = {}) {
    _record('crash', { message: err?.message, context });
    console.error('[Monitor] Exception:', err?.message || err, context);
    _trySentry().then(s => { if (s) s.captureException(err, { extra: context }); });
    _checkCrashRate();
}

/**
 * Capture a string-only message (for non-Error events).
 */
export function captureMessage(message, level = 'info') {
    console.log(`[Monitor:${level}] ${message}`);
    _trySentry().then(s => { if (s) s.captureMessage(message, level); });
}

// ─── INSTRUMENTATION HOOKS ──────────────────────────────────────────────────

/**
 * Express middleware: tracks every request and 5xx response.
 * Mount this BEFORE your routes:
 *   app.use(monitor.expressMiddleware());
 */
export function expressMiddleware() {
    return (req, res, next) => {
        _record('request');
        res.on('finish', () => {
            if (res.statusCode >= 500) {
                _record('api_error', { path: req.path, status: res.statusCode });
                _checkApiErrorRate();
            }
        });
        next();
    };
}

/**
 * Express error handler: catches thrown errors in routes.
 * Mount this AFTER your routes:
 *   app.use(monitor.expressErrorHandler());
 */
export function expressErrorHandler() {
    return (err, req, res, next) => {
        captureException(err, { path: req.path, method: req.method });
        if (!res.headersSent) {
            res.status(500).json({ error: 'Internal server error.' });
        } else {
            next(err);
        }
    };
}

/**
 * WebSocket lifecycle hooks. Call from wss.on('connection') and ws.on('close').
 */
export function trackWsConnect() { _record('ws_connect'); }
export function trackWsDisconnect(reason = null) {
    _record('ws_disconnect', { reason });
    _checkWsSpike();
}
export function trackWsError(err) {
    captureException(err, { source: 'websocket' });
}

// ─── PROCESS-LEVEL HANDLERS ─────────────────────────────────────────────────

/**
 * Install global handlers for uncaughtException and unhandledRejection.
 *
 * After an uncaughtException, Node's process state is UNDEFINED — in-memory
 * maps may be partially mutated, file writes may be half-flushed, and the
 * event loop may be in an inconsistent state. Continuing risks routing
 * messages to the wrong user or corrupting persisted data.
 *
 * Correct pattern: capture → give the captureException pipeline a brief
 * moment to flush → exit non-zero so the supervisor (pm2) restarts cleanly.
 */
let _shuttingDown = false;
function _fatalShutdown(err, source) {
    if (_shuttingDown) return;
    _shuttingDown = true;
    try { captureException(err, { source, fatal: true }); } catch (_) { }
    // Allow up to 1s for the alert webhook / Sentry flush, then hard-exit.
    setTimeout(() => process.exit(1), 1000).unref();
}

export function installProcessHandlers() {
    process.on('uncaughtException', (err) => {
        _fatalShutdown(err, 'uncaughtException');
    });
    process.on('unhandledRejection', (reason) => {
        const err = reason instanceof Error ? reason : new Error(String(reason));
        _fatalShutdown(err, 'unhandledRejection');
    });
}

// ─── ALERTING ───────────────────────────────────────────────────────────────

function _checkCrashRate() {
    const crashes = _countByKind('crash');
    const requests = _countByKind('request');
    const total = Math.max(crashes + requests, 1);
    if (total < MIN_SAMPLES_FOR_RATE) return;
    const rate = crashes / total;
    if (rate > CRASH_RATE_THRESHOLD) {
        _alert('crash_rate', `Crash rate ${(rate * 100).toFixed(2)}% exceeds 1% (${crashes}/${total} in last 5m)`);
    }
}

function _checkApiErrorRate() {
    const errors = _countByKind('api_error');
    const requests = _countByKind('request');
    if (requests < MIN_SAMPLES_FOR_RATE) return;
    const rate = errors / requests;
    if (rate > API_ERROR_RATE_THRESHOLD) {
        _alert('api_error_rate', `API 5xx rate ${(rate * 100).toFixed(2)}% exceeds 5% (${errors}/${requests} in last 5m)`);
    }
}

// Baseline = average disconnects/minute over the window. Spike = current minute > 3x baseline.
function _checkWsSpike() {
    const now = Date.now();
    const oneMinAgo = now - 60 * 1000;
    const lastMinute = events.filter(e => e.kind === 'ws_disconnect' && e.ts >= oneMinAgo).length;
    const totalDisconnects = _countByKind('ws_disconnect');
    const baselinePerMin = totalDisconnects / (WINDOW_MS / 60000);
    if (baselinePerMin < 1) return; // not enough baseline yet
    if (lastMinute > baselinePerMin * WS_DISCONNECT_SPIKE_MULTIPLIER && lastMinute >= 5) {
        _alert('ws_disconnect_spike', `WS disconnect spike: ${lastMinute}/min vs baseline ${baselinePerMin.toFixed(1)}/min`);
    }
}

function _alert(kind, message) {
    const now = Date.now();
    const last = lastAlertAt.get(kind) || 0;
    if (now - last < cooldownSec * 1000) return;
    lastAlertAt.set(kind, now);

    console.error(`[Monitor:ALERT] ${kind} — ${message}`);

    if (!webhookUrl) return;
    const payload = JSON.stringify({
        text: ` Kryptos alert (${kind}): ${message}`,
        kind, message, timestamp: new Date(now).toISOString(),
    });
    // Fire-and-forget POST. We use built-in fetch (Node 18+).
    fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
    }).catch(err => console.error('[Monitor] Alert webhook failed:', err.message));
}

// ─── HEALTH SNAPSHOT (for /health endpoint) ─────────────────────────────────

export function getMetrics() {
    _prune(Date.now());
    const crashes = _countByKind('crash');
    const requests = _countByKind('request');
    const apiErrors = _countByKind('api_error');
    const wsConnects = _countByKind('ws_connect');
    const wsDisconnects = _countByKind('ws_disconnect');
    return {
        windowMinutes: WINDOW_MS / 60000,
        crashes,
        requests,
        apiErrors,
        wsConnects,
        wsDisconnects,
        crashRate: requests + crashes > 0 ? crashes / (crashes + requests) : 0,
        apiErrorRate: requests > 0 ? apiErrors / requests : 0,
    };
}

export default {
    captureException,
    captureMessage,
    expressMiddleware,
    expressErrorHandler,
    trackWsConnect,
    trackWsDisconnect,
    trackWsError,
    installProcessHandlers,
    getMetrics,
};
