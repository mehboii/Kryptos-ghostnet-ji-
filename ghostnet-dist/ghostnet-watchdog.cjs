#!/usr/bin/env node
'use strict';

const https = require('https');
const http = require('http');
const net = require('net');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const { WebSocket } = require('ws');

const ALLOWED_SERVICE_NAMES = new Set([
    'ghostnet-server',
    'ghostnet-bridge',
    'ghostnet-client',
    'ghostnet-messages',
    'ghostnet-relay-1',
    'ghostnet-relay-2',
    'ghostnet-relay-3',
    'ghostnet-registry'
]);

function parseInterval() {
    const arg = process.argv.find(a => a.startsWith('--interval='));
    if (!arg) return 30000;
    const raw = parseInt(arg.split('=')[1], 10);
    if (isNaN(raw) || raw < 5 || raw > 3600) {
        console.error('[watchdog] Invalid --interval. Must be 5-3600 seconds. Using 30s.');
        return 30000;
    }
    return raw * 1000;
}

const CHECK_INTERVAL = parseInterval();
const ONCE_MODE = process.argv.includes('--once');
const MAX_RESTARTS_PER_HOUR = 5;
const RESTART_WINDOW_MS = 60 * 60 * 1000;
const MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024;
const MAX_LOG_FILES = 5;
const ROOT = path.resolve(__dirname);
const LOGS_DIR = path.join(ROOT, 'logs');
const LOG_FILE = path.join(LOGS_DIR, 'watchdog.log');

const SERVICES = [
    { name: 'ghostnet-server', port: 8080, healthUrl: 'https://127.0.0.1:8080/status', wsUrl: 'wss://127.0.0.1:8080/ws', critical: true },
    { name: 'ghostnet-bridge', port: 3001, healthUrl: 'https://127.0.0.1:3001/wallet', wsUrl: null, critical: false },
    { name: 'ghostnet-client', port: 3000, healthUrl: 'https://127.0.0.1:3000/health', wsUrl: null, critical: false },
    { name: 'ghostnet-messages', port: 8090, healthUrl: null, wsUrl: null, critical: false },
    { name: 'ghostnet-relay-1', port: 8081, healthUrl: null, wsUrl: 'wss://127.0.0.1:8081', critical: false },
    { name: 'ghostnet-relay-2', port: 8082, healthUrl: null, wsUrl: 'wss://127.0.0.1:8082', critical: false },
    { name: 'ghostnet-relay-3', port: 8083, healthUrl: null, wsUrl: 'wss://127.0.0.1:8083', critical: false },
    { name: 'ghostnet-registry', port: 9000, healthUrl: 'https://127.0.0.1:9000/nodes', wsUrl: null, critical: false }
];

for (const svc of SERVICES) {
    if (!ALLOWED_SERVICE_NAMES.has(svc.name)) {
        throw new Error(`[watchdog] FATAL: "${svc.name}" not in ALLOWED_SERVICE_NAMES.`);
    }
}

const serviceState = new Map();
let checkCount = 0;
let lastFullReport = 0;

SERVICES.forEach(svc => {
    serviceState.set(svc.name, {
        status: 'unknown', lastCheck: 0, lastHealthy: 0,
        consecutiveFails: 0, restartCount: 0,
        restartTimestamps: [], metrics: {}
    });
});

function rotateLogs() {
    try {
        if (!fs.existsSync(LOG_FILE)) return;
        const stat = fs.statSync(LOG_FILE);
        if (stat.size < MAX_LOG_SIZE_BYTES) return;
        for (let i = MAX_LOG_FILES - 1; i >= 1; i--) {
            const from = `${LOG_FILE}.${i}`;
            const to = `${LOG_FILE}.${i + 1}`;
            if (fs.existsSync(from)) {
                if (i === MAX_LOG_FILES - 1) fs.unlinkSync(from);
                else fs.renameSync(from, to);
            }
        }
        fs.renameSync(LOG_FILE, `${LOG_FILE}.1`);
    } catch (e) {
        console.error('[watchdog] Log rotation failed:', e.message);
    }
}

function logEntry(level, msg, meta = {}) {
    const entry = { ts: new Date().toISOString(), level, msg, ...meta };
    const icons = { info: '📋', warn: '⚠️', error: '🔴', ok: '✅', sys: '⚙️' };
    console.log(`[${entry.ts.substr(11, 8)}] ${icons[level] || '📋'} ${msg}`);
    try {
        rotateLogs();
        fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
    } catch (e) { }
}

function checkPort(port, host = '127.0.0.1', timeout = 3000) {
    return new Promise(resolve => {
        const socket = new net.Socket();
        socket.setTimeout(timeout);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.on('error', () => { socket.destroy(); resolve(false); });
        socket.connect(port, host);
    });
}

function httpsCheck(url, timeout = 5000) {
    const MAX_BODY = 64 * 1024;
    return new Promise(resolve => {
        const timer = setTimeout(() => resolve({ ok: false, status: 0, data: null }), timeout);
        const protocol = url.startsWith('https') ? https : http;
        protocol.get(url, { rejectUnauthorized: false }, res => {
            clearTimeout(timer);
            let body = '', aborted = false;
            res.on('data', chunk => {
                if (aborted) return;
                body += chunk;
                if (Buffer.byteLength(body) > MAX_BODY) {
                    aborted = true;
                    res.destroy();
                    resolve({ ok: false, status: res.statusCode, data: null, error: 'body too large' });
                }
            });
            res.on('end', () => {
                if (aborted) return;
                let parsed = null;
                try { parsed = JSON.parse(body); } catch (e) { }
                resolve({ ok: res.statusCode >= 200 && res.statusCode < 400, status: res.statusCode, data: parsed });
            });
        }).on('error', () => { clearTimeout(timer); resolve({ ok: false, status: 0, data: null }); });
    });
}

function wsCheck(url, timeout = 5000) {
    return new Promise(resolve => {
        if (!url) return resolve({ ok: false, reason: 'no url' });
        if (!url.startsWith('wss://')) return resolve({ ok: false, reason: 'insecure ws:// rejected' });
        const timer = setTimeout(() => { try { ws.terminate(); } catch (_) { } resolve({ ok: false, reason: 'timeout' }); }, timeout);
        let ws;
        try { ws = new WebSocket(url, { rejectUnauthorized: false }); }
        catch (e) { clearTimeout(timer); return resolve({ ok: false, reason: e.message }); }
        ws.on('open', () => { clearTimeout(timer); ws.send(JSON.stringify({ type: 'HEARTBEAT', id: 'watchdog' })); ws.close(); resolve({ ok: true }); });
        ws.on('error', e => { clearTimeout(timer); resolve({ ok: false, reason: e.message }); });
    });
}

function pm2Restart(serviceName) {
    if (!ALLOWED_SERVICE_NAMES.has(serviceName)) {
        logEntry('error', `pm2Restart blocked: "${serviceName}" not in allowlist`);
        return Promise.resolve(false);
    }
    const state = serviceState.get(serviceName);
    const now = Date.now();
    state.restartTimestamps = state.restartTimestamps.filter(t => now - t < RESTART_WINDOW_MS);
    if (state.restartTimestamps.length >= MAX_RESTARTS_PER_HOUR) {
        logEntry('warn', `pm2Restart RATE LIMITED for ${serviceName}`);
        return Promise.resolve(false);
    }
    return new Promise(resolve => {
        execFile('pm2', ['restart', serviceName], { timeout: 15000 }, err => {
            if (err) { logEntry('error', `pm2Restart failed: ${err.message}`); resolve(false); }
            else { state.restartTimestamps.push(now); resolve(true); }
        });
    });
}

async function checkService(svc) {
    const state = serviceState.get(svc.name);
    const result = { name: svc.name, port: false, http: false, ws: null, httpData: null, healthy: false };
    result.port = await checkPort(svc.port);
    if (result.port && svc.healthUrl) {
        const r = await httpsCheck(svc.healthUrl);
        result.http = r.ok; result.httpData = r.data;
    }
    if (result.port && svc.wsUrl) {
        const r = await wsCheck(svc.wsUrl);
        result.ws = r.ok;
    }
    result.healthy = result.port && (svc.healthUrl ? result.http : true);
    state.lastCheck = Date.now();
    if (result.healthy) {
        state.status = 'healthy'; state.lastHealthy = Date.now();
        state.consecutiveFails = 0;
        if (result.httpData) state.metrics = result.httpData;
    } else {
        state.status = 'unhealthy'; state.consecutiveFails++;
    }
    return result;
}

async function runCheckCycle() {
    checkCount++;
    const isFullReport = (Date.now() - lastFullReport) > 300000;
    const results = [];
    for (const svc of SERVICES) {
        const result = await checkService(svc);
        results.push(result);
        const state = serviceState.get(svc.name);
        if (!result.healthy) {
            logEntry('error', `${svc.name} UNHEALTHY`, { port: result.port, http: result.http, ws: result.ws, consecutiveFails: state.consecutiveFails });
            if (state.consecutiveFails >= 3 && state.consecutiveFails % 3 === 0) {
                logEntry('warn', `Auto-restarting ${svc.name} (${state.consecutiveFails} consecutive failures)`);
                const restarted = await pm2Restart(svc.name);
                if (restarted) { state.restartCount++; logEntry('ok', `${svc.name} restarted (attempt ${state.restartCount})`); }
                else { logEntry('error', `Failed to restart ${svc.name}`); }
            }
        } else if (isFullReport) {
            logEntry('ok', `${svc.name} healthy`, { port: svc.port, uptime: result.httpData?.uptimeHuman || 'N/A' });
        }
    }
    if (isFullReport) {
        lastFullReport = Date.now();
        logEntry('sys', `Health Check #${checkCount}: ${results.filter(r => r.healthy).length}/${results.length} healthy`);
    }
    if (checkCount % 10 === 0) await checkInterServiceComms();
    return results;
}

async function checkInterServiceComms() {
    logEntry('sys', 'Running inter-service communication check...');
    const r = await httpsCheck('https://127.0.0.1:8080/health/bridge');
    if (r.ok) logEntry('ok', 'Server → Bridge OK');
    else logEntry('warn', 'Server → Bridge FAILED', { status: r.status });
}

async function main() {
    if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });
    console.log('\n╔══════════════════════════════════════════╗');
    console.log('║    GhostNet Health Watchdog (Hardened)    ║');
    console.log(`║    Interval: ${CHECK_INTERVAL / 1000}s | Mode: ${ONCE_MODE ? 'ONE-SHOT  ' : 'CONTINUOUS'} ║`);
    console.log('╚══════════════════════════════════════════╝\n');
    logEntry('sys', `Watchdog started (interval: ${CHECK_INTERVAL / 1000}s)`);

    if (ONCE_MODE) {
        const results = await runCheckCycle();
        const allHealthy = results.every(r => r.healthy);
        console.log('\n┌───────────────────┬────────┬────────┬────────┐');
        console.log('│ Service           │ Port   │ HTTP   │ WS     │');
        console.log('├───────────────────┼────────┼────────┼────────┤');
        for (const r of results) {
            const p = r.port ? '  ✅  ' : '  ❌  ';
            const h = r.http ? '  ✅  ' : (r.httpData === null && r.port ? '  ➖  ' : '  ❌  ');
            const w = r.ws === null ? '  ➖  ' : (r.ws ? '  ✅  ' : '  ❌  ');
            console.log(`│ ${r.name.padEnd(17)} │${p}│${h}│${w}│`);
        }
        console.log('└───────────────────┴────────┴────────┴────────┘\n');
        process.exit(allHealthy ? 0 : 1);
    }

    await runCheckCycle();
    setInterval(async () => {
        try { await runCheckCycle(); }
        catch (e) { logEntry('error', `Check cycle failed: ${e.message}`); }
    }, CHECK_INTERVAL);

    process.on('SIGINT', () => { logEntry('sys', 'Watchdog shutting down'); process.exit(0); });
    process.on('SIGTERM', () => { logEntry('sys', 'Watchdog terminated'); process.exit(0); });
}

main().catch(e => { console.error('Watchdog fatal error:', e); process.exit(1); });