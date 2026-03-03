#!/usr/bin/env node
/**
 * GhostNet Health Watchdog
 * ========================
 * Continuous health monitoring daemon for all GhostNet services.
 * Runs alongside PM2 as an additional safety layer.
 * 
 * Features:
 *  - Periodic port checks for all services
 *  - HTTP health endpoint verification
 *  - WebSocket connectivity testing
 *  - Inter-service communication validation
 *  - Auto-restart of failed services via PM2
 *  - Structured JSON logging
 * 
 * Usage:
 *   node ghostnet-watchdog.cjs                 → default 30s interval
 *   node ghostnet-watchdog.cjs --interval=10   → check every 10s
 *   node ghostnet-watchdog.cjs --once          → single check, then exit
 */

const http = require('http');
const net = require('net');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { WebSocket } = require('ws');

// ─── CONFIG ─────────────────────────────────────────────

const ROOT = __dirname;
const LOG_FILE = path.join(ROOT, 'logs', 'watchdog.log');

const CHECK_INTERVAL = (() => {
    const arg = process.argv.find(a => a.startsWith('--interval='));
    return arg ? parseInt(arg.split('=')[1]) * 1000 : 30000;
})();

const ONCE_MODE = process.argv.includes('--once');

const SERVICES = [
    {
        name: 'ghostnet-server',
        port: 8080,
        healthUrl: 'http://127.0.0.1:8080/status',
        wsUrl: 'ws://127.0.0.1:8080/ws',
        critical: true
    },
    {
        name: 'ghostnet-bridge',
        port: 3001,
        healthUrl: 'http://127.0.0.1:3001/wallet',
        wsUrl: null,
        critical: false
    },
    {
        name: 'ghostnet-client',
        port: 3000,
        healthUrl: 'http://127.0.0.1:3000/health',
        wsUrl: null,
        critical: false
    },
    {
        name: 'ghostnet-messages',
        port: 8090,
        healthUrl: null,
        wsUrl: null,
        critical: false
    },
    {
        name: 'ghostnet-relay-1',
        port: 8081,
        healthUrl: null,
        wsUrl: 'ws://127.0.0.1:8081',
        critical: false
    },
    {
        name: 'ghostnet-relay-2',
        port: 8082,
        healthUrl: null,
        wsUrl: 'ws://127.0.0.1:8082',
        critical: false
    },
    {
        name: 'ghostnet-relay-3',
        port: 8083,
        healthUrl: null,
        wsUrl: 'ws://127.0.0.1:8083',
        critical: false
    },
    {
        name: 'ghostnet-registry',
        port: 9000,
        healthUrl: 'http://127.0.0.1:9000/nodes',
        wsUrl: null,
        critical: false
    }
];

// ─── STATE ──────────────────────────────────────────────

const serviceState = new Map();
let checkCount = 0;
let lastFullReport = 0;

// Initialize state
SERVICES.forEach(svc => {
    serviceState.set(svc.name, {
        status: 'unknown',
        lastCheck: 0,
        lastHealthy: 0,
        consecutiveFails: 0,
        restartCount: 0,
        metrics: {}
    });
});

// ─── UTILITIES ──────────────────────────────────────────

function logEntry(level, msg, meta = {}) {
    const entry = {
        ts: new Date().toISOString(),
        level,
        msg,
        ...meta
    };

    const icons = { info: '📋', warn: '⚠️', error: '🔴', ok: '✅', sys: '⚙️' };
    const icon = icons[level] || '📋';

    // Console
    console.log(`[${entry.ts.substr(11, 8)}] ${icon} ${msg}`);

    // File log (append)
    try {
        fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n');
    } catch (e) { /* ignore log write errors */ }
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

function httpCheck(url, timeout = 5000) {
    return new Promise(resolve => {
        const timer = setTimeout(() => resolve({ ok: false, status: 0, data: null }), timeout);
        http.get(url, res => {
            clearTimeout(timer);
            let body = '';
            res.on('data', d => body += d);
            res.on('end', () => {
                let parsed = null;
                try { parsed = JSON.parse(body); } catch (e) { /* not JSON */ }
                resolve({ ok: res.statusCode >= 200 && res.statusCode < 400, status: res.statusCode, data: parsed });
            });
        }).on('error', () => {
            clearTimeout(timer);
            resolve({ ok: false, status: 0, data: null });
        });
    });
}

function wsCheck(url, timeout = 5000) {
    return new Promise(resolve => {
        if (!url) return resolve({ ok: false, reason: 'no url' });

        const timer = setTimeout(() => {
            ws.terminate();
            resolve({ ok: false, reason: 'timeout' });
        }, timeout);

        let ws;
        try {
            ws = new WebSocket(url);
        } catch (e) {
            clearTimeout(timer);
            return resolve({ ok: false, reason: e.message });
        }

        ws.on('open', () => {
            clearTimeout(timer);
            // Test by sending a heartbeat
            ws.send(JSON.stringify({ type: 'HEARTBEAT', id: 'watchdog' }));
            ws.close();
            resolve({ ok: true });
        });

        ws.on('error', (e) => {
            clearTimeout(timer);
            resolve({ ok: false, reason: e.message });
        });
    });
}

function pm2Restart(serviceName) {
    try {
        execSync(`pm2 restart ${serviceName}`, { encoding: 'utf8', stdio: 'pipe', timeout: 15000 });
        return true;
    } catch (e) {
        return false;
    }
}

// ─── HEALTH CHECK CYCLE ─────────────────────────────────

async function checkService(svc) {
    const state = serviceState.get(svc.name);
    const result = {
        name: svc.name,
        port: false,
        http: false,
        ws: null,
        httpData: null,
        healthy: false
    };

    // 1. Port check
    result.port = await checkPort(svc.port);

    // 2. HTTP health check
    if (result.port && svc.healthUrl) {
        const httpResult = await httpCheck(svc.healthUrl);
        result.http = httpResult.ok;
        result.httpData = httpResult.data;
    }

    // 3. WebSocket check (server only)
    if (result.port && svc.wsUrl) {
        const wsResult = await wsCheck(svc.wsUrl);
        result.ws = wsResult.ok;
    }

    // Determine overall health
    result.healthy = result.port && (svc.healthUrl ? result.http : true);

    // Update state
    state.lastCheck = Date.now();
    if (result.healthy) {
        state.status = 'healthy';
        state.lastHealthy = Date.now();
        state.consecutiveFails = 0;
        if (result.httpData) state.metrics = result.httpData;
    } else {
        state.status = 'unhealthy';
        state.consecutiveFails++;
    }

    return result;
}

async function runCheckCycle() {
    checkCount++;
    const isFullReport = (Date.now() - lastFullReport) > 300000; // Full report every 5 min
    const results = [];

    for (const svc of SERVICES) {
        const result = await checkService(svc);
        results.push(result);

        const state = serviceState.get(svc.name);

        if (!result.healthy) {
            logEntry('error', `${svc.name} UNHEALTHY`, {
                port: result.port,
                http: result.http,
                ws: result.ws,
                consecutiveFails: state.consecutiveFails
            });

            // Auto-restart after 3 consecutive failures
            if (state.consecutiveFails >= 3 && state.consecutiveFails % 3 === 0) {
                logEntry('warn', `Auto-restarting ${svc.name} (${state.consecutiveFails} consecutive failures)`);
                const restarted = pm2Restart(svc.name);
                if (restarted) {
                    state.restartCount++;
                    logEntry('ok', `${svc.name} restart triggered (attempt ${state.restartCount})`);
                } else {
                    logEntry('error', `Failed to restart ${svc.name} via PM2`);
                }
            }
        } else if (isFullReport) {
            logEntry('ok', `${svc.name} healthy`, {
                port: svc.port,
                uptime: result.httpData?.uptimeHuman || 'N/A',
                memory: result.httpData?.memory?.rss ? `${result.httpData.memory.rss}MB` : 'N/A'
            });
        }
    }

    // Full status report
    if (isFullReport) {
        lastFullReport = Date.now();
        const healthy = results.filter(r => r.healthy).length;
        const total = results.length;
        logEntry('sys', `Health Check #${checkCount}: ${healthy}/${total} services healthy`);
    }

    // Inter-service comms check (every 10th cycle)
    if (checkCount % 10 === 0) {
        await checkInterServiceComms();
    }

    return results;
}

// ─── INTER-SERVICE CHECK ────────────────────────────────

async function checkInterServiceComms() {
    logEntry('sys', 'Running inter-service communication check...');

    // Server → Bridge connectivity
    const bridgeCheck = await httpCheck('http://127.0.0.1:8080/health/bridge');
    if (bridgeCheck.ok) {
        logEntry('ok', 'Server → Bridge communication OK');
    } else {
        logEntry('warn', 'Server → Bridge communication FAILED', { status: bridgeCheck.status, data: bridgeCheck.data });
    }
}

// ─── MAIN LOOP ──────────────────────────────────────────

async function main() {
    // Ensure logs directory exists
    const logsDir = path.join(ROOT, 'logs');
    if (!fs.existsSync(logsDir)) {
        fs.mkdirSync(logsDir, { recursive: true });
    }

    console.log('');
    console.log('╔══════════════════════════════════════════╗');
    console.log('║    GhostNet Health Watchdog               ║');
    console.log(`║    Interval: ${(CHECK_INTERVAL / 1000)}s | Mode: ${ONCE_MODE ? 'ONE-SHOT' : 'CONTINUOUS'}      ║`);
    console.log('╚══════════════════════════════════════════╝');
    console.log('');

    logEntry('sys', `Watchdog started (interval: ${CHECK_INTERVAL / 1000}s, mode: ${ONCE_MODE ? 'once' : 'continuous'})`);

    if (ONCE_MODE) {
        const results = await runCheckCycle();
        const allHealthy = results.every(r => r.healthy);

        console.log('');
        console.log('┌───────────────────┬────────┬────────┬────────┐');
        console.log('│ Service           │ Port   │ HTTP   │ WS     │');
        console.log('├───────────────────┼────────┼────────┼────────┤');
        for (const r of results) {
            const p = r.port ? '  ✅  ' : '  ❌  ';
            const h = r.http ? '  ✅  ' : (r.httpData === null && r.port ? '  ➖  ' : '  ❌  ');
            const w = r.ws === null ? '  ➖  ' : (r.ws ? '  ✅  ' : '  ❌  ');
            console.log(`│ ${r.name.padEnd(17)} │${p}│${h}│${w}│`);
        }
        console.log('└───────────────────┴────────┴────────┴────────┘');
        console.log('');

        process.exit(allHealthy ? 0 : 1);
    }

    // Continuous mode
    await runCheckCycle();

    setInterval(async () => {
        try {
            await runCheckCycle();
        } catch (e) {
            logEntry('error', `Check cycle failed: ${e.message}`);
        }
    }, CHECK_INTERVAL);

    // Graceful shutdown
    process.on('SIGINT', () => {
        logEntry('sys', 'Watchdog shutting down');
        process.exit(0);
    });

    process.on('SIGTERM', () => {
        logEntry('sys', 'Watchdog terminated');
        process.exit(0);
    });
}

main().catch(e => {
    console.error('Watchdog error:', e);
    process.exit(1);
});
