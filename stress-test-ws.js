/**
 * GhostNet WebSocket Stress Test
 *
 * Simulates 50+ concurrent users connecting to the Railway backend.
 * Logs every connect, disconnect, reconnect, error, and message event.
 *
 * Usage:
 *   node stress-test-ws.js                          # 50 clients, production
 *   node stress-test-ws.js --clients=100            # 100 clients
 *   node stress-test-ws.js --url=ws://localhost:8080 # local server
 *   node stress-test-ws.js --duration=120           # run for 120 seconds
 *   node stress-test-ws.js --chaos                  # enable random disconnect/reconnect cycles
 *
 * Requires: npm install ws (already in package.json)
 */

import WebSocket from 'ws';
import crypto from 'crypto';
import http from 'http';
import https from 'https';

// ─── CLI Args ────────────────────────────────────────────────────────────────

const args = Object.fromEntries(
    process.argv.slice(2).map(a => {
        const [k, v] = a.replace(/^--/, '').split('=');
        return [k, v ?? true];
    })
);

const NUM_CLIENTS     = parseInt(args.clients || '50', 10);
const BACKEND_URL     = args.url || 'https://ghostnet-ji-production.up.railway.app';
const WS_URL          = args.wsurl || null; // auto-derived if not set
const DURATION_SEC    = parseInt(args.duration || '60', 10);
const CHAOS_MODE      = !!args.chaos;
const STAGGER_MS      = parseInt(args.stagger || '100', 10); // delay between client spawns
const AUTH_ENDPOINT   = `${BACKEND_URL}/auth/node`;

// ─── Stats ───────────────────────────────────────────────────────────────────

const stats = {
    totalConnects: 0,
    totalDisconnects: 0,
    totalReconnects: 0,
    totalErrors: 0,
    totalMessagesSent: 0,
    totalMessagesReceived: 0,
    totalAuthFailures: 0,
    peakConcurrent: 0,
    currentConnected: 0,
    latencies: [],       // round-trip ping latencies
    events: [],          // detailed event log
};

function logEvent(clientId, event, detail = '') {
    const ts = new Date().toISOString();
    const entry = `[${ts}] Client #${String(clientId).padStart(3, '0')} | ${event.padEnd(14)} | ${detail}`;
    stats.events.push(entry);
    console.log(entry);
}

function updateConcurrent(delta) {
    stats.currentConnected += delta;
    if (stats.currentConnected > stats.peakConcurrent) {
        stats.peakConcurrent = stats.currentConnected;
    }
}

// ─── Auth ────────────────────────────────────────────────────────────────────

async function getNodeToken(clientId) {
    const nodeId = crypto.randomBytes(32).toString('hex'); // valid 64-char hex nodeId

    return new Promise((resolve, reject) => {
        const body = JSON.stringify({ nodeId });
        const url = new URL(AUTH_ENDPOINT);
        const mod = url.protocol === 'https:' ? https : http;

        const req = mod.request(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
            timeout: 10000,
        }, res => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const json = JSON.parse(data);
                    if (json.token) {
                        resolve({ token: json.token, nodeId });
                    } else {
                        stats.totalAuthFailures++;
                        logEvent(clientId, 'AUTH_FAIL', `No token in response: ${data.slice(0, 100)}`);
                        reject(new Error('No token'));
                    }
                } catch (e) {
                    stats.totalAuthFailures++;
                    logEvent(clientId, 'AUTH_FAIL', `Parse error: ${e.message}`);
                    reject(e);
                }
            });
        });

        req.on('error', e => {
            stats.totalAuthFailures++;
            logEvent(clientId, 'AUTH_FAIL', e.message);
            reject(e);
        });

        req.on('timeout', () => {
            stats.totalAuthFailures++;
            logEvent(clientId, 'AUTH_TIMEOUT', 'Request timed out');
            req.destroy();
            reject(new Error('Auth timeout'));
        });

        req.write(body);
        req.end();
    });
}

// ─── Client ──────────────────────────────────────────────────────────────────

class StressClient {
    constructor(id) {
        this.id = id;
        this.ws = null;
        this.nodeId = null;
        this.token = null;
        this.alive = true;
        this.connectCount = 0;
        this.messageCount = 0;
        this.pendingPing = null;
    }

    async start() {
        try {
            const auth = await getNodeToken(this.id);
            this.token = auth.token;
            this.nodeId = auth.nodeId;
            logEvent(this.id, 'AUTHENTICATED', `nodeId: ${this.nodeId.slice(0, 12)}...`);
            this.connect();
        } catch (e) {
            logEvent(this.id, 'START_FAIL', e.message);
        }
    }

    connect() {
        if (!this.alive) return;

        // Derive WS URL
        let wsBase;
        if (WS_URL) {
            wsBase = WS_URL;
        } else {
            const base = new URL(BACKEND_URL);
            wsBase = `${base.protocol === 'https:' ? 'wss:' : 'ws:'}//${base.host}/ws`;
        }

        const wsUrl = `${wsBase}?token=${encodeURIComponent(this.token)}`;
        this.connectCount++;

        try {
            this.ws = new WebSocket(wsUrl, {
                handshakeTimeout: 10000,
                headers: { 'User-Agent': `GhostNet-StressTest/${this.id}` }
            });
        } catch (e) {
            logEvent(this.id, 'CONNECT_ERR', e.message);
            stats.totalErrors++;
            this.scheduleReconnect();
            return;
        }

        const connectStart = Date.now();

        this.ws.on('open', () => {
            const elapsed = Date.now() - connectStart;
            stats.totalConnects++;
            updateConcurrent(1);

            if (this.connectCount > 1) {
                stats.totalReconnects++;
                logEvent(this.id, 'RECONNECTED', `attempt #${this.connectCount}, handshake: ${elapsed}ms`);
            } else {
                logEvent(this.id, 'CONNECTED', `handshake: ${elapsed}ms`);
            }

            // Register as mesh peer
            this.send({
                type: 'register',
                id: this.nodeId,
                nodeId: this.nodeId,
                capabilities: { ble: false, ws: true }
            });

            // Start heartbeat
            this.heartbeatInterval = setInterval(() => this.heartbeat(), 15000);

            // Start ping latency measurement
            this.pingInterval = setInterval(() => this.measurePing(), 10000);
        });

        this.ws.on('message', (data) => {
            stats.totalMessagesReceived++;
            this.messageCount++;

            try {
                const msg = JSON.parse(data.toString());

                switch (msg.type) {
                    case 'welcome':
                        logEvent(this.id, 'MSG_WELCOME', '');
                        break;
                    case 'MESH_PEERS':
                        logEvent(this.id, 'MSG_PEERS', `${msg.peers?.length || 0} peers`);
                        break;
                    case 'PEER_JOIN':
                        logEvent(this.id, 'PEER_JOIN', `peer: ${(msg.id || '').slice(0, 12)}...`);
                        break;
                    case 'PEER_LEAVE':
                        logEvent(this.id, 'PEER_LEAVE', `peer: ${(msg.id || '').slice(0, 12)}...`);
                        break;
                    case 'pong':
                        if (this.pendingPing) {
                            const latency = Date.now() - this.pendingPing;
                            stats.latencies.push(latency);
                            this.pendingPing = null;
                        }
                        break;
                    default:
                        logEvent(this.id, 'MSG_OTHER', `type: ${msg.type}`);
                }
            } catch (_) {
                logEvent(this.id, 'MSG_PARSE_ERR', data.toString().slice(0, 50));
            }
        });

        this.ws.on('close', (code, reason) => {
            updateConcurrent(-1);
            stats.totalDisconnects++;
            clearInterval(this.heartbeatInterval);
            clearInterval(this.pingInterval);
            logEvent(this.id, 'DISCONNECTED', `code: ${code}, reason: ${reason?.toString() || 'none'}`);

            if (this.alive) this.scheduleReconnect();
        });

        this.ws.on('error', (err) => {
            stats.totalErrors++;
            logEvent(this.id, 'ERROR', err.message);
            // onclose will fire after this — reconnect handled there
        });

        this.ws.on('unexpected-response', (req, res) => {
            stats.totalErrors++;
            logEvent(this.id, 'WS_REJECTED', `HTTP ${res.statusCode}`);
        });
    }

    send(payload) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            try {
                this.ws.send(JSON.stringify(payload));
                stats.totalMessagesSent++;
            } catch (e) {
                logEvent(this.id, 'SEND_FAIL', e.message);
                stats.totalErrors++;
            }
        }
    }

    heartbeat() {
        this.send({ type: 'HEARTBEAT', id: this.nodeId, ts: Date.now(), peers: 0 });
    }

    measurePing() {
        this.pendingPing = Date.now();
        this.send({ type: 'ping', timestamp: Date.now() });
    }

    scheduleReconnect() {
        if (!this.alive) return;
        const delay = Math.min(3000 * Math.pow(1.5, Math.min(this.connectCount - 1, 6)), 30000);
        const jitter = Math.floor(Math.random() * 1000);
        logEvent(this.id, 'RECONNECTING', `in ${Math.round(delay + jitter)}ms`);
        setTimeout(() => this.connect(), delay + jitter);
    }

    /** Simulate random disconnect (chaos mode) */
    chaosDisconnect() {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            logEvent(this.id, 'CHAOS_KILL', 'Simulated abrupt disconnect');
            this.ws.terminate(); // hard kill, not graceful close
        }
    }

    stop() {
        this.alive = false;
        clearInterval(this.heartbeatInterval);
        clearInterval(this.pingInterval);
        if (this.ws) {
            this.ws.onclose = null;
            this.ws.close();
            this.ws = null;
        }
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
    console.log('='.repeat(80));
    console.log('  GhostNet WebSocket Stress Test');
    console.log('='.repeat(80));
    console.log(`  Backend:    ${BACKEND_URL}`);
    console.log(`  Clients:    ${NUM_CLIENTS}`);
    console.log(`  Duration:   ${DURATION_SEC}s`);
    console.log(`  Chaos Mode: ${CHAOS_MODE ? 'ON' : 'OFF'}`);
    console.log(`  Stagger:    ${STAGGER_MS}ms between client spawns`);
    console.log('='.repeat(80));
    console.log('');

    const clients = [];

    // Stagger client connections to avoid thundering herd
    for (let i = 0; i < NUM_CLIENTS; i++) {
        const client = new StressClient(i + 1);
        clients.push(client);
        client.start();
        if (i < NUM_CLIENTS - 1) {
            await new Promise(r => setTimeout(r, STAGGER_MS));
        }
    }

    // Chaos mode: randomly kill connections throughout the test
    let chaosInterval;
    if (CHAOS_MODE) {
        chaosInterval = setInterval(() => {
            const liveClients = clients.filter(c => c.ws && c.ws.readyState === WebSocket.OPEN);
            if (liveClients.length > 0) {
                const victim = liveClients[Math.floor(Math.random() * liveClients.length)];
                victim.chaosDisconnect();
            }
        }, 5000); // kill a random client every 5s
    }

    // Live stats every 10s
    const statsInterval = setInterval(() => {
        printLiveStats();
    }, 10000);

    // Run for specified duration
    await new Promise(r => setTimeout(r, DURATION_SEC * 1000));

    // Cleanup
    console.log('\n--- Stopping all clients ---\n');
    clearInterval(chaosInterval);
    clearInterval(statsInterval);
    clients.forEach(c => c.stop());

    // Wait for close events to flush
    await new Promise(r => setTimeout(r, 2000));

    // Final report
    await printFinalReport();

    process.exit(0);
}

function printLiveStats() {
    const p50 = percentile(stats.latencies, 50);
    const p99 = percentile(stats.latencies, 99);
    console.log('');
    console.log(`  ── Live Stats ── Connected: ${stats.currentConnected}/${NUM_CLIENTS} | Peak: ${stats.peakConcurrent} | Errors: ${stats.totalErrors} | p50 latency: ${p50}ms | p99: ${p99}ms`);
    console.log('');
}

async function printFinalReport() {
    const p50 = percentile(stats.latencies, 50);
    const p95 = percentile(stats.latencies, 95);
    const p99 = percentile(stats.latencies, 99);
    const avg = stats.latencies.length > 0
        ? Math.round(stats.latencies.reduce((a, b) => a + b, 0) / stats.latencies.length)
        : 0;

    console.log('\n' + '='.repeat(80));
    console.log('  STRESS TEST RESULTS');
    console.log('='.repeat(80));
    console.log(`  Duration:              ${DURATION_SEC}s`);
    console.log(`  Clients:               ${NUM_CLIENTS}`);
    console.log(`  Chaos Mode:            ${CHAOS_MODE ? 'ON' : 'OFF'}`);
    console.log('');
    console.log('  ── Connections ──');
    console.log(`  Total connects:        ${stats.totalConnects}`);
    console.log(`  Total disconnects:     ${stats.totalDisconnects}`);
    console.log(`  Total reconnects:      ${stats.totalReconnects}`);
    console.log(`  Peak concurrent:       ${stats.peakConcurrent}`);
    console.log(`  Auth failures:         ${stats.totalAuthFailures}`);
    console.log(`  Errors:                ${stats.totalErrors}`);
    console.log('');
    console.log('  ── Messages ──');
    console.log(`  Sent:                  ${stats.totalMessagesSent}`);
    console.log(`  Received:              ${stats.totalMessagesReceived}`);
    console.log('');
    console.log('  ── Latency (ping/pong round-trip) ──');
    console.log(`  Samples:               ${stats.latencies.length}`);
    console.log(`  Average:               ${avg}ms`);
    console.log(`  p50:                   ${p50}ms`);
    console.log(`  p95:                   ${p95}ms`);
    console.log(`  p99:                   ${p99}ms`);
    console.log(`  Min:                   ${stats.latencies.length > 0 ? Math.min(...stats.latencies) : 0}ms`);
    console.log(`  Max:                   ${stats.latencies.length > 0 ? Math.max(...stats.latencies) : 0}ms`);
    console.log('');

    // Failure analysis
    const disconnectRate = stats.totalConnects > 0
        ? ((stats.totalDisconnects / stats.totalConnects) * 100).toFixed(1)
        : '0';
    const errorRate = stats.totalMessagesSent > 0
        ? ((stats.totalErrors / stats.totalMessagesSent) * 100).toFixed(2)
        : '0';

    console.log('  ── Health ──');
    console.log(`  Disconnect rate:       ${disconnectRate}%`);
    console.log(`  Error rate:            ${errorRate}%`);

    if (stats.totalErrors > 0 || stats.totalAuthFailures > 0) {
        console.log('');
        console.log('  !! ISSUES DETECTED:');
        if (stats.totalAuthFailures > 0) console.log(`     - ${stats.totalAuthFailures} auth failures (rate limiting or server issue)`);
        if (stats.totalErrors > 0) console.log(`     - ${stats.totalErrors} WebSocket errors`);
        if (stats.totalReconnects > NUM_CLIENTS) console.log(`     - High reconnect count (${stats.totalReconnects}) suggests instability`);
    } else {
        console.log('');
        console.log('  All clear — no errors detected.');
    }

    console.log('='.repeat(80));

    // Write event log to file
    const logFile = `stress-test-log-${Date.now()}.txt`;
    try {
        const fs = await import('fs');
        fs.writeFileSync(logFile, stats.events.join('\n') + '\n');
        console.log(`\n  Full event log written to: ${logFile}`);
    } catch (_) {
        console.log('\n  (Could not write log file)');
    }
}

function percentile(arr, p) {
    if (arr.length === 0) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)];
}

main().catch(e => {
    console.error('Stress test crashed:', e);
    process.exit(1);
});
