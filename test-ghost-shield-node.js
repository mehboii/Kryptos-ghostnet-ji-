/**
 * Ghost Shield — Node.js Test Runner
 * Simulates browser globals and runs all testable logic.
 */

// ── Simulate browser globals ────────────────────────────────────
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Mock window, localStorage, document, crypto, WebSocket, CustomEvent
const storage = {};
global.window = {
    ShieldConfig: null,
    GhostShield: null,
    SignalIntelligence: null,
    GhostRadar: null,
    SignalIntelService: null,
    GhostMesh: null,
    app: null,
    fetch: async () => ({ ok: false }),
    location: { origin: 'https://localhost' },
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
    Capacitor: undefined,
};
global.localStorage = {
    _data: {},
    getItem(k) { return this._data[k] || null; },
    setItem(k, v) { this._data[k] = String(v); },
    removeItem(k) { delete this._data[k]; },
};
global.sessionStorage = global.localStorage;
global.document = {
    addEventListener: (evt, cb) => { if (evt === 'DOMContentLoaded') setTimeout(cb, 10); },
    getElementById: () => null,
    querySelector: () => null,
    head: { appendChild: () => {} },
    createElement: () => ({ textContent: '', className: '', id: '', innerHTML: '', appendChild: () => {}, style: {} }),
};
// Node 20+ has global crypto; patch getRandomValues if missing
if (!global.crypto.getRandomValues) {
    Object.defineProperty(global, 'crypto', {
        value: {
            getRandomValues: (arr) => { const buf = crypto.randomBytes(arr.length); arr.set(buf); return arr; },
            randomUUID: () => crypto.randomUUID(),
        }
    });
}
global.WebSocket = class MockWebSocket {
    constructor() { this.readyState = 1; }
    send() {}
    close() {}
    static OPEN = 1;
};
global.CustomEvent = class CustomEvent {
    constructor(type, opts) { this.type = type; this.detail = opts?.detail; }
};
global.URL = URL;
global.Headers = class Headers {
    constructor(init) { this._h = init || {}; }
    set(k, v) { this._h[k] = v; }
};
global.Request = class Request { constructor(url) { this.url = url; } };
global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
global.navigator = { bluetooth: null, connection: null };

// ── Load scripts by eval ─────────────────────────────────────────
async function loadScript(filename) {
    try {
        // Controlled dynamic import of the script by file URL (no arbitrary eval).
        // The scripts attach their API to the global `window` as a side effect.
        await import(pathToFileURL(path.join(__dirname, filename)).href);
    } catch (e) {
        console.error(`  ERROR loading ${filename}: ${e.message}`);
    }
}

await loadScript('shieldConfig.js');
await loadScript('signal-intelligence.js');
await loadScript('ghost-shield.js');

// ── Test framework ───────────────────────────────────────────────
let passed = 0, failed = 0, skipped = 0;
const RED = '\x1b[31m', GREEN = '\x1b[32m', YELLOW = '\x1b[33m', CYAN = '\x1b[36m', RESET = '\x1b[0m', BOLD = '\x1b[1m';

function assert(name, condition, detail) {
    if (condition) {
        passed++;
        console.log(`  ${GREEN}PASS${RESET} ${name}${detail ? ` ${CYAN}(${detail})${RESET}` : ''}`);
    } else {
        failed++;
        console.log(`  ${RED}FAIL${RESET} ${name}${detail ? ` ${RED}(${detail})${RESET}` : ''}`);
    }
}

function skip(name, reason) {
    skipped++;
    console.log(`  ${YELLOW}SKIP${RESET} ${name} — ${reason}`);
}

// ═══════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════

console.log(`\n${BOLD}${CYAN}═══ Ghost Shield Test Suite ═══${RESET}\n`);

// ── ShieldConfig ──────────────────────────────────────────────
console.log(`${BOLD}ShieldConfig${RESET}`);

const cfg = window.ShieldConfig;
assert('ShieldConfig exists', !!cfg);
if (cfg) {
    assert('stealth.dohUrl defined', typeof cfg.stealth.dohUrl === 'string' && cfg.stealth.dohUrl.includes('cloudflare'), cfg.stealth.dohUrl);
    assert('stealth.dohFallbackUrl defined', typeof cfg.stealth.dohFallbackUrl === 'string');
    assert('ghost.paddingMinBytes = 128', cfg.ghost.paddingMinBytes === 128);
    assert('ghost.paddingMaxBytes = 512', cfg.ghost.paddingMaxBytes === 512);
    assert('ghost.timingDelayMinMs = 100', cfg.ghost.timingDelayMinMs === 100);
    assert('ghost.timingDelayMaxMs = 2000', cfg.ghost.timingDelayMaxMs === 2000);
    assert('ghost.dummyPacketIntervalMs = 3000', cfg.ghost.dummyPacketIntervalMs === 3000);
    assert('ghost.dummyPacketSize = 256', cfg.ghost.dummyPacketSize === 256);
    assert('phantom.decoyIntervalMs = 5000', cfg.phantom.decoyIntervalMs === 5000);
    assert('phantom.decoyNames has 12 entries', cfg.phantom.decoyNames.length === 12);
    assert('phantom.decoyServiceUUIDs has 6 entries', cfg.phantom.decoyServiceUUIDs.length === 6);
    assert('phantom.macRotationIntervalMs = 300000', cfg.phantom.macRotationIntervalMs === 300000);
    assert('phantom.forcedMaxHops = 7', cfg.phantom.forcedMaxHops === 7);
    assert('signalIntel.scanIntervalMs = 15000', cfg.signalIntel.scanIntervalMs === 15000);
    assert('storage keys defined', typeof cfg.storage.shieldStateKey === 'string' && typeof cfg.storage.blockedMacsKey === 'string');

    // Frozen test
    let frozen = true;
    try { cfg.stealth.dohUrl = 'hacked'; if (cfg.stealth.dohUrl === 'hacked') frozen = false; } catch (_) {}
    assert('config is frozen (immutable)', frozen);
}

// ── GhostShield Engine ────────────────────────────────────────
console.log(`\n${BOLD}GhostShield Engine${RESET}`);

const gs = window.GhostShield;
assert('GhostShield exists', !!gs);
if (gs) {
    gs.disableAll();

    // Initial state
    assert('initial level = 0', gs.getStatus().level === 0);
    assert('initial isActive = false', gs.isActive() === false);
    assert('initial activeStates all false', !gs.getStatus().activeStates[1] && !gs.getStatus().activeStates[2] && !gs.getStatus().activeStates[3]);

    // Enable Level 1
    gs.enable(1);
    assert('L1 enables', gs.getStatus().activeStates[1] === true);
    assert('level = 1', gs.getStatus().level === 1);
    assert('isActive = true', gs.isActive() === true);

    // Enable Level 2
    gs.enable(2);
    assert('L2 enables', gs.getStatus().activeStates[2] === true);
    assert('level = 2', gs.getStatus().level === 2);

    // Enable Level 3
    gs.enable(3);
    assert('L3 enables', gs.getStatus().activeStates[3] === true);
    assert('currentLevel = ALL', gs.getStatus().currentLevel === 'ALL');

    // Toggle off
    gs.enable(2);
    assert('toggle L2 off', gs.getStatus().activeStates[2] === false);
    assert('L1 + L3 still active', gs.getStatus().activeStates[1] && gs.getStatus().activeStates[3]);

    // disableAll
    gs.disableAll();
    assert('disableAll → level 0', gs.getStatus().level === 0);
    assert('disableAll → inactive', gs.isActive() === false);

    // enableAll
    gs.enableAll();
    assert('enableAll → all active', gs.getStatus().activeStates[1] && gs.getStatus().activeStates[2] && gs.getStatus().activeStates[3]);
    assert('enableAll → currentLevel ALL', gs.getStatus().currentLevel === 'ALL');

    // Block/unblock
    gs.blockDevice('AA:BB:CC:DD:EE:FF');
    assert('blockDevice adds MAC', gs.blockedMacs.has('AA:BB:CC:DD:EE:FF'));
    assert('devicesBlocked = 1', gs.getStatus().stats.devicesBlocked === 1);
    gs.unblockDevice('AA:BB:CC:DD:EE:FF');
    assert('unblockDevice removes MAC', !gs.blockedMacs.has('AA:BB:CC:DD:EE:FF'));

    // Invalid levels
    gs.disableAll();
    gs.enable(5);
    assert('invalid level 5 ignored', gs.getStatus().level === 0);
    gs.enable(0);
    assert('invalid level 0 ignored', gs.getStatus().level === 0);

    // Uptime
    gs.enableAll();
    assert('startTime set when active', gs.startTime !== null);
    assert('uptime >= 0', gs.getStatus().stats.uptime >= 0);

    // _secureId
    const id1 = gs._secureId('test_');
    assert('_secureId has prefix', id1.startsWith('test_'));
    assert('_secureId length = 21', id1.length === 21, id1);
    const ids = new Set();
    for (let i = 0; i < 1000; i++) ids.add(gs._secureId('x_'));
    assert('1000 secureIds unique', ids.size === 1000);

    // _randomMAC
    const mac = gs._randomMAC();
    const macRe = /^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$/;
    assert('_randomMAC valid format', macRe.test(mac), mac);
    const firstOctet = parseInt(mac.substring(0, 2), 16);
    assert('locally administered bit set', (firstOctet & 0x02) !== 0);
    assert('multicast bit cleared', (firstOctet & 0x01) === 0);
    const macs = new Set();
    for (let i = 0; i < 100; i++) macs.add(gs._randomMAC());
    assert('100 MACs unique', macs.size === 100);

    // _randomHex
    const hex = gs._randomHex(16);
    assert('_randomHex(16) = 32 hex chars', hex.length === 32 && /^[0-9a-f]+$/.test(hex));

    gs.disableAll();
}

// ── Persistence ───────────────────────────────────────────────
console.log(`\n${BOLD}Persistence${RESET}`);

if (gs && cfg) {
    gs.disableAll();
    global.localStorage._data = {};

    gs.enableAll();
    gs.blockDevice('11:22:33:44:55:66');
    const stored = global.localStorage.getItem(cfg.storage.shieldStateKey);
    assert('state saved to localStorage', stored !== null);

    let parsed;
    try { parsed = JSON.parse(stored); } catch (_) {}
    assert('stored state is valid JSON', !!parsed);
    assert('stored L1 = true', parsed?.activeStates?.[1] === true);
    assert('stored L2 = true', parsed?.activeStates?.[2] === true);
    assert('stored L3 = true', parsed?.activeStates?.[3] === true);
    assert('blocked MAC persisted', parsed?.blockedMacs?.includes('11:22:33:44:55:66'));
    assert('savedAt timestamp present', typeof parsed?.savedAt === 'number');

    gs.unblockDevice('11:22:33:44:55:66');
    gs.disableAll();
}

// ── MAC Rotation ──────────────────────────────────────────────
console.log(`\n${BOLD}MAC Rotation${RESET}`);

if (gs) {
    gs.disableAll();
    const rotsBefore = gs.stats.macRotations;
    gs.enableLevel(3);
    assert('macRotations incremented after L3', gs.stats.macRotations > rotsBefore, `before: ${rotsBefore}, after: ${gs.stats.macRotations}`);
    gs.disableAll();
}

// ── Intervals Management ──────────────────────────────────────
console.log(`\n${BOLD}Intervals Management${RESET}`);

if (gs) {
    gs.disableAll();
    gs._intervals = { global: [], ghost: [], phantom: [] };

    gs.enableLevel(2);
    assert('ghost intervals created on L2 enable', gs._intervals.ghost.length > 0, `${gs._intervals.ghost.length} intervals`);
    gs.disableLevel(2);
    assert('ghost intervals cleared on L2 disable', gs._intervals.ghost.length === 0);

    gs.enableLevel(3);
    assert('phantom intervals created on L3 enable', gs._intervals.phantom.length > 0, `${gs._intervals.phantom.length} intervals`);
    gs.disableLevel(3);
    assert('phantom intervals cleared on L3 disable', gs._intervals.phantom.length === 0);

    gs.disableAll();
}

// ── Signal Intelligence ───────────────────────────────────────
console.log(`\n${BOLD}Signal Intelligence${RESET}`);

const si = window.SignalIntelligence;
assert('SignalIntelligence exists', !!si);

if (si) {
    si.signals.clear();

    // Safe device
    const safe = si.processSignal({ mac: 'A2:B3:C4:D5:E6:F7', rssi: -75, name: 'iPhone 15', hasBLE: true, hasWiFi: true });
    assert('safe device processed', safe !== null);
    assert('safe → type Smartphone', safe?.type === 'Smartphone', safe?.type);
    assert('safe → threatLevel ALLOWED', safe?.threatLevel === 'ALLOWED');
    assert('safe → score low', safe?.threatScore < 30, `score: ${safe?.threatScore}`);

    // Threat device
    const threat = si.processSignal({ mac: '00:1A:2B:3C:4D:5E', rssi: -25, name: '', channels: [1, 6, 11] });
    assert('threat device processed', threat !== null);
    assert('threat → score > 60', threat?.threatScore > 60, `score: ${threat?.threatScore}`);
    assert('threat → threatLevel WARNING', threat?.threatLevel === 'WARNING');
    assert('threat → MULTI_CHANNEL flag', threat?.interferenceFlags?.includes('MULTI_CHANNEL_BROADCAST'));

    // GhostNode
    const node = si.processSignal({ mac: '0xa752f1234567', rssi: -50, isGhostNode: true });
    assert('GhostNode → score = 0', node?.threatScore === 0);
    assert('GhostNode → type = "Kryptos Node"', node?.type === 'Kryptos Node');
    assert('GhostNode → threatLevel ALLOWED', node?.threatLevel === 'ALLOWED');

    // Report
    const report = si.getSignalReport();
    assert('report has 3 entries', report.length === 3);
    assert('report sorted by RSSI desc', report[0].rssi >= report[1].rssi);

    // Overall threat
    assert('getThreatLevel = ELEVATED', si.getThreatLevel() === 'ELEVATED');

    // Interference
    assert('getInterference found', si.getInterference().length > 0);

    // Known OUI detection
    const oui = si.processSignal({ mac: '00:1A:11:AA:BB:CC', rssi: -60, name: '' });
    assert('known surveillance OUI boosts score', oui?.threatScore >= 40, `score: ${oui?.threatScore}`);

    si.signals.clear();
}

// ═══════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════

console.log(`\n${BOLD}${'═'.repeat(50)}${RESET}`);
const total = passed + failed + skipped;
if (failed === 0) {
    console.log(`${GREEN}${BOLD}ALL ${passed}/${total} TESTS PASSED${RESET} (${skipped} skipped)`);
} else {
    console.log(`${RED}${BOLD}${failed} FAILED${RESET} | ${GREEN}${passed} passed${RESET} | ${YELLOW}${skipped} skipped${RESET} | ${total} total`);
}
console.log(`${'═'.repeat(50)}\n`);

process.exit(failed > 0 ? 1 : 0);
