#!/usr/bin/env node
'use strict';

const { execFile } = require('child_process');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const os = require('os');

const ROOT = path.resolve(__dirname);
const LOCK_FILE = path.join(os.tmpdir(), 'kryptos-orchestrator.lock');
const ECOSYSTEM_FILE = path.resolve(ROOT, 'ecosystem.config.cjs');
const ENV_FILE = path.resolve(ROOT, '.env');

let LOGS_DIR;
try {
    LOGS_DIR = assertWithinRoot(path.resolve(ROOT, 'logs'));
} catch (e) {
    console.error(`FATAL: LOGS_DIR outside ROOT: ${e.message}`);
    process.exit(1);
}

const VALID_MODES = new Set(['development', 'cloud', 'local']); // [E]

const CHILD_ENV_ALLOWLIST = new Set([  // [H]
    'NODE_ENV', 'PATH', 'HOME', 'USER',
    'KRYPTOS_MODE', 'KRYPTOS_SERVER_PORT', 'KRYPTOS_BRIDGE_PORT',
    'KRYPTOS_CLIENT_PORT', 'LOG_LEVEL',
]);

const MAX_RESTARTS = 5;       // [D]
const RESTART_BASE_MS = 3000;
const _restartCounts = Object.create(null);

const SERVICES = {
    'kryptos-server': {
        port: 8080, script: 'kryptos-server.js', cwd: ROOT,
        healthUrl: 'http://127.0.0.1:8080/status',
        modes: ['cloud', 'local', 'development'], critical: true, order: 1,
    },
    'kryptos-bridge': {
        port: 3001, script: path.join('kryptos-bridge', 'bridge.js'),
        cwd: path.join(ROOT, 'kryptos-bridge'),
        healthUrl: 'http://127.0.0.1:3001/wallet',
        modes: ['cloud', 'local', 'development'], critical: false, order: 2,
    },
    'kryptos-client': {
        port: 3000, script: path.join('kryptos-client', 'server.js'),
        cwd: path.join(ROOT, 'kryptos-client'), healthUrl: null,
        modes: ['local', 'development'], critical: false, order: 3,
    },
    'kryptos-messages': {
        port: 8090, script: path.join('kryptos-messages', 'server.js'),
        cwd: path.join(ROOT, 'kryptos-messages'), healthUrl: null,
        modes: ['local', 'development'], critical: false, order: 4,
    },
    'kryptos-chain': {
        port: 4000, script: path.join('kryptos-chain', 'chain-service.js'),
        cwd: path.join(ROOT, 'kryptos-chain'), healthUrl: null,
        modes: ['cloud', 'local', 'development'], critical: false, order: 5,
    },
    'kryptos-vault': {
        port: 4001, script: path.join('kryptos-vault', 'vault-service.js'),
        cwd: path.join(ROOT, 'kryptos-vault'), healthUrl: 'http://127.0.0.1:4001/health',
        modes: ['cloud', 'local', 'development'], critical: false, order: 6,
    },
};

// ─── [R] PATH SAFETY ─────────────────────────────────────────────────────────

function assertWithinRoot(resolved) {
    if (resolved !== ROOT && !resolved.startsWith(ROOT + path.sep))
        throw new Error(`Path escapes ROOT: ${resolved}`);
    return resolved;
}

function safeScriptPath(rel) {
    return assertWithinRoot(path.resolve(ROOT, rel));
}

// ─── [P] LOCK FILE ───────────────────────────────────────────────────────────

function acquireLock() {
    if (fs.existsSync(LOCK_FILE)) {
        const pid = parseInt(fs.readFileSync(LOCK_FILE, 'utf8').trim(), 10);
        try {
            process.kill(pid, 0);
            log('error', `Orchestrator already running (PID ${pid}). Exiting.`);
            process.exit(1);
        } catch (_) {
            log('warn', `Removing stale lock (PID ${pid} gone)`);
            fs.unlinkSync(LOCK_FILE);
        }
    }
    fs.writeFileSync(LOCK_FILE, String(process.pid), { mode: 0o600 });
}

function releaseLock() {
    try {
        if (fs.existsSync(LOCK_FILE)) {
            const pid = parseInt(fs.readFileSync(LOCK_FILE, 'utf8').trim(), 10);
            if (pid === process.pid) fs.unlinkSync(LOCK_FILE);
        }
    } catch (_) { }
}

// ─── [Q] PROCESS TRACKING ────────────────────────────────────────────────────

const _children = [];
function trackChild(c) { _children.push(c); return c; }

function cleanupAndExit(code = 0) {
    log('sys', 'Cleaning up...');
    _children.forEach(c => { try { c._manualStop = true; c.kill('SIGTERM'); } catch (_) { } });
    releaseLock();
    process.exit(code);
}

// ─── LOGGING ─────────────────────────────────────────────────────────────────

const C = {
    reset: '\x1b[0m', red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
    magenta: '\x1b[35m', cyan: '\x1b[36m', gray: '\x1b[90m', bold: '\x1b[1m', dim: '\x1b[2m',
};

function log(level, msg) {
    const safe = String(msg).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, ''); // [O]
    const ts = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const icon = { info: '', warn: '', error: '', ok: '', sys: ' ', boot: '' }[level] || '';
    const col = { info: C.cyan, warn: C.yellow, error: C.red, ok: C.green, sys: C.gray, boot: C.magenta }[level] || C.reset;
    console.log(`${C.dim}[${ts}]${C.reset} ${icon} ${col}${safe}${C.reset}`);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── [A] SAFE EXEC ───────────────────────────────────────────────────────────

function safeExec(bin, args = [], cwd = ROOT, timeoutMs = 60_000) {
    return new Promise(resolve => {
        execFile(bin, args, { cwd, encoding: 'utf8', timeout: timeoutMs }, (err, stdout, stderr) => {
            resolve({ stdout: (stdout || '').trim(), stderr: (stderr || '').trim(), code: err ? (err.code || 1) : 0 });
        });
    });
}

// ─── PORT & HEALTH ───────────────────────────────────────────────────────────

function checkPort(port) {
    return new Promise(resolve => {
        const s = new net.Socket();
        s.setTimeout(2000);
        s.on('connect', () => { s.destroy(); resolve(true); });
        s.on('timeout', () => { s.destroy(); resolve(false); });
        s.on('error', () => { s.destroy(); resolve(false); });
        s.connect(port, '127.0.0.1'); // [G]
    });
}

function httpHealthCheck(url) {
    return new Promise(resolve => {
        let parsed;
        try { parsed = new URL(url); } catch (_) { resolve(false); return; }
        if (!['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname)) { // [G]
            log('warn', `Health URL rejected — non-loopback: ${parsed.hostname}`);
            resolve(false); return;
        }
        const lib = parsed.protocol === 'https:' ? https : http; // [G]
        const timer = setTimeout(() => resolve(false), 5000);
        lib.get(url, res => {
            clearTimeout(timer); res.resume();
            resolve(res.statusCode >= 200 && res.statusCode < 500);
        }).on('error', () => { clearTimeout(timer); resolve(false); });
    });
}

// ─── [K] POLL-BASED READINESS ────────────────────────────────────────────────

async function waitForService(name, svc, timeoutMs = 30_000) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const portUp = await checkPort(svc.port);
        if (portUp) {
            if (!svc.healthUrl) return true;
            if (await httpHealthCheck(svc.healthUrl)) return true;
        }
        await sleep(1000);
    }
    log('warn', `${name} not ready within ${timeoutMs / 1000}s`);
    return false;
}

// ─── ENVIRONMENT ─────────────────────────────────────────────────────────────

async function validateEnvironment() {
    log('sys', 'Validating environment...');
    const issues = [], warnings = [];

    const major = parseInt(process.version.slice(1), 10);
    if (major < 18) issues.push(`Node ${process.version} too old. Requires v18+.`);
    else log('ok', `Node.js ${process.version}`);

    const npm = await safeExec('npm', ['--version']); // [A]
    if (npm.code !== 0) issues.push('npm not found');
    else log('ok', `npm v${npm.stdout}`);

    const pm2 = await safeExec('pm2', ['--version']); // [A]
    if (pm2.code !== 0) warnings.push('PM2 not installed — will install');
    else log('ok', `PM2 v${pm2.stdout}`);

    if (!fs.existsSync(ENV_FILE)) warnings.push('.env missing — will create');
    else log('ok', '.env present');

    if (!fs.existsSync(LOGS_DIR)) {
        fs.mkdirSync(LOGS_DIR, { recursive: true, mode: 0o750 }); // [L]
        log('ok', 'Created logs/');
    }

    for (const [name, svc] of Object.entries(SERVICES)) {
        let abs;
        try { abs = safeScriptPath(svc.script); } // [R]
        catch (e) { issues.push(`Bad path for ${name}: ${e.message}`); continue; }
        if (!fs.existsSync(abs)) (svc.critical ? issues : warnings).push(`Script missing: ${name}`);
        else log('ok', `${name} found`);
    }

    return { issues, warnings };
}

async function installDependencies() {
    log('sys', 'Checking dependencies...');
    const dirs = [
        { name: 'root', dir: ROOT },
        { name: 'kryptos-bridge', dir: path.join(ROOT, 'kryptos-bridge') },
        { name: 'kryptos-client', dir: path.join(ROOT, 'kryptos-client') },
        { name: 'antigravity-network', dir: path.join(ROOT, 'antigravity-network') },
    ];
    for (const { name, dir } of dirs) {
        try { assertWithinRoot(path.resolve(dir)); } catch (_) { continue; } // [R]
        if (!fs.existsSync(path.join(dir, 'package.json'))) { log('warn', `No package.json in ${name}`); continue; }
        if (fs.existsSync(path.join(dir, 'node_modules'))) { log('ok', `Deps OK: ${name}`); continue; }
        log('sys', `Installing ${name}...`);
        const r = await safeExec('npm', ['install', '--prefer-offline'], dir, 120_000); // [A][N]
        if (r.code === 0) log('ok', `Installed: ${name}`);
        else log('error', `Install failed (${name}): ${r.stderr.slice(0, 200)}`); // [F]
    }
}

function repairEnvFile() {
    if (fs.existsSync(ENV_FILE)) {
        try {
            const count = fs.readFileSync(ENV_FILE, 'utf8').split('\n')
                .filter(l => l.trim() && !l.startsWith('#') && l.includes('=')).length;
            log('ok', `${count} env vars configured`);
        } catch (_) {
            log('error', '.env corrupted — regenerating');
            fs.renameSync(ENV_FILE, ENV_FILE + '.bak');
            createDefaultEnv();
        }
    } else {
        createDefaultEnv();
    }
}

function createDefaultEnv() {
    const secret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(ENV_FILE, [
        '# Kryptos Environment (auto-generated)',
        'KRYPTOS_MODE=development',
        'KRYPTOS_SERVER_PORT=8080',
        'KRYPTOS_BRIDGE_PORT=3001',
        'KRYPTOS_CLIENT_PORT=3000',
        `AUTH_JWT_SECRET=${secret}`,
        'ETH_RPC_URL=http://127.0.0.1:8545',
        'LOG_LEVEL=debug', '',
    ].join('\n'), { mode: 0o600 }); // [C]
    log('ok', '.env created (mode 600). Rotate AUTH_JWT_SECRET before production.'); // [C] never logs secret
}

// ─── [B] ECOSYSTEM CONFIG ────────────────────────────────────────────────────

function validateEcosystem() {
    log('sys', 'Validating ecosystem config...');
    if (!fs.existsSync(ECOSYSTEM_FILE)) { log('warn', 'ecosystem.config.cjs missing'); return false; }

    // [B] SHA-256 integrity check
    const shaFile = ECOSYSTEM_FILE + '.sha256';
    if (fs.existsSync(shaFile)) {
        const expected = fs.readFileSync(shaFile, 'utf8').trim();
        const actual = crypto.createHash('sha256').update(fs.readFileSync(ECOSYSTEM_FILE)).digest('hex');
        if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual))) {
            log('error', 'SECURITY: ecosystem.config.cjs SHA-256 mismatch — possible tampering');
            return false;
        }
        log('ok', 'Ecosystem integrity verified');
    } else {
        log('warn', 'No .sha256 sidecar. Generate: sha256sum ecosystem.config.cjs > ecosystem.config.cjs.sha256');
    }

    // [B] Parse without require() — no code execution
    try {
        const src = fs.readFileSync(ECOSYSTEM_FILE, 'utf8');
        const m = src.match(/module\.exports\s*=\s*(\{[\s\S]*\})\s*;?\s*$/);
        if (!m) { log('error', 'Cannot extract config object'); return false; }
        const cleaned = m[1]
            .replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*/g, '').replace(/,(\s*[}\]])/g, '$1');
        const config = JSON.parse(cleaned);
        if (!Array.isArray(config.apps)) { log('error', 'apps must be an array'); return false; }
        for (const app of config.apps) {
            if (typeof app.name !== 'string' || typeof app.script !== 'string') {
                log('error', 'Invalid app entry'); return false;
            }
            try { safeScriptPath(app.script); } catch (e) { // [R]
                log('error', `Path traversal in app "${app.name}": ${e.message}`); return false;
            }
        }
        log('ok', `Ecosystem valid (${config.apps.length} services)`);
        return true;
    } catch (e) { log('error', `Parse error: ${e.message}`); return false; }
}

// ─── PM2 / DIRECT START ──────────────────────────────────────────────────────

async function ensurePM2() {
    const r = await safeExec('pm2', ['--version']); // [A]
    if (r.code === 0) return true;
    log('sys', 'Installing PM2...');
    const i = await safeExec('npm', ['install', '-g', 'pm2'], ROOT, 120_000); // [A][N]
    if (i.code === 0) { log('ok', 'PM2 installed'); return true; }
    log('error', `PM2 install failed: ${i.stderr.slice(0, 200)}`); // [F]
    return false;
}

function getRunningMode() { // [E]
    for (const arg of process.argv.slice(2)) {
        if (arg.startsWith('--mode=')) {
            const v = arg.split('=')[1];
            if (VALID_MODES.has(v)) return v;
            log('error', `Invalid --mode="${v}". Allowed: ${[...VALID_MODES].join(', ')}`);
            cleanupAndExit(1);
        }
    }
    const env = process.env.KRYPTOS_MODE;
    return (env && VALID_MODES.has(env)) ? env : 'development';
}

function getServicesByMode(mode) {
    return Object.entries(SERVICES)
        .filter(([, s]) => s.modes.includes(mode))
        .sort(([, a], [, b]) => a.order - b.order);
}

function buildChildEnv(extras = {}) { // [H]
    const env = Object.create(null);
    for (const k of CHILD_ENV_ALLOWLIST) if (process.env[k] !== undefined) env[k] = process.env[k];
    return { ...env, ...extras };
}

async function startWithPM2(mode) {
    log('boot', `Starting in ${mode.toUpperCase()} mode via PM2...`);
    const services = getServicesByMode(mode);
    for (const [name] of services) await safeExec('pm2', ['delete', name]); // [A][J]
    for (const [name, svc] of services) {
        log('sys', `Starting ${name}...`);
        const r = await safeExec('pm2', [ // [A]
            'start', ECOSYSTEM_FILE, '--only', name,
            ...(mode === 'production' ? ['--env', 'production'] : []),
        ], ROOT);
        if (r.code === 0) log('ok', `${name} started`);
        else { log(svc.critical ? 'error' : 'warn', `${name} failed: ${r.stderr.slice(0, 200)}`); if (svc.critical) return false; } // [F]
        await sleep(1500);
    }
    return true;
}

async function startDirect(mode) {
    log('boot', `Starting in ${mode.toUpperCase()} mode (direct)...`);
    for (const [name, svc] of getServicesByMode(mode)) {
        let abs;
        try { abs = safeScriptPath(svc.script); } catch (e) { log('error', `Skip ${name}: ${e.message}`); continue; } // [R]
        if (!fs.existsSync(abs)) { log('warn', `Skip ${name}: not found`); continue; }
        spawnService(name, svc, abs, mode);
        await sleep(2000);
    }
    process.on('SIGINT', () => cleanupAndExit(0)); // [Q]
    process.on('SIGTERM', () => cleanupAndExit(0));
    return true;
}

function spawnService(name, svc, absScript, mode) {
    log('sys', `Spawning ${name}...`);
    const child = spawn('node', [absScript], {
        cwd: svc.cwd, stdio: 'pipe',
        env: buildChildEnv({ PORT: String(svc.port), KRYPTOS_SERVICE: name, KRYPTOS_MODE: mode }), // [H]
    });
    trackChild(child); // [Q]
    child.stdout.on('data', d => d.toString().trim().split('\n').forEach(l => log('info', `[${name}] ${l}`)));
    child.stderr.on('data', d => d.toString().trim().split('\n').forEach(l => log('error', `[${name}] ${l}`)));
    child.on('exit', code => {
        if (child._manualStop) return; // [M]
        if (code !== 0) {
            const n = (_restartCounts[name] = (_restartCounts[name] || 0) + 1); // [D]
            if (n > MAX_RESTARTS) { log('error', `${name} crashed ${n}x — giving up`); return; }
            const delay = RESTART_BASE_MS * Math.pow(2, n - 1);
            log('sys', `${name} exited (${code}). Restart ${n}/${MAX_RESTARTS} in ${delay}ms`);
            setTimeout(() => spawnService(name, svc, absScript, mode), delay); // [D][M]
        } else { _restartCounts[name] = 0; }
    });
}

// ─── HEALTH CHECKS ───────────────────────────────────────────────────────────

async function runHealthChecks(mode) {
    log('sys', 'Running health checks...');
    const results = Object.create(null); // [I]
    let allHealthy = true;
    for (const [name, svc] of getServicesByMode(mode)) {
        let abs; try { abs = safeScriptPath(svc.script); } catch (_) { continue; }
        if (!fs.existsSync(abs)) continue;
        const portReady = await checkPort(svc.port);
        const httpOk = (svc.healthUrl && portReady) ? await httpHealthCheck(svc.healthUrl) : true;
        const status = portReady && httpOk ? 'HEALTHY' : 'DOWN';
        results[name] = { port: svc.port, portReady, httpOk, status };
        if (status === 'HEALTHY') log('ok', `${name} → ${svc.port} ✓`);
        else log('error', `${name} → ${portReady ? 'port OK' : 'UNREACHABLE'}`);
        if (status !== 'HEALTHY') allHealthy = false;
    }
    return { results, allHealthy };
}

async function showStatus() {
    const r = await safeExec('pm2', ['jlist']); // [A]
    if (r.code !== 0 || !r.stdout) { log('warn', 'PM2 not running'); return; }
    try {
        const raw = JSON.parse(r.stdout);
        if (!Array.isArray(raw)) throw new Error('Expected array');
        const procs = raw.map(p => ({ // [I] whitelist fields
            name: String(p.name || '').slice(0, 64),
            status: String(p.pm2_env?.status || 'unknown').slice(0, 20),
            memory: Number(p.monit?.memory || 0),
            cpu: Number(p.monit?.cpu || 0),
            restarts: Number(p.pm2_env?.restart_time || 0),
        }));
        console.log(`\n${C.bold}╔══════════════════════════════════════════════════╗`);
        console.log(`║         Kryptos Service Status                  ║`);
        console.log(`╠══════════════════════════════════════════════════╣${C.reset}`);
        for (const p of procs) {
            const icon = p.status === 'online' ? '' : p.status === 'errored' ? '' : '';
            const mem = `${Math.round(p.memory / 1024 / 1024)}MB`;
            // [O] all values sanitized through whitelist map above
            console.log(`${C.bold}║${C.reset} ${icon} ${p.name.padEnd(20)} ${p.status.padEnd(10)} MEM:${mem.padEnd(7)} CPU:${String(p.cpu).padEnd(3)}% ↻${p.restarts}`);
        }
        console.log(`${C.bold}╚══════════════════════════════════════════════════╝${C.reset}\n`);
    } catch (e) {
        log('error', `PM2 parse failed: ${e.message}`);
        const list = await safeExec('pm2', ['list']); // [A]
        if (list.code === 0) console.log(list.stdout);
    }
}

function showBanner(mode) {
    const safe = VALID_MODES.has(mode) ? mode : 'unknown'; // [O]
    console.log(`\n${C.cyan}${C.bold}`);
    console.log('  ╔══════════════════════════════════════════════════════╗');
    console.log('  ║         Kryptos Decentralized Infrastructure        ║');
    console.log(`  ║         Mode: ${safe.toUpperCase().padEnd(38)}║`);
    console.log(`  ╚══════════════════════════════════════════════════════╝${C.reset}\n`);
}

// ─── MAIN ────────────────────────────────────────────────────────────────────

async function main() {
    const args = process.argv.slice(2);
    const mode = getRunningMode(); // [E]

    acquireLock(); // [P]
    process.on('exit', releaseLock);
    process.on('SIGINT', () => cleanupAndExit(0));
    process.on('SIGTERM', () => cleanupAndExit(0));
    process.on('uncaughtException', e => { log('error', `Uncaught: ${e.message}`); cleanupAndExit(1); });

    if (args.includes('--status')) { await showStatus(); releaseLock(); return; }
    if (args.includes('--health')) { const { allHealthy } = await runHealthChecks(mode); cleanupAndExit(allHealthy ? 0 : 1); }
    if (args.includes('--stop')) {
        for (const [name] of getServicesByMode(mode)) await safeExec('pm2', ['delete', name]); // [A][J]
        log('ok', 'Services stopped'); cleanupAndExit(0);
    }

    showBanner(mode);

    log('boot', 'STEP 1/6: Validate'); const { issues, warnings } = await validateEnvironment();
    warnings.forEach(w => log('warn', w)); issues.forEach(i => log('error', i));

    log('boot', 'STEP 2/6: Repair env'); repairEnvFile();
    log('boot', 'STEP 3/6: Dependencies'); await installDependencies();
    log('boot', 'STEP 4/6: Ecosystem'); const ecosystemValid = validateEcosystem(); // [B]
    log('boot', 'STEP 5/6: Start'); const hasPM2 = await ensurePM2();

    const started = (hasPM2 && ecosystemValid) ? await startWithPM2(mode) : await startDirect(mode);
    if (!started) { log('error', 'Failed to start'); cleanupAndExit(1); } // [Q]

    log('boot', 'STEP 6/6: Health');
    for (const [name, svc] of getServicesByMode(mode)) { // [K]
        let abs; try { abs = safeScriptPath(svc.script); } catch (_) { continue; }
        if (fs.existsSync(abs)) await waitForService(name, svc, 30_000);
    }

    const { results, allHealthy } = await runHealthChecks(mode);
    if (allHealthy) {
        console.log(`\n${C.green}${C.bold}  ╔══════════════════════════════════════════╗`);
        console.log(`  ║       KRYPTOS IS READY                ║`);
        console.log(`  ║  Server:  http://localhost:8080          ║`);
        console.log(`  ║  Bridge:  http://localhost:3001          ║`);
        console.log(`  ║  Client:  http://localhost:3000          ║`);
        console.log(`  ║  Stop:    node orchestrator --stop       ║`);
        console.log(`  ╚══════════════════════════════════════════╝${C.reset}\n`);
    } else {
        log('warn', 'Some services unhealthy:');
        for (const [n, r] of Object.entries(results)) if (r.status !== 'HEALTHY') log('warn', `  pm2 logs ${n}`);
    }
    if (hasPM2) await showStatus();
}

main().catch(e => { log('error', `Crashed: ${e.message}`); cleanupAndExit(1); });