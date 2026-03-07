#!/usr/bin/env node
/**
 * ╔══════════════════════════════════════════════════════╗
 * ║        GhostNet Infrastructure Orchestrator          ║
 * ║   Self-healing multi-service decentralized runtime   ║
 * ╚══════════════════════════════════════════════════════╝
 * 
 * Responsibilities:
 *  1. Validate environment & configuration
 *  2. Ensure dependencies are installed
 *  3. Generate/repair PM2 ecosystem config
 *  4. Start all services in correct order
 *  5. Run health checks before marking READY
 *  6. Monitor & auto-recover failed services
 * 
 * Usage:
 *   node ghostnet-orchestrator.cjs                  → development mode
 *   node ghostnet-orchestrator.cjs --mode=cloud     → cloud mode
 *   node ghostnet-orchestrator.cjs --mode=local     → local node mode
 *   node ghostnet-orchestrator.cjs --health         → health check only
 *   node ghostnet-orchestrator.cjs --status         → show service status
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');
const net = require('net');

// ─── CONSTANTS ──────────────────────────────────────────
const ROOT = __dirname;
const LOGS_DIR = path.join(ROOT, 'logs');
const ENV_FILE = path.join(ROOT, '.env');
const ECOSYSTEM_FILE = path.join(ROOT, 'ecosystem.config.cjs');

const SERVICES = {
    'ghostnet-server': {
        port: 8080,
        script: path.join(ROOT, 'ghostnet-server.js'),
        cwd: ROOT,
        healthUrl: 'http://127.0.0.1:8080/status',
        modes: ['cloud', 'local', 'development'],
        critical: true,
        order: 1
    },
    'ghostnet-bridge': {
        port: 3001,
        script: path.join(ROOT, 'ghostnet-bridge', 'bridge.js'),
        cwd: path.join(ROOT, 'ghostnet-bridge'),
        healthUrl: 'http://127.0.0.1:3001/wallet',
        modes: ['cloud', 'local', 'development'],
        critical: false,
        order: 2
    },
    'ghostnet-client': {
        port: 3000,
        script: path.join(ROOT, 'ghostnet-client', 'server.js'),
        cwd: path.join(ROOT, 'ghostnet-client'),
        healthUrl: null, // static file server, check port only
        modes: ['local', 'development'],
        critical: false,
        order: 3
    },
    'ghostnet-messages': {
        port: 8090,
        script: path.join(ROOT, 'ghostnet-messages', 'server.js'),
        cwd: path.join(ROOT, 'ghostnet-messages'),
        healthUrl: null,
        modes: ['local', 'development'],
        critical: false,
        order: 4
    }
};

// ─── HELPERS ────────────────────────────────────────────

const COLORS = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    gray: '\x1b[90m',
    bold: '\x1b[1m',
    dim: '\x1b[2m'
};

function log(level, msg, ...args) {
    const ts = new Date().toISOString().replace('T', ' ').substr(0, 19);
    const icons = { info: '🔵', warn: '🟡', error: '🔴', ok: '🟢', sys: '⚙️ ', boot: '🚀' };
    const colors = { info: COLORS.cyan, warn: COLORS.yellow, error: COLORS.red, ok: COLORS.green, sys: COLORS.gray, boot: COLORS.magenta };
    const icon = icons[level] || '📋';
    const color = colors[level] || COLORS.reset;
    console.log(`${COLORS.dim}[${ts}]${COLORS.reset} ${icon} ${color}${msg}${COLORS.reset}`, ...args);
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

function shellExec(cmd, cwd = ROOT) {
    try {
        return execSync(cmd, { cwd, encoding: 'utf8', stdio: 'pipe', timeout: 60000 }).trim();
    } catch (e) {
        return null;
    }
}

// ─── PORT CHECKER ───────────────────────────────────────

function checkPort(port, host = '127.0.0.1') {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(2000);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.on('error', () => { socket.destroy(); resolve(false); });
        socket.connect(port, host);
    });
}

// ─── HTTP HEALTH CHECK ──────────────────────────────────

function httpHealthCheck(url) {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(false), 5000);
        http.get(url, (res) => {
            clearTimeout(timeout);
            resolve(res.statusCode >= 200 && res.statusCode < 500);
        }).on('error', () => {
            clearTimeout(timeout);
            resolve(false);
        });
    });
}

// ─── ENVIRONMENT VALIDATION ─────────────────────────────

function validateEnvironment() {
    log('sys', 'Validating environment...');
    const issues = [];
    const warnings = [];

    // Node.js version
    const nodeVersion = process.version;
    const major = parseInt(nodeVersion.slice(1));
    if (major < 18) {
        issues.push(`Node.js ${nodeVersion} is too old. GhostNet requires v18+.`);
    } else {
        log('ok', `Node.js ${nodeVersion}`);
    }

    // npm
    const npmVer = shellExec('npm --version');
    if (!npmVer) {
        issues.push('npm not found in PATH');
    } else {
        log('ok', `npm v${npmVer}`);
    }

    // PM2
    const pm2Ver = shellExec('pm2 --version');
    if (!pm2Ver) {
        warnings.push('PM2 not installed. Will attempt to install.');
    } else {
        log('ok', `PM2 v${pm2Ver}`);
    }

    // .env file
    if (!fs.existsSync(ENV_FILE)) {
        warnings.push('.env file missing. Will create from .env.example');
    } else {
        log('ok', '.env file exists');
    }

    // logs directory
    if (!fs.existsSync(LOGS_DIR)) {
        fs.mkdirSync(LOGS_DIR, { recursive: true });
        log('ok', 'Created logs/ directory');
    }

    // Check each service script exists
    for (const [name, svc] of Object.entries(SERVICES)) {
        if (!fs.existsSync(svc.script)) {
            if (svc.critical) {
                issues.push(`Critical script missing: ${svc.script}`);
            } else {
                warnings.push(`Optional script missing: ${name} → ${svc.script}`);
            }
        } else {
            log('ok', `${name} script found`);
        }
    }

    // Check each service has node_modules
    const serviceDirs = [ROOT, path.join(ROOT, 'ghostnet-bridge'), path.join(ROOT, 'ghostnet-client')];
    for (const dir of serviceDirs) {
        const pkgJson = path.join(dir, 'package.json');
        const nodeModules = path.join(dir, 'node_modules');
        if (fs.existsSync(pkgJson) && !fs.existsSync(nodeModules)) {
            warnings.push(`Missing node_modules in ${path.basename(dir) || 'root'}. Will install.`);
        }
    }

    return { issues, warnings };
}

// ─── DEPENDENCY INSTALLER ───────────────────────────────

function installDependencies() {
    log('sys', 'Checking dependencies...');

    const dirs = [
        { name: 'root', dir: ROOT },
        { name: 'ghostnet-bridge', dir: path.join(ROOT, 'ghostnet-bridge') },
        { name: 'ghostnet-client', dir: path.join(ROOT, 'ghostnet-client') },
        { name: 'antigravity-network', dir: path.join(ROOT, 'antigravity-network') }
    ];

    for (const { name, dir } of dirs) {
        const pkgJson = path.join(dir, 'package.json');
        const nodeModules = path.join(dir, 'node_modules');

        if (!fs.existsSync(pkgJson)) {
            log('warn', `No package.json in ${name}, skipping`);
            continue;
        }

        if (!fs.existsSync(nodeModules)) {
            log('sys', `Installing dependencies for ${name}...`);
            const result = shellExec('npm install --prefer-offline', dir);
            if (result !== null) {
                log('ok', `Dependencies installed for ${name}`);
            } else {
                log('error', `Failed to install dependencies for ${name}`);
            }
        } else {
            log('ok', `Dependencies OK for ${name}`);
        }
    }
}

// ─── ENV FILE REPAIR ────────────────────────────────────

function repairEnvFile() {
    if (fs.existsSync(ENV_FILE)) {
        log('ok', '.env file present');

        // Validate it can be parsed
        try {
            const content = fs.readFileSync(ENV_FILE, 'utf8');
            const lines = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
            const vars = {};
            for (const line of lines) {
                const [key] = line.split('=');
                if (key) vars[key.trim()] = true;
            }
            log('ok', `${Object.keys(vars).length} environment variables configured`);
        } catch (e) {
            log('error', '.env file corrupted, backing up and regenerating');
            fs.renameSync(ENV_FILE, ENV_FILE + '.bak');
            createDefaultEnv();
        }
    } else {
        log('warn', '.env file missing, creating default');
        createDefaultEnv();
    }
}

function createDefaultEnv() {
    const template = `# GhostNet Environment (auto-generated)
GHOSTNET_MODE=development
GHOSTNET_SERVER_PORT=8080
GHOSTNET_BRIDGE_PORT=3001
GHOSTNET_CLIENT_PORT=3000
AUTH_JWT_SECRET=${require('crypto').randomBytes(32).toString('hex')}
ETH_RPC_URL=http://127.0.0.1:8545
LOG_LEVEL=debug
`;
    fs.writeFileSync(ENV_FILE, template);
    log('ok', '.env file created with secure defaults');
}

// ─── ECOSYSTEM CONFIG VALIDATOR ─────────────────────────

function validateEcosystem() {
    log('sys', 'Validating PM2 ecosystem config...');

    if (!fs.existsSync(ECOSYSTEM_FILE)) {
        log('warn', 'ecosystem.config.cjs missing — will be auto-generated');
        return false;
    }

    try {
        // Clear require cache to get fresh config
        delete require.cache[require.resolve(ECOSYSTEM_FILE)];
        const config = require(ECOSYSTEM_FILE);

        if (!config || !config.apps || !Array.isArray(config.apps)) {
            log('error', 'Invalid ecosystem config structure');
            return false;
        }

        for (const app of config.apps) {
            if (!app.name || !app.script) {
                log('error', `Invalid app entry: missing name or script`);
                return false;
            }
            if (!fs.existsSync(app.script)) {
                log('warn', `Script not found for ${app.name}: ${app.script}`);
            }
        }

        log('ok', `Ecosystem config valid (${config.apps.length} services)`);
        return true;
    } catch (e) {
        log('error', `Ecosystem config parse error: ${e.message}`);
        return false;
    }
}

// ─── PM2 MANAGEMENT ─────────────────────────────────────

function ensurePM2() {
    const pm2Ver = shellExec('pm2 --version');
    if (!pm2Ver) {
        log('sys', 'Installing PM2 globally...');
        const result = shellExec('npm install -g pm2');
        if (result !== null) {
            log('ok', 'PM2 installed');
        } else {
            log('error', 'Failed to install PM2. Falling back to direct process management.');
            return false;
        }
    }
    return true;
}

function getRunningMode() {
    const args = process.argv.slice(2);
    for (const arg of args) {
        if (arg.startsWith('--mode=')) {
            return arg.split('=')[1];
        }
    }
    return process.env.GHOSTNET_MODE || 'development';
}

function getServicesByMode(mode) {
    const entries = Object.entries(SERVICES)
        .filter(([_, svc]) => svc.modes.includes(mode))
        .sort(([, a], [, b]) => a.order - b.order);
    return entries;
}

async function startWithPM2(mode) {
    log('boot', `Starting GhostNet in ${COLORS.bold}${mode.toUpperCase()}${COLORS.reset} mode via PM2...`);

    const services = getServicesByMode(mode);

    // First stop any existing instances
    shellExec('pm2 delete all 2>&1');

    for (const [name, svc] of services) {
        log('sys', `Starting ${name} on port ${svc.port}...`);

        const envArg = mode === 'production' ? '--env production' : '';
        const result = shellExec(`pm2 start "${ECOSYSTEM_FILE}" --only ${name} ${envArg}`, ROOT);

        if (result !== null) {
            log('ok', `${name} → started`);
        } else {
            if (svc.critical) {
                log('error', `CRITICAL: ${name} failed to start!`);
                return false;
            } else {
                log('warn', `${name} failed to start (non-critical, continuing)`);
            }
        }

        // Stagger starts to avoid port conflicts
        await sleep(1500);
    }

    return true;
}

async function startDirect(mode) {
    log('boot', `Starting GhostNet in ${COLORS.bold}${mode.toUpperCase()}${COLORS.reset} mode (direct process)...`);

    const services = getServicesByMode(mode);
    const processes = [];

    for (const [name, svc] of services) {
        if (!fs.existsSync(svc.script)) {
            log('warn', `Skipping ${name}: script not found`);
            continue;
        }

        log('sys', `Starting ${name} on port ${svc.port}...`);

        const child = spawn('node', [svc.script], {
            cwd: svc.cwd,
            stdio: 'pipe',
            env: { ...process.env, PORT: String(svc.port), GHOSTNET_SERVICE: name }
        });

        child.stdout.on('data', (d) => {
            const lines = d.toString().trim().split('\n');
            lines.forEach(l => log('info', `[${name}] ${l}`));
        });

        child.stderr.on('data', (d) => {
            const lines = d.toString().trim().split('\n');
            lines.forEach(l => log('error', `[${name}] ${l}`));
        });

        child.on('exit', (code) => {
            if (code !== 0) {
                log('error', `${name} exited with code ${code}`);
                // Auto-restart if not manually stopped
                if (!child._manualStop) {
                    log('sys', `Auto-restarting ${name} in 3s...`);
                    setTimeout(() => {
                        startDirect(mode); // simplified restart
                    }, 3000);
                }
            }
        });

        processes.push({ name, child });
        await sleep(2000);
    }

    // Handle graceful shutdown
    const shutdown = () => {
        log('sys', 'Shutting down all services...');
        processes.forEach(({ name, child }) => {
            child._manualStop = true;
            child.kill('SIGTERM');
            log('sys', `Stopped ${name}`);
        });
        process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    return true;
}

// ─── HEALTH CHECKS ──────────────────────────────────────

async function runHealthChecks(mode) {
    log('sys', 'Running health checks...');
    const services = getServicesByMode(mode);
    const results = {};
    let allHealthy = true;

    for (const [name, svc] of services) {
        if (!fs.existsSync(svc.script)) continue;

        // Check port
        const portReady = await checkPort(svc.port);

        // Check HTTP health endpoint if available
        let httpOk = true;
        if (svc.healthUrl && portReady) {
            httpOk = await httpHealthCheck(svc.healthUrl);
        }

        const status = portReady && httpOk ? 'HEALTHY' : 'DOWN';
        results[name] = { port: svc.port, portReady, httpOk, status };

        if (status === 'HEALTHY') {
            log('ok', `${name} → port ${svc.port} ✓ ${svc.healthUrl ? 'HTTP ✓' : ''}`);
        } else {
            log('error', `${name} → ${portReady ? 'port OK' : 'port UNREACHABLE'} ${svc.healthUrl ? (httpOk ? 'HTTP ✓' : 'HTTP ✗') : ''}`);
            allHealthy = false;
        }
    }

    return { results, allHealthy };
}

// ─── STATUS DISPLAY ─────────────────────────────────────

function showStatus() {
    log('sys', 'Querying PM2 status...');
    const result = shellExec('pm2 jlist');
    if (!result) {
        log('warn', 'PM2 not running or no processes');
        return;
    }

    try {
        const procs = JSON.parse(result);
        console.log('');
        console.log(`${COLORS.bold}╔══════════════════════════════════════════════════╗${COLORS.reset}`);
        console.log(`${COLORS.bold}║         GhostNet Service Status                  ║${COLORS.reset}`);
        console.log(`${COLORS.bold}╠══════════════════════════════════════════════════╣${COLORS.reset}`);

        for (const proc of procs) {
            const status = proc.pm2_env.status;
            const icon = status === 'online' ? '🟢' : status === 'errored' ? '🔴' : '🟡';
            const mem = proc.monit ? `${Math.round(proc.monit.memory / 1024 / 1024)}MB` : 'N/A';
            const cpu = proc.monit ? `${proc.monit.cpu}%` : 'N/A';
            const restarts = proc.pm2_env.restart_time || 0;

            console.log(`${COLORS.bold}║${COLORS.reset} ${icon} ${proc.name.padEnd(20)} ${status.padEnd(10)} MEM: ${mem.padEnd(8)} CPU: ${cpu.padEnd(6)} ↻ ${restarts}`);
        }

        console.log(`${COLORS.bold}╚══════════════════════════════════════════════════╝${COLORS.reset}`);
        console.log('');
    } catch (e) {
        const table = shellExec('pm2 list');
        if (table) console.log(table);
    }
}

// ─── BANNER ─────────────────────────────────────────────

function showBanner(mode) {
    console.log('');
    console.log(`${COLORS.cyan}${COLORS.bold}`);
    console.log('  ╔══════════════════════════════════════════════════════╗');
    console.log('  ║                                                      ║');
    console.log('  ║     ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗       ║');
    console.log('  ║    ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝       ║');
    console.log('  ║    ██║  ███╗███████║██║   ██║███████╗   ██║          ║');
    console.log('  ║    ██║   ██║██╔══██║██║   ██║╚════██║   ██║          ║');
    console.log('  ║    ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║          ║');
    console.log('  ║     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝          ║');
    console.log('  ║                     N E T W O R K                    ║');
    console.log('  ║                                                      ║');
    console.log('  ║        Decentralized Mesh Infrastructure             ║');
    console.log(`  ║         Mode: ${mode.toUpperCase().padEnd(38)}║`);
    console.log('  ║                                                      ║');
    console.log('  ╚══════════════════════════════════════════════════════╝');
    console.log(`${COLORS.reset}`);
    console.log('');
}

// ─── MAIN ORCHESTRATOR ──────────────────────────────────

async function main() {
    const args = process.argv.slice(2);
    const mode = getRunningMode();

    // Handle --status flag
    if (args.includes('--status')) {
        showStatus();
        return;
    }

    // Handle --health flag
    if (args.includes('--health')) {
        const { results, allHealthy } = await runHealthChecks(mode);
        process.exit(allHealthy ? 0 : 1);
    }

    // Handle --stop flag
    if (args.includes('--stop')) {
        log('sys', 'Stopping all GhostNet services...');
        shellExec('pm2 delete all');
        log('ok', 'All services stopped');
        return;
    }

    showBanner(mode);

    // STEP 1: Validate environment
    log('boot', 'STEP 1/6: Environment validation');
    const { issues, warnings } = validateEnvironment();

    warnings.forEach(w => log('warn', w));

    if (issues.length > 0) {
        issues.forEach(i => log('error', i));
        log('error', 'Critical issues detected. Attempting repair...');
    }

    // STEP 2: Repair environment
    log('boot', 'STEP 2/6: Environment repair');
    repairEnvFile();

    // STEP 3: Install dependencies
    log('boot', 'STEP 3/6: Dependencies');
    installDependencies();

    // STEP 4: Validate ecosystem config
    log('boot', 'STEP 4/6: PM2 ecosystem config');
    const ecosystemValid = validateEcosystem();

    if (!ecosystemValid) {
        log('error', 'Ecosystem config invalid or missing. Please check ecosystem.config.cjs');
        log('sys', 'Falling back to direct process management');
    }

    // STEP 5: Start services
    log('boot', 'STEP 5/6: Starting services');
    const hasPM2 = ensurePM2();

    let started = false;
    if (hasPM2 && ecosystemValid) {
        started = await startWithPM2(mode);
    } else {
        started = await startDirect(mode);
    }

    if (!started) {
        log('error', 'Failed to start services');
        process.exit(1);
    }

    // STEP 6: Health checks
    log('boot', 'STEP 6/6: Health verification');

    // Wait for services to initialize
    log('sys', 'Waiting for services to initialize (8s)...');
    await sleep(8000);

    const { results, allHealthy } = await runHealthChecks(mode);

    if (allHealthy) {
        console.log('');
        console.log(`${COLORS.green}${COLORS.bold}  ╔══════════════════════════════════════════╗${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ║      ✅ GHOSTNET IS READY                ║${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ╠══════════════════════════════════════════╣${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ║  Server:  http://localhost:8080          ║${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ║  Bridge:  http://localhost:3001          ║${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ║  Client:  http://localhost:3000          ║${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ║                                          ║${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ║  Status:  pm2 list                       ║${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ║  Logs:    pm2 logs                       ║${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ║  Stop:    pm2 stop all                   ║${COLORS.reset}`);
        console.log(`${COLORS.green}${COLORS.bold}  ╚══════════════════════════════════════════╝${COLORS.reset}`);
        console.log('');
    } else {
        console.log('');
        log('warn', 'Some services are not healthy. Check individual logs:');
        for (const [name, r] of Object.entries(results)) {
            if (r.status !== 'HEALTHY') {
                log('warn', `  pm2 logs ${name}`);
            }
        }
        console.log('');
        log('sys', 'System is partially operational. Non-critical services may still be starting.');
    }

    // Show PM2 status table
    if (hasPM2) {
        showStatus();
    }
}

// ─── RUN ─────────────────────────────────────────────────
main().catch(e => {
    log('error', `Orchestrator crashed: ${e.message}`);
    console.error(e);
    process.exit(1);
});
