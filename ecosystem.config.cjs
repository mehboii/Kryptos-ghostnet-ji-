/**
 * GhostNet PM2 Ecosystem Configuration
 * ======================================
 * ALL backend services — one command to start everything.
 * 
 * Usage:
 *   pm2 start ecosystem.config.cjs              → start ALL services
 *   pm2 start ecosystem.config.cjs --only ghostnet-server  → single service
 *   pm2 start ecosystem.config.cjs --env production
 *   pm2 stop all                                 → stop all
 *   pm2 restart all                              → restart all
 *   pm2 logs                                     → live tail all logs
 * 
 * Services:
 *   ┌──────────────────────┬───────┬──────────────────────────────┐
 *   │ Service              │ Port  │ Description                  │
 *   ├──────────────────────┼───────┼──────────────────────────────┤
 *   │ ghostnet-server      │ 8080  │ Main API + WebSocket + Auth  │
 *   │ ghostnet-bridge      │ 3001  │ Multi-chain Blockchain Bridge│
 *   │ ghostnet-client      │ 3000  │ UI Static File Server        │
 *   │ ghostnet-messages    │ 8090  │ SQLite Message Persistence   │
 *   │ ghostnet-chain       │ 4000  │ Blockchain Abstraction Layer │
 *   │ ghostnet-vault       │ 4001  │ Encrypted File Vault         │
 *   │ ghostnet-relay-1     │ 8081  │ Onion Relay Node #1          │
 *   │ ghostnet-relay-2     │ 8082  │ Onion Relay Node #2          │
 *   │ ghostnet-relay-3     │ 8083  │ Onion Relay Node #3          │
 *   │ ghostnet-registry    │ 9000  │ Node Discovery Registry      │
 *   │ ghostnet-ble         │  —    │ BLE Peripheral (Bluetooth)   │
 *   │ ghostnet-watchdog    │  —    │ Health Monitor & Auto-Restart│
 *   └──────────────────────┴───────┴──────────────────────────────┘
 */

const path = require('path');

// Resolve root directory
const ROOT = __dirname;

// Helper: build env block
function buildEnv(overrides = {}) {
    return {
        NODE_ENV: 'development',
        GHOSTNET_MODE: 'development',
        DOTENV_CONFIG_PATH: path.join(ROOT, '.env'),
        ...overrides
    };
}

// Helper: standard PM2 app config
function service(name, script, cwd, port, opts = {}) {
    const config = {
        name,
        script,
        cwd: cwd || ROOT,
        instances: 1,
        autorestart: true,
        watch: false,
        max_restarts: opts.maxRestarts || 10,
        restart_delay: opts.restartDelay || 2000,
        max_memory_restart: opts.maxMemory || '200M',
        env: buildEnv({
            ...(port ? { PORT: port } : {}),
            GHOSTNET_SERVICE: name
        }),
        env_production: buildEnv({
            NODE_ENV: 'production',
            GHOSTNET_MODE: 'cloud',
            ...(port ? { PORT: port } : {}),
            GHOSTNET_SERVICE: name
        }),
        error_file: path.join(ROOT, 'logs', `${name}-error.log`),
        out_file: path.join(ROOT, 'logs', `${name}-out.log`),
        log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
        merge_logs: true,
        listen_timeout: opts.listenTimeout || 10000,
        kill_timeout: opts.killTimeout || 5000
    };

    // ESM modules need node_args
    if (opts.esm) {
        config.node_args = '--experimental-vm-modules';
    }

    // Custom args
    if (opts.args) {
        config.args = opts.args;
    }

    return config;
}

module.exports = {
    apps: [
        // ══════════════════════════════════════════════════
        //  CORE SERVICES
        // ══════════════════════════════════════════════════

        // ── Main API + WebSocket + Auth ──────────────────
        service(
            'ghostnet-server',
            path.join(ROOT, 'ghostnet-server.js'),
            ROOT,
            8080,
            { esm: true, maxMemory: '300M' }
        ),

        // ── Multi-chain Blockchain Bridge ────────────────
        service(
            'ghostnet-bridge',
            path.join(ROOT, 'ghostnet-bridge', 'bridge.js'),
            path.join(ROOT, 'ghostnet-bridge'),
            3001,
            { maxMemory: '250M', restartDelay: 3000, listenTimeout: 15000 }
        ),

        // ── Client UI Server ─────────────────────────────
        service(
            'ghostnet-client',
            path.join(ROOT, 'ghostnet-client', 'server.js'),
            path.join(ROOT, 'ghostnet-client'),
            3000,
            { maxMemory: '150M', listenTimeout: 8000 }
        ),

        // ══════════════════════════════════════════════════
        //  DATA SERVICES
        // ══════════════════════════════════════════════════

        // ── SQLite Message Persistence ───────────────────
        service(
            'ghostnet-messages',
            path.join(ROOT, 'ghostnet-messages', 'server.js'),
            path.join(ROOT, 'ghostnet-messages'),
            8090,
            { esm: true, listenTimeout: 8000 }
        ),

        // ── Blockchain Abstraction Layer ─────────────────
        service(
            'ghostnet-chain',
            path.join(ROOT, 'ghostnet-chain', 'chain-service.js'),
            path.join(ROOT, 'ghostnet-chain'),
            4000,
            { esm: true, maxMemory: '200M', listenTimeout: 10000 }
        ),

        // ── Encrypted File Vault ─────────────────────────
        service(
            'ghostnet-vault',
            path.join(ROOT, 'ghostnet-vault', 'vault-service.js'),
            path.join(ROOT, 'ghostnet-vault'),
            4001,
            { esm: true, maxMemory: '250M', listenTimeout: 10000 }
        ),

        // ══════════════════════════════════════════════════
        //  RELAY / ONION ROUTING NETWORK
        //  Multi-hop encrypted relay chain for anonymous
        //  message routing. Each relay peels one encryption
        //  layer and forwards to the next hop.
        // ══════════════════════════════════════════════════

        // ── Relay Node #1 ────────────────────────────────
        service(
            'ghostnet-relay-1',
            path.join(ROOT, 'ghostnet-bridge', 'relay', 'server.js'),
            path.join(ROOT, 'ghostnet-bridge', 'relay'),
            8081,
            { maxMemory: '150M', restartDelay: 1000 }
        ),

        // ── Relay Node #2 ────────────────────────────────
        service(
            'ghostnet-relay-2',
            path.join(ROOT, 'ghostnet-bridge', 'relay', 'server.js'),
            path.join(ROOT, 'ghostnet-bridge', 'relay'),
            8082,
            { maxMemory: '150M', restartDelay: 1000 }
        ),

        // ── Relay Node #3 ────────────────────────────────
        service(
            'ghostnet-relay-3',
            path.join(ROOT, 'ghostnet-bridge', 'relay', 'server.js'),
            path.join(ROOT, 'ghostnet-bridge', 'relay'),
            8083,
            { maxMemory: '150M', restartDelay: 1000 }
        ),

        // ══════════════════════════════════════════════════
        //  DISCOVERY & MESH
        // ══════════════════════════════════════════════════

        // ── Node Discovery Registry ──────────────────────
        //    Serves /nodes endpoint listing all relay nodes
        //    so clients can auto-discover the onion chain.
        service(
            'ghostnet-registry',
            path.join(ROOT, 'ghostnet-bridge', 'registry.js'),
            path.join(ROOT, 'ghostnet-bridge'),
            9000,
            { maxMemory: '100M', listenTimeout: 5000 }
        ),

        // ── BLE Peripheral Service ───────────────────────
        //    Bluetooth Low Energy advertising service for
        //    proximity-based mesh networking. Advertises
        //    this node to nearby BLE-capable devices.
        service(
            'ghostnet-ble',
            path.join(ROOT, 'ble-peripheral.js'),
            ROOT,
            null,  // No HTTP port — uses BLE protocol
            { maxMemory: '100M', maxRestarts: 5, restartDelay: 5000 }
        ),

        // ══════════════════════════════════════════════════
        //  MONITORING
        // ══════════════════════════════════════════════════

        // ── Health Watchdog ──────────────────────────────
        //    Monitors all above services, auto-restarts on
        //    3 consecutive failures, logs to watchdog.log.
        service(
            'ghostnet-watchdog',
            path.join(ROOT, 'ghostnet-watchdog.cjs'),
            ROOT,
            null,
            {
                maxMemory: '100M',
                maxRestarts: 5,
                restartDelay: 10000,  // Wait 10s before restart (gives services time to boot)
                args: '--interval=30'
            }
        )
    ]
};
