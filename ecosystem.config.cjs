/**
 * Kryptos PM2 Ecosystem Configuration — SECURITY HARDENED
 *
 * Vulnerabilities found and fixed:
 *
 * [A] DEFAULT ENVIRONMENT IS 'development'
 *     Running `pm2 start ecosystem.config.cjs` (no --env flag) starts every
 *     service in development mode, which typically disables auth checks,
 *     enables verbose logging of secrets, and relaxes CORS. The safe default
 *     must be production.
 *     Fixed: NODE_ENV defaults to 'production'; dev mode requires explicit
 *     --env development flag.
 *
 * [B] DOTENV_CONFIG_PATH BROADCAST TO ALL CHILD PROCESSES
 *     Every service received DOTENV_CONFIG_PATH pointing to the .env file.
 *     Any child process (or a dependency with a supply-chain compromise) can
 *     read process.env.DOTENV_CONFIG_PATH and then read the secrets file
 *     directly. Environment variables are also visible in `pm2 env <id>`,
 *     /proc/<pid>/environ on Linux, and crash dumps.
 *     Fixed: removed from env blocks entirely. Each service must load its
 *     own dotenv at startup via its own code, not via an advertised path.
 *
 * [C] ALL SERVICES INHERIT ALL SECRETS (NO LEAST-PRIVILEGE)
 *     buildEnv() was applied identically to all 12 services. If the .env
 *     is loaded into the environment, the BLE peripheral inherits the vault
 *     encryption key; the client UI server inherits the chain RPC secret;
 *     the relay nodes inherit everything. A compromise of any single service
 *     exposes all credentials.
 *     Fixed: each service gets only the env vars it actually needs, declared
 *     explicitly per-service. Shared base contains only non-secret values.
 *
 * [D] NO uid/gid — SERVICES RUN AS INVOKING USER
 *     PM2 inherits the uid/gid of whoever ran `pm2 start`. In production
 *     deployments PM2 is commonly started by root or a sudoer. All 12
 *     services then run as root with full filesystem and network access.
 *     Fixed: uid/gid fields added, pointing to a dedicated unprivileged
 *     service account. Change 'kryptos' to your actual service user.
 *     NOTE: PM2 must itself be started as root to drop privileges; the
 *     service account must not have login shell or sudo rights.
 *
 * [E] LOGS ARE NEVER ROTATED
 *     Out/error log files grow without bound. Over time this fills the disk
 *     (denial of service) and retains sensitive data (keys, addresses, message
 *     metadata) indefinitely. merge_logs: true also merges stdout and stderr,
 *     making security auditing and incident response harder.
 *     Fixed: merge_logs disabled; log rotation configured via pm2-logrotate
 *     settings comment; max_size and retain values documented.
 *     Run: pm2 install pm2-logrotate && pm2 set pm2-logrotate:max_size 20M
 *          && pm2 set pm2-logrotate:retain 7 && pm2 set pm2-logrotate:compress true
 *
 * [F] RELAY NODES SHARE IDENTICAL CONFIG — NO ISOLATION
 *     kryptos-relay-1/2/3 all run the same script from the same cwd with the
 *     same environment. They share any file-based state (SQLite, PID files,
 *     lock files). A compromise of relay-1 is therefore identical to a
 *     compromise of relay-2 and relay-3. For an onion routing system, relay
 *     node isolation is a core security property.
 *     Fixed: each relay gets its own RELAY_INDEX and RELAY_PORT env var so it
 *     can use isolated storage paths. In a hardened deployment each relay
 *     should also run under a distinct uid.
 *
 * [G] autorestart WITH FIXED DELAY AND NO stop_exit_codes
 *     Services restart unconditionally — including on exit code 0 (clean
 *     intentional shutdown). A deliberately stopped service is immediately
 *     restarted. Also, a service crashing in a tight loop (e.g. under an
 *     attack causing repeated OOM) restarts at full speed until max_restarts
 *     is hit, amplifying resource exhaustion.
 *     Fixed: stop_exit_codes: [0] prevents restart on clean exit.
 *     exp_backoff_restart_delay replaces fixed restart_delay for crash loops.
 *
 * [H] --experimental-vm-modules IN PRODUCTION
 *     Experimental Node.js flags have unstable semantics, are unsupported in
 *     LTS, and can affect module sandbox boundaries. vm-modules in particular
 *     affects how code isolation works at the V8 level.
 *     Fixed: removed. ESM support in modern Node (18+) does not require this
 *     flag for standard ESM imports. If a service genuinely needs it, it must
 *     be explicitly justified and pinned to a tested Node version.
 *
 * Usage:
 *   pm2 start ecosystem.config.cjs                   → production (default)
 *   pm2 start ecosystem.config.cjs --env development → development
 *   pm2 start ecosystem.config.cjs --only kryptos-server
 *   pm2 stop all | pm2 restart all | pm2 logs
 *
 * Before first run:
 *   useradd -r -s /sbin/nologin kryptos       (create service account)
 *   pm2 install pm2-logrotate
 *   pm2 set pm2-logrotate:max_size 20M
 *   pm2 set pm2-logrotate:retain 7
 *   pm2 set pm2-logrotate:compress true
 */

'use strict';

const path = require('path');
const ROOT = __dirname;

// ─── Service account (must exist on the host) ─────────────────────────────
// [FIX D] All services run as this unprivileged user, not as root.
const SERVICE_USER = 'kryptos';
const SERVICE_GROUP = 'kryptos';

// ─── Shared non-secret base environment ──────────────────────────────────
// [FIX A] Production is the default.
// [FIX B] No DOTENV_CONFIG_PATH — services load their own env at startup.
// [FIX C] Only values that are genuinely safe to share across all services.
function baseEnv(overrides = {}) {
    return {
        NODE_ENV: 'production',
        KRYPTOS_MODE: 'cloud',
        ...overrides,
    };
}

// Development overrides — only applied when --env development is passed.
function baseDevEnv(overrides = {}) {
    return {
        NODE_ENV: 'development',
        KRYPTOS_MODE: 'development',
        ...overrides,
    };
}

// ─── Standard service factory ─────────────────────────────────────────────
function service(name, script, cwd, port, opts = {}) {
    const portEnv = port ? { PORT: String(port) } : {};

    return {
        name,
        script,
        cwd: cwd || ROOT,
        instances: 1,
        autorestart: true,
        watch: false,

        // [FIX G] Don't restart on intentional clean shutdown (exit 0).
        stop_exit_codes: [0],

        max_restarts: opts.maxRestarts || 10,
        // [FIX G] Exponential back-off instead of fixed delay.
        exp_backoff_restart_delay: opts.restartDelay || 2000,

        max_memory_restart: opts.maxMemory || '200M',
        listen_timeout: opts.listenTimeout || 10000,
        kill_timeout: opts.killTimeout || 5000,

        // [FIX D] Run as unprivileged service account.
        uid: SERVICE_USER,
        gid: SERVICE_GROUP,

        // [FIX E] Separate stdout/stderr; no merge.
        merge_logs: false,
        error_file: path.join(ROOT, 'logs', `${name}-error.log`),
        out_file: path.join(ROOT, 'logs', `${name}-out.log`),
        log_date_format: 'YYYY-MM-DD HH:mm:ss Z',

        // [FIX A] Production is the default env.
        // [FIX C] Only service-specific, non-secret values here.
        env: baseEnv({
            KRYPTOS_SERVICE: name,
            ...portEnv,
            ...(opts.env || {}),
        }),

        env_development: baseDevEnv({
            KRYPTOS_SERVICE: name,
            ...portEnv,
            ...(opts.devEnv || {}),
        }),

        // [FIX H] --experimental-vm-modules removed entirely.
        ...(opts.args ? { args: opts.args } : {}),
    };
}

// ─────────────────────────────────────────────────────────────────────────
module.exports = {
    apps: [

        // ══════════════════════════════════════════════════
        //  CORE SERVICES
        // ══════════════════════════════════════════════════

        // ── Main API + WebSocket + Auth ──────────────────
        service(
            'kryptos-server',
            path.join(ROOT, 'kryptos-server.js'),
            ROOT,
            8080,
            {
                maxMemory: '300M',
                // [FIX C] DB + JWT secrets loaded by the service itself from
                //         its own scoped .env — not injected via PM2 env block.
            }
        ),

        // ── Multi-chain Blockchain Bridge ─────────────────
        service(
            'kryptos-bridge',
            path.join(ROOT, 'kryptos-bridge', 'bridge.js'),
            path.join(ROOT, 'kryptos-bridge'),
            3001,
            { maxMemory: '250M', restartDelay: 3000, listenTimeout: 15000 }
        ),

        // ── Client UI Static File Server ──────────────────
        service(
            'kryptos-client',
            path.join(ROOT, 'kryptos-client', 'server.js'),
            path.join(ROOT, 'kryptos-client'),
            3000,
            { maxMemory: '150M', listenTimeout: 8000 }
        ),

        // ══════════════════════════════════════════════════
        //  DATA SERVICES
        // ══════════════════════════════════════════════════

        // ── SQLite Message Persistence ────────────────────
        service(
            'kryptos-messages',
            path.join(ROOT, 'kryptos-messages', 'server.js'),
            path.join(ROOT, 'kryptos-messages'),
            8090,
            { listenTimeout: 8000 }
        ),

        // ── Blockchain Abstraction Layer ──────────────────
        service(
            'kryptos-chain',
            path.join(ROOT, 'kryptos-chain', 'chain-service.js'),
            path.join(ROOT, 'kryptos-chain'),
            4000,
            { maxMemory: '200M', listenTimeout: 10000 }
        ),

        // ── Encrypted File Vault ──────────────────────────
        // Vault is the highest-value target — tightest restart policy.
        service(
            'kryptos-vault',
            path.join(ROOT, 'kryptos-vault', 'vault-service.js'),
            path.join(ROOT, 'kryptos-vault'),
            4001,
            {
                maxMemory: '250M',
                listenTimeout: 10000,
                maxRestarts: 5,
                restartDelay: 5000,
            }
        ),

        // ══════════════════════════════════════════════════
        //  RELAY / ONION ROUTING NETWORK
        //
        //  [FIX F] Each relay gets its own RELAY_INDEX and
        //  RELAY_PORT so it can use isolated storage paths
        //  and state. In a hardened deployment each should
        //  also run under a distinct uid:
        //    kryptos-relay1 / kryptos-relay2 / kryptos-relay3
        // ══════════════════════════════════════════════════

        // ── Relay Node #1 ─────────────────────────────────
        service(
            'kryptos-relay-1',
            path.join(ROOT, 'kryptos-bridge', 'relay', 'server.js'),
            path.join(ROOT, 'kryptos-bridge', 'relay'),
            8081,
            {
                maxMemory: '150M',
                restartDelay: 1000,
                env: { RELAY_INDEX: '1', RELAY_PORT: '8081' },
                devEnv: { RELAY_INDEX: '1', RELAY_PORT: '8081' },
            }
        ),

        // ── Relay Node #2 ─────────────────────────────────
        service(
            'kryptos-relay-2',
            path.join(ROOT, 'kryptos-bridge', 'relay', 'server.js'),
            path.join(ROOT, 'kryptos-bridge', 'relay'),
            8082,
            {
                maxMemory: '150M',
                restartDelay: 1000,
                env: { RELAY_INDEX: '2', RELAY_PORT: '8082' },
                devEnv: { RELAY_INDEX: '2', RELAY_PORT: '8082' },
            }
        ),

        // ── Relay Node #3 ─────────────────────────────────
        service(
            'kryptos-relay-3',
            path.join(ROOT, 'kryptos-bridge', 'relay', 'server.js'),
            path.join(ROOT, 'kryptos-bridge', 'relay'),
            8083,
            {
                maxMemory: '150M',
                restartDelay: 1000,
                env: { RELAY_INDEX: '3', RELAY_PORT: '8083' },
                devEnv: { RELAY_INDEX: '3', RELAY_PORT: '8083' },
            }
        ),

        // ══════════════════════════════════════════════════
        //  DISCOVERY & MESH
        // ══════════════════════════════════════════════════

        // ── Node Discovery Registry ───────────────────────
        service(
            'kryptos-registry',
            path.join(ROOT, 'kryptos-bridge', 'registry.js'),
            path.join(ROOT, 'kryptos-bridge'),
            9000,
            { maxMemory: '100M', listenTimeout: 5000 }
        ),

        // ── BLE Peripheral Service ────────────────────────
        // Requires the service account to be in the 'bluetooth' group:
        //   usermod -aG bluetooth kryptos
        service(
            'kryptos-ble',
            path.join(ROOT, 'ble-peripheral.js'),
            ROOT,
            null,
            {
                maxMemory: '100M',
                maxRestarts: 5,
                restartDelay: 5000,
            }
        ),

        // ══════════════════════════════════════════════════
        //  MONITORING
        // ══════════════════════════════════════════════════

        // ── Health Watchdog ───────────────────────────────
        service(
            'kryptos-watchdog',
            path.join(ROOT, 'kryptos-watchdog.cjs'),
            ROOT,
            null,
            {
                maxMemory: '100M',
                maxRestarts: 5,
                restartDelay: 10000,
                args: '--interval=30',
            }
        ),
    ]
};