'use strict';

/**
 * Kryptos ETH Node Health Check — HARDENED
 *
 * Security fixes:
 *
 * CRITICAL
 *  [01] RPC_URL hardcoded as http:// — plaintext; leaks chain data unencrypted
 *       → http:// rejected for non-loopback hosts; https:// required for remote nodes
 *  [02] RPC_URL hardcoded in source — committed to version history
 *       → Read from ETH_RPC_URL env var; no default for non-loopback targets
 *
 * HIGH
 *  [03] No chainId validation — mainnet node (chainId=1) reported as "ONLINE"
 *       → EXPECTED_CHAIN_ID env var checked; mismatch = exit(2) with clear message
 *  [04] provider.getBlockNumber() called outside timeout race — could hang forever
 *       → Both getNetwork() and getBlockNumber() wrapped in a single raceTimeout()
 *  [05] process.exit() called with open provider handles — ethers may log noise
 *       → provider.destroy() called before every exit to close internal polling
 *
 * MEDIUM
 *  [06] Dangling setTimeout when getNetwork() resolved first — spurious rejections
 *       → raceTimeout() clears the timer on resolution via finally block
 *  [07] e.message printed verbatim — could expose URL or internal detail
 *       → sanitizeMessage() strips the RPC URL from error strings before logging
 *  [08] No URL validation before passing to ethers — cryptic internal errors
 *       → validateRpcUrl() parses and validates before provider construction
 *  [09] staticNetwork: true hides chainId mismatch from ethers itself
 *       → staticNetwork removed; ethers validates chain on connect; we re-check too
 *
 * LOW
 *  [10] Script called process.exit() directly — untestable, non-importable
 *       → Logic in checkEth() returns result object; main() handles exit codes
 *       → require.main === module guard so import doesn't auto-execute
 *  [11] exit(1) used for both timeout and connection error — indistinguishable
 *       → EXIT_OFFLINE=1, EXIT_TIMEOUT=2, EXIT_WRONG_NETWORK=3, EXIT_INVALID_URL=4
 *  [12] Full RPC_URL logged — leaks credentials if URL contains user:pass
 *       → safeUrl() logs only scheme+host+port, never credentials or path
 */

const { ethers } = require('ethers');

// ─── Exit codes [11] ─────────────────────────────────────────────────────────

const EXIT = Object.freeze({
    OK: 0,
    OFFLINE: 1,
    TIMEOUT: 2,
    WRONG_NETWORK: 3,
    INVALID_URL: 4,
});

// ─── Configuration ────────────────────────────────────────────────────────────

// [02] Read from environment — no hardcoded value
const RPC_URL = process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';

// [03] Optional chain ID guard — set ETH_EXPECTED_CHAIN_ID=31337 for Hardhat
const EXPECTED_CHAIN_ID = process.env.ETH_EXPECTED_CHAIN_ID
    ? BigInt(process.env.ETH_EXPECTED_CHAIN_ID)
    : null;

const TIMEOUT_MS = parseInt(process.env.ETH_CHECK_TIMEOUT_MS || '5000', 10);

// ─── [08] URL validation ──────────────────────────────────────────────────────

function validateRpcUrl(raw) {
    let u;
    try { u = new URL(raw); }
    catch (_) { throw Object.assign(new Error('ETH_RPC_URL is not a valid URL'), { exitCode: EXIT.INVALID_URL }); }

    const isLoopback = ['localhost', '127.0.0.1', '::1'].includes(u.hostname);

    // [01] Reject http:// for non-loopback — require https:// for remote nodes
    if (u.protocol === 'http:' && !isLoopback) {
        throw Object.assign(
            new Error(`http:// is not allowed for non-loopback RPC endpoints (got host: ${u.hostname}). Use https://.`),
            { exitCode: EXIT.INVALID_URL }
        );
    }

    if (u.protocol !== 'http:' && u.protocol !== 'https:' &&
        u.protocol !== 'ws:' && u.protocol !== 'wss:') {
        throw Object.assign(
            new Error(`Unsupported RPC URL protocol: ${u.protocol}`),
            { exitCode: EXIT.INVALID_URL }
        );
    }

    return u;
}

// ─── [12] Safe URL for logging — strips credentials ──────────────────────────

function safeUrl(u) {
    // u is a URL object; only log scheme + hostname + port
    return `${u.protocol}//${u.hostname}${u.port ? ':' + u.port : ''}`;
}

// ─── [07] Sanitize error messages ────────────────────────────────────────────

function sanitizeMessage(msg, rawUrl) {
    // Strip the raw URL (which may contain credentials) from error strings
    return String(msg).replace(rawUrl, '[RPC_URL]');
}

// ─── [06] Timeout race that cleans up the timer ───────────────────────────────

function raceTimeout(promise, ms, label) {
    let timerId;
    const timer = new Promise((_, reject) => {
        timerId = setTimeout(
            () => reject(Object.assign(new Error(`${label} timed out after ${ms}ms`), { isTimeout: true })),
            ms
        );
    });
    return Promise.race([promise, timer]).finally(() => clearTimeout(timerId)); // [06]
}

// ─── Main health check ────────────────────────────────────────────────────────

async function checkEth() {
    // [08] Validate URL before touching ethers
    let parsedUrl;
    try { parsedUrl = validateRpcUrl(RPC_URL); }
    catch (e) {
        console.error(` Invalid RPC URL: ${e.message}`);
        return { ok: false, exitCode: e.exitCode || EXIT.INVALID_URL };
    }

    console.log(` Checking Ethereum node at ${safeUrl(parsedUrl)}...`); // [12]

    // [09] No staticNetwork — let ethers validate chain normally, then we re-check
    const provider = new ethers.JsonRpcProvider(RPC_URL);

    try {
        // [04] Both calls inside a single timeout race
        const [net, blockNumber] = await raceTimeout(
            Promise.all([provider.getNetwork(), provider.getBlockNumber()]),
            TIMEOUT_MS,
            'ETH RPC'
        );

        // [03] Chain ID guard
        if (EXPECTED_CHAIN_ID !== null && net.chainId !== EXPECTED_CHAIN_ID) {
            console.error(
                ` Wrong network: expected chainId ${EXPECTED_CHAIN_ID}, ` +
                `got ${net.chainId}. Are you connected to the right node?`
            );
            return { ok: false, exitCode: EXIT.WRONG_NETWORK };
        }

        console.log(` ETH node online`);
        console.log(`   Chain ID    : ${net.chainId}`);
        console.log(`   Block Number: ${blockNumber}`);
        // [12] Never log the full RPC_URL
        return { ok: true, exitCode: EXIT.OK, chainId: net.chainId, blockNumber };

    } catch (e) {
        // [07] Sanitize before logging
        const safeMsg = sanitizeMessage(e.message, RPC_URL);

        if (e.isTimeout) {
            console.error(` ETH node timed out: ${safeMsg}`);
            console.error(`   → Is Hardhat/Ganache running? (npx hardhat node)`);
            return { ok: false, exitCode: EXIT.TIMEOUT };
        }

        console.error(` ETH node offline: ${safeMsg}`); // [07]
        console.error(`   → Is Hardhat/Ganache running? (npx hardhat node)`);
        return { ok: false, exitCode: EXIT.OFFLINE };

    } finally {
        // [05] Always destroy provider to close internal polling handles
        try { provider.destroy(); } catch (_) { }
    }
}

// ─── [10] Entry point — only auto-runs when executed directly ─────────────────

async function main() {
    const result = await checkEth();
    process.exit(result.exitCode);
}

if (require.main === module) { // [10]
    main().catch(e => {
        console.error('Unexpected error:', sanitizeMessage(e.message, RPC_URL));
        process.exit(EXIT.OFFLINE);
    });
}

// [10] Exported for testing — does not auto-execute on import
module.exports = { checkEth, validateRpcUrl, EXIT };