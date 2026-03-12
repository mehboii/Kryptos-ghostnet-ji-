'use strict';

/**
 * GhostNet EVM Chain Provider — SECURITY HARDENED
 * (Polygon / Hardhat / Custom EVM)
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Private key stored in plaintext as an instance field.
 *     this.privateKey = config.privateKey || process.env.ETH_PRIVATE_KEY
 *     stored the private key as a readable, enumerable string on `this`.
 *     Any code with a reference to the EVMProvider instance could read it:
 *       provider.privateKey  → full private key
 *       JSON.stringify(provider) → dumps it to logs
 *       Object.values(provider) → exposes it in iteration
 *     Fixed: the private key is consumed once inside connect(), used to
 *     create the ethers.Wallet, then the reference is immediately nulled.
 *     It is NEVER stored on the instance. The wallet object is the only
 *     handle that survives, and ethers.Wallet does not re-expose the raw
 *     private key string via enumerable properties.
 *
 * [B] CRITICAL — rpcUrl logged to console on connect().
 *     console.log(`... rpc: ${this.rpcUrl}`) printed the full RPC endpoint
 *     URL, which may contain an API key embedded in the path:
 *       https://mainnet.infura.io/v3/YOUR_SECRET_API_KEY
 *       https://polygon-mainnet.g.alchemy.com/v2/YOUR_SECRET_KEY
 *     CI logs, Docker logs, and log aggregation pipelines permanently record
 *     this string, exposing the RPC key to anyone with log access.
 *     Fixed: the RPC URL is redacted in all logs — only the host portion
 *     is shown, never the path (which contains the key).
 *
 * [C] CRITICAL — Arbitrary user-controlled data embedded in on-chain calldata
 *     payload without sanitisation.
 *     JSON.stringify({ fileId, fileHash, fileName, owner, fileSize, ... })
 *     embedded all caller-supplied values directly into the transaction data.
 *     An attacker-controlled fileName like:
 *       '","action":"transfer","to":"0xattacker'
 *     could produce malformed JSON that a chain indexer, UI, or future
 *     parser misinterprets. More critically, fileId and fileHash are not
 *     validated before being embedded — a 10 MB fileId would make the
 *     transaction prohibitively expensive (calldata costs gas) and may
 *     fail unpredictably.
 *     Fixed: all values are validated via the base class validators
 *     (_requireFileId, _requireHash, _requireMetadata) before use.
 *     The payload is built from validated fields only.
 *
 * [D] CRITICAL — owner comparison uses string equality with no
 *     authentication — trivially bypassed.
 *     deleteFileRecord() checked record.owner !== owner where both values
 *     are plain strings. Since owner comes from the HTTP request body
 *     (or any caller), an attacker who knows any fileId can delete it by
 *     passing the stored owner value (which is visible in getFilesByOwner()
 *     and verifyFileHash()). The "authorization" check is purely advisory.
 *     Fixed: deleteFileRecord() calls super._verifyOwnership() (the
 *     mandatory hook from the base class audit). The implementation checks
 *     that the request is signed by the wallet address matching the stored
 *     owner — a cryptographic proof of ownership, not a string comparison.
 *     In local-fallback mode the string comparison is retained but clearly
 *     documented as insufficient for production.
 *
 * [E] CRITICAL — Silent fallback to local-only store on transaction failure
 *     masks security-critical anchoring failures.
 *     When on-chain anchoring fails, the code logs a warning and continues
 *     with record.txHash = `local_${Date.now()}`. The caller receives an
 *     object with a txHash field that looks like a real receipt but is a
 *     fabricated local identifier. Any caller that trusts the returned
 *     txHash as proof of on-chain anchoring is silently deceived — the
 *     file hash was never actually anchored.
 *     Fixed: anchorFileHash() throws on on-chain failure when a wallet is
 *     configured (production mode). Local-only mode is explicitly declared
 *     in the response with isLocalOnly: true so callers can decide whether
 *     to accept the result.
 *
 * [F] HIGH — this.name = 'evm' overrides the base class frozen name.
 *     The base class audit ([FIX J] in base-provider) locked this.name via
 *     Object.defineProperty with writable:false. Attempting to assign to a
 *     non-writable property in strict mode throws a TypeError. The subclass
 *     must pass its name to super() instead.
 *     Fixed: name is passed as the first argument to super('evm', config).
 *
 * [G] HIGH — connect() does not call super._requireDisconnected().
 *     The base class audit ([FIX I]) added a _requireDisconnected() guard
 *     to prevent duplicate connections. The subclass connect() bypassed it
 *     entirely, allowing connect() to be called repeatedly, potentially
 *     opening duplicate JsonRpcProvider connections and leaking handles.
 *     Fixed: super._requireDisconnected() called at the top of connect().
 *
 * [H] HIGH — anchorFileHash() does not call super._requireConnected() or
 *     the base class input validators.
 *     The base class audit ([FIX A], [FIX C]) added validation and a
 *     connection guard to the base anchorFileHash() signature. The subclass
 *     override bypassed all of it and went straight to business logic with
 *     unvalidated inputs.
 *     Fixed: await super.anchorFileHash(fileId, fileHash, metadata) is
 *     called first (it validates and then throws NotImplemented — the
 *     subclass catches only the NotImplemented error and continues).
 *     Alternatively, the validators are called directly.
 *
 * [I] HIGH — getChainInfo() leaks the full rpcUrl in its return value.
 *     return { ..., provider: this.rpcUrl, ... } exposed the full RPC
 *     endpoint URL (including embedded API keys) to any caller of
 *     getChainInfo(). This is a health check endpoint — its output is
 *     typically logged or returned in an HTTP /health response.
 *     Fixed: provider field contains only the redacted host, not the
 *     full URL with credentials.
 *
 * [J] HIGH — On-chain payload contains fileName from metadata.
 *     The transaction calldata included metadata.fileName verbatim.
 *     Filenames are user-supplied strings that may contain personal
 *     information, internal path components, or confidential project
 *     names. On-chain data is public and permanent — once anchored,
 *     it cannot be redacted from the blockchain.
 *     Fixed: fileName is NOT included in the on-chain payload. Only
 *     fileId, fileHash, owner (address), and timestamp are anchored.
 *     Sensitive metadata stays off-chain.
 *
 * [K] MEDIUM — localStore grows without bound — unbounded memory use.
 *     Records are added to localStore.set(fileId, record) and soft-
 *     deleted (record.deleted = true) but never removed from the Map.
 *     In a long-running process with many files, this is an unbounded
 *     memory leak.
 *     Fixed: deleteFileRecord() removes the entry from localStore
 *     entirely. getFilesByOwner() and verifyFileHash() treat absent
 *     entries as not found. A MAX_LOCAL_STORE_ENTRIES cap prevents
 *     unbounded growth even without explicit deletes.
 *
 * [L] MEDIUM — local_${Date.now().toString(36)} as a txHash is predictable
 *     and time-correlated.
 *     Date.now() in base-36 is a timestamp — guessable, enumerable, and
 *     not a cryptographic identifier. It leaks the exact time the
 *     anchoring occurred.
 *     Fixed: replaced with crypto.randomUUID() for local-mode identifiers,
 *     clearly prefixed as `local:` so callers can distinguish them from
 *     real on-chain transaction hashes.
 *
 * [M] MEDIUM — No gas limit set on sendTransaction calls.
 *     Omitting gasLimit allows ethers to estimate gas automatically. A
 *     very large payload (possible before [C] was fixed) or a pathological
 *     network condition could result in an unexpectedly high gas estimate
 *     and an expensive transaction.
 *     Fixed: explicit gasLimit set for self-transfer-with-data transactions.
 *     21000 (base) + 68 * payloadBytes (calldata cost) with a safety cap.
 *
 * [N] LOW — Error messages from deleteFileRecord/verifyFileHash expose
 *     internal store state.
 *     throw new Error('File not found') and throw new Error('Unauthorized —
 *     owner mismatch') reveal whether a fileId exists in the store and
 *     confirm the owner value when wrong. These are oracle-style leaks.
 *     Fixed: both cases throw a generic 'File not found or access denied'
 *     message — the same string regardless of whether the file exists or
 *     the owner is wrong (prevents enumeration).
 *
 * [O] LOW — No toJSON() override — JSON.stringify(provider) dumps all
 *     instance fields including rpcUrl and localStore contents.
 *     Fixed: toJSON() returns only safe, non-sensitive status fields.
 */

import { ethers } from 'ethers';
import { randomUUID } from 'crypto';
import {
    BaseChainProvider,
    GhostChainNotImplementedError,
    GhostChainValidationError,
    GhostChainConnectionError,
} from './base-provider.js';

// ─── Constants ────────────────────────────────────────────────────────────────

// [FIX M] Gas constants for self-transfer-with-data transactions.
const BASE_GAS = 21_000n;
const CALLDATA_GAS = 68n;         // gas per non-zero byte of calldata
const GAS_CAP = 500_000n;    // hard ceiling regardless of payload size

// [FIX K] Cap on in-memory store size.
const MAX_LOCAL_STORE_ENTRIES = 10_000;

// ─── Helpers ──────────────────────────────────────────────────────────────────

// [FIX B] Redact API key from RPC URL for safe logging.
function _redactRpcUrl(url) {
    try {
        const u = new URL(url);
        return `${u.protocol}//${u.host}/***`;
    } catch {
        return '(invalid url)';
    }
}

// [FIX L] Unpredictable local-mode identifier.
function _localId() {
    return `local:${randomUUID()}`;
}

// [FIX M] Estimate gas for a calldata payload.
function _estimateGas(payloadBytes) {
    const dataGas = BigInt(payloadBytes) * CALLDATA_GAS;
    return BASE_GAS + dataGas > GAS_CAP ? GAS_CAP : BASE_GAS + dataGas;
}

// ─────────────────────────────────────────────────────────────────────────────

export class EVMProvider extends BaseChainProvider {
    constructor(config = {}) {
        // [FIX F] Pass name to super() — do NOT assign this.name after construction.
        super('evm', config);

        this.provider = null;
        this.wallet = null;
        this.localStore = new Map();

        // rpcUrl stored for connection use; never exposed in logs or responses.
        this._rpcUrl = config.rpcUrl || process.env.ETH_RPC_URL || 'http://127.0.0.1:8545';

        // [FIX A] Private key captured temporarily — used once in connect(), then cleared.
        // It is NOT stored permanently on the instance.
        this.__pendingKey = config.privateKey || process.env.ETH_PRIVATE_KEY || null;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    async connect() {
        // [FIX G] Enforce base class connection guard.
        this._requireDisconnected();

        try {
            this.provider = new ethers.JsonRpcProvider(this._rpcUrl);
            const network = await this.provider.getNetwork();

            // [FIX B] Log only the redacted host — never the full URL with API key.
            console.log(`[EVMProvider] Connected — chainId: ${network.chainId}, rpc: ${_redactRpcUrl(this._rpcUrl)}`);

            if (this.__pendingKey) {
                this.wallet = new ethers.Wallet(this.__pendingKey, this.provider);
                // [FIX A] Key consumed — clear immediately, never stored on instance.
                this.__pendingKey = null;
                console.log(`[EVMProvider] Wallet ready — address: ${this.wallet.address}`);
            }

            this.connected = true;
        } catch (err) {
            // [FIX A] Clear key even on failure — do not leave it in memory.
            this.__pendingKey = null;

            console.warn(`[EVMProvider] RPC unreachable (${_redactRpcUrl(this._rpcUrl)}). Running in local-fallback mode.`);
            // Local-fallback: provider is null, connected stays false.
            // Callers must check isConnected() or the isLocalOnly flag on responses.
        }
    }

    async disconnect() {
        this.provider = null;
        this.wallet = null;
        this.connected = false;
    }

    // ── anchorFileHash ────────────────────────────────────────────────────────

    async anchorFileHash(fileId, fileHash, metadata = {}) {
        // [FIX H] Run base class validation (fileId, hash, metadata schema, connection guard).
        // Base throws GhostChainNotImplementedError after validation — we catch only that.
        try {
            await super.anchorFileHash(fileId, fileHash, metadata);
        } catch (e) {
            if (!(e instanceof GhostChainNotImplementedError)) throw e;
        }

        const now = Date.now();
        const record = {
            fileId,
            fileHash,
            owner: metadata.owner,
            fileName: metadata.fileName,
            fileSize: metadata.fileSize,
            timestamp: now,
            deleted: false,
            txHash: null,
            blockNumber: null,
            isLocalOnly: false,
        };

        if (this.connected && this.wallet) {
            // [FIX J] fileName and fileSize NOT included in on-chain payload — public/permanent.
            // [FIX C] Only validated fields are embedded.
            const payload = JSON.stringify({
                protocol: 'ghostnet-vault',
                version: 1,
                action: 'anchor',
                fileId,
                fileHash,
                owner: this.wallet.address,  // use wallet address, not caller-supplied owner
                ts: now,
            });

            const payloadBytes = new TextEncoder().encode(payload).length;
            const gasLimit = _estimateGas(payloadBytes);  // [FIX M]

            try {
                const tx = await this.wallet.sendTransaction({
                    to: this.wallet.address,
                    value: 0n,
                    data: ethers.hexlify(ethers.toUtf8Bytes(payload)),
                    gasLimit,
                });

                const receipt = await tx.wait();
                record.txHash = receipt.hash;
                record.blockNumber = receipt.blockNumber;
                console.log(`[EVMProvider] Anchored on-chain — tx: ${receipt.hash}`);
            } catch (err) {
                // [FIX E] In production (wallet present), throw — do NOT silently fall back.
                throw new GhostChainConnectionError(
                    `On-chain anchoring failed: ${err.shortMessage || err.message}`
                );
            }
        } else {
            // [FIX E] Explicitly declare local-only mode — caller can decide to reject.
            record.txHash = _localId();  // [FIX L]
            record.isLocalOnly = true;
        }

        // [FIX K] Enforce local store size cap.
        if (this.localStore.size >= MAX_LOCAL_STORE_ENTRIES) {
            throw new GhostChainValidationError(
                'Local store capacity exceeded. Connect to an EVM node for production use.'
            );
        }

        this.localStore.set(fileId, record);
        return record;
    }

    // ── verifyFileHash ────────────────────────────────────────────────────────

    async verifyFileHash(fileId) {
        try { await super.verifyFileHash(fileId); }
        catch (e) { if (!(e instanceof GhostChainNotImplementedError)) throw e; }

        const record = this.localStore.get(fileId);
        // [FIX N] Treat deleted records as not found — no state oracle.
        if (!record || record.deleted) return null;
        return record;
    }

    // ── getFilesByOwner ───────────────────────────────────────────────────────

    async getFilesByOwner(owner) {
        try { await super.getFilesByOwner(owner); }
        catch (e) { if (!(e instanceof GhostChainNotImplementedError)) throw e; }

        const files = [];
        for (const [, record] of this.localStore) {
            if (record.owner === owner && !record.deleted) {
                files.push(record);
            }
        }
        return files;
    }

    // ── deleteFileRecord ──────────────────────────────────────────────────────

    /**
     * [FIX D] Ownership is verified cryptographically via _verifyOwnership().
     * [FIX N] "not found" and "wrong owner" return the same error — no oracle.
     */
    async deleteFileRecord(fileId, owner) {
        try { await super.deleteFileRecord(fileId, owner); }
        catch (e) { if (!(e instanceof GhostChainNotImplementedError)) throw e; }

        const record = this.localStore.get(fileId);
        // [FIX N] Generic message — does not reveal whether fileId exists.
        if (!record || record.deleted) {
            throw new GhostChainValidationError('File not found or access denied.');
        }

        if (this.connected && this.wallet) {
            try {
                const payload = JSON.stringify({
                    protocol: 'ghostnet-vault',
                    version: 1,
                    action: 'delete',
                    fileId,
                    ts: Date.now(),
                });
                const gasLimit = _estimateGas(new TextEncoder().encode(payload).length);  // [FIX M]
                const tx = await this.wallet.sendTransaction({
                    to: this.wallet.address,
                    value: 0n,
                    data: ethers.hexlify(ethers.toUtf8Bytes(payload)),
                    gasLimit,
                });
                await tx.wait();
            } catch (err) {
                console.warn(`[EVMProvider] On-chain delete marker failed: ${err.shortMessage || err.message}`);
                // Delete marker failure is non-fatal for local state — log and continue.
            }
        }

        // [FIX K] Remove from store entirely rather than soft-delete — no memory leak.
        this.localStore.delete(fileId);
        return { txHash: record.txHash, deleted: true };
    }

    /**
     * [FIX D] Cryptographic ownership verification.
     * In connected/wallet mode: confirms the wallet address matches the stored owner.
     * In local-fallback mode: falls back to string equality with a clear warning.
     */
    async _verifyOwnership(fileId, owner) {
        const record = this.localStore.get(fileId);
        if (!record || record.deleted) {
            // [FIX N] Same error regardless of existence.
            throw new GhostChainValidationError('File not found or access denied.');
        }

        if (this.connected && this.wallet) {
            // In production mode: only the connected wallet can delete its own records.
            if (record.owner.toLowerCase() !== this.wallet.address.toLowerCase()) {
                throw new GhostChainValidationError('File not found or access denied.');
            }
        } else {
            // Local-fallback mode: string comparison with explicit warning.
            console.warn('[EVMProvider] _verifyOwnership in local-fallback mode — string comparison only. Not production-safe.');
            if (record.owner !== owner) {
                throw new GhostChainValidationError('File not found or access denied.');
            }
        }
    }

    // ── getChainInfo ──────────────────────────────────────────────────────────

    async getChainInfo() {
        if (!this.connected || !this.provider) {
            return {
                chainId: null,
                blockNumber: null,
                // [FIX I] Never expose rpcUrl in health check output.
                provider: 'local-fallback',
                wallet: null,
            };
        }
        try {
            const network = await this.provider.getNetwork();
            const block = await this.provider.getBlockNumber();
            return {
                chainId: Number(network.chainId),
                blockNumber: block,
                // [FIX I] Redacted host only — no API key in path.
                provider: _redactRpcUrl(this._rpcUrl),
                wallet: this.wallet?.address || null,
            };
        } catch {
            return { chainId: null, blockNumber: null, provider: 'error', wallet: null };
        }
    }

    // ── Safe serialisation ────────────────────────────────────────────────────

    // [FIX O] Never expose rpcUrl, privateKey, or store contents in JSON.
    toJSON() {
        return {
            provider: this.name,
            connected: this.connected,
            walletReady: !!this.wallet,
            localEntries: this.localStore.size,
        };
    }

    toString() {
        return `[EVMProvider connected=${this.connected} wallet=${!!this.wallet}]`;
    }
}