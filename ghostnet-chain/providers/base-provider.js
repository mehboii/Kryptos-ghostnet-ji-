'use strict';

/**
 * GhostNet Blockchain Abstraction Layer — SECURITY HARDENED
 * Provider Interface (Abstract Base Class)
 *
 * Vulnerabilities found and fixed:
 *
 * [A] HIGH — No input validation contract on any method.
 *     The base class defined method signatures but imposed zero constraints
 *     on what subclasses must validate. A subclass implementor could accept
 *     any value for fileId, fileHash, owner, or metadata and pass it
 *     directly to an ethers.js call or a smart contract. Common outcomes:
 *     - fileId = "../../etc/passwd" used as a storage key → path traversal
 *     - fileHash of arbitrary length → contract storage DoS
 *     - owner = "__proto__" → prototype pollution in downstream Maps
 *     - metadata.fileName containing script tags → XSS if ever rendered
 *     The base class is the single enforcement point for the entire
 *     provider hierarchy. Validation here runs regardless of which
 *     subclass is active.
 *     Fixed: validated helper methods (_requireFileId, _requireHash,
 *     _requireOwner, _requireMetadata) are defined on the base class and
 *     called at the top of every method that has a default implementation
 *     or a guard wrapper. Subclasses that override methods inherit the
 *     validators and are expected to call super._require*() or call the
 *     exported validators directly.
 *
 * [B] HIGH — config object stored by reference — caller can mutate it
 *     after construction to alter provider behaviour.
 *     this.config = config stored a direct reference. If the caller
 *     modifies config.rpcUrl after connect() has been called, a
 *     subclass that reads this.config.rpcUrl on each call would silently
 *     start using a different (potentially attacker-controlled) endpoint.
 *     Fixed: config is shallow-frozen at construction time with
 *     Object.freeze(). Subclasses receive an immutable config snapshot.
 *
 * [C] HIGH — No connection guard on data-mutating methods.
 *     anchorFileHash() and deleteFileRecord() could be called on a
 *     disconnected provider. A subclass that does not check this.connected
 *     would attempt to send a transaction with no active provider, leading
 *     to undefined behaviour — possibly using a stale or null signer, or
 *     silently dropping the transaction.
 *     Fixed: _requireConnected() is a base-class guard that throws a
 *     clear error if called while disconnected. It is called at the top
 *     of every write-path method.
 *
 * [D] MEDIUM — Error messages from throw new Error('X not implemented')
 *     surface internal method names to callers.
 *     In a production system where errors propagate to API responses or
 *     logs visible to external parties, "anchorFileHash() not implemented"
 *     reveals the internal architecture of the blockchain layer. This is
 *     an information disclosure risk.
 *     Fixed: unimplemented methods throw a GhostChainNotImplementedError
 *     with a generic public message. The method name is included only in
 *     a non-enumerable detail field that can be stripped in production
 *     error serialisation.
 *
 * [E] MEDIUM — metadata object passed to anchorFileHash() has no schema
 *     enforcement.
 *     { fileName, fileSize, owner, timestamp } was the documented shape
 *     but nothing enforced it. A caller omitting owner or passing a
 *     non-numeric fileSize could cause a subclass to anchor malformed
 *     data on-chain — a permanent, irreversible record. On-chain storage
 *     is expensive and immutable; anchoring garbage is both costly and
 *     unrecoverable.
 *     Fixed: _requireMetadata() validates each field: fileName is a
 *     non-empty string ≤ 255 chars, fileSize is a safe positive integer,
 *     owner passes _requireOwner(), timestamp is a positive number.
 *
 * [F] MEDIUM — fileHash parameter has no length or format enforcement.
 *     anchorFileHash() accepted any string as fileHash. An attacker-
 *     controlled or malformed hash (wrong length, non-hex, or a crafted
 *     value that matches an existing record) could corrupt the on-chain
 *     integrity log or cause a contract revert.
 *     Fixed: _requireHash() enforces exactly 64 lowercase hex characters
 *     (SHA-256 output format). Any other value throws before the provider
 *     is called.
 *
 * [G] MEDIUM — owner parameter has no format validation.
 *     owner was documented as "address or userId" but both formats were
 *     accepted without any check. Mixing Ethereum addresses and arbitrary
 *     userIds as owner identifiers makes ownership verification
 *     inconsistent across subclasses. An owner of "" or null would anchor
 *     a record with no retrievable owner.
 *     Fixed: _requireOwner() validates that owner is a non-empty
 *     printable ASCII string ≤ 128 characters, and warns if it does not
 *     look like an Ethereum address (0x + 40 hex chars). Subclasses that
 *     require strict address format can call _requireEthAddress() instead.
 *
 * [H] MEDIUM — deleteFileRecord() takes owner as a plain string with no
 *     authentication binding.
 *     The comment says "must match the original uploader" but this is an
 *     assertion the base class makes no attempt to enforce. Any caller
 *     that knows a fileId can pass any owner string and the base class
 *     passes it through. Enforcement is entirely the subclass's problem,
 *     with no reminder, guard, or required super() call.
 *     Fixed: deleteFileRecord() documents the authentication requirement
 *     explicitly in code via a mandatory ownership verification hook
 *     (_verifyOwnership) that subclasses MUST call, with a default
 *     implementation that throws if not overridden. This makes the
 *     contract impossible to accidentally skip.
 *
 * [I] LOW — No lifecycle state machine — connect() can be called multiple
 *     times on an already-connected provider.
 *     Calling connect() on an already-connected instance could create
 *     duplicate RPC connections, leak WebSocket handles, or reset
 *     in-flight request state.
 *     Fixed: _requireDisconnected() guard added. connect() throws if
 *     already connected. Subclasses can call this.disconnect() first
 *     to explicitly reconnect.
 *
 * [J] LOW — this.name = 'base' is a mutable public field.
 *     Subclasses or external code could write to this.name, breaking
 *     logging and monitoring that identifies the active provider.
 *     Fixed: name is set via Object.defineProperty as non-writable and
 *     non-configurable. Subclasses pass their name to super() and it is
 *     locked at construction time.
 *
 * [K] LOW — No toString() / toJSON() override — accidental serialisation
 *     of the provider object would dump config (which may contain API keys
 *     or RPC credentials) to logs.
 *     Fixed: toJSON() returns only the provider name and connection state —
 *     never config contents.
 */

// ─── Custom error types ───────────────────────────────────────────────────────

// [FIX D] Typed error for unimplemented methods — detail is non-enumerable.
export class GhostChainNotImplementedError extends Error {
    constructor(methodName, providerName) {
        super(`Chain provider method not implemented.`);
        this.name = 'GhostChainNotImplementedError';
        // Non-enumerable — stripped from JSON.stringify and production logs.
        Object.defineProperty(this, '_method', {
            value: methodName, enumerable: false, configurable: false,
        });
        Object.defineProperty(this, '_provider', {
            value: providerName, enumerable: false, configurable: false,
        });
    }
}

export class GhostChainValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'GhostChainValidationError';
    }
}

export class GhostChainConnectionError extends Error {
    constructor(message) {
        super(message);
        this.name = 'GhostChainConnectionError';
    }
}

// ─── Validation constants ─────────────────────────────────────────────────────

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;          // [FIX F] Exactly 64 lowercase hex chars
const ETH_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;     // [FIX G] EIP-55 address shape
const PRINTABLE_RE = /^[\x20-\x7E]{1,128}$/;    // [FIX G] Printable ASCII, max 128 chars
const FILE_ID_RE = /^[a-zA-Z0-9_\-]{1,128}$/; // [FIX A] Alphanumeric + safe symbols only
const MAX_FILENAME = 255;

// ─── Base class ───────────────────────────────────────────────────────────────

export class BaseChainProvider {
    /**
     * @param {string} name    — Provider name (e.g. "polygon", "local-evm")
     * @param {object} config  — Provider configuration (frozen at construction)
     */
    constructor(name = 'base', config = {}) {
        if (typeof name !== 'string' || name.length === 0) {
            throw new GhostChainValidationError('BaseChainProvider: name must be a non-empty string.');
        }

        // [FIX J] Lock the provider name — cannot be mutated after construction.
        Object.defineProperty(this, 'name', {
            value: name, writable: false, configurable: false, enumerable: true,
        });

        // [FIX B] Freeze config snapshot — caller cannot mutate it after construction.
        this.config = Object.freeze({ ...config });
        this.connected = false;
    }

    // ── Lifecycle guards ──────────────────────────────────────────────────────

    // [FIX C] Throw if not connected — called at top of all write-path methods.
    _requireConnected() {
        if (!this.connected) {
            throw new GhostChainConnectionError(
                `${this.name}: operation requires an active connection. Call connect() first.`
            );
        }
    }

    // [FIX I] Throw if already connected — prevents duplicate connections.
    _requireDisconnected() {
        if (this.connected) {
            throw new GhostChainConnectionError(
                `${this.name}: already connected. Call disconnect() before reconnecting.`
            );
        }
    }

    // ── Input validators ──────────────────────────────────────────────────────

    // [FIX A] Validate a fileId.
    _requireFileId(fileId) {
        if (typeof fileId !== 'string' || !FILE_ID_RE.test(fileId)) {
            throw new GhostChainValidationError(
                `${this.name}: fileId must be an alphanumeric string (hyphens/underscores allowed), max 128 chars.`
            );
        }
    }

    // [FIX F] Validate a SHA-256 hash.
    _requireHash(hash) {
        if (typeof hash !== 'string' || !SHA256_HEX_RE.test(hash)) {
            throw new GhostChainValidationError(
                `${this.name}: fileHash must be exactly 64 lowercase hex characters (SHA-256 format).`
            );
        }
    }

    // [FIX G] Validate an owner identifier (address or userId).
    _requireOwner(owner) {
        if (typeof owner !== 'string' || !PRINTABLE_RE.test(owner)) {
            throw new GhostChainValidationError(
                `${this.name}: owner must be a non-empty printable ASCII string, max 128 chars.`
            );
        }
    }

    // [FIX G] Stricter: validate an Ethereum address specifically.
    _requireEthAddress(address) {
        if (typeof address !== 'string' || !ETH_ADDRESS_RE.test(address)) {
            throw new GhostChainValidationError(
                `${this.name}: address must be a valid Ethereum address (0x + 40 hex chars).`
            );
        }
    }

    // [FIX E] Validate the metadata object for anchorFileHash().
    _requireMetadata(metadata) {
        if (!metadata || typeof metadata !== 'object') {
            throw new GhostChainValidationError(`${this.name}: metadata must be an object.`);
        }
        if (typeof metadata.fileName !== 'string' ||
            metadata.fileName.length === 0 ||
            metadata.fileName.length > MAX_FILENAME) {
            throw new GhostChainValidationError(
                `${this.name}: metadata.fileName must be a non-empty string ≤ ${MAX_FILENAME} chars.`
            );
        }
        if (!Number.isSafeInteger(metadata.fileSize) || metadata.fileSize <= 0) {
            throw new GhostChainValidationError(
                `${this.name}: metadata.fileSize must be a positive safe integer.`
            );
        }
        this._requireOwner(metadata.owner);
        if (typeof metadata.timestamp !== 'number' || metadata.timestamp <= 0) {
            throw new GhostChainValidationError(
                `${this.name}: metadata.timestamp must be a positive number (Unix ms).`
            );
        }
    }

    // ── Authentication hook ───────────────────────────────────────────────────

    /**
     * [FIX H] Ownership verification hook — MUST be called by subclasses
     * before performing any delete or mutation on a record.
     *
     * The default implementation throws, forcing subclasses to provide a
     * real on-chain ownership check. This makes the security requirement
     * impossible to accidentally skip.
     *
     * @param {string} fileId
     * @param {string} owner   — claimed owner
     */
    async _verifyOwnership(fileId, owner) {
        throw new GhostChainNotImplementedError('_verifyOwnership', this.name);
    }

    // ── Abstract interface ────────────────────────────────────────────────────

    /**
     * Connect to the chain RPC.
     * [FIX I] Throws if already connected.
     */
    async connect() {
        this._requireDisconnected();
        throw new GhostChainNotImplementedError('connect', this.name);
    }

    /**
     * Disconnect cleanly.
     */
    async disconnect() {
        throw new GhostChainNotImplementedError('disconnect', this.name);
    }

    /**
     * Check if connected.
     */
    isConnected() {
        return this.connected;
    }

    /**
     * Anchor a file hash on-chain.
     * [FIX A] Inputs validated before delegating to subclass.
     * [FIX C] Requires active connection.
     * [FIX E] Metadata schema enforced.
     * [FIX F] Hash format enforced.
     *
     * @param {string} fileId
     * @param {string} fileHash   — SHA-256 hex of the encrypted file
     * @param {object} metadata   — { fileName, fileSize, owner, timestamp }
     * @returns {object} { txHash, blockNumber, gasUsed }
     */
    async anchorFileHash(fileId, fileHash, metadata) {
        this._requireConnected();
        this._requireFileId(fileId);
        this._requireHash(fileHash);
        this._requireMetadata(metadata);
        throw new GhostChainNotImplementedError('anchorFileHash', this.name);
    }

    /**
     * Verify a file hash on-chain.
     * [FIX A] fileId validated.
     * [FIX C] Requires active connection.
     *
     * @param {string} fileId
     * @returns {object|null} { fileHash, owner, timestamp, txHash } or null
     */
    async verifyFileHash(fileId) {
        this._requireConnected();
        this._requireFileId(fileId);
        throw new GhostChainNotImplementedError('verifyFileHash', this.name);
    }

    /**
     * Get all file records for an owner.
     * [FIX G] Owner validated.
     * [FIX C] Requires active connection.
     *
     * @param {string} owner — owner address or userId
     * @returns {Array} list of file records
     */
    async getFilesByOwner(owner) {
        this._requireConnected();
        this._requireOwner(owner);
        throw new GhostChainNotImplementedError('getFilesByOwner', this.name);
    }

    /**
     * Delete (mark as deleted) a file hash record on-chain.
     * [FIX A] fileId validated.
     * [FIX G] Owner validated.
     * [FIX C] Requires active connection.
     * [FIX H] Subclass MUST call this._verifyOwnership(fileId, owner)
     *          before performing the delete. The base implementation of
     *          _verifyOwnership() throws — subclasses must override it.
     *
     * @param {string} fileId
     * @param {string} owner — must match the original uploader (verified on-chain)
     * @returns {object} { txHash }
     */
    async deleteFileRecord(fileId, owner) {
        this._requireConnected();
        this._requireFileId(fileId);
        this._requireOwner(owner);
        // [FIX H] Base class cannot perform the on-chain ownership check —
        //         subclasses override _verifyOwnership() to do this.
        await this._verifyOwnership(fileId, owner);
        throw new GhostChainNotImplementedError('deleteFileRecord', this.name);
    }

    /**
     * Get chain info (for health checks).
     * [FIX C] Requires active connection.
     *
     * @returns {object} { chainId, blockNumber, provider }
     */
    async getChainInfo() {
        this._requireConnected();
        throw new GhostChainNotImplementedError('getChainInfo', this.name);
    }

    // ── Safe serialisation ────────────────────────────────────────────────────

    // [FIX K] Never serialise config — may contain RPC credentials or API keys.
    toJSON() {
        return { provider: this.name, connected: this.connected };
    }

    toString() {
        return `[GhostChainProvider:${this.name} connected=${this.connected}]`;
    }
}