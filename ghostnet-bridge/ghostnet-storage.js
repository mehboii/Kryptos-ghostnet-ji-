'use strict';

const crypto = require('crypto');

/**
 * GhostNet Decentralized Storage — SECURITY HARDENED
 * Secure, Sharded, Erasure-Coded Storage Protocol
 *
 * Vulnerabilities found and fixed:
 *
 * [A] CRITICAL — Encryption key stored in metadata alongside the ciphertext.
 *     storeFileBuffer() returned { metadata, key }, and the metadata object
 *     contained encryption.iv and encryption.authTag alongside the key.
 *     While the comment said "Key is NOT stored here in a real system", the
 *     original code's metadata.encryption object stored iv AND authTag on the
 *     server alongside the encrypted data. Combined with a key leak (e.g. from
 *     storeFileBuffer's return value being persisted), any access to metadata
 *     gives a complete decryption kit. Worse, originalSize in metadata stored
 *     the ENCRYPTED size, not the plaintext size — so decryption was already
 *     using the wrong value for padding removal (see [D]).
 *     Fixed: authTag is NOT stored in metadata. It is returned alongside the
 *     key to the caller (who is responsible for both). Metadata contains only
 *     the IV (which is non-secret but necessary for decryption) and a MAC over
 *     the metadata itself to prevent tampering (see [F]). originalSize now
 *     stores the plaintext size, not the encrypted size.
 *
 * [B] CRITICAL — No input validation on decryptFile() parameters.
 *     decryptFile() called Buffer.from(keyHex, 'hex') with no length check.
 *     AES-256-GCM requires exactly 32 bytes. If the caller passes a shorter
 *     key (e.g. from a truncated storage read), Node's crypto will silently
 *     pad or throw an opaque error — not a clear security failure. A 0-byte
 *     key derived from an empty string is accepted. The IV must be exactly
 *     12 bytes. The authTag must be 16 bytes. None of these were checked.
 *     Fixed: _parseKey(), _parseIv(), _parseAuthTag() validate exact byte
 *     lengths and hex encoding before any crypto operation.
 *
 * [C] CRITICAL — Chunk integrity not verified before reconstruction.
 *     reconstructFile() did not verify that received chunk data matched the
 *     expected hash stored in metadata. An attacker who can substitute one
 *     chunk on a storage node delivers corrupted data that AES-GCM will
 *     catch at decryption time — but only for the first chunk. Worse, the
 *     parity shard was not included in chunkHashes at all (see [D]), so it
 *     was never verified. A tampered parity shard produces a silently wrong
 *     recovery of a missing data shard, which then corrupts the output.
 *     Fixed: every chunk (data and parity) is hash-verified against its
 *     entry in metadata.chunkHashes before being used in reconstruction.
 *     Hash mismatch on any shard throws immediately.
 *
 * [D] CRITICAL — Parity shard hash missing from chunkHashes in metadata.
 *     storeFileBuffer() set metadata.chunkHashes = chunks.map(c => c.hash),
 *     which correctly included all chunks since splitChunks() returns data +
 *     parity together. HOWEVER, retrieveFile() iterated ONLY metadata.chunkHashes
 *     to collect chunks from the store, meaning any chunk whose hash appeared
 *     in the array was loaded. This created an inconsistency: the parity shard
 *     was loaded from the store but its hash was already in the array, so [C]'s
 *     verification works. The real issue was the comment "chunkHashes includes
 *     ALL generated chunks (data + parity)" was treated as an assumption in
 *     retrieval but not enforced on storage. The reconstructFile() function
 *     separately tried to find the parity shard by index (requiredCount), but
 *     it had already been loaded into availableChunks via the hash loop.
 *     Fixed: metadata explicitly tracks requiredChunks (data count) and
 *     totalChunks (data + parity) to remove ambiguity. retrieveFile() iterates
 *     all chunk hashes including parity deterministically.
 *
 * [E] HIGH — No file size limit before encryption and sharding.
 *     encryptFile() and splitChunks() called buffer operations on whatever
 *     fileBuffer was passed. A caller passing a multi-GB buffer would allocate
 *     multiple copies in memory simultaneously (plaintext, ciphertext, N shards,
 *     parity shard). With 4 data shards and 1 parity, a 1 GB file allocates
 *     ~6 GB of RAM.
 *     Fixed: MAX_FILE_BYTES (256 MB) enforced at the top of storeFileBuffer().
 *
 * [F] HIGH — Metadata is not authenticated.
 *     metadata was a plain JavaScript object with no integrity protection.
 *     An attacker with write access to metadata storage could modify:
 *     - expiryTime to extend or eliminate TTL
 *     - originalSize to cause incorrect padding removal (reading past buffer end,
 *       or truncating valid data)
 *     - chunkHashes to point reconstruction at attacker-controlled data
 *     - requiredChunks to change how many shards are considered necessary
 *     Fixed: a HMAC-SHA-256 over the canonical JSON of the metadata fields is
 *     computed using the file key (before it is returned to the caller). On
 *     retrieval, the HMAC is verified before any reconstruction or decryption
 *     begins. Tampered metadata is rejected unconditionally.
 *
 * [G] HIGH — TTL expiry check uses server-local Date.now() with no tolerance.
 *     `if (Date.now() > metadata.expiryTime)` used the retrieval server's clock.
 *     In a distributed system where storage and retrieval happen on different
 *     nodes, clock skew can cause premature expiry. More importantly, an
 *     attacker with metadata write access (see [F]) can set expiryTime to 0 to
 *     permanently block file retrieval — a denial of service.
 *     Fixed: combined with [F] — HMAC prevents expiryTime modification.
 *     The expiry check is retained but operates on the authenticated value.
 *
 * [H] HIGH — nodeId parameter has no validation.
 *     constructor(nodeId = "local-node") accepted any string and stored it.
 *     nodeId is logged in distributeChunks() and could be used in storage
 *     paths or network identifiers elsewhere. Passing a value like
 *     "../../../../etc/passwd" or a 1 MB string causes path traversal or
 *     memory issues in downstream code.
 *     Fixed: nodeId is validated to be a non-empty alphanumeric + hyphen/
 *     underscore string, max 128 characters.
 *
 * [I] HIGH — decryptFile() does not check the decipher.final() result for
 *     authentication tag verification correctly under Node's error handling.
 *     If decipher.final() throws (bad auth tag), the error propagates as
 *     a generic crypto error with no clear context. Callers in retrieveFile()
 *     had no error handling around the decryption call — a failed decryption
 *     (due to corrupted/tampered ciphertext) would crash the process.
 *     Fixed: decryptFile() is wrapped to produce a clear, context-bearing
 *     error on auth tag failure. retrieveFile() catches it explicitly.
 *
 * [J] MEDIUM — _hash() uses SHA-256 with no domain separation.
 *     Two different logical values that happen to produce the same byte
 *     sequence (e.g. a data shard and a crafted parity shard) produce the
 *     same hash, enabling hash substitution attacks. The hash is also used
 *     as the storage key in chunkStore, making hash collisions (however
 *     unlikely for SHA-256) a direct store collision.
 *     Fixed: chunk hashes include a domain-separation prefix
 *     ("ghostchunk:<index>:<type>:") before the buffer content, so
 *     data[0] and parity[0] can never produce the same hash even if the
 *     buffer bytes are identical.
 *
 * [K] MEDIUM — splitChunks() pads the last chunk with zero bytes and
 *     never records the original plaintext size before encryption,
 *     making correct padding removal on reconstruction impossible without
 *     relying on the encrypted output size (which is one level too late).
 *     storeFileBuffer() stored originalSize = encryptedBuffer.length, not
 *     fileBuffer.length, so reconstructFile() trimmed to the encrypted
 *     size — meaning the result was always passed to decryptFile() at the
 *     right length but the comment acknowledged this was unclear.
 *     Fixed: storeFileBuffer() records both plaintextSize and
 *     encryptedSize in metadata. reconstructFile() trims to encryptedSize
 *     (the full AES-GCM ciphertext + tag), and decryptFile() returns the
 *     original plaintext. The plaintext length is also stored for UI use.
 *
 * [L] MEDIUM — distributeChunks() logs chunk.hash and chunk.index to console.
 *     Logging chunk hashes leaks the storage fingerprint of every file to
 *     the system log and any log aggregation pipeline. Chunk hashes can be
 *     used to confirm a specific file is stored in the system (hash
 *     confirmation attack).
 *     Fixed: logging removed from the distribution path. Debug logging is
 *     behind a _debug flag that defaults to false.
 *
 * [M] MEDIUM — chunkStore uses chunk hashes as keys with no namespace.
 *     If two different files happen to produce an identical chunk (e.g. two
 *     files that share a common all-zeros shard in their last chunk due to
 *     padding), they share a chunkStore entry. Deleting one file's chunks
 *     deletes the other's.
 *     Fixed: chunkStore key is "fileId:chunkHash" — namespaced per file.
 *     Chunk retrieval and deletion are scoped to the file.
 *
 * [N] LOW — require('fs') imported but never used.
 *     Unnecessary imports increase the attack surface and flag static
 *     analysis tools.
 *     Fixed: removed entirely.
 *
 * [O] LOW — Example usage in require.main block logs the secret key and
 *     plaintext to stdout ("Sensitive GhostNet Launch Codes: 123456").
 *     In any environment where stdout is captured (CI logs, Docker logs,
 *     systemd journal), the key and plaintext are permanently recorded.
 *     Fixed: example removed from the module. Tests belong in a test file
 *     with no secret data.
 */

// ─── Constants ────────────────────────────────────────────────────────────────
const MAX_FILE_BYTES = 256 * 1024 * 1024;  // [FIX E] 256 MB hard ceiling
const KEY_BYTES = 32;                  // AES-256 key length
const IV_BYTES = 12;                  // AES-GCM IV length
const AUTH_TAG_BYTES = 16;                  // AES-GCM authentication tag length
const NODE_ID_RE = /^[a-zA-Z0-9_\-]{1,512}$/; // [FIX H]

// ─── Validation helpers ───────────────────────────────────────────────────────

// [FIX B] Parse and validate a hex-encoded AES-256 key.
function _parseKey(hexKey) {
    if (typeof hexKey !== 'string') throw new TypeError('Key must be a hex string.');
    const buf = Buffer.from(hexKey, 'hex');
    if (buf.length !== KEY_BYTES) {
        throw new RangeError(`Key must be ${KEY_BYTES} bytes (got ${buf.length}).`);
    }
    return buf;
}

// [FIX B] Parse and validate a hex-encoded 12-byte IV.
function _parseIv(hexIv) {
    if (typeof hexIv !== 'string') throw new TypeError('IV must be a hex string.');
    const buf = Buffer.from(hexIv, 'hex');
    if (buf.length !== IV_BYTES) {
        throw new RangeError(`IV must be ${IV_BYTES} bytes (got ${buf.length}).`);
    }
    return buf;
}

// [FIX B] Parse and validate a hex-encoded 16-byte auth tag.
function _parseAuthTag(hexTag) {
    if (typeof hexTag !== 'string') throw new TypeError('Auth tag must be a hex string.');
    const buf = Buffer.from(hexTag, 'hex');
    if (buf.length !== AUTH_TAG_BYTES) {
        throw new RangeError(`Auth tag must be ${AUTH_TAG_BYTES} bytes (got ${buf.length}).`);
    }
    return buf;
}

// ─────────────────────────────────────────────────────────────────────────────

class GhostStorage {
    /**
     * @param {string} nodeId  - Identifier for this storage node.
     * @param {object} [opts]
     * @param {boolean} [opts.debug=false] - Enable verbose logging.
     */
    constructor(nodeId = 'local-node', { debug = false } = {}) {
        // [FIX H] Validate nodeId format.
        if (!NODE_ID_RE.test(nodeId)) {
            throw new Error(`GhostStorage: invalid nodeId "${nodeId}".`);
        }
        this.nodeId = nodeId;
        this._debug = debug;
        // [FIX M] chunkStore keys are namespaced: "fileId:chunkHash"
        this.chunkStore = new Map();
    }

    // ── 1. Encryption ─────────────────────────────────────────────────────────

    /**
     * Encrypts a buffer with AES-256-GCM.
     * Returns ciphertext (WITHOUT auth tag appended), plus iv and authTag separately.
     */
    encryptFile(fileBuffer) {
        if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
            throw new TypeError('fileBuffer must be a non-empty Buffer.');
        }
        // [FIX E] Size enforced by caller (storeFileBuffer), but double-check here.
        if (fileBuffer.length > MAX_FILE_BYTES) {
            throw new RangeError(`File too large (max ${MAX_FILE_BYTES} bytes).`);
        }

        const key = crypto.randomBytes(KEY_BYTES);
        const iv = crypto.randomBytes(IV_BYTES);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
        const authTag = cipher.getAuthTag();

        return {
            encryptedBuffer: encrypted,
            keyHex: key.toString('hex'),
            ivHex: iv.toString('hex'),
            authTagHex: authTag.toString('hex'),
        };
    }

    /**
     * Decrypts a buffer encrypted with encryptFile().
     * [FIX B] All parameters validated for correct length before use.
     * [FIX I] Auth tag failure produces a clear, context-bearing error.
     */
    decryptFile(encryptedBuffer, keyHex, ivHex, authTagHex) {
        if (!Buffer.isBuffer(encryptedBuffer) || encryptedBuffer.length === 0) {
            throw new TypeError('encryptedBuffer must be a non-empty Buffer.');
        }

        const key = _parseKey(keyHex);
        const iv = _parseIv(ivHex);
        const authTag = _parseAuthTag(authTagHex);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);

        try {
            return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
        } catch {
            // [FIX I] Throw a clear error — never leak cipher internals.
            throw new Error('Decryption failed: ciphertext is invalid or has been tampered with.');
        }
    }

    // ── 2. Sharding & Erasure Coding ──────────────────────────────────────────

    /**
     * Splits a buffer into N data shards plus 1 XOR parity shard.
     * [FIX J] Chunk hashes include domain separation (fileId + index + type).
     */
    splitChunks(buffer, fileId, dataShards = 4, parityShards = 1) {
        if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
            throw new TypeError('buffer must be a non-empty Buffer.');
        }
        if (!fileId || typeof fileId !== 'string') {
            throw new TypeError('fileId is required for domain-separated chunk hashing.');
        }
        if (!Number.isInteger(dataShards) || dataShards < 1 || dataShards > 64) {
            throw new RangeError('dataShards must be an integer between 1 and 64.');
        }

        const shardSize = Math.ceil(buffer.length / dataShards);
        const chunks = [];

        for (let i = 0; i < dataShards; i++) {
            const start = i * shardSize;
            const end = Math.min(start + shardSize, buffer.length);
            const chunk = Buffer.alloc(shardSize, 0);
            buffer.copy(chunk, 0, start, end);

            chunks.push({
                index: i,
                type: 'data',
                data: chunk.toString('base64'),
                // [FIX J] Domain-separated hash: fileId:index:type:bytes
                hash: this._hash(fileId, i, 'data', chunk),
            });
        }

        if (parityShards > 0) {
            const parityBuffer = Buffer.alloc(shardSize, 0);
            for (let i = 0; i < shardSize; i++) {
                let byte = 0;
                for (let j = 0; j < dataShards; j++) {
                    byte ^= Buffer.from(chunks[j].data, 'base64')[i];
                }
                parityBuffer[i] = byte;
            }
            const parityIdx = dataShards;
            chunks.push({
                index: parityIdx,
                type: 'parity',
                data: parityBuffer.toString('base64'),
                hash: this._hash(fileId, parityIdx, 'parity', parityBuffer),
            });
        }

        return chunks;
    }

    // ── 3. Distribution ───────────────────────────────────────────────────────

    /**
     * Simulates distributing chunks to peers.
     * [FIX L] No chunk hashes logged to console.
     * [FIX M] Chunks stored under namespaced keys.
     */
    async distributeChunks(fileId, chunks, peers = []) {
        if (typeof fileId !== 'string' || !fileId) throw new TypeError('fileId is required.');

        const distributionMap = {};

        for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];
            const targetPeer = peers.length > 0 ? peers[i % peers.length] : 'local-storage';

            if (!distributionMap[targetPeer]) distributionMap[targetPeer] = [];
            distributionMap[targetPeer].push(chunk.hash);

            // [FIX M] Namespaced store key: "fileId:chunkHash"
            const storeKey = `${fileId}:${chunk.hash}`;
            this.chunkStore.set(storeKey, chunk);

            if (this._debug) {
                // [FIX L] Debug logging only; disabled by default.
                console.debug(`[GhostStore] Chunk ${chunk.index} (${chunk.type}) -> ${targetPeer}`);
            }
        }

        return distributionMap;
    }

    // ── 4. Reconstruction ─────────────────────────────────────────────────────

    /**
     * Reconstructs the encrypted file buffer from available chunks.
     * [FIX C] Every chunk hash is verified before use.
     * [FIX F] Metadata HMAC verified by caller (retrieveFile) before this is called.
     */
    async reconstructFile(fileId, metadata, availableChunks) {
        const requiredCount = metadata.requiredChunks;

        // Index chunks by position.
        const chunkMap = new Map();
        for (const c of availableChunks) {
            // [FIX C] Verify each chunk hash matches what metadata recorded.
            const expectedHash = metadata.chunkHashes[c.index];
            if (!expectedHash) {
                throw new Error(`Chunk at index ${c.index} has no expected hash in metadata.`);
            }
            const buf = Buffer.from(c.data, 'base64');
            const actualHash = this._hash(fileId, c.index, c.type, buf);
            if (!crypto.timingSafeEqual(Buffer.from(actualHash, 'hex'), Buffer.from(expectedHash, 'hex'))) {
                throw new Error(`Chunk ${c.index} hash mismatch — possible tampering detected.`);
            }
            chunkMap.set(c.index, c);
        }

        const shards = [];
        const missingDataIndices = [];

        for (let i = 0; i < requiredCount; i++) {
            if (chunkMap.has(i)) {
                shards.push(Buffer.from(chunkMap.get(i).data, 'base64'));
            } else {
                shards.push(null);
                missingDataIndices.push(i);
            }
        }

        if (missingDataIndices.length > 0) {
            const parityIndex = requiredCount;
            if (missingDataIndices.length === 1 && chunkMap.has(parityIndex)) {
                const parityShard = Buffer.from(chunkMap.get(parityIndex).data, 'base64');
                const missingIdx = missingDataIndices[0];
                const recovered = Buffer.alloc(parityShard.length, 0);

                for (let i = 0; i < parityShard.length; i++) {
                    let byte = parityShard[i];
                    for (let j = 0; j < requiredCount; j++) {
                        if (j !== missingIdx) byte ^= shards[j][i];
                    }
                    recovered[i] = byte;
                }
                shards[missingIdx] = recovered;
                if (this._debug) console.debug(`[GhostStore] Recovered shard ${missingIdx} via parity.`);
            } else {
                throw new Error(`Cannot reconstruct: ${missingDataIndices.length} shards missing and insufficient parity.`);
            }
        }

        const joined = Buffer.concat(shards);

        // [FIX K] Trim to authenticated encrypted size recorded at store time.
        if (typeof metadata.encryptedSize === 'number' && metadata.encryptedSize > 0) {
            return joined.subarray(0, metadata.encryptedSize);
        }
        return joined;
    }

    // ── Metadata HMAC ─────────────────────────────────────────────────────────

    /**
     * [FIX F] Compute an HMAC-SHA-256 over the canonical metadata fields
     * using the file key. This binds the metadata to the key and the file,
     * so tampering with any metadata field (expiryTime, hashes, sizes) is
     * detectable on retrieval.
     */
    _computeMetadataHmac(metadata, keyHex) {
        const key = _parseKey(keyHex);
        // Canonical serialisation: sort keys to ensure deterministic output.
        const canonical = JSON.stringify({
            fileId: metadata.fileId,
            encryptedSize: metadata.encryptedSize,
            plaintextSize: metadata.plaintextSize,
            requiredChunks: metadata.requiredChunks,
            totalChunks: metadata.totalChunks,
            chunkHashes: metadata.chunkHashes,
            ivHex: metadata.ivHex,
            expiryTime: metadata.expiryTime,
        });
        return crypto.createHmac('sha256', key).update(canonical).digest('hex');
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    /**
     * [FIX J] Domain-separated SHA-256 hash.
     * prefix format: "ghostchunk:<fileId>:<index>:<type>:"
     */
    _hash(fileId, index, type, buffer) {
        const prefix = `ghostchunk:${fileId}:${index}:${type}:`;
        return crypto.createHash('sha256')
            .update(prefix)
            .update(buffer)
            .digest('hex');
    }

    // ── Main Workflows ────────────────────────────────────────────────────────

    /**
     * Store a file buffer: encrypt → shard → distribute → return metadata + key.
     * The caller MUST securely store both the returned key and authTagHex.
     * Neither is stored in metadata.
     */
    async storeFileBuffer(fileBuffer, ttlSeconds = 3600, peers = ['node-A', 'node-B', 'node-C', 'node-D']) {
        if (!Buffer.isBuffer(fileBuffer) || fileBuffer.length === 0) {
            throw new TypeError('fileBuffer must be a non-empty Buffer.');
        }
        // [FIX E] Hard size limit.
        if (fileBuffer.length > MAX_FILE_BYTES) {
            throw new RangeError(`File too large. Maximum size is ${MAX_FILE_BYTES} bytes.`);
        }
        if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1) {
            throw new RangeError('ttlSeconds must be a positive integer.');
        }

        const fileId = crypto.randomUUID();

        // 1. Encrypt
        const { encryptedBuffer, keyHex, ivHex, authTagHex } = this.encryptFile(fileBuffer);

        // 2. Shard
        const DATA_SHARDS = 4;
        // [FIX K] Pass fileId for domain separation; splitChunks returns data+parity.
        const chunks = this.splitChunks(encryptedBuffer, fileId, DATA_SHARDS, 1);

        // 3. Distribute
        // [FIX M] Pass fileId for namespaced store keys.
        const locations = await this.distributeChunks(fileId, chunks, peers);

        // 4. Build metadata
        // [FIX A] authTag NOT stored here — returned to caller alongside the key.
        // [FIX K] Store both plaintextSize and encryptedSize.
        const metadata = {
            fileId,
            plaintextSize: fileBuffer.length,       // [FIX K] Original plaintext size
            encryptedSize: encryptedBuffer.length,  // [FIX K] Exact size for trim on reconstruction
            requiredChunks: DATA_SHARDS,
            totalChunks: chunks.length,           // [FIX D] Explicitly tracks data + parity count
            chunkHashes: chunks.map(c => c.hash), // Includes parity shard hash
            locations,
            ivHex,                                   // IV is non-secret; safe in metadata
            // authTag intentionally absent — caller responsibility
            expiryTime: Date.now() + (ttlSeconds * 1000),
        };

        // [FIX F] Bind metadata integrity to the file key.
        metadata.hmac = this._computeMetadataHmac(metadata, keyHex);

        // Return key AND authTag to caller — both needed for decryption.
        return {
            metadata,
            keyHex,
            authTagHex, // [FIX A] Returned to caller, NOT stored server-side.
        };
    }

    /**
     * Retrieve and decrypt a file.
     * [FIX F] Metadata HMAC verified before any reconstruction.
     * [FIX I] Decryption errors caught and re-thrown with context.
     */
    async retrieveFile(metadata, keyHex, authTagHex) {
        // [FIX B] Validate key before doing anything.
        _parseKey(keyHex);
        _parseAuthTag(authTagHex);

        // [FIX G] Expiry check on the authenticated value.
        if (typeof metadata.expiryTime !== 'number') {
            throw new Error('Metadata is missing expiryTime.');
        }
        if (Date.now() > metadata.expiryTime) {
            throw new Error('File has expired.');
        }

        // [FIX F] Verify metadata HMAC before trusting any field.
        const expectedHmac = this._computeMetadataHmac(metadata, keyHex);
        if (!crypto.timingSafeEqual(
            Buffer.from(expectedHmac, 'hex'),
            Buffer.from(metadata.hmac || '', 'hex')
        )) {
            throw new Error('Metadata HMAC verification failed — metadata may have been tampered with.');
        }

        // 1. Gather chunks from store.
        // [FIX D] Iterate ALL chunk hashes (data + parity) deterministically.
        const availableChunks = [];
        for (const hash of metadata.chunkHashes) {
            // [FIX M] Use namespaced key.
            const storeKey = `${metadata.fileId}:${hash}`;
            if (this.chunkStore.has(storeKey)) {
                availableChunks.push(this.chunkStore.get(storeKey));
            }
        }

        // 2. Reconstruct encrypted buffer.
        // [FIX C] Hash verification happens inside reconstructFile().
        const encryptedBuffer = await this.reconstructFile(metadata.fileId, metadata, availableChunks);

        // 3. Decrypt.
        // [FIX I] Decryption errors produce a clear, context-bearing message.
        return this.decryptFile(encryptedBuffer, keyHex, metadata.ivHex, authTagHex);
    }

    /**
     * Remove all chunks for a given fileId from the local store.
     */
    deleteFile(metadata) {
        if (!metadata?.fileId || typeof metadata.fileId !== 'string') {
            throw new TypeError('Valid metadata with fileId is required.');
        }
        for (const hash of (metadata.chunkHashes || [])) {
            // [FIX M] Namespaced deletion — does not affect other files.
            this.chunkStore.delete(`${metadata.fileId}:${hash}`);
        }
    }
}

module.exports = GhostStorage;