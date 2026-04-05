/**
 * GhostNet Node Identity System — BLAKE3
 * ═══════════════════════════════════════
 *
 * Deterministic, fast, and cryptographically secure node identity
 * derivation using BLAKE3 hashing of Ed25519 public keys.
 *
 * ─────────────────────────────────────────────────────────────
 * WHY BLAKE3 (NOT SHA-256, NOT Keccak, NOT Argon2)
 * ─────────────────────────────────────────────────────────────
 *
 * BLAKE3 vs SHA-256:
 *   • 5–15× faster on modern CPUs (Merkle tree internal structure,
 *     SIMD-friendly, parallelisable across cores).
 *   • No length-extension attack vulnerability (unlike SHA-256 in raw
 *     HMAC-less usage — BLAKE3 is a secure PRF natively).
 *   • Designed in 2020 with lessons from SHA-3/BLAKE2; 256-bit security
 *     margin with extensible output length.
 *   • Same 128-bit collision resistance as SHA-256 (256-bit output,
 *     birthday bound at 2^128).
 *
 * BLAKE3 vs Keccak (SHA-3 / ethers.id):
 *   • ~6× faster than Keccak-256 on x86.
 *   • Keccak is a sponge construction; BLAKE3 is a Merkle-Damgård
 *     variant with a tree structure — both are secure, BLAKE3 is faster.
 *   • GhostNet previously used ethers.id() (Keccak256). Replacing with
 *     BLAKE3 removes the ethers dependency for identity derivation and
 *     improves performance on resource-constrained mobile nodes.
 *
 * WHY NOT ARGON2 FOR NODE IDs:
 *   Argon2 is a memory-hard key derivation function designed to be
 *   intentionally SLOW (~200ms–800ms per evaluation). This is perfect
 *   for hashing low-entropy secrets like PINs and passwords, where you
 *   WANT to slow down brute-force attacks.
 *
 *   Node IDs are derived from PUBLIC KEYS — which have 128+ bits of
 *   entropy. There is no brute-force threat to defend against. Using
 *   Argon2 would:
 *     • Waste ~200ms per node ID computation (vs ~1μs for BLAKE3).
 *     • Consume 64–256 MiB of RAM per computation (catastrophic in a
 *       mesh network where nodes constantly compute IDs for routing).
 *     • Block the event loop on single-threaded runtimes (Node.js).
 *     • Make peer discovery and routing table updates 200,000× slower
 *       for zero security benefit.
 *
 *   RULE OF THUMB:
 *     Low-entropy secret (PIN, password) → Argon2id (SLOW, memory-hard)
 *     High-entropy input (public key)    → BLAKE3 (FAST, collision-resistant)
 *
 * ─────────────────────────────────────────────────────────────
 * WHY PUBLIC KEY–BASED IDENTITY
 * ─────────────────────────────────────────────────────────────
 *
 *   1. SELF-SOVEREIGN: No central authority issues identities.
 *      A node generates its own key pair and derives its own ID.
 *
 *   2. VERIFIABLE: Any peer can verify that a message from node N
 *      was signed by the private key whose public key hashes to N.
 *      This is the foundation of trust in decentralised systems.
 *
 *   3. SYBIL-RESISTANT (when combined with proof-of-work or stake):
 *      Generating a key pair is cheap, but if the network requires
 *      a proof tied to the node ID, mass identity generation becomes
 *      expensive.
 *
 *   4. DETERMINISTIC: The same public key always produces the same
 *      node ID. Peers can independently verify identity without
 *      consensus or coordination.
 *
 *   5. PRIVACY: The node ID does not reveal the public key (BLAKE3
 *      is a one-way function). The public key is only shared when
 *      the node chooses to identify itself for authentication.
 *
 * ─────────────────────────────────────────────────────────────
 * ARCHITECTURE
 * ─────────────────────────────────────────────────────────────
 *
 *   [Generate Ed25519 Key Pair]
 *           │
 *           ▼
 *   publicKey (32 bytes raw)
 *           │
 *           ▼
 *   BLAKE3(context || publicKey)    ← domain-separated PRF
 *           │
 *           ▼
 *   nodeId = "gn_" + hex(32 bytes)  ← 256-bit, human-readable
 *
 *   Stored: { nodeId, publicKey, createdAt }
 *   NOT stored in nodeId: private key, any secret material
 *
 * @module node-identity-blake3
 */

import { blake3 } from '@noble/hashes/blake3.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import crypto from 'crypto';

// ─── CONSTANTS ──────────────────────────────────────────────────────────────

/**
 * Domain separation context string for BLAKE3.
 *
 * WHY DOMAIN SEPARATION:
 *   Without a context prefix, the same public key bytes could produce
 *   the same hash in a different protocol. An attacker who controls
 *   identity in protocol A could impersonate the same node in protocol B.
 *
 *   By prepending "GhostNet.NodeIdentity.v1" we ensure that GhostNet
 *   node IDs are unique to this protocol even if the same key pair is
 *   used elsewhere.
 *
 *   BLAKE3 natively supports keyed hashing and derive_key modes, but
 *   for maximum portability (including browser WASM builds), we use
 *   simple context concatenation which is equally secure for this use
 *   case (the context is a fixed, public, non-secret string).
 */
const DOMAIN_CONTEXT = 'GhostNet.NodeIdentity.v1';
const CONTEXT_BYTES = new TextEncoder().encode(DOMAIN_CONTEXT);

/**
 * Node ID prefix for human readability and protocol identification.
 * "gn_" identifies this as a GhostNet node ID at a glance.
 */
const NODE_ID_PREFIX = 'gn_';

/**
 * Hash output length in bytes. 32 bytes = 256 bits.
 * Birthday collision probability: 2^128 — effectively impossible.
 */
const HASH_OUTPUT_LENGTH = 32;

/**
 * Validation regex for node IDs: prefix + exactly 64 hex chars.
 */
const NODE_ID_REGEX = /^gn_[0-9a-f]{64}$/;

// ─── CORE: NODE ID DERIVATION ───────────────────────────────────────────────

/**
 * Derive a node ID from a raw public key using BLAKE3.
 *
 * This is the core identity function. Given any public key (as bytes
 * or hex string), it deterministically produces a unique, fixed-length,
 * collision-resistant node identifier.
 *
 * PROPERTIES:
 *   • Deterministic: same key → same ID, always.
 *   • One-way: node ID does not reveal the public key.
 *   • Collision-resistant: 2^128 birthday bound (256-bit output).
 *   • Fast: ~1μs per derivation on modern hardware.
 *   • Domain-separated: GhostNet-specific context prevents cross-protocol
 *     identity reuse attacks.
 *
 * @param {Uint8Array|string} publicKey — 32-byte Ed25519 public key
 *                                        (raw bytes or hex string)
 * @returns {string} Node ID in format "gn_<64 hex chars>"
 * @throws {Error} If publicKey is invalid
 */
function getNodeId(publicKey) {
    // ── Normalise input ─────────────────────────────────────────────
    let keyBytes;
    if (typeof publicKey === 'string') {
        // Accept hex-encoded public key
        if (!/^[0-9a-fA-F]{64}$/.test(publicKey)) {
            throw new Error('Public key hex string must be exactly 64 characters (32 bytes).');
        }
        keyBytes = hexToBytes(publicKey);
    } else if (publicKey instanceof Uint8Array) {
        if (publicKey.length !== 32) {
            throw new Error(`Ed25519 public key must be exactly 32 bytes, got ${publicKey.length}.`);
        }
        keyBytes = publicKey;
    } else {
        throw new TypeError('publicKey must be a Uint8Array or 64-char hex string.');
    }

    // ── Domain-separated BLAKE3 hash ────────────────────────────────
    //
    // Input: CONTEXT_BYTES || keyBytes
    //
    // This concatenation is safe because:
    //   1. CONTEXT_BYTES has a fixed, known length (25 bytes for
    //      "GhostNet.NodeIdentity.v1").
    //   2. keyBytes has a fixed, validated length (32 bytes).
    //   3. There is no ambiguity in parsing — no variable-length fields.
    //   4. BLAKE3 is not vulnerable to length-extension attacks.
    //
    const input = new Uint8Array(CONTEXT_BYTES.length + keyBytes.length);
    input.set(CONTEXT_BYTES, 0);
    input.set(keyBytes, CONTEXT_BYTES.length);

    const hash = blake3(input, { dkLen: HASH_OUTPUT_LENGTH });

    return NODE_ID_PREFIX + bytesToHex(hash);
}

// ─── CORE: KEY PAIR GENERATION ──────────────────────────────────────────────

/**
 * Generate a complete node identity: Ed25519 key pair + BLAKE3 node ID.
 *
 * WHY Ed25519:
 *   • Fast key generation (~50μs) and signature verification (~70μs).
 *   • 32-byte keys (compact for mesh network packets).
 *   • Deterministic signatures (no nonce reuse vulnerability like
 *     ECDSA without RFC 6979).
 *   • Widely audited and used in production systems (SSH, Signal,
 *     WireGuard, Tor).
 *   • No point validation issues that plague some ECDSA curves.
 *
 * SECURITY:
 *   The private key is generated from 32 bytes of OS-level CSPRNG
 *   (crypto.getRandomValues / /dev/urandom). It has 256 bits of
 *   entropy — no brute-force attack is feasible.
 *
 * @returns {{
 *   nodeId: string,           — "gn_<64 hex chars>" — the network identity
 *   publicKey: string,        — 64-char hex — safe to share with all peers
 *   privateKey: string,       — 64-char hex — NEVER share, NEVER log
 *   publicKeyBytes: Uint8Array, — raw 32-byte public key
 *   privateKeyBytes: Uint8Array, — raw 32-byte private key (handle carefully)
 *   createdAt: number,        — Unix timestamp (ms)
 *   algorithm: string,        — "Ed25519" — for future multi-algo support
 *   hashFunction: string,     — "BLAKE3" — for migration tracking
 * }}
 */
function generateNodeIdentity() {
    // ── Generate Ed25519 key pair ───────────────────────────────────
    // @noble/curves uses OS CSPRNG internally (crypto.getRandomValues).
    const privateKeyBytes = ed25519.utils.randomSecretKey();
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);

    // ── Derive node ID ──────────────────────────────────────────────
    const nodeId = getNodeId(publicKeyBytes);

    // ── Encode keys as hex for storage/transmission ─────────────────
    const publicKey = bytesToHex(publicKeyBytes);
    const privateKey = bytesToHex(privateKeyBytes);

    return {
        nodeId,
        publicKey,
        privateKey,
        publicKeyBytes,
        privateKeyBytes,
        createdAt: Date.now(),
        algorithm: 'Ed25519',
        hashFunction: 'BLAKE3',
    };
}

// ─── SIGNING & VERIFICATION ─────────────────────────────────────────────────

/**
 * Sign a message with the node's private key.
 *
 * The signature proves that the message was created by the holder of
 * the private key corresponding to the public key that hashes to the
 * node ID. Any peer can verify this without trusting a central authority.
 *
 * @param {string|Uint8Array} message — Message to sign
 * @param {string|Uint8Array} privateKey — 32-byte Ed25519 private key
 * @returns {string} — 128-char hex signature (64 bytes)
 */
function signMessage(message, privateKey) {
    const msgBytes = typeof message === 'string'
        ? new TextEncoder().encode(message)
        : message;

    const keyBytes = typeof privateKey === 'string'
        ? hexToBytes(privateKey)
        : privateKey;

    const signature = ed25519.sign(msgBytes, keyBytes);
    return bytesToHex(signature);
}

/**
 * Verify a signature against a message and public key.
 *
 * VERIFICATION FLOW:
 *   1. Peer receives: { message, signature, senderNodeId, senderPublicKey }
 *   2. Peer checks: getNodeId(senderPublicKey) === senderNodeId
 *      → Confirms the public key matches the claimed identity.
 *   3. Peer checks: verifySignature(message, signature, senderPublicKey)
 *      → Confirms the message was signed by the corresponding private key.
 *
 *   Both checks must pass. If step 2 fails, the sender is lying about
 *   their identity. If step 3 fails, the message was tampered with.
 *
 * @param {string|Uint8Array} message   — Original message
 * @param {string} signature            — 128-char hex signature
 * @param {string|Uint8Array} publicKey — 32-byte Ed25519 public key
 * @returns {boolean} — true if signature is valid
 */
function verifySignature(message, signature, publicKey) {
    try {
        const msgBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;

        const sigBytes = typeof signature === 'string'
            ? hexToBytes(signature)
            : signature;

        const keyBytes = typeof publicKey === 'string'
            ? hexToBytes(publicKey)
            : publicKey;

        return ed25519.verify(sigBytes, msgBytes, keyBytes);
    } catch {
        // Invalid key format, corrupted signature, etc.
        // Return false rather than throwing — matches Web Crypto API behaviour.
        return false;
    }
}

/**
 * Verify that a claimed node ID matches a public key.
 *
 * This is the identity binding check: given a public key and a claimed
 * node ID, verify that the ID was correctly derived from that key.
 *
 * USE CASE: When a peer announces "I am node gn_abc123..." and presents
 * their public key, any other peer can verify this claim locally without
 * contacting a server.
 *
 * @param {string} claimedNodeId — The node ID the peer claims to own
 * @param {string|Uint8Array} publicKey — The peer's public key
 * @returns {boolean} — true if the node ID is correctly derived
 */
function verifyNodeId(claimedNodeId, publicKey) {
    try {
        const derivedId = getNodeId(publicKey);
        // Simple string comparison is safe here — node IDs are not secrets,
        // and timing attacks on public identity checks are not a threat.
        return derivedId === claimedNodeId;
    } catch {
        return false;
    }
}

// ─── VALIDATION ─────────────────────────────────────────────────────────────

/**
 * Validate that a string is a well-formed GhostNet node ID.
 *
 * This does NOT verify that the ID corresponds to a real public key —
 * it only checks the format (prefix + 64 hex chars).
 *
 * @param {string} nodeId — Candidate node ID
 * @returns {boolean}
 */
function isValidNodeIdFormat(nodeId) {
    return typeof nodeId === 'string' && NODE_ID_REGEX.test(nodeId);
}

/**
 * Shorten a node ID for display purposes.
 * Example: "gn_a1b2c3d4...ef56" → "gn_a1b2c3…ef56"
 *
 * @param {string} nodeId — Full node ID
 * @param {number} [prefixLen=8] — Chars to show after "gn_"
 * @param {number} [suffixLen=4] — Chars to show at end
 * @returns {string}
 */
function shortenNodeId(nodeId, prefixLen = 8, suffixLen = 4) {
    if (!nodeId || nodeId.length < NODE_ID_PREFIX.length + prefixLen + suffixLen) {
        return nodeId || '';
    }
    const start = nodeId.slice(0, NODE_ID_PREFIX.length + prefixLen);
    const end = nodeId.slice(-suffixLen);
    return `${start}…${end}`;
}

// ─── BENCHMARKING UTILITY ───────────────────────────────────────────────────

/**
 * Benchmark node ID derivation speed.
 * Useful for tuning and verifying performance claims.
 *
 * @param {number} [iterations=10000] — Number of derivations to time
 * @returns {{ totalMs: number, avgMicroseconds: number, opsPerSecond: number }}
 */
function benchmarkNodeId(iterations = 10000) {
    // Generate a key once
    const identity = generateNodeIdentity();
    const pubKeyBytes = identity.publicKeyBytes;

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
        getNodeId(pubKeyBytes);
    }
    const totalMs = performance.now() - start;

    return {
        totalMs: Math.round(totalMs * 100) / 100,
        avgMicroseconds: Math.round((totalMs / iterations) * 1000 * 100) / 100,
        opsPerSecond: Math.round(iterations / (totalMs / 1000)),
    };
}

// ─── EXPORTS ────────────────────────────────────────────────────────────────

export {
    // Core identity
    generateNodeIdentity,
    getNodeId,

    // Cryptographic operations
    signMessage,
    verifySignature,
    verifyNodeId,

    // Validation & display
    isValidNodeIdFormat,
    shortenNodeId,

    // Benchmarking
    benchmarkNodeId,

    // Constants (for external validation)
    NODE_ID_PREFIX,
    NODE_ID_REGEX,
    DOMAIN_CONTEXT,
};
