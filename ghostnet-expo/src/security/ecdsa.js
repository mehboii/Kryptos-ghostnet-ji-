import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';

/**
 * Convert a Uint8Array to a hex string.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert a hex string to Uint8Array.
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Compute SHA-256 hash of arbitrary data.
 * @param {Uint8Array|string} data - raw bytes or UTF-8 string
 * @returns {Uint8Array} 32-byte hash
 */
export function hashData(data) {
  if (typeof data === 'string') {
    const encoder = new TextEncoder();
    return sha256(encoder.encode(data));
  }
  return sha256(data);
}

/**
 * Sign a SHA-256 message hash with a private key.
 * All operations are local — no network calls.
 * @param {Uint8Array} msgHash - 32-byte SHA-256 hash
 * @param {string} privKeyHex - hex-encoded private key (32 bytes)
 * @returns {string} hex-encoded compact signature (64 bytes = 128 hex chars)
 */
export function signHash(msgHash, privKeyHex) {
  if (!(msgHash instanceof Uint8Array) || msgHash.length !== 32) {
    throw new Error('msgHash must be a 32-byte Uint8Array');
  }
  if (!privKeyHex || typeof privKeyHex !== 'string') {
    throw new Error('privKeyHex is required');
  }
  const privKeyBytes = hexToBytes(privKeyHex);
  const sigBytes = p256.sign(msgHash, privKeyBytes, { lowS: true });
  return bytesToHex(sigBytes);
}

/**
 * Verify a signature against a message hash and public key.
 * All operations are local — no network calls.
 * @param {Uint8Array} msgHash - 32-byte SHA-256 hash
 * @param {string} sigHex - hex-encoded compact signature
 * @param {string} pubKeyHex - hex-encoded compressed or uncompressed public key
 * @returns {boolean} true if signature is valid
 */
export function verifySignature(msgHash, sigHex, pubKeyHex) {
  if (!(msgHash instanceof Uint8Array) || msgHash.length !== 32) {
    return false;
  }
  if (!sigHex || !pubKeyHex) {
    return false;
  }
  try {
    const sigBytes = hexToBytes(sigHex);
    const pubKeyBytes = hexToBytes(pubKeyHex);
    return p256.verify(sigBytes, msgHash, pubKeyBytes, { lowS: true });
  } catch {
    return false;
  }
}

/**
 * Sign a plaintext payload: hash it, then sign the hash.
 * Convenience wrapper combining hashData + signHash.
 * @param {Uint8Array|string} payload - the raw message content
 * @param {string} privKeyHex - hex-encoded private key
 * @returns {{ checksum: string, signature: string }} hex checksum and signature
 */
export function signPayload(payload, privKeyHex) {
  const hash = hashData(payload);
  const checksum = bytesToHex(hash);
  const signature = signHash(hash, privKeyHex);
  return { checksum, signature };
}

/**
 * Full receiver-side verification pipeline:
 *   1. Recompute SHA-256 checksum (fast fail)
 *   2. Verify ECDSA signature against sender's public key
 * @param {Uint8Array|string} payload - the raw message content
 * @param {string} checksum - hex-encoded SHA-256 the sender claims
 * @param {string} sigHex - hex-encoded DER signature
 * @param {string} pubKeyHex - sender's hex-encoded public key
 * @returns {{ valid: boolean, reason?: string }}
 */
export function verifyPayload(payload, checksum, sigHex, pubKeyHex) {
  const hash = hashData(payload);
  const computedChecksum = bytesToHex(hash);

  if (computedChecksum !== checksum) {
    return { valid: false, reason: 'checksum_mismatch' };
  }

  if (!verifySignature(hash, sigHex, pubKeyHex)) {
    return { valid: false, reason: 'signature_invalid' };
  }

  return { valid: true };
}
