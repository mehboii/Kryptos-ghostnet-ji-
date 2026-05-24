import { randomBytes } from 'node:crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import type { ProofOfWork } from './types.js';

/**
 * Proof-of-work for DHT join and store operations.
 * DEFENSE: Sybil — makes creating many identities computationally expensive.
 * Uses BLAKE3 for fast verification but expensive generation at target difficulty.
 */

/** Generate a proof-of-work: find a nonce where BLAKE3(nodeId + nonce) has `difficulty` leading zero bits. */
export function generatePoW(nodeId: string, difficulty: number): ProofOfWork {
  const maxIterations = 1 << 28;
  for (let i = 0; i < maxIterations; i++) {
    const nonce = bytesToHex(randomBytes(16));
    const hash = bytesToHex(blake3(new TextEncoder().encode(`${nodeId}:${nonce}`)));
    if (hasLeadingZeroBits(hash, difficulty)) {
      return { nonce, difficulty, hash };
    }
  }
  throw new Error('PoW generation exceeded max iterations');
}

/** Verify a proof-of-work is valid. */
export function verifyPoW(nodeId: string, pow: ProofOfWork): boolean {
  if (pow.difficulty < 1 || pow.difficulty > 64) return false;
  const expected = bytesToHex(blake3(new TextEncoder().encode(`${nodeId}:${pow.nonce}`)));
  if (expected !== pow.hash) return false;
  return hasLeadingZeroBits(expected, pow.difficulty);
}

function hasLeadingZeroBits(hexHash: string, bits: number): boolean {
  const fullNibbles = Math.floor(bits / 4);
  const remainingBits = bits % 4;

  for (let i = 0; i < fullNibbles; i++) {
    if (hexHash[i] !== '0') return false;
  }

  if (remainingBits > 0) {
    const nibble = parseInt(hexHash[fullNibbles], 16);
    if (nibble >= (1 << (4 - remainingBits))) return false;
  }

  return true;
}
