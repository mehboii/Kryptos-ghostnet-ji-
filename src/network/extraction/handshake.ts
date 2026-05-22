import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const HANDSHAKE_TTL_MS = 30_000;

export interface HandshakeMessage {
  nodeId: string;
  claimedLanIp: string;
  claimedPublicIp: string;
  publicKey: string;
  signature: string;
  timestamp: number;
}

export interface ClaimedEndpoint {
  nodeId: string;
  claimedLanIp: string;
  claimedPublicIp: string;
  signature: string;
  verified: boolean;
}

export class HandshakeParser {
  /**
   * Parse a raw handshake from Buffer or plain object and verify it.
   *
   * Auth order per spec: signature FIRST → nodeId → freshness → schema.
   * No field inspection leaks info before the signature is proven valid.
   */
  parse(input: Buffer | HandshakeMessage): ClaimedEndpoint {
    const msg = Buffer.isBuffer(input)
      ? (JSON.parse(input.toString('utf8')) as HandshakeMessage)
      : input;

    const result: ClaimedEndpoint = {
      nodeId: msg.nodeId,
      claimedLanIp: msg.claimedLanIp,
      claimedPublicIp: msg.claimedPublicIp,
      signature: msg.signature,
      verified: false,
    };

    // Step 1: Decode keys (prerequisite for sig check)
    const pubKeyBytes = this.decodeKey(msg.publicKey);
    if (!pubKeyBytes) return result;
    const sigBytes = this.decodeKey(msg.signature);
    if (!sigBytes) return result;

    // Step 2: Ed25519 signature — MUST be first real check (spec requirement)
    const payload = this.buildPayload(msg);
    let sigValid = false;
    try {
      sigValid = ed25519.verify(sigBytes, payload, pubKeyBytes);
    } catch {
      return result;
    }
    if (!sigValid) return result;

    // Step 3: Verify nodeId === BLAKE3(publicKey)
    if (!this.verifyNodeId(msg.nodeId, pubKeyBytes)) return result;

    // Step 4: Timestamp freshness (replay protection)
    if (!this.isFresh(msg.timestamp)) return result;

    // Step 5: Schema validation (IP format)
    if (!this.isValidIpFormat(msg.claimedLanIp) || !this.isValidIpFormat(msg.claimedPublicIp)) return result;

    result.verified = true;
    return result;
  }

  /** Check whether a handshake timestamp is within the replay window. */
  isFresh(timestamp: number): boolean {
    return Math.abs(Date.now() - timestamp) <= HANDSHAKE_TTL_MS;
  }

  /** Verify that nodeId === BLAKE3(publicKey). */
  verifyNodeId(nodeId: string, pubKeyBytes: Uint8Array): boolean {
    const expected = bytesToHex(blake3(pubKeyBytes));
    return nodeId === expected;
  }

  private buildPayload(msg: HandshakeMessage): Uint8Array {
    const text = `${msg.nodeId}:${msg.claimedLanIp}:${msg.claimedPublicIp}:${msg.timestamp}`;
    return new TextEncoder().encode(text);
  }

  private isValidIpFormat(ip: string): boolean {
    let normalized = ip;
    if (normalized.startsWith('::ffff:')) normalized = normalized.slice(7);
    if (/[:\n\r]/.test(normalized)) return false;
    const parts = normalized.split('.');
    if (parts.length !== 4) return false;
    return parts.every(p => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }

  private decodeKey(value: string): Uint8Array | null {
    try {
      if (/^[0-9a-f]+$/i.test(value)) return hexToBytes(value);
      return Uint8Array.from(Buffer.from(value, 'base64'));
    } catch {
      return null;
    }
  }
}
