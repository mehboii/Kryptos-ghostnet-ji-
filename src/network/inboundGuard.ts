import { EventEmitter } from 'node:events';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const NONCE_WINDOW_MS = 30_000;
const MAX_NONCE_CACHE = 50_000;
const MAX_PACKET_SIZE = 65_536;

export type InboundSource = 'socket' | 'ble' | 'qr' | 'mesh_relay' | 'handshake' | 'hole_punch';

export type DropReason =
  | 'oversized'
  | 'unparseable'
  | 'missing_fields'
  | 'signature_invalid'
  | 'schema_invalid'
  | 'nonce_replayed'
  | 'nonce_stale'
  | 'nodeId_mismatch';

export interface InboundPacket {
  nodeId: string;
  publicKey: string;
  signature: string;
  nonce: string;
  timestamp: number;
  payload: Record<string, unknown>;
}

export interface GuardVerdict {
  accepted: boolean;
  source: InboundSource;
  dropReason?: DropReason;
  nodeId?: string;
  packet?: InboundPacket;
}

export interface SignalIntelEntry {
  reason: DropReason;
  source: InboundSource;
  timestamp: number;
  sourceIp?: string;
}

export interface InboundGuardEvents {
  'guard:accepted': [verdict: GuardVerdict];
  'guard:dropped': [verdict: GuardVerdict];
  'guard:sigint': [entry: SignalIntelEntry];
}

export class InboundGuard extends EventEmitter<InboundGuardEvents> {
  private readonly seenNonces = new Map<string, number>();

  /**
   * The single entry point for ALL inbound data — sockets, BLE, QR, mesh relay.
   *
   * Spec-mandated auth flow:
   *   raw bytes → parse → Ed25519 sig valid? NO → DROP (silent)
   *                → YES → decrypt/decode payload
   *                → schema valid? NO → DROP + flag in Signal Intelligence
   *                → YES → nonce fresh? NO → DROP
   *                → YES → return accepted verdict
   *
   * Returns null on drop (silent — no error response to sender).
   */
  process(raw: Buffer | string, source: InboundSource, sourceIp?: string): GuardVerdict | null {
    const bytes = typeof raw === 'string' ? Buffer.from(raw, 'utf8') : raw;

    if (bytes.length > MAX_PACKET_SIZE || bytes.length === 0) {
      this.silentDrop('oversized', source, sourceIp);
      return null;
    }

    let packet: InboundPacket;
    try {
      packet = JSON.parse(bytes.toString('utf8'));
    } catch {
      this.silentDrop('unparseable', source, sourceIp);
      return null;
    }

    if (!packet.nodeId || !packet.publicKey || !packet.signature || !packet.nonce || !packet.timestamp || !packet.payload) {
      this.silentDrop('missing_fields', source, sourceIp);
      return null;
    }

    // Step 1: Ed25519 signature — FIRST check, per spec
    const sigValid = this.verifySignature(packet);
    if (!sigValid) {
      this.silentDrop('signature_invalid', source, sourceIp);
      return null;
    }

    // Step 2: Schema validation on decrypted payload
    if (!this.validateSchema(packet)) {
      this.flagAndDrop('schema_invalid', source, sourceIp);
      return null;
    }

    // Step 3: Nonce freshness — reject replays
    const nonceResult = this.checkNonce(packet.nonce, packet.timestamp);
    if (nonceResult !== 'fresh') {
      this.silentDrop(nonceResult === 'replayed' ? 'nonce_replayed' : 'nonce_stale', source, sourceIp);
      return null;
    }

    // Step 4: Verify nodeId === BLAKE3(publicKey)
    if (!this.verifyNodeId(packet)) {
      this.silentDrop('nodeId_mismatch', source, sourceIp);
      return null;
    }

    this.recordNonce(packet.nonce, packet.timestamp);

    const verdict: GuardVerdict = {
      accepted: true,
      source,
      nodeId: packet.nodeId,
      packet,
    };
    this.emit('guard:accepted', verdict);
    return verdict;
  }

  /** Signal intelligence log — recent drop events for monitoring. */
  get nonceCount(): number {
    return this.seenNonces.size;
  }

  /** Flush nonce cache and reset state. */
  clear(): void {
    this.seenNonces.clear();
  }

  private verifySignature(packet: InboundPacket): boolean {
    try {
      const pubKeyBytes = this.decodeKey(packet.publicKey);
      const sigBytes = this.decodeKey(packet.signature);
      if (!pubKeyBytes || !sigBytes) return false;

      const payload = new TextEncoder().encode(
        `${packet.nodeId}:${packet.nonce}:${packet.timestamp}:${JSON.stringify(packet.payload)}`,
      );
      return ed25519.verify(sigBytes, payload, pubKeyBytes);
    } catch {
      return false;
    }
  }

  private verifyNodeId(packet: InboundPacket): boolean {
    try {
      const pubKeyBytes = this.decodeKey(packet.publicKey);
      if (!pubKeyBytes) return false;
      const expected = bytesToHex(blake3(pubKeyBytes));
      return packet.nodeId === expected;
    } catch {
      return false;
    }
  }

  private validateSchema(packet: InboundPacket): boolean {
    if (typeof packet.payload !== 'object' || packet.payload === null) return false;
    if (typeof packet.nodeId !== 'string' || packet.nodeId.length === 0) return false;
    if (typeof packet.nonce !== 'string' || packet.nonce.length < 16) return false;
    if (typeof packet.timestamp !== 'number' || !Number.isFinite(packet.timestamp)) return false;
    return true;
  }

  private checkNonce(nonce: string, timestamp: number): 'fresh' | 'replayed' | 'stale' {
    const age = Math.abs(Date.now() - timestamp);
    if (age > NONCE_WINDOW_MS) return 'stale';
    if (this.seenNonces.has(nonce)) return 'replayed';
    return 'fresh';
  }

  private recordNonce(nonce: string, timestamp: number): void {
    if (this.seenNonces.size >= MAX_NONCE_CACHE) {
      const now = Date.now();
      for (const [key, ts] of this.seenNonces) {
        if (now - ts > NONCE_WINDOW_MS) this.seenNonces.delete(key);
      }
      if (this.seenNonces.size >= MAX_NONCE_CACHE) {
        const oldest = this.seenNonces.keys().next().value!;
        this.seenNonces.delete(oldest);
      }
    }
    this.seenNonces.set(nonce, timestamp);
  }

  /** Silent drop — no response to sender. Only internal event. */
  private silentDrop(reason: DropReason, source: InboundSource, sourceIp?: string): void {
    const verdict: GuardVerdict = { accepted: false, source, dropReason: reason };
    this.emit('guard:dropped', verdict);
  }

  /** Drop + flag in Signal Intelligence (schema failures get extra scrutiny). */
  private flagAndDrop(reason: DropReason, source: InboundSource, sourceIp?: string): void {
    const entry: SignalIntelEntry = { reason, source, timestamp: Date.now(), sourceIp };
    this.emit('guard:sigint', entry);
    this.silentDrop(reason, source, sourceIp);
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
