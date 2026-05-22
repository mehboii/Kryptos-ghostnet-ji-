import * as dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { TurnAllocation, EncryptedPayload, RelayStats, RelayTier } from './types.js';

const ALLOCATE_TIMEOUT_MS = 8000;
const HEARTBEAT_MS = 30000;
const ALLOCATION_LIFETIME_S = 600;
const CHANNEL_HEADER = 4;
const MAX_RETRIES = 3;
const ACK_TIMEOUT_MS = 5000;

interface TierQuota { bytes: number; window: number }

const TIER_QUOTAS: Record<RelayTier, TierQuota> = {
  ghost:   { bytes: 100 * 1024 * 1024, window: 600_000 },
  phantom: { bytes: 1024 * 1024 * 1024, window: 3_600_000 },
  spectre: { bytes: 10 * 1024 * 1024 * 1024, window: Infinity },
};

export interface TurnClientEvents {
  'relay:allocated': [allocation: TurnAllocation];
  'relay:connected': [];
  'relay:migrating': [];
  'relay:migrated': [];
  'relay:failed': [error: string];
  'relay:quota_warning': [used: number, limit: number];
  'relay:quota_exceeded': [];
}

interface PendingAck {
  seq: number;
  data: EncryptedPayload;
  retries: number;
  timer: ReturnType<typeof setTimeout>;
}

export class TurnClient extends EventEmitter<TurnClientEvents> {
  private readonly tier: RelayTier;
  private readonly quota: TierQuota;
  private socket: dgram.Socket | null = null;
  private allocation: TurnAllocation | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private coverTimer: ReturnType<typeof setInterval> | null = null;
  private blacklistedServers = new Set<string>();
  private pendingAcks = new Map<number, PendingAck>();
  private lastSeqSeen = new Map<string, number>();
  private incomingQueue: EncryptedPayload[] = [];
  private receiveResolve: ((v: IteratorResult<Buffer>) => void) | null = null;
  private closed = false;

  private stats: RelayStats = {
    bytesRelayed: 0,
    packetsRelayed: 0,
    currentServer: '',
    sessionDuration: 0,
    quotaUsed: 0,
    quotaLimit: 0,
  };

  private quotaWindowStart = Date.now();

  constructor(tier: RelayTier = 'ghost') {
    super();
    this.tier = tier;
    this.quota = TIER_QUOTAS[tier];
    this.stats.quotaLimit = this.quota.bytes;
  }

  /** Allocate a TURN relay. Returns the allocation details. */
  async allocateRelay(server: { host: string; port: number }): Promise<TurnAllocation> {
    const key = `${server.host}:${server.port}`;
    if (this.blacklistedServers.has(key)) throw new Error('Server blacklisted');

    this.socket = dgram.createSocket('udp4');

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.teardown();
        reject(new Error('TURN allocation timed out'));
      }, ALLOCATE_TIMEOUT_MS);

      this.socket!.on('message', (msg) => {
        if (this.allocation) {
          this.handleIncoming(msg);
          return;
        }
        if (msg.length < 20) return;
        const type = msg.readUInt16BE(0);
        if (type !== 0x0103) return;

        clearTimeout(timeout);
        this.allocation = {
          relayIp: server.host,
          relayPort: server.port,
          lifetime: ALLOCATION_LIFETIME_S,
          server: key,
          allocatedAt: Date.now(),
        };
        this.stats.currentServer = key;
        this.startHeartbeat();
        if (this.tier === 'phantom' || this.tier === 'spectre') this.startCoverTraffic();
        this.emit('relay:allocated', this.allocation);
        resolve(this.allocation);
      });

      this.socket!.on('error', (err) => {
        clearTimeout(timeout);
        this.emit('relay:failed', err.message);
        reject(err);
      });

      this.socket!.bind(0, () => {
        const buf = Buffer.alloc(20);
        buf.writeUInt16BE(0x0003, 0);
        buf.writeUInt16BE(0, 2);
        buf.writeUInt32BE(0x2112a442, 4);
        randomBytes(12).copy(buf, 8);
        this.socket!.send(buf, server.port, server.host);
      });
    });
  }

  /** Create permission for a specific peer. */
  createPermission(peerIp: string, peerPort: number): void {
    if (!this.socket || !this.allocation) throw new Error('Not allocated');
    const buf = Buffer.alloc(32);
    buf.writeUInt16BE(0x0008, 0);
    buf.writeUInt16BE(12, 2);
    buf.writeUInt32BE(0x2112a442, 4);
    randomBytes(12).copy(buf, 8);
    buf.writeUInt16BE(0x0012, 20);
    buf.writeUInt16BE(8, 22);
    buf.writeUInt16BE(0x01, 24);
    buf.writeUInt16BE(peerPort ^ (0x2112a442 >>> 16), 26);
    const parts = peerIp.split('.').map(Number);
    const ipNum = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    buf.writeUInt32BE(ipNum ^ 0x2112a442, 28);
    this.socket.send(buf, this.allocation.relayPort, this.allocation.relayIp);
  }

  /** Send E2E encrypted data via relay. Only accepts EncryptedPayload. */
  sendViaRelay(payload: EncryptedPayload): boolean {
    if (!this.socket || !this.allocation) return false;

    this.resetQuotaIfNeeded();
    const size = payload.ciphertext.length;
    if (this.stats.quotaUsed + size > this.quota.bytes) {
      this.emit('relay:quota_exceeded');
      return false;
    }
    if (this.stats.quotaUsed + size > this.quota.bytes * 0.8) {
      this.emit('relay:quota_warning', this.stats.quotaUsed, this.quota.bytes);
    }

    const padded = this.padPayload(payload);
    const channelData = this.wrapChannel(0x4001, padded);
    this.socket.send(channelData, this.allocation.relayPort, this.allocation.relayIp);

    this.stats.bytesRelayed += size;
    this.stats.packetsRelayed++;
    this.stats.quotaUsed += size;
    this.stats.sessionDuration = Date.now() - this.allocation.allocatedAt;

    this.setupAck(payload);
    return true;
  }

  /** Receive decrypted data from relay. Caller must verify via PacketAuthenticator. */
  async *receiveFromRelay(): AsyncGenerator<Buffer> {
    while (!this.closed) {
      if (this.incomingQueue.length > 0) {
        const item = this.incomingQueue.shift()!;
        yield item.ciphertext;
        continue;
      }
      yield await new Promise<Buffer>((resolve) => {
        this.receiveResolve = (result) => resolve(result.value);
      });
    }
  }

  /** Get relay statistics. */
  getStats(): Readonly<RelayStats> {
    if (this.allocation) {
      this.stats.sessionDuration = Date.now() - this.allocation.allocatedAt;
    }
    return { ...this.stats };
  }

  get isAllocated(): boolean { return this.allocation !== null; }

  /** Blacklist a relay server after repeated failures. */
  blacklistServer(server: string): void {
    this.blacklistedServers.add(server);
  }

  /** Tear down relay connection. */
  teardown(): void {
    this.closed = true;
    if (this.heartbeatTimer) { clearInterval(this.heartbeatTimer); this.heartbeatTimer = null; }
    if (this.coverTimer) { clearInterval(this.coverTimer); this.coverTimer = null; }
    for (const ack of this.pendingAcks.values()) clearTimeout(ack.timer);
    this.pendingAcks.clear();
    if (this.socket) { try { this.socket.close(); } catch {} this.socket = null; }
    this.allocation = null;
  }

  private handleIncoming(msg: Buffer): void {
    if (msg.length < CHANNEL_HEADER) return;
    const ch = msg.readUInt16BE(0);
    const len = msg.readUInt16BE(2);
    if (ch < 0x4000 || ch > 0x7ffe) return;
    if (msg.length < CHANNEL_HEADER + len) return;

    const data = msg.subarray(CHANNEL_HEADER, CHANNEL_HEADER + len);

    // ACK handling
    if (data.length === 4 && data.toString('utf8').startsWith('ACK:')) {
      return;
    }

    try {
      const payload: EncryptedPayload = JSON.parse(data.toString('utf8'));

      // Replay check: monotonic sequence
      const peerKey = 'relay';
      const lastSeq = this.lastSeqSeen.get(peerKey) ?? -1;
      if (payload.sequenceNumber <= lastSeq) return;

      // Timestamp check
      if (Math.abs(Date.now() - payload.timestamp) > 30000) return;

      this.lastSeqSeen.set(peerKey, payload.sequenceNumber);
      this.stats.bytesRelayed += payload.ciphertext.length;
      this.stats.packetsRelayed++;

      if (this.receiveResolve) {
        const resolve = this.receiveResolve;
        this.receiveResolve = null;
        resolve({ value: Buffer.from(payload.ciphertext), done: false });
      } else {
        this.incomingQueue.push(payload);
      }
    } catch {
      // Malformed — silent drop
    }
  }

  private padPayload(payload: EncryptedPayload): Buffer {
    const json = JSON.stringify({
      ...payload,
      ciphertext: payload.ciphertext.toString('base64'),
      nonce: payload.nonce.toString('base64'),
    });
    const buf = Buffer.from(json, 'utf8');
    const target = payload.paddedSize;
    if (buf.length >= target) return buf;
    const padded = Buffer.alloc(target);
    buf.copy(padded);
    randomBytes(target - buf.length).copy(padded, buf.length);
    return padded;
  }

  private wrapChannel(channelId: number, data: Buffer): Buffer {
    const header = Buffer.alloc(CHANNEL_HEADER);
    header.writeUInt16BE(channelId, 0);
    header.writeUInt16BE(data.length, 2);
    return Buffer.concat([header, data]);
  }

  private setupAck(payload: EncryptedPayload): void {
    const seq = payload.sequenceNumber;
    const timer = setTimeout(() => {
      const pending = this.pendingAcks.get(seq);
      if (!pending) return;
      pending.retries++;
      if (pending.retries >= MAX_RETRIES) {
        this.pendingAcks.delete(seq);
        if (this.allocation) this.blacklistServer(this.allocation.server);
        return;
      }
      this.sendViaRelay(pending.data);
    }, ACK_TIMEOUT_MS);
    this.pendingAcks.set(seq, { seq, data: payload, retries: 0, timer });
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      if (!this.allocation || !this.socket) return;
      if (Date.now() - this.allocation.allocatedAt >= this.allocation.lifetime * 1000) {
        this.emit('relay:failed', 'allocation_expired');
        this.teardown();
        return;
      }
      const buf = Buffer.alloc(20);
      buf.writeUInt16BE(0x0004, 0);
      buf.writeUInt16BE(0, 2);
      buf.writeUInt32BE(0x2112a442, 4);
      randomBytes(12).copy(buf, 8);
      this.socket.send(buf, this.allocation.relayPort, this.allocation.relayIp);
    }, HEARTBEAT_MS);
  }

  private startCoverTraffic(): void {
    this.coverTimer = setInterval(() => {
      if (!this.socket || !this.allocation) return;
      const noise = randomBytes(128 + Math.floor(Math.random() * 384));
      this.socket.send(this.wrapChannel(0x4001, noise), this.allocation.relayPort, this.allocation.relayIp);
    }, 3000 + Math.floor(Math.random() * 4000));
  }

  private resetQuotaIfNeeded(): void {
    if (Date.now() - this.quotaWindowStart >= this.quota.window && this.quota.window !== Infinity) {
      this.stats.quotaUsed = 0;
      this.quotaWindowStart = Date.now();
    }
  }
}
