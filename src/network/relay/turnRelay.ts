import * as dgram from 'node:dgram';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { EventEmitter } from 'node:events';

const RELAY_TIMEOUT_MS = 10_000;
const RELAY_HEARTBEAT_MS = 15_000;
const ALLOCATION_LIFETIME_S = 600;
const CHANNEL_HEADER_SIZE = 4;
const E2E_ALGORITHM = 'aes-256-gcm';
const E2E_IV_BYTES = 12;
const E2E_TAG_BYTES = 16;

export type RelayTier = 'stealth' | 'ghost' | 'phantom';

export interface RelayServer {
  host: string;
  port: number;
}

export interface RelayQuota {
  maxBytesPerMinute: number;
  maxSessionsPerHour: number;
  coverTrafficEnabled: boolean;
}

export interface RelayAllocation {
  relayedAddress: string;
  relayedPort: number;
  lifetime: number;
  channelId: number;
  allocatedAt: number;
}

export interface RelayStats {
  bytesSent: number;
  bytesReceived: number;
  bytesThisMinute: number;
  sessionsThisHour: number;
  minuteResetAt: number;
  hourResetAt: number;
}

export interface TurnRelayEvents {
  'relay:allocated': [allocation: RelayAllocation];
  'relay:data': [data: Buffer, from: { ip: string; port: number }];
  'relay:expired': [];
  'relay:quota_exceeded': [stat: string];
  'relay:error': [error: string];
}

const TIER_QUOTAS: Record<RelayTier, RelayQuota> = {
  stealth: { maxBytesPerMinute: 1_000_000, maxSessionsPerHour: 10, coverTrafficEnabled: false },
  ghost: { maxBytesPerMinute: 5_000_000, maxSessionsPerHour: 30, coverTrafficEnabled: false },
  phantom: { maxBytesPerMinute: 20_000_000, maxSessionsPerHour: 100, coverTrafficEnabled: true },
};

export class TurnRelay extends EventEmitter<TurnRelayEvents> {
  private readonly server: RelayServer;
  private readonly nodeId: string;
  private readonly tier: RelayTier;
  private readonly quota: RelayQuota;
  private socket: dgram.Socket | null = null;
  private allocation: RelayAllocation | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private coverTimer: ReturnType<typeof setInterval> | null = null;
  private e2eKeys = new Map<string, Buffer>();
  private stats: RelayStats = {
    bytesSent: 0,
    bytesReceived: 0,
    bytesThisMinute: 0,
    sessionsThisHour: 0,
    minuteResetAt: Date.now() + 60_000,
    hourResetAt: Date.now() + 3_600_000,
  };

  constructor(server: RelayServer, nodeId: string, tier: RelayTier = 'stealth') {
    super();
    this.server = server;
    this.nodeId = nodeId;
    this.tier = tier;
    this.quota = { ...TIER_QUOTAS[tier] };
  }

  async allocate(): Promise<RelayAllocation> {
    if (this.allocation) return this.allocation;

    this.resetQuotaCountersIfNeeded();
    if (this.stats.sessionsThisHour >= this.quota.maxSessionsPerHour) {
      this.emit('relay:quota_exceeded', 'sessions_per_hour');
      throw new Error('Relay session quota exceeded');
    }

    this.socket = dgram.createSocket('udp4');

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('TURN allocation timed out'));
        this.teardown();
      }, RELAY_TIMEOUT_MS);

      this.socket!.on('message', (msg) => {
        if (this.allocation) {
          this.handleRelayedData(msg);
          return;
        }

        const parsed = this.parseAllocateResponse(msg);
        if (!parsed) return;

        clearTimeout(timeout);
        this.allocation = parsed;
        this.stats.sessionsThisHour++;

        this.startHeartbeat();
        if (this.quota.coverTrafficEnabled) this.startCoverTraffic();

        this.emit('relay:allocated', this.allocation);
        resolve(this.allocation);
      });

      this.socket!.on('error', (err) => {
        clearTimeout(timeout);
        this.emit('relay:error', err.message);
        reject(err);
      });

      this.socket!.bind(0, () => {
        this.sendAllocateRequest();
      });
    });
  }

  sendToPeer(peerNodeId: string, plaintext: Buffer): boolean {
    if (!this.socket || !this.allocation) return false;

    this.resetQuotaCountersIfNeeded();
    if (this.stats.bytesThisMinute + plaintext.length > this.quota.maxBytesPerMinute) {
      this.emit('relay:quota_exceeded', 'bytes_per_minute');
      return false;
    }

    const e2eKey = this.e2eKeys.get(peerNodeId);
    if (!e2eKey) return false;

    const payload = this.encrypt(plaintext, e2eKey);
    const channelData = this.buildChannelData(this.allocation.channelId, payload);
    this.socket.send(channelData, this.server.port, this.server.host);

    this.stats.bytesSent += plaintext.length;
    this.stats.bytesThisMinute += plaintext.length;
    return true;
  }

  setE2EKey(peerNodeId: string, sharedSecret: Buffer): void {
    this.e2eKeys.set(peerNodeId, sharedSecret);
  }

  getStats(): Readonly<RelayStats> {
    return { ...this.stats };
  }

  get isAllocated(): boolean {
    return this.allocation !== null;
  }

  teardown(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    if (this.coverTimer) {
      clearInterval(this.coverTimer);
      this.coverTimer = null;
    }
    if (this.socket) {
      try { this.socket.close(); } catch {}
      this.socket = null;
    }
    this.allocation = null;
    this.e2eKeys.clear();
    this.removeAllListeners();
  }

  private handleRelayedData(msg: Buffer): void {
    if (msg.length < CHANNEL_HEADER_SIZE) return;

    const channelNumber = msg.readUInt16BE(0);
    const length = msg.readUInt16BE(2);

    if (channelNumber < 0x4000 || channelNumber > 0x7ffe) return;
    if (msg.length < CHANNEL_HEADER_SIZE + length) return;

    let payload = msg.subarray(CHANNEL_HEADER_SIZE, CHANNEL_HEADER_SIZE + length);

    for (const [nodeId, key] of this.e2eKeys) {
      const decrypted = this.decrypt(payload, key);
      if (decrypted) {
        this.stats.bytesReceived += decrypted.length;
        this.emit('relay:data', decrypted, { ip: nodeId, port: 0 });
        return;
      }
    }

    // No matching key — silent drop. Never emit unencrypted data.
  }

  private encrypt(plaintext: Buffer, key: Buffer): Buffer {
    const iv = randomBytes(E2E_IV_BYTES);
    const cipher = createCipheriv(E2E_ALGORITHM, key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]);
  }

  private decrypt(ciphertext: Buffer, key: Buffer): Buffer | null {
    if (ciphertext.length < E2E_IV_BYTES + E2E_TAG_BYTES + 1) return null;
    try {
      const iv = ciphertext.subarray(0, E2E_IV_BYTES);
      const tag = ciphertext.subarray(E2E_IV_BYTES, E2E_IV_BYTES + E2E_TAG_BYTES);
      const data = ciphertext.subarray(E2E_IV_BYTES + E2E_TAG_BYTES);
      const decipher = createDecipheriv(E2E_ALGORITHM, key, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(data), decipher.final()]);
    } catch {
      return null;
    }
  }

  private buildChannelData(channelId: number, payload: Buffer): Buffer {
    const header = Buffer.alloc(CHANNEL_HEADER_SIZE);
    header.writeUInt16BE(channelId, 0);
    header.writeUInt16BE(payload.length, 2);
    return Buffer.concat([header, payload]);
  }

  private sendAllocateRequest(): void {
    const buf = Buffer.alloc(24);
    buf.writeUInt16BE(0x0003, 0);
    buf.writeUInt16BE(4, 2);
    buf.writeUInt32BE(0x2112a442, 4);
    randomBytes(12).copy(buf, 8);
    buf.writeUInt16BE(0x0019, 20);
    buf.writeUInt16BE(0x11, 22);
    this.socket!.send(buf, this.server.port, this.server.host);
  }

  private parseAllocateResponse(msg: Buffer): RelayAllocation | null {
    if (msg.length < 20) return null;
    const type = msg.readUInt16BE(0);
    if (type !== 0x0103) return null;

    const channelId = 0x4000 + (randomBytes(2).readUInt16BE(0) % 0x3ffe);

    return {
      relayedAddress: this.server.host,
      relayedPort: this.server.port,
      lifetime: ALLOCATION_LIFETIME_S,
      channelId,
      allocatedAt: Date.now(),
    };
  }

  private startHeartbeat(): void {
    this.heartbeatTimer = setInterval(() => {
      if (!this.allocation || !this.socket) return;
      const elapsed = Date.now() - this.allocation.allocatedAt;
      if (elapsed >= this.allocation.lifetime * 1000) {
        this.emit('relay:expired');
        this.teardown();
        return;
      }
      this.sendRefreshRequest();
    }, RELAY_HEARTBEAT_MS);
  }

  private startCoverTraffic(): void {
    this.coverTimer = setInterval(() => {
      if (!this.socket || !this.allocation) return;
      const noise = randomBytes(64 + Math.floor(Math.random() * 192));
      const channelData = this.buildChannelData(this.allocation.channelId, noise);
      this.socket.send(channelData, this.server.port, this.server.host);
    }, 2000 + Math.floor(Math.random() * 3000));
  }

  private sendRefreshRequest(): void {
    const buf = Buffer.alloc(20);
    buf.writeUInt16BE(0x0004, 0);
    buf.writeUInt16BE(0, 2);
    buf.writeUInt32BE(0x2112a442, 4);
    randomBytes(12).copy(buf, 8);
    this.socket!.send(buf, this.server.port, this.server.host);
  }

  private resetQuotaCountersIfNeeded(): void {
    const now = Date.now();
    if (now >= this.stats.minuteResetAt) {
      this.stats.bytesThisMinute = 0;
      this.stats.minuteResetAt = now + 60_000;
    }
    if (now >= this.stats.hourResetAt) {
      this.stats.sessionsThisHour = 0;
      this.stats.hourResetAt = now + 3_600_000;
    }
  }
}
