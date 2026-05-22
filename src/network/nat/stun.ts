import * as dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { StunResult, ServerResult, NatType, Confidence } from './types.js';

const MAGIC_COOKIE = 0x2112a442;
const BINDING_REQUEST = 0x0001;
const BINDING_RESPONSE = 0x0101;
const ATTR_MAPPED = 0x0001;
const ATTR_XOR_MAPPED = 0x0020;
const SERVER_TIMEOUT_MS = 3000;
const TOTAL_TIMEOUT_MS = 10000;
const CACHE_TTL_MS = 60000;

interface StunServer { host: string; port: number }

const DEFAULT_SERVERS: StunServer[] = [
  { host: 'stun.l.google.com', port: 19302 },
  { host: 'stun.cloudflare.com', port: 3478 },
  { host: 'stun.nextcloud.com', port: 3478 },
];

export interface StunClientEvents {
  'discovery:started': [];
  'discovery:complete': [result: StunResult];
  'discovery:failed': [error: string];
  'server:disagreement': [details: { servers: string[]; ips: string[] }];
}

export class StunClient extends EventEmitter<StunClientEvents> {
  private readonly servers: StunServer[];
  private pendingTxIds = new Map<string, { resolve: (v: { ip: string; port: number } | null) => void; timer: ReturnType<typeof setTimeout> }>();
  private cached: { result: StunResult; at: number } | null = null;

  constructor(servers?: StunServer[]) {
    super();
    this.servers = servers ?? DEFAULT_SERVERS;
  }

  /** Discover public endpoint via multi-STUN consensus. */
  async discover(): Promise<StunResult> {
    if (this.cached && Date.now() - this.cached.at < CACHE_TTL_MS) {
      return this.cached.result;
    }

    this.emit('discovery:started');

    const deadline = Date.now() + TOTAL_TIMEOUT_MS;
    const serverResults: ServerResult[] = [];
    const responses: { ip: string; port: number; server: string; time: number }[] = [];

    const queries = this.servers.map(async (srv) => {
      const label = `${srv.host}:${srv.port}`;
      const start = Date.now();
      try {
        const resp = await this.querySingle(srv, Math.min(SERVER_TIMEOUT_MS, deadline - Date.now()));
        if (resp) {
          responses.push({ ip: resp.ip, port: resp.port, server: label, time: Date.now() - start });
          serverResults.push({ server: label, ip: resp.ip, port: resp.port, responded: true, responseTime: Date.now() - start });
        } else {
          serverResults.push({ server: label, responded: false, responseTime: Date.now() - start });
        }
      } catch {
        serverResults.push({ server: label, responded: false, responseTime: Date.now() - start });
      }
    });

    await Promise.allSettled(queries);

    if (responses.length === 0) {
      const result: StunResult = { success: false, natType: 'unknown', confidence: 'low', serverResults, error: 'no_servers_responded' };
      this.emit('discovery:failed', 'no_servers_responded');
      return result;
    }

    const ipCounts = new Map<string, number>();
    for (const r of responses) {
      ipCounts.set(r.ip, (ipCounts.get(r.ip) ?? 0) + 1);
    }

    let majorityIp = '';
    let majorityCount = 0;
    for (const [ip, count] of ipCounts) {
      if (count > majorityCount) { majorityIp = ip; majorityCount = count; }
    }

    const uniqueIps = [...ipCounts.keys()];
    if (uniqueIps.length > 1 && responses.length >= 3 && ipCounts.size === responses.length) {
      const result: StunResult = { success: false, natType: 'unknown', confidence: 'low', serverResults, error: 'stun_consensus_failed' };
      this.emit('server:disagreement', { servers: responses.map(r => r.server), ips: uniqueIps });
      this.emit('discovery:failed', 'stun_consensus_failed');
      return result;
    }

    if (uniqueIps.length > 1) {
      this.emit('server:disagreement', { servers: responses.filter(r => r.ip !== majorityIp).map(r => r.server), ips: uniqueIps });
    }

    const majorityResponses = responses.filter(r => r.ip === majorityIp);
    const majorityPort = majorityResponses[0].port;
    const confidence = this.computeConfidence(responses.length, majorityCount);
    const natType = this.detectNatType(majorityResponses);

    const result: StunResult = {
      success: true,
      publicIp: majorityIp,
      publicPort: majorityPort,
      natType,
      confidence,
      serverResults,
    };

    this.cached = { result, at: Date.now() };
    this.emit('discovery:complete', result);
    return result;
  }

  /** Clear the cached STUN result. */
  clearCache(): void {
    this.cached = null;
  }

  private querySingle(server: StunServer, timeout: number): Promise<{ ip: string; port: number } | null> {
    return new Promise((resolve) => {
      if (timeout <= 0) { resolve(null); return; }

      const socket = dgram.createSocket('udp4');
      const txId = randomBytes(12);
      const txHex = txId.toString('hex');
      let done = false;

      const finish = (result: { ip: string; port: number } | null) => {
        if (done) return;
        done = true;
        this.pendingTxIds.delete(txHex);
        try { socket.close(); } catch {}
        resolve(result);
      };

      const timer = setTimeout(() => finish(null), timeout);
      this.pendingTxIds.set(txHex, { resolve: finish, timer });

      socket.on('message', (msg) => {
        const parsed = this.parseResponse(msg, txId);
        if (parsed) {
          clearTimeout(timer);
          finish(parsed);
        }
      });

      socket.on('error', () => {
        clearTimeout(timer);
        finish(null);
      });

      socket.send(this.buildRequest(txId), server.port, server.host);
    });
  }

  private buildRequest(txId: Buffer): Buffer {
    const buf = Buffer.alloc(20);
    buf.writeUInt16BE(BINDING_REQUEST, 0);
    buf.writeUInt16BE(0, 2);
    buf.writeUInt32BE(MAGIC_COOKIE, 4);
    txId.copy(buf, 8);
    return buf;
  }

  private parseResponse(data: Buffer, expectedTxId: Buffer): { ip: string; port: number } | null {
    if (data.length < 20) return null;
    if (data.readUInt16BE(0) !== BINDING_RESPONSE) return null;
    if (data.readUInt32BE(4) !== MAGIC_COOKIE) return null;
    if (!data.subarray(8, 20).equals(expectedTxId)) return null;

    const msgLen = data.readUInt16BE(2);
    let offset = 20;
    const end = Math.min(20 + msgLen, data.length);

    while (offset + 4 <= end) {
      const attrType = data.readUInt16BE(offset);
      const attrLen = data.readUInt16BE(offset + 2);
      const start = offset + 4;

      if (attrType === ATTR_XOR_MAPPED && attrLen >= 8 && data[start + 1] === 0x01) {
        const xPort = data.readUInt16BE(start + 2) ^ (MAGIC_COOKIE >>> 16);
        const xIp = data.readUInt32BE(start + 4) ^ MAGIC_COOKIE;
        return { ip: `${(xIp >>> 24) & 0xff}.${(xIp >>> 16) & 0xff}.${(xIp >>> 8) & 0xff}.${xIp & 0xff}`, port: xPort };
      }

      if (attrType === ATTR_MAPPED && attrLen >= 8 && data[start + 1] === 0x01) {
        const port = data.readUInt16BE(start + 2);
        const ipNum = data.readUInt32BE(start + 4);
        return { ip: `${(ipNum >>> 24) & 0xff}.${(ipNum >>> 16) & 0xff}.${(ipNum >>> 8) & 0xff}.${ipNum & 0xff}`, port };
      }

      offset += 4 + attrLen;
      if (attrLen % 4 !== 0) offset += 4 - (attrLen % 4);
    }
    return null;
  }

  private computeConfidence(total: number, agreeing: number): Confidence {
    if (total >= 3 && agreeing >= 3) return 'high';
    if (total >= 2 && agreeing >= 2) return 'medium';
    return 'low';
  }

  private detectNatType(responses: { ip: string; port: number; server: string }[]): NatType {
    if (responses.length < 2) return 'unknown';
    const ports = new Set(responses.map(r => r.port));
    if (ports.size === 1) return 'full_cone';
    const ips = new Set(responses.map(r => r.ip));
    if (ips.size === 1 && ports.size > 1) return 'symmetric';
    return 'restricted_cone';
  }
}
