import * as dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';

const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_RESPONSE = 0x0101;
const STUN_MAGIC_COOKIE = 0x2112a442;
const STUN_ATTR_XOR_MAPPED = 0x0020;
const STUN_ATTR_MAPPED = 0x0001;
const STUN_TIMEOUT_MS = 3000;

export interface StunServer {
  host: string;
  port: number;
}

export interface StunResult {
  ip: string;
  port: number;
  server: string;
  latencyMs: number;
}

export interface MultiStunResult {
  publicIp: string;
  publicPort: number;
  consensus: boolean;
  results: StunResult[];
  disagreements: string[];
  aborted: boolean;
}

export interface StunDiscoveryEvents {
  'stun:result': [result: StunResult];
  'stun:consensus': [result: MultiStunResult];
  'stun:disagreement': [details: { server: string; ip: string; expected: string }];
}

const DEFAULT_SERVERS: StunServer[] = [
  { host: 'stun.l.google.com', port: 19302 },
  { host: 'stun1.l.google.com', port: 19302 },
  { host: 'stun.cloudflare.com', port: 3478 },
];

export function buildBindingRequest(): { buffer: Buffer; txId: Buffer } {
  const txId = randomBytes(12);

  const buf = Buffer.alloc(20);
  buf.writeUInt16BE(STUN_BINDING_REQUEST, 0);
  buf.writeUInt16BE(0, 2); // message length
  buf.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
  txId.copy(buf, 8);
  return { buffer: buf, txId };
}

function parseBindingResponse(data: Buffer, txId: Buffer): { ip: string; port: number } | null {
  if (data.length < 20) return null;
  const type = data.readUInt16BE(0);
  if (type !== STUN_BINDING_RESPONSE) return null;

  const cookie = data.readUInt32BE(4);
  if (cookie !== STUN_MAGIC_COOKIE) return null;

  // Verify transaction ID matches what we sent
  if (!data.subarray(8, 20).equals(txId)) return null;

  const msgLen = data.readUInt16BE(2);
  let offset = 20;
  const end = 20 + msgLen;

  while (offset + 4 <= end) {
    const attrType = data.readUInt16BE(offset);
    const attrLen = data.readUInt16BE(offset + 2);
    const attrStart = offset + 4;

    if (attrType === STUN_ATTR_XOR_MAPPED && attrLen >= 8) {
      const family = data[attrStart + 1];
      if (family === 0x01) { // IPv4
        const xPort = data.readUInt16BE(attrStart + 2) ^ (STUN_MAGIC_COOKIE >>> 16);
        const xIp = data.readUInt32BE(attrStart + 4) ^ STUN_MAGIC_COOKIE;
        const ip = `${(xIp >>> 24) & 0xff}.${(xIp >>> 16) & 0xff}.${(xIp >>> 8) & 0xff}.${xIp & 0xff}`;
        return { ip, port: xPort };
      }
    }

    if (attrType === STUN_ATTR_MAPPED && attrLen >= 8) {
      const family = data[attrStart + 1];
      if (family === 0x01) {
        const port = data.readUInt16BE(attrStart + 2);
        const ipNum = data.readUInt32BE(attrStart + 4);
        const ip = `${(ipNum >>> 24) & 0xff}.${(ipNum >>> 16) & 0xff}.${(ipNum >>> 8) & 0xff}.${ipNum & 0xff}`;
        return { ip, port };
      }
    }

    offset += 4 + attrLen;
    if (attrLen % 4 !== 0) offset += 4 - (attrLen % 4); // padding
  }

  return null;
}

/** Query a single STUN server for our public IP:port. */
function querySingleStun(server: StunServer, timeoutMs = STUN_TIMEOUT_MS): Promise<StunResult | null> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    const { buffer, txId } = buildBindingRequest();
    const start = Date.now();
    let resolved = false;

    const timer = setTimeout(() => {
      if (!resolved) { resolved = true; socket.close(); resolve(null); }
    }, timeoutMs);

    socket.on('message', (msg) => {
      if (resolved) return;
      const parsed = parseBindingResponse(msg, txId);
      if (parsed) {
        resolved = true;
        clearTimeout(timer);
        socket.close();
        resolve({
          ip: parsed.ip,
          port: parsed.port,
          server: `${server.host}:${server.port}`,
          latencyMs: Date.now() - start,
        });
      }
    });

    socket.on('error', () => {
      if (!resolved) { resolved = true; clearTimeout(timer); socket.close(); resolve(null); }
    });

    socket.send(buffer, server.port, server.host);
  });
}

export class StunDiscovery extends EventEmitter<StunDiscoveryEvents> {
  private readonly servers: StunServer[];

  constructor(servers?: StunServer[]) {
    super();
    this.servers = servers ?? DEFAULT_SERVERS;
  }

  /** Query a single STUN server. */
  async querySingle(server?: StunServer): Promise<StunResult | null> {
    const target = server ?? this.servers[0];
    const result = await querySingleStun(target);
    if (result) this.emit('stun:result', result);
    return result;
  }

  /**
   * Multi-STUN verification: query 3 independent servers, take majority.
   * If one disagrees → flag it, use majority IP.
   * If all 3 disagree → abort (reflection attack likely).
   */
  async discoverPublicEndpoint(): Promise<MultiStunResult> {
    const results = await Promise.all(this.servers.map(s => querySingleStun(s)));
    const valid = results.filter((r): r is StunResult => r !== null);

    if (valid.length === 0) {
      return { publicIp: '', publicPort: 0, consensus: false, results: [], disagreements: [], aborted: true };
    }

    valid.forEach(r => this.emit('stun:result', r));

    // Count votes per IP
    const votes = new Map<string, StunResult[]>();
    for (const r of valid) {
      const group = votes.get(r.ip) ?? [];
      group.push(r);
      votes.set(r.ip, group);
    }

    // Find majority
    let majorityIp = '';
    let majorityCount = 0;
    for (const [ip, group] of votes) {
      if (group.length > majorityCount) {
        majorityCount = group.length;
        majorityIp = ip;
      }
    }

    const disagreements: string[] = [];
    for (const r of valid) {
      if (r.ip !== majorityIp) {
        disagreements.push(r.server);
        this.emit('stun:disagreement', { server: r.server, ip: r.ip, expected: majorityIp });
      }
    }

    // All disagree (each IP unique and >= 3 servers responded) → abort
    const allDisagree = valid.length >= 3 && votes.size === valid.length;

    const majorityGroup = votes.get(majorityIp) ?? [];
    const majorityPort = majorityGroup[0]?.port ?? 0;

    const result: MultiStunResult = {
      publicIp: allDisagree ? '' : majorityIp,
      publicPort: allDisagree ? 0 : majorityPort,
      consensus: disagreements.length === 0 && valid.length >= 2,
      results: valid,
      disagreements,
      aborted: allDisagree,
    };

    this.emit('stun:consensus', result);
    return result;
  }
}
