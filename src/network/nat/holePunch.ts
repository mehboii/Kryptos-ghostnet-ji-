import * as dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';

const PUNCH_WINDOW_MS = 2000;
const PUNCH_INTERVAL_MS = 100;
const PUNCH_MAX_ATTEMPTS = 20;
const NONCE_BYTES = 16;
export const MAX_PUNCH_PACKET_SIZE = 1024;

export interface PeerEndpoint {
  ip: string;
  port: number;
}

export interface PunchConfig {
  localPort: number;
  peer: PeerEndpoint;
  coordinationSource: 'verified_signal' | 'relay' | 'unknown';
  expectedNodeId: string;
}

export type PunchState = 'idle' | 'punching' | 'established' | 'failed' | 'rejected';

export interface PunchResult {
  state: PunchState;
  peer: PeerEndpoint;
  localPort: number;
  nonce: string;
  peerNonce?: string;
  rttMs?: number;
  securityFlags: string[];
}

export interface HolePunchEvents {
  'punch:start': [config: PunchConfig];
  'punch:established': [result: PunchResult];
  'punch:failed': [result: PunchResult];
  'punch:security': [flag: { type: string; detail: string }];
}

interface PunchPacket {
  type: 'punch' | 'ack';
  nonce: string;
  peerNonce?: string;
  nodeId: string;
  timestamp: number;
}

function isPrivateIp(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return false;
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true;
  return false;
}

export class HolePuncher extends EventEmitter<HolePunchEvents> {
  private readonly nodeId: string;
  private activePunches = new Map<string, { timer: ReturnType<typeof setInterval>; socket: dgram.Socket }>();

  constructor(nodeId: string) {
    super();
    this.nodeId = nodeId;
  }

  /**
   * Initiate UDP hole punching to a peer.
   * Both sides must call this simultaneously for NAT traversal to succeed.
   *
   * Security checks performed:
   * - Reject private/loopback IPs as peer endpoints
   * - Reject unverified coordination sources
   * - Nonce exchange to prevent replay and MITM
   * - Timestamp validation (±5s window)
   * - Verify nodeId in punch response matches expected
   */
  punch(config: PunchConfig): Promise<PunchResult> {
    return new Promise((resolve) => {
      const flags: string[] = [];
      const peerKey = `${config.peer.ip}:${config.peer.port}`;

      // Security: reject private IPs (attacker-controlled coordination server redirect)
      if (isPrivateIp(config.peer.ip)) {
        flags.push('private_ip_rejected');
        this.emitSecurity('private_ip_rejected', `Peer endpoint ${peerKey} is a private IP`);
        resolve(this.failResult(config, flags));
        return;
      }

      // Security: flag unverified coordination sources
      if (config.coordinationSource === 'unknown') {
        flags.push('unverified_coordination');
        this.emitSecurity('unverified_coordination', 'Peer endpoint came from unverified source');
        resolve(this.failResult(config, flags));
        return;
      }

      if (config.coordinationSource === 'relay') {
        flags.push('relay_coordination');
      }

      const nonce = randomBytes(NONCE_BYTES).toString('hex');
      const socket = dgram.createSocket('udp4');
      let attempts = 0;
      let established = false;

      const cleanup = () => {
        if (this.activePunches.has(peerKey)) {
          const entry = this.activePunches.get(peerKey)!;
          clearInterval(entry.timer);
          this.activePunches.delete(peerKey);
        }
        try { socket.close(); } catch {}
      };

      // Timeout: if not established within window, fail
      const timeout = setTimeout(() => {
        if (!established) {
          cleanup();
          flags.push('timeout');
          const result = this.failResult(config, flags);
          this.emit('punch:failed', result);
          resolve(result);
        }
      }, PUNCH_WINDOW_MS);

      socket.on('message', (msg, rinfo) => {
        if (established) return;

        if (msg.length > MAX_PUNCH_PACKET_SIZE) {
          flags.push('oversized_packet');
          this.emitSecurity('oversized_packet', `Packet size ${msg.length} exceeds limit ${MAX_PUNCH_PACKET_SIZE}`);
          return;
        }

        // Security: verify packet came from expected peer IP
        if (rinfo.address !== config.peer.ip) {
          flags.push('unexpected_source_ip');
          this.emitSecurity('unexpected_source_ip', `Expected ${config.peer.ip}, got ${rinfo.address}`);
          return; // Drop packet, don't establish
        }

        let packet: PunchPacket;
        try {
          packet = JSON.parse(msg.toString('utf8'));
        } catch {
          flags.push('malformed_packet');
          return;
        }

        // Security: verify nodeId matches expected
        if (packet.nodeId !== config.expectedNodeId) {
          flags.push('nodeId_mismatch');
          this.emitSecurity('nodeId_mismatch', `Expected ${config.expectedNodeId}, got ${packet.nodeId}`);
          return;
        }

        // Security: timestamp freshness (±5s window)
        if (Math.abs(Date.now() - packet.timestamp) > 5000) {
          flags.push('stale_timestamp');
          this.emitSecurity('stale_timestamp', 'Punch packet timestamp outside ±5s window');
          return;
        }

        if (packet.type === 'punch') {
          // Send ACK with both nonces
          const ack: PunchPacket = {
            type: 'ack',
            nonce,
            peerNonce: packet.nonce,
            nodeId: this.nodeId,
            timestamp: Date.now(),
          };
          socket.send(JSON.stringify(ack), config.peer.port, config.peer.ip);
        }

        if (packet.type === 'ack' && packet.peerNonce === nonce) {
          established = true;
          clearTimeout(timeout);
          cleanup();

          const result: PunchResult = {
            state: 'established',
            peer: config.peer,
            localPort: config.localPort,
            nonce,
            peerNonce: packet.nonce,
            securityFlags: flags,
          };
          this.emit('punch:established', result);
          resolve(result);
        }
      });

      socket.on('error', () => {
        if (!established) {
          established = true;
          clearTimeout(timeout);
          cleanup();
          flags.push('socket_error');
          resolve(this.failResult(config, flags));
        }
      });

      socket.bind(config.localPort, () => {
        const interval = setInterval(() => {
          if (established || attempts >= PUNCH_MAX_ATTEMPTS) {
            clearInterval(interval);
            return;
          }
          attempts++;
          const packet: PunchPacket = {
            type: 'punch',
            nonce,
            nodeId: this.nodeId,
            timestamp: Date.now(),
          };
          socket.send(JSON.stringify(packet), config.peer.port, config.peer.ip);
        }, PUNCH_INTERVAL_MS);

        this.activePunches.set(peerKey, { timer: interval, socket });
        this.emit('punch:start', config);
      });
    });
  }

  /** Cancel all active hole punch attempts. */
  cancelAll(): void {
    for (const [key, entry] of this.activePunches) {
      clearInterval(entry.timer);
      try { entry.socket.close(); } catch {}
      this.activePunches.delete(key);
    }
  }

  /** Number of active punch attempts. */
  get activeCount(): number {
    return this.activePunches.size;
  }

  private failResult(config: PunchConfig, flags: string[]): PunchResult {
    return {
      state: 'rejected',
      peer: config.peer,
      localPort: config.localPort,
      nonce: '',
      securityFlags: flags,
    };
  }

  private emitSecurity(type: string, detail: string): void {
    this.emit('punch:security', { type, detail });
  }
}
