import { EventEmitter } from 'node:events';
import type { Socket as TcpSocket } from 'node:net';
import type { RemoteInfo, Socket as UdpSocket } from 'node:dgram';

export interface ObservedEndpoint {
  ip: string;
  port: number;
  family: 'IPv4' | 'IPv6';
  observedAt: number;
}

export interface SocketObserverEvents {
  'endpoint:observed': [endpoint: ObservedEndpoint];
}

const MAX_OBSERVATIONS = 10_000;

export class SocketObserver extends EventEmitter<SocketObserverEvents> {
  private readonly observations: ObservedEndpoint[] = [];

  /** Observe a TCP socket and extract its remote endpoint. */
  observeTcp(socket: TcpSocket): ObservedEndpoint | null {
    const raw = socket.remoteAddress;
    const port = socket.remotePort;

    if (!raw || port == null) return null;

    const endpoint = this.resolve(raw, port);
    if (!endpoint) return null;

    this.record(endpoint);

    socket.once('error', () => {});
    return endpoint;
  }

  /** Attach to a UDP socket; emits on every incoming message. */
  observeUdp(socket: UdpSocket): void {
    socket.on('message', (_msg: Buffer, rinfo: RemoteInfo) => {
      const endpoint = this.resolve(rinfo.address, rinfo.port);
      if (!endpoint) return;
      this.record(endpoint);
    });
  }

  /** Return all observed endpoints so far. */
  getObservations(): readonly ObservedEndpoint[] {
    return this.observations;
  }

  /** Clear all in-memory observations. */
  clear(): void {
    this.observations.length = 0;
  }

  private resolve(raw: string, port: number): ObservedEndpoint | null {
    let ip = raw;
    let family: 'IPv4' | 'IPv6';

    if (ip.startsWith('::ffff:')) {
      ip = ip.slice(7);
      family = 'IPv4';
    } else if (ip.includes(':')) {
      // Pure IPv6 — skip
      return null;
    } else {
      family = 'IPv4';
    }

    return { ip, port, family, observedAt: Date.now() };
  }

  private record(endpoint: ObservedEndpoint): void {
    if (this.observations.length >= MAX_OBSERVATIONS) {
      this.observations.shift();
    }
    this.observations.push(endpoint);
    this.emit('endpoint:observed', endpoint);
  }
}
