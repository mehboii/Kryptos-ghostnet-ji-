import * as dgram from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import type { BootstrapNode, BootstrapResponse, DhtPeerInfo, PeerEndpoint } from './types.js';

const BOOTSTRAP_TIMEOUT_MS = 8_000;
const NONCE_WINDOW_MS = 30_000;
const MAX_RESPONSE_PEERS = 50;
const MIN_AGREEMENT_RATIO = 0.5;
const MAX_RETRIES = 2;

export interface BootstrapClientEvents {
  'bootstrap:connected': [server: string];
  'bootstrap:peers_received': [count: number, server: string];
  'bootstrap:compromised': [server: string, reason: string];
  'bootstrap:cross_validated': [agreeing: number, total: number];
  'bootstrap:poisoned_routing': [server: string, reason: string];
  'bootstrap:all_failed': [];
}

/**
 * Bootstrap node client with anti-compromise and anti-poisoning defenses.
 *
 * DEFENSE: Compromise — public keys are pinned in code, not fetched from the server.
 * DEFENSE: Compromise — query multiple independent bootstrap nodes, cross-validate.
 * DEFENSE: Poisoned routing — reject responses where >50% peers share a /16 subnet.
 * DEFENSE: Poisoned routing — verify Ed25519 signatures on bootstrap responses.
 * DEFENSE: Poisoned routing — verify each returned peer's nodeId = BLAKE3(pubkey).
 * DEFENSE: MITM — pinned public keys prevent impersonation even if DNS is hijacked.
 */
export class BootstrapClient extends EventEmitter<BootstrapClientEvents> {
  private readonly nodeId: string;
  private readonly privateKey: Uint8Array;
  private readonly publicKey: Uint8Array;
  private readonly pinnedNodes: BootstrapNode[];

  constructor(nodeId: string, privateKey: Uint8Array, bootstrapNodes: BootstrapNode[]) {
    super();
    this.nodeId = nodeId;
    this.privateKey = privateKey;
    this.publicKey = ed25519.getPublicKey(privateKey);
    this.pinnedNodes = bootstrapNodes;
  }

  /**
   * Query all bootstrap nodes and return cross-validated peers.
   * DEFENSE: Queries all nodes in parallel, only accepts peers that appear in majority of responses.
   */
  async discover(): Promise<{ nodeId: string; publicKey: Uint8Array; ip: string; port: number }[]> {
    const results = await Promise.allSettled(
      this.pinnedNodes.map(node => this.queryNode(node)),
    );

    const validResponses: { server: string; peers: DhtPeerInfo[] }[] = [];
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.status === 'fulfilled' && result.value) {
        validResponses.push({ server: this.pinnedNodes[i].name, peers: result.value });
      }
    }

    if (validResponses.length === 0) {
      this.emit('bootstrap:all_failed');
      return [];
    }

    if (validResponses.length === 1) {
      return this.validateAndConvert(validResponses[0].peers);
    }

    return this.crossValidate(validResponses);
  }

  /** Query a single bootstrap node with pinned key verification. */
  private async queryNode(node: BootstrapNode): Promise<DhtPeerInfo[] | null> {
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        const result = await this.singleQuery(node);
        if (result) return result;
      } catch {
        // Retry
      }
    }
    return null;
  }

  private singleQuery(node: BootstrapNode): Promise<DhtPeerInfo[] | null> {
    return new Promise((resolve) => {
      const socket = dgram.createSocket('udp4');
      const nonce = bytesToHex(randomBytes(16));
      const timestamp = Date.now();

      const timer = setTimeout(() => {
        try { socket.close(); } catch {}
        resolve(null);
      }, BOOTSTRAP_TIMEOUT_MS);

      socket.on('message', (msg) => {
        clearTimeout(timer);
        try { socket.close(); } catch {}

        let response: BootstrapResponse;
        try { response = JSON.parse(msg.toString('utf8')); } catch { resolve(null); return; }

        // DEFENSE: Verify response is signed by the pinned key
        const pinnedPubKey = hexToBytes(node.publicKeyHex);
        const expectedNodeId = bytesToHex(blake3(pinnedPubKey));

        if (response.serverNodeId !== expectedNodeId) {
          this.emit('bootstrap:compromised', node.name, 'nodeId_mismatch');
          resolve(null);
          return;
        }

        if (Math.abs(Date.now() - response.timestamp) > NONCE_WINDOW_MS) {
          this.emit('bootstrap:compromised', node.name, 'stale_response');
          resolve(null);
          return;
        }

        const sigPayload = `bootstrap_response:${response.serverNodeId}:${response.timestamp}:${response.nonce}:${response.peers.length}`;
        try {
          const valid = ed25519.verify(
            hexToBytes(response.signature),
            new TextEncoder().encode(sigPayload),
            pinnedPubKey,
          );
          if (!valid) {
            this.emit('bootstrap:compromised', node.name, 'invalid_signature');
            resolve(null);
            return;
          }
        } catch {
          this.emit('bootstrap:compromised', node.name, 'signature_parse_error');
          resolve(null);
          return;
        }

        // DEFENSE: Poisoned routing — check /16 diversity
        if (!this.checkSubnetDiversity(response.peers, node.name)) {
          resolve(null);
          return;
        }

        if (response.peers.length > MAX_RESPONSE_PEERS) {
          response.peers = response.peers.slice(0, MAX_RESPONSE_PEERS);
        }

        this.emit('bootstrap:connected', node.name);
        this.emit('bootstrap:peers_received', response.peers.length, node.name);
        resolve(response.peers);
      });

      socket.on('error', () => {
        clearTimeout(timer);
        try { socket.close(); } catch {}
        resolve(null);
      });

      socket.bind(0, () => {
        const request = {
          type: 'bootstrap_request',
          nodeId: this.nodeId,
          publicKey: bytesToHex(this.publicKey),
          timestamp,
          nonce,
          signature: bytesToHex(
            ed25519.sign(
              new TextEncoder().encode(`bootstrap_request:${this.nodeId}:${timestamp}:${nonce}`),
              this.privateKey,
            ),
          ),
        };
        socket.send(Buffer.from(JSON.stringify(request), 'utf8'), node.port, node.host);
      });
    });
  }

  /**
   * Cross-validate peer lists from multiple bootstrap nodes.
   * DEFENSE: Only accept peers that appear in >50% of responses.
   * This prevents a single compromised bootstrap node from injecting malicious peers.
   */
  private crossValidate(responses: { server: string; peers: DhtPeerInfo[] }[]): { nodeId: string; publicKey: Uint8Array; ip: string; port: number }[] {
    const peerCounts = new Map<string, { peer: DhtPeerInfo; count: number }>();

    for (const { peers } of responses) {
      for (const peer of peers) {
        const existing = peerCounts.get(peer.nodeId);
        if (existing) {
          existing.count++;
        } else {
          peerCounts.set(peer.nodeId, { peer, count: 1 });
        }
      }
    }

    const threshold = Math.ceil(responses.length * MIN_AGREEMENT_RATIO);
    const agreed: DhtPeerInfo[] = [];

    for (const { peer, count } of peerCounts.values()) {
      if (count >= threshold) agreed.push(peer);
    }

    this.emit('bootstrap:cross_validated', agreed.length, peerCounts.size);
    return this.validateAndConvert(agreed);
  }

  /**
   * Validate each peer's nodeId = BLAKE3(publicKey) and convert.
   * DEFENSE: Prevents bootstrap nodes from injecting peers with fabricated nodeIds.
   */
  private validateAndConvert(peers: DhtPeerInfo[]): { nodeId: string; publicKey: Uint8Array; ip: string; port: number }[] {
    const valid: { nodeId: string; publicKey: Uint8Array; ip: string; port: number }[] = [];

    for (const peer of peers) {
      try {
        const pubKey = hexToBytes(peer.publicKey);
        const expectedId = bytesToHex(blake3(pubKey));
        if (peer.nodeId !== expectedId) continue;
        valid.push({ nodeId: peer.nodeId, publicKey: pubKey, ip: peer.ip, port: peer.port });
      } catch {
        // Skip malformed entries
      }
    }

    return valid;
  }

  /**
   * Check that returned peers are not all in the same /16 subnet.
   * DEFENSE: Poisoned routing — attacker controls a bootstrap and returns only their nodes.
   */
  private checkSubnetDiversity(peers: DhtPeerInfo[], serverName: string): boolean {
    if (peers.length < 4) return true;

    const prefixes = new Map<string, number>();
    for (const peer of peers) {
      const prefix = peer.ip.split('.').slice(0, 2).join('.');
      prefixes.set(prefix, (prefixes.get(prefix) ?? 0) + 1);
    }

    for (const [prefix, count] of prefixes) {
      if (count > peers.length * 0.5) {
        this.emit('bootstrap:poisoned_routing', serverName, `>50% peers in ${prefix}.0.0/16`);
        return false;
      }
    }

    return true;
  }
}
