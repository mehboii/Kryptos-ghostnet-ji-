export type TransportMode = 'internet' | 'ble';
export type DiscoverySource = 'dht' | 'mdns' | 'bootstrap' | 'ble' | 'manual';

export interface DiscoveryPeer {
  nodeId: string;
  publicKey: Uint8Array;
  endpoints: PeerEndpoint[];
  discoveredVia: DiscoverySource;
  discoveredAt: number;
  lastVerified: number;
  trustScore: number;
}

export interface PeerEndpoint {
  ip: string;
  port: number;
  transport: TransportMode;
  verified: boolean;
}

export interface KBucketEntry {
  nodeId: string;
  publicKey: Uint8Array;
  endpoint: PeerEndpoint;
  lastSeen: number;
  lastPonged: number;
  failCount: number;
  ipPrefix: string;
  addedAt: number;
}

export interface DhtMessage {
  type: 'find_node' | 'find_node_reply' | 'ping' | 'pong' | 'store' | 'store_reply';
  nodeId: string;
  publicKey: string;
  target?: string;
  token?: string;
  closest?: DhtPeerInfo[];
  key?: string;
  value?: string;
  timestamp: number;
  nonce: string;
  signature: string;
  proofOfWork?: string;
}

export interface DhtPeerInfo {
  nodeId: string;
  publicKey: string;
  ip: string;
  port: number;
  signature: string;
}

export interface MdnsAnnouncement {
  nodeId: string;
  publicKey: string;
  port: number;
  timestamp: number;
  nonce: string;
  signature: string;
  challengeToken?: string;
}

export interface BootstrapNode {
  host: string;
  port: number;
  publicKeyHex: string;
  name: string;
}

export interface BootstrapResponse {
  peers: DhtPeerInfo[];
  timestamp: number;
  nonce: string;
  signature: string;
  serverNodeId: string;
}

export interface ProofOfWork {
  nonce: string;
  difficulty: number;
  hash: string;
}

export interface DhtConfig {
  k: number;
  alpha: number;
  bucketCount: number;
  maxIpPrefixPerBucket: number;
  pingIntervalMs: number;
  staleThresholdMs: number;
  refreshIntervalMs: number;
  powDifficulty: number;
  maxEntriesPerIp: number;
  maxGlobalPerPrefix: number;
  lookupTimeoutMs: number;
}

export const DEFAULT_DHT_CONFIG: DhtConfig = {
  k: 20,
  alpha: 3,
  bucketCount: 256,
  maxIpPrefixPerBucket: 2,
  pingIntervalMs: 60_000,
  staleThresholdMs: 900_000,
  refreshIntervalMs: 3_600_000,
  powDifficulty: 16,
  maxEntriesPerIp: 3,
  maxGlobalPerPrefix: 10,
  lookupTimeoutMs: 10_000,
};
