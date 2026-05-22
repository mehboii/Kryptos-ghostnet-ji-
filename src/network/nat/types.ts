export type NatType = 'full_cone' | 'restricted_cone' | 'port_restricted' | 'symmetric' | 'unknown';
export type Confidence = 'high' | 'medium' | 'low';
export type PaddedSize = 512 | 1024 | 2048 | 4096;
export type ConnectionMethod = 'direct' | 'relay';
export type PunchMethod = 'direct_punch' | 'port_prediction' | 'turn_fallback';
export type RelayTier = 'ghost' | 'phantom' | 'spectre';

export interface ServerResult {
  server: string;
  ip?: string;
  port?: number;
  responded: boolean;
  responseTime: number;
}

export interface StunResult {
  success: boolean;
  publicIp?: string;
  publicPort?: number;
  natType: NatType;
  confidence: Confidence;
  serverResults: ServerResult[];
  error?: string;
}

export interface ValidationResult {
  valid: boolean;
  trustedIp?: string;
  trustedPort?: number;
  warnings: string[];
  attacks_detected: string[];
  confidence: Confidence;
}

export interface TurnAllocation {
  relayIp: string;
  relayPort: number;
  lifetime: number;
  server: string;
  allocatedAt: number;
}

export interface EncryptedPayload {
  ciphertext: Buffer;
  nonce: Buffer;
  signature: string;
  sequenceNumber: number;
  timestamp: number;
  paddedSize: PaddedSize;
  nodeId?: string;
}

export interface RelayStats {
  bytesRelayed: number;
  packetsRelayed: number;
  currentServer: string;
  sessionDuration: number;
  quotaUsed: number;
  quotaLimit: number;
}

export interface SignedEndpoint {
  nodeId: string;
  ip: string;
  port: number;
  timestamp: number;
  signature: string;
}

export interface HolePunchResult {
  success: boolean;
  reason?: string;
  socket?: import('node:dgram').Socket;
  peerEndpoint?: { ip: string; port: number };
  peerNodeId?: string;
  natType: NatType;
  punchAttempts: number;
  totalTime: number;
  method: PunchMethod;
}

export interface AuthResult {
  valid: boolean;
  reason?: string;
  peerNodeId?: string;
  data?: unknown;
  timestamp?: number;
}

export interface Connection {
  send(data: Buffer): Promise<void>;
  receive(): AsyncGenerator<Buffer>;
  method: ConnectionMethod;
  peerNodeId: string;
  established: number;
  close(): void;
}

export interface ConnectionStatus {
  connected: boolean;
  method: ConnectionMethod;
  peerNodeId?: string;
  natType: NatType;
  relayStats?: RelayStats;
  uptime: number;
}
