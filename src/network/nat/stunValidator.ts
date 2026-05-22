import type { StunResult, ValidationResult, Confidence } from './types.js';

const HISTORY_SIZE = 10;

interface HistoryEntry {
  ip: string;
  port: number;
  at: number;
}

export class StunValidator {
  private history: HistoryEntry[] = [];
  private knownStunServerIps = new Set<string>();

  /** Register a STUN server's IP so we can detect reflection. */
  addStunServerIp(ip: string): void {
    this.knownStunServerIps.add(ip);
  }

  /** Run all 5 validation checks on a STUN result. */
  validate(result: StunResult): ValidationResult {
    const warnings: string[] = [];
    const attacks: string[] = [];

    if (!result.success || !result.publicIp || !result.publicPort) {
      return { valid: false, warnings: ['stun_failed'], attacks_detected: [], confidence: 'low' };
    }

    const ip = result.publicIp;
    const port = result.publicPort;

    // Check 1: Consensus
    const responded = result.serverResults.filter(s => s.responded);
    const agreeing = responded.filter(s => s.ip === ip);
    if (responded.length >= 2 && agreeing.length < 2) {
      attacks.push('consensus_failure');
      warnings.push(`Only ${agreeing.length}/${responded.length} servers agree on IP`);
    }

    // Check 2: Private IP returned as public
    if (isPrivateIp(ip)) {
      attacks.push('private_ip_as_public');
      return { valid: false, trustedIp: undefined, trustedPort: undefined, warnings, attacks_detected: attacks, confidence: 'low' };
    }

    // Check 3: Historical consistency
    if (this.history.length >= 3) {
      const lastSubnet = this.history[this.history.length - 1].ip.split('.').slice(0, 2).join('.');
      const currentSubnet = ip.split('.').slice(0, 2).join('.');
      if (lastSubnet !== currentSubnet) {
        warnings.push('subnet_change_detected');
        const recentSubnets = new Set(this.history.slice(-5).map(h => h.ip.split('.').slice(0, 2).join('.')));
        if (!recentSubnets.has(currentSubnet)) {
          attacks.push('sudden_subnet_change');
        }
      }
    }

    // Check 4: Loopback/reserved
    if (isReservedIp(ip)) {
      attacks.push('reserved_ip_returned');
      return { valid: false, trustedIp: undefined, trustedPort: undefined, warnings, attacks_detected: attacks, confidence: 'low' };
    }

    // Check 5: Own server IP returned
    if (this.knownStunServerIps.has(ip)) {
      attacks.push('server_ip_reflection');
      return { valid: false, trustedIp: undefined, trustedPort: undefined, warnings, attacks_detected: attacks, confidence: 'low' };
    }

    // Record in history
    this.history.push({ ip, port, at: Date.now() });
    if (this.history.length > HISTORY_SIZE) this.history.shift();

    const confidence: Confidence = attacks.length > 0 ? 'low' : result.confidence;

    return {
      valid: attacks.length === 0,
      trustedIp: attacks.length === 0 ? ip : undefined,
      trustedPort: attacks.length === 0 ? port : undefined,
      warnings,
      attacks_detected: attacks,
      confidence,
    };
  }

  /** Clear validation history. */
  clear(): void {
    this.history = [];
  }

  /** Get history length for diagnostics. */
  get historyLength(): number {
    return this.history.length;
  }
}

function isPrivateIp(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n))) return false;
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true;
  return false;
}

function isReservedIp(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n))) return false;
  if (p[0] === 127) return true;
  if (p[0] === 0) return true;
  if (p[0] === 255 && p[1] === 255 && p[2] === 255 && p[3] === 255) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] === 198 && (p[1] === 18 || p[1] === 19)) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
  if (p[0] >= 224) return true;
  return false;
}
