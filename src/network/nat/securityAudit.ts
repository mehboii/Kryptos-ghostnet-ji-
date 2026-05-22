import { EventEmitter } from 'node:events';
import type { MultiStunResult, StunResult } from './stun.js';
import type { PunchResult, PunchConfig } from './holePunch.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface AuditFinding {
  id: string;
  severity: Severity;
  category: 'stun' | 'hole_punch' | 'coordination' | 'network';
  title: string;
  detail: string;
  recommendation: string;
  timestamp: number;
}

export interface AuditReport {
  findings: AuditFinding[];
  score: number; // 0-100, higher = more secure
  stunAudited: boolean;
  holePunchAudited: boolean;
  generatedAt: number;
}

export interface SecurityAuditEvents {
  'audit:finding': [finding: AuditFinding];
  'audit:complete': [report: AuditReport];
}

export class NatSecurityAuditor extends EventEmitter<SecurityAuditEvents> {
  private findings: AuditFinding[] = [];

  /** Audit a multi-STUN discovery result for reflection attacks and anomalies. */
  auditStun(result: MultiStunResult): AuditFinding[] {
    const stunFindings: AuditFinding[] = [];

    // STUN-01: No servers responded
    if (result.results.length === 0) {
      stunFindings.push(this.finding('STUN-01', 'critical', 'stun',
        'No STUN servers responded',
        'All STUN queries failed or timed out. Public IP discovery is unavailable.',
        'Check network connectivity. Verify STUN servers are reachable and not blocked by firewall.',
      ));
    }

    // STUN-02: Only one server responded (no verification possible)
    if (result.results.length === 1) {
      stunFindings.push(this.finding('STUN-02', 'high', 'stun',
        'Single STUN server response — no multi-verification',
        `Only ${result.results[0].server} responded. A fake STUN server could lie about public IP without detection.`,
        'Ensure at least 2 independent STUN servers are reachable for majority verification.',
      ));
    }

    // STUN-03: Disagreement detected (possible reflection attack)
    if (result.disagreements.length > 0 && !result.aborted) {
      stunFindings.push(this.finding('STUN-03', 'high', 'stun',
        'STUN server disagreement — possible reflection attack',
        `Servers disagreed on public IP: ${result.disagreements.join(', ')} reported different IPs. Majority was used.`,
        'Investigate the disagreeing server. It may be compromised or a fake STUN endpoint.',
      ));
    }

    // STUN-04: All servers disagree (abort scenario)
    if (result.aborted) {
      stunFindings.push(this.finding('STUN-04', 'critical', 'stun',
        'All STUN servers disagree — discovery aborted',
        'Each STUN server returned a different public IP. This indicates a STUN reflection attack or severely broken network.',
        'Do not trust any discovered IP. Fall back to relay-only mode.',
      ));
    }

    // STUN-05: Unusually high latency (potential interception)
    for (const r of result.results) {
      if (r.latencyMs > 1000) {
        stunFindings.push(this.finding('STUN-05', 'medium', 'stun',
          'High STUN latency — possible interception',
          `${r.server} responded in ${r.latencyMs}ms. Normal is <200ms. May indicate MITM or network manipulation.`,
          'Verify network path. Consider blacklisting slow STUN servers.',
        ));
      }
    }

    // STUN-06: Consensus achieved
    if (result.consensus) {
      stunFindings.push(this.finding('STUN-06', 'info', 'stun',
        'STUN multi-verification consensus achieved',
        `${result.results.length} servers agree on public IP. Reflection attack risk is minimal.`,
        'No action needed.',
      ));
    }

    // STUN-07: Private IP returned as public
    if (result.publicIp && isPrivateIp(result.publicIp)) {
      stunFindings.push(this.finding('STUN-07', 'critical', 'stun',
        'STUN returned private IP as public',
        `Discovered IP ${result.publicIp} is a private address. STUN server may be spoofed or device is behind symmetric NAT.`,
        'Do not use this IP for peer communication. Fall back to relay.',
      ));
    }

    stunFindings.forEach(f => this.addFinding(f));
    return stunFindings;
  }

  /** Audit a hole punch configuration before execution. */
  auditPunchConfig(config: PunchConfig): AuditFinding[] {
    const punchFindings: AuditFinding[] = [];

    // PUNCH-01: Private/loopback peer endpoint
    if (isPrivateIp(config.peer.ip)) {
      punchFindings.push(this.finding('PUNCH-01', 'critical', 'hole_punch',
        'Hole punch target is a private IP',
        `Peer endpoint ${config.peer.ip}:${config.peer.port} is private/loopback. Coordination server may be compromised.`,
        'Reject this punch attempt. Verify coordination server integrity.',
      ));
    }

    // PUNCH-02: Unverified coordination source
    if (config.coordinationSource === 'unknown') {
      punchFindings.push(this.finding('PUNCH-02', 'critical', 'coordination',
        'Coordination source is unverified',
        'Peer endpoint was provided by an untrusted source. Attacker could redirect to malicious endpoint.',
        'Only accept peer endpoints from authenticated signaling channels.',
      ));
    }

    // PUNCH-03: Relay-sourced coordination
    if (config.coordinationSource === 'relay') {
      punchFindings.push(this.finding('PUNCH-03', 'medium', 'coordination',
        'Coordination via relay — moderate trust',
        'Peer endpoint came from a relay server. If the relay is compromised, the endpoint could be attacker-controlled.',
        'Verify peer identity via nonce exchange after punch succeeds.',
      ));
    }

    // PUNCH-04: Well-known port (possible honeypot)
    if (config.peer.port < 1024) {
      punchFindings.push(this.finding('PUNCH-04', 'medium', 'hole_punch',
        'Peer uses privileged port',
        `Port ${config.peer.port} is in the privileged range (<1024). Legitimate peers typically use ephemeral ports.`,
        'Flag for additional verification.',
      ));
    }

    punchFindings.forEach(f => this.addFinding(f));
    return punchFindings;
  }

  /** Audit a hole punch result after execution. */
  auditPunchResult(result: PunchResult): AuditFinding[] {
    const postFindings: AuditFinding[] = [];

    // PUNCH-05: Unexpected source IP during punch
    if (result.securityFlags.includes('unexpected_source_ip')) {
      postFindings.push(this.finding('PUNCH-05', 'critical', 'hole_punch',
        'Received punch packet from unexpected IP — possible MITM',
        'A packet arrived from a different IP than the expected peer during the punch window. An attacker may have won the race condition.',
        'Abort connection. Do not trust this peer.',
      ));
    }

    // PUNCH-06: NodeId mismatch
    if (result.securityFlags.includes('nodeId_mismatch')) {
      postFindings.push(this.finding('PUNCH-06', 'critical', 'hole_punch',
        'Node ID mismatch in punch response',
        'The punch response contained a different nodeId than expected. Attacker may be impersonating the peer.',
        'Reject connection immediately.',
      ));
    }

    // PUNCH-07: Stale timestamp
    if (result.securityFlags.includes('stale_timestamp')) {
      postFindings.push(this.finding('PUNCH-07', 'high', 'hole_punch',
        'Stale timestamp in punch packet — possible replay',
        'Punch packet timestamp is outside the ±5s window. May be a replayed punch from a previous session.',
        'Reject packet. Require fresh nonce exchange.',
      ));
    }

    // PUNCH-08: Timeout
    if (result.securityFlags.includes('timeout')) {
      postFindings.push(this.finding('PUNCH-08', 'low', 'hole_punch',
        'Hole punch timed out',
        'No response received within the 2-second punch window. NAT may be symmetric or peer is unreachable.',
        'Fall back to relay transport.',
      ));
    }

    // PUNCH-09: Successfully established
    if (result.state === 'established') {
      postFindings.push(this.finding('PUNCH-09', 'info', 'hole_punch',
        'Hole punch established with nonce verification',
        `Mutual nonce exchange completed with ${result.peer.ip}:${result.peer.port}. Connection is verified.`,
        'Proceed with encrypted communication.',
      ));
    }

    postFindings.forEach(f => this.addFinding(f));
    return postFindings;
  }

  /** Generate a full security report from all accumulated findings. */
  generateReport(): AuditReport {
    const score = this.computeScore();
    const report: AuditReport = {
      findings: [...this.findings],
      score,
      stunAudited: this.findings.some(f => f.category === 'stun'),
      holePunchAudited: this.findings.some(f => f.category === 'hole_punch' || f.category === 'coordination'),
      generatedAt: Date.now(),
    };
    this.emit('audit:complete', report);
    return report;
  }

  /** Clear all findings. */
  clear(): void {
    this.findings = [];
  }

  /** All findings collected so far. */
  get allFindings(): readonly AuditFinding[] {
    return this.findings;
  }

  private addFinding(f: AuditFinding): void {
    this.findings.push(f);
    this.emit('audit:finding', f);
  }

  private finding(
    id: string, severity: Severity, category: AuditFinding['category'],
    title: string, detail: string, recommendation: string,
  ): AuditFinding {
    return { id, severity, category, title, detail, recommendation, timestamp: Date.now() };
  }

  private computeScore(): number {
    let score = 100;
    const penalties: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
    for (const f of this.findings) {
      score -= penalties[f.severity];
    }
    return Math.max(0, Math.min(100, score));
  }
}

function isPrivateIp(ip: string): boolean {
  let normalized = ip;
  if (normalized.startsWith('::ffff:')) normalized = normalized.slice(7);
  const p = normalized.split('.').map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n) || n < 0 || n > 255)) return false;
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 127) return true;
  if (p[0] === 0) return true;
  return false;
}
