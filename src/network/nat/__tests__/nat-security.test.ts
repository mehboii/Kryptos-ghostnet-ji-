import { describe, it, expect, beforeEach } from 'vitest';
import { NatSecurityAuditor } from '../securityAudit.js';
import type { MultiStunResult, StunResult } from '../stun.js';
import type { PunchConfig, PunchResult } from '../holePunch.js';

// ── Helpers ───────────────────────────────────────────────────────────

function stunResult(ip: string, server: string, latency = 50): StunResult {
  return { ip, port: 40000, server, latencyMs: latency };
}

function multiStun(overrides: Partial<MultiStunResult> = {}): MultiStunResult {
  return {
    publicIp: '203.0.113.10',
    publicPort: 40000,
    consensus: true,
    results: [
      stunResult('203.0.113.10', 'stun.l.google.com:19302'),
      stunResult('203.0.113.10', 'stun1.l.google.com:19302'),
      stunResult('203.0.113.10', 'stun.cloudflare.com:3478'),
    ],
    disagreements: [],
    aborted: false,
    ...overrides,
  };
}

function punchConfig(overrides: Partial<PunchConfig> = {}): PunchConfig {
  return {
    localPort: 50000,
    peer: { ip: '203.0.113.20', port: 50001 },
    coordinationSource: 'verified_signal',
    expectedNodeId: 'abc123',
    ...overrides,
  };
}

function punchResult(overrides: Partial<PunchResult> = {}): PunchResult {
  return {
    state: 'established',
    peer: { ip: '203.0.113.20', port: 50001 },
    localPort: 50000,
    nonce: 'aabb',
    peerNonce: 'ccdd',
    securityFlags: [],
    ...overrides,
  };
}

// ── STUN Security Audit ──────────────────────────────────────────────

describe('NatSecurityAuditor — STUN', () => {
  let auditor: NatSecurityAuditor;
  beforeEach(() => { auditor = new NatSecurityAuditor(); });

  it('STUN-06: consensus with 3 agreeing servers → info', () => {
    const findings = auditor.auditStun(multiStun());
    expect(findings.some(f => f.id === 'STUN-06' && f.severity === 'info')).toBe(true);
  });

  it('STUN-01: no servers responded → critical', () => {
    const findings = auditor.auditStun(multiStun({ results: [], publicIp: '', aborted: true }));
    expect(findings.some(f => f.id === 'STUN-01' && f.severity === 'critical')).toBe(true);
  });

  it('STUN-02: single server response → high (no verification)', () => {
    const findings = auditor.auditStun(multiStun({
      results: [stunResult('203.0.113.10', 'stun.l.google.com:19302')],
      consensus: false,
    }));
    expect(findings.some(f => f.id === 'STUN-02' && f.severity === 'high')).toBe(true);
  });

  it('STUN-03: one server disagrees → high (reflection attack warning)', () => {
    const findings = auditor.auditStun(multiStun({
      results: [
        stunResult('203.0.113.10', 'stun.l.google.com:19302'),
        stunResult('203.0.113.10', 'stun1.l.google.com:19302'),
        stunResult('198.51.100.99', 'evil.stun.com:3478'),
      ],
      disagreements: ['evil.stun.com:3478'],
      consensus: false,
    }));
    expect(findings.some(f => f.id === 'STUN-03' && f.severity === 'high')).toBe(true);
  });

  it('STUN-04: all 3 disagree → critical abort', () => {
    const findings = auditor.auditStun(multiStun({
      publicIp: '',
      publicPort: 0,
      results: [
        stunResult('1.1.1.1', 'a:19302'),
        stunResult('2.2.2.2', 'b:19302'),
        stunResult('3.3.3.3', 'c:3478'),
      ],
      disagreements: ['a:19302', 'b:19302', 'c:3478'],
      consensus: false,
      aborted: true,
    }));
    expect(findings.some(f => f.id === 'STUN-04' && f.severity === 'critical')).toBe(true);
  });

  it('STUN-05: high latency → medium', () => {
    const findings = auditor.auditStun(multiStun({
      results: [
        stunResult('203.0.113.10', 'stun.l.google.com:19302', 1500),
        stunResult('203.0.113.10', 'stun1.l.google.com:19302', 80),
      ],
      consensus: false,
    }));
    expect(findings.some(f => f.id === 'STUN-05' && f.severity === 'medium')).toBe(true);
  });

  it('STUN-07: private IP returned as public → critical', () => {
    const findings = auditor.auditStun(multiStun({
      publicIp: '192.168.1.1',
      results: [
        stunResult('192.168.1.1', 'a:19302'),
        stunResult('192.168.1.1', 'b:19302'),
      ],
    }));
    expect(findings.some(f => f.id === 'STUN-07' && f.severity === 'critical')).toBe(true);
  });
});

// ── Hole Punch Pre-Execution Audit ───────────────────────────────────

describe('NatSecurityAuditor — Hole Punch Config', () => {
  let auditor: NatSecurityAuditor;
  beforeEach(() => { auditor = new NatSecurityAuditor(); });

  it('PUNCH-01: private IP as peer → critical', () => {
    const findings = auditor.auditPunchConfig(punchConfig({ peer: { ip: '192.168.1.50', port: 5000 } }));
    expect(findings.some(f => f.id === 'PUNCH-01' && f.severity === 'critical')).toBe(true);
  });

  it('PUNCH-01: loopback as peer → critical', () => {
    const findings = auditor.auditPunchConfig(punchConfig({ peer: { ip: '127.0.0.1', port: 5000 } }));
    expect(findings.some(f => f.id === 'PUNCH-01' && f.severity === 'critical')).toBe(true);
  });

  it('PUNCH-02: unknown coordination source → critical', () => {
    const findings = auditor.auditPunchConfig(punchConfig({ coordinationSource: 'unknown' }));
    expect(findings.some(f => f.id === 'PUNCH-02' && f.severity === 'critical')).toBe(true);
  });

  it('PUNCH-03: relay coordination → medium', () => {
    const findings = auditor.auditPunchConfig(punchConfig({ coordinationSource: 'relay' }));
    expect(findings.some(f => f.id === 'PUNCH-03' && f.severity === 'medium')).toBe(true);
  });

  it('PUNCH-04: privileged port → medium', () => {
    const findings = auditor.auditPunchConfig(punchConfig({ peer: { ip: '203.0.113.20', port: 80 } }));
    expect(findings.some(f => f.id === 'PUNCH-04' && f.severity === 'medium')).toBe(true);
  });

  it('clean config produces no critical/high findings', () => {
    const findings = auditor.auditPunchConfig(punchConfig());
    expect(findings.filter(f => f.severity === 'critical' || f.severity === 'high')).toHaveLength(0);
  });
});

// ── Hole Punch Post-Execution Audit ──────────────────────────────────

describe('NatSecurityAuditor — Hole Punch Result', () => {
  let auditor: NatSecurityAuditor;
  beforeEach(() => { auditor = new NatSecurityAuditor(); });

  it('PUNCH-05: unexpected source IP → critical MITM', () => {
    const findings = auditor.auditPunchResult(punchResult({ securityFlags: ['unexpected_source_ip'] }));
    expect(findings.some(f => f.id === 'PUNCH-05' && f.severity === 'critical')).toBe(true);
  });

  it('PUNCH-06: nodeId mismatch → critical', () => {
    const findings = auditor.auditPunchResult(punchResult({ securityFlags: ['nodeId_mismatch'] }));
    expect(findings.some(f => f.id === 'PUNCH-06' && f.severity === 'critical')).toBe(true);
  });

  it('PUNCH-07: stale timestamp → high replay', () => {
    const findings = auditor.auditPunchResult(punchResult({ securityFlags: ['stale_timestamp'] }));
    expect(findings.some(f => f.id === 'PUNCH-07' && f.severity === 'high')).toBe(true);
  });

  it('PUNCH-08: timeout → low', () => {
    const findings = auditor.auditPunchResult(punchResult({ state: 'failed', securityFlags: ['timeout'] }));
    expect(findings.some(f => f.id === 'PUNCH-08' && f.severity === 'low')).toBe(true);
  });

  it('PUNCH-09: successful establishment → info', () => {
    const findings = auditor.auditPunchResult(punchResult({ state: 'established' }));
    expect(findings.some(f => f.id === 'PUNCH-09' && f.severity === 'info')).toBe(true);
  });
});

// ── HolePuncher Unit Tests ───────────────────────────────────────────

describe('HolePuncher — Security Rejections', () => {
  it('rejects private IP peer endpoint', async () => {
    const { HolePuncher } = await import('../holePunch.js');
    const puncher = new HolePuncher('mynode');
    const result = await puncher.punch({
      localPort: 0,
      peer: { ip: '10.0.0.1', port: 5000 },
      coordinationSource: 'verified_signal',
      expectedNodeId: 'peernode',
    });
    expect(result.state).toBe('rejected');
    expect(result.securityFlags).toContain('private_ip_rejected');
    puncher.cancelAll();
  });

  it('rejects loopback peer endpoint', async () => {
    const { HolePuncher } = await import('../holePunch.js');
    const puncher = new HolePuncher('mynode');
    const result = await puncher.punch({
      localPort: 0,
      peer: { ip: '127.0.0.1', port: 5000 },
      coordinationSource: 'verified_signal',
      expectedNodeId: 'peernode',
    });
    expect(result.state).toBe('rejected');
    expect(result.securityFlags).toContain('private_ip_rejected');
    puncher.cancelAll();
  });

  it('rejects unknown coordination source', async () => {
    const { HolePuncher } = await import('../holePunch.js');
    const puncher = new HolePuncher('mynode');
    const result = await puncher.punch({
      localPort: 0,
      peer: { ip: '203.0.113.5', port: 5000 },
      coordinationSource: 'unknown',
      expectedNodeId: 'peernode',
    });
    expect(result.state).toBe('rejected');
    expect(result.securityFlags).toContain('unverified_coordination');
    puncher.cancelAll();
  });
});

// ── Full Report ──────────────────────────────────────────────────────

describe('NatSecurityAuditor — Report Generation', () => {
  it('generates report with score penalization', () => {
    const auditor = new NatSecurityAuditor();

    // Simulate: STUN works but one disagrees, punch has relay coordination
    auditor.auditStun(multiStun({
      results: [
        stunResult('203.0.113.10', 'a:19302'),
        stunResult('203.0.113.10', 'b:19302'),
        stunResult('198.51.100.99', 'c:3478'),
      ],
      disagreements: ['c:3478'],
      consensus: false,
    }));
    auditor.auditPunchConfig(punchConfig({ coordinationSource: 'relay' }));
    auditor.auditPunchResult(punchResult({ state: 'established' }));

    const report = auditor.generateReport();
    expect(report.stunAudited).toBe(true);
    expect(report.holePunchAudited).toBe(true);
    expect(report.score).toBeGreaterThan(0);
    expect(report.score).toBeLessThan(100);
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it('perfect scenario scores high', () => {
    const auditor = new NatSecurityAuditor();
    auditor.auditStun(multiStun()); // all agree
    auditor.auditPunchConfig(punchConfig()); // verified signal, public IP
    auditor.auditPunchResult(punchResult({ state: 'established' })); // clean

    const report = auditor.generateReport();
    expect(report.score).toBe(100); // only info findings, 0 penalty
  });

  it('worst case: all attacks present scores 0', () => {
    const auditor = new NatSecurityAuditor();
    auditor.auditStun(multiStun({ results: [], publicIp: '', aborted: true })); // STUN-01 + STUN-04
    auditor.auditPunchConfig(punchConfig({
      peer: { ip: '192.168.1.1', port: 80 },
      coordinationSource: 'unknown',
    })); // PUNCH-01 + PUNCH-02 + PUNCH-04
    auditor.auditPunchResult(punchResult({
      securityFlags: ['unexpected_source_ip', 'nodeId_mismatch', 'stale_timestamp'],
    })); // PUNCH-05 + PUNCH-06 + PUNCH-07 + PUNCH-09

    const report = auditor.generateReport();
    expect(report.score).toBe(0);
  });

  it('emits audit:finding for each finding', () => {
    const auditor = new NatSecurityAuditor();
    const emitted: string[] = [];
    auditor.on('audit:finding', (f) => emitted.push(f.id));
    auditor.auditStun(multiStun());
    expect(emitted.length).toBeGreaterThan(0);
  });

  it('clear resets findings', () => {
    const auditor = new NatSecurityAuditor();
    auditor.auditStun(multiStun());
    expect(auditor.allFindings.length).toBeGreaterThan(0);
    auditor.clear();
    expect(auditor.allFindings.length).toBe(0);
  });
});
