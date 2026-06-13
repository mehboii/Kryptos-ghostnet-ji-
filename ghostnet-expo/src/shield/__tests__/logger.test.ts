import { describe, expect, it } from 'vitest';
import { createLogger } from '../logger';

describe('redacted, opt-in, local-only logger', () => {
  it('is a no-op when disabled (zero retention)', () => {
    const lines: string[] = [];
    const log = createLogger({ enabled: false, sink: (l) => lines.push(l) });
    log.debug('rotated', { count: 3 });
    log.warn('failclosed');
    expect(lines).toEqual([]);
    expect(log.enabled).toBe(false);
  });

  it('redacts identifier-shaped values, keeps scalars', () => {
    const lines: string[] = [];
    const log = createLogger({ enabled: true, sink: (l) => lines.push(l) });
    log.debug('rotated', {
      newId: '0xabcdef0123456789abcdef0123456789',
      peer: 'aGhostTagLikeHandle',
      count: 3,
      ok: true,
    });
    const line = lines[0];
    expect(line).toContain('shield:rotated');
    expect(line).not.toContain('abcdef0123456789');
    expect(line).not.toContain('aGhostTagLikeHandle');
    expect(line).toContain('"count":3');
    expect(line).toContain('"ok":true');
    expect(line).toContain('[redacted]');
  });

  it('does not leak a raw node id passed as a field', () => {
    const lines: string[] = [];
    const log = createLogger({ enabled: true, sink: (l) => lines.push(l) });
    log.warn('transition', { nodeId: 'deadbeefdeadbeefdeadbeef' });
    expect(lines[0]).not.toContain('deadbeef');
  });
});
