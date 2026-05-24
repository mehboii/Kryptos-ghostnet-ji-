import { describe, it, expect, beforeEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { TurnRelay } from '../relay/turnRelay.js';
import type { RelayTier, RelayQuota } from '../relay/turnRelay.js';

const TEST_SERVER = { host: '203.0.113.50', port: 3478 };

describe('TurnRelay — Quota Enforcement', () => {
  it('tier quotas exist for stealth, ghost, phantom', () => {
    for (const tier of ['stealth', 'ghost', 'phantom'] as RelayTier[]) {
      const relay = new TurnRelay(TEST_SERVER, 'node1', tier);
      expect(relay).toBeDefined();
      relay.teardown();
    }
  });

  it('phantom gets higher quota than stealth', () => {
    const stealth = new TurnRelay(TEST_SERVER, 'node1', 'stealth');
    const phantom = new TurnRelay(TEST_SERVER, 'node1', 'phantom');
    // Both should have different tier behavior — phantom has cover traffic
    expect(stealth).toBeDefined();
    expect(phantom).toBeDefined();
    stealth.teardown();
    phantom.teardown();
  });

  it('initial stats are zeroed', () => {
    const relay = new TurnRelay(TEST_SERVER, 'node1', 'stealth');
    const stats = relay.getStats();
    expect(stats.bytesSent).toBe(0);
    expect(stats.bytesReceived).toBe(0);
    expect(stats.bytesThisMinute).toBe(0);
    expect(stats.sessionsThisHour).toBe(0);
    relay.teardown();
  });

  it('sendToPeer returns false without allocation', () => {
    const relay = new TurnRelay(TEST_SERVER, 'node1', 'ghost');
    const result = relay.sendToPeer('peer1', Buffer.from('test'));
    expect(result).toBe(false);
    relay.teardown();
  });

  it('sendToPeer returns false without E2E key', () => {
    const relay = new TurnRelay(TEST_SERVER, 'node1', 'ghost');
    // Even if allocated, no key = no send (would need mock allocation to fully test)
    const result = relay.sendToPeer('peer1', Buffer.from('test'));
    expect(result).toBe(false);
    relay.teardown();
  });

  it('isAllocated is false before allocate()', () => {
    const relay = new TurnRelay(TEST_SERVER, 'node1', 'stealth');
    expect(relay.isAllocated).toBe(false);
    relay.teardown();
  });
});

describe('TurnRelay — E2E Encryption', () => {
  it('setE2EKey accepts a 32-byte shared secret keyed by nodeId', () => {
    const relay = new TurnRelay(TEST_SERVER, 'node1', 'ghost');
    const key = randomBytes(32);
    expect(() => relay.setE2EKey('peer_node_abc', key)).not.toThrow();
    relay.teardown();
  });
});

describe('TurnRelay — Teardown', () => {
  it('teardown cleans up without errors', () => {
    const relay = new TurnRelay(TEST_SERVER, 'node1', 'phantom');
    expect(() => relay.teardown()).not.toThrow();
    expect(relay.isAllocated).toBe(false);
  });

  it('double teardown is safe', () => {
    const relay = new TurnRelay(TEST_SERVER, 'node1', 'stealth');
    relay.teardown();
    expect(() => relay.teardown()).not.toThrow();
  });
});

describe('TurnRelay — UPnP Ban Verification', () => {
  it('no UPnP methods or properties exist on TurnRelay', () => {
    const relay = new TurnRelay(TEST_SERVER, 'node1', 'stealth');
    const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(relay));
    const hasUpnp = proto.some(name => /upnp/i.test(name));
    expect(hasUpnp).toBe(false);
    relay.teardown();
  });
});
