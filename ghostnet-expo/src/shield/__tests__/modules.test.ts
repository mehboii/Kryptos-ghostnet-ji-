import { beforeEach, describe, expect, it } from 'vitest';
import { REASON } from '../capabilities';
import { PADDING_BUCKETS, resolveConfig } from '../config';
import { BleCloak } from '../modules/BleCloak';
import { DecoyEngine } from '../modules/DecoyEngine';
import { DnsGuard } from '../modules/DnsGuard';
import { MeshRouting } from '../modules/MeshRouting';
import { NodeIdRotator } from '../modules/NodeIdRotator';
import { TrafficShaper, unpadFrame } from '../modules/TrafficShaper';
import { TrafficModel } from '../traffic-model';
import { createFakePorts, type FakePorts } from '../testing';
import { ShieldTier, type MeshFrame } from '../types';

let ports: FakePorts;
beforeEach(() => {
  ports = createFakePorts();
});

/** Fresh shared traffic model for a set of ports. */
function mkModel(p: FakePorts): TrafficModel {
  return new TrafficModel(p.random, { buckets: PADDING_BUCKETS });
}

describe('capability degradation reporting', () => {
  it('BleCloak: degrades (not silent) when advertising control is unsupported', async () => {
    const p = createFakePorts({ ble: { supportsAdvertisingControl: false } });
    const mod = new BleCloak(p);
    const rep = await mod.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.requested).toBe(true);
    expect(rep.active).toBe(true); // did the achievable subset
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.BLE_ADV_UNSUPPORTED);
    expect(p.ble.discoveryBeacon).toBe(false); // beacon WAS silenced
    expect(p.ble.advertising).toBe(true); // honest: advertising could not be stopped
  });

  it('BleCloak: fully active when supported', async () => {
    const mod = new BleCloak(ports);
    const rep = await mod.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.degraded).toBe(false);
    expect(ports.ble.advertising).toBe(false);
  });

  it('DnsGuard: fails closed (blocks plaintext) when DoH is unreachable', async () => {
    const p = createFakePorts({ dns: { reachable: false } });
    const mod = new DnsGuard(p);
    const rep = await mod.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.active).toBe(true);
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.DOH_UNREACHABLE_FAILCLOSED);
    expect(p.dns.plaintextBlocked).toBe(true); // did NOT fall back to plaintext
  });

  it('DnsGuard: degrades when DoH is unsupported on the platform', async () => {
    const p = createFakePorts({ dns: { supportsDoh: false } });
    const mod = new DnsGuard(p);
    const rep = await mod.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.active).toBe(false);
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.DOH_UNSUPPORTED);
  });

  it('DnsGuard: clean DoH when reachable', async () => {
    const mod = new DnsGuard(ports);
    const rep = await mod.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.degraded).toBe(false);
    expect(ports.dns.mode).toBe('doh');
    expect(ports.dns.plaintextBlocked).toBe(false);
  });

  it('MeshRouting: degrades when hop control is unsupported', async () => {
    const p = createFakePorts({ mesh: { supportsHopControl: false } });
    const mod = new MeshRouting(p);
    const rep = await mod.enable(resolveConfig(ShieldTier.PHANTOM));
    expect(rep.active).toBe(false);
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.HOP_CONTROL_UNSUPPORTED);
  });

  it('NodeIdRotator: degrades when rotation is unsupported', async () => {
    const p = createFakePorts({ mesh: { supportsNodeIdRotation: false } });
    const mod = new NodeIdRotator(p);
    const rep = await mod.enable(resolveConfig(ShieldTier.PHANTOM));
    expect(rep.active).toBe(false);
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.NODE_ID_ROTATION_UNSUPPORTED);
  });
});

describe('TrafficShaper: jitter preserves order, E2EE intact', () => {
  it('delivers jittered frames in enqueue order', async () => {
    const shaper = new TrafficShaper(ports, mkModel(ports));
    await shaper.enable(resolveConfig(ShieldTier.GHOST));

    for (let i = 0; i < 6; i++) {
      const body = new Uint8Array([i, 0xaa, 0xbb]);
      shaper.send({ bytes: body, to: 'peer' } satisfies MeshFrame);
    }
    ports.clock.advance(2_000);

    const realFrames = ports.mesh.sent.filter((f) => f.to === 'peer');
    expect(realFrames).toHaveLength(6);
    const order = realFrames.map((f) => unpadFrame(f).bytes[0]);
    expect(order).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it('pads every sent frame to a bucket length', async () => {
    const shaper = new TrafficShaper(ports, mkModel(ports));
    await shaper.enable(resolveConfig(ShieldTier.GHOST));
    shaper.send({ bytes: new Uint8Array(50), to: 'peer' });
    ports.clock.advance(500);
    const f = ports.mesh.sent.find((x) => x.to === 'peer');
    expect(f).toBeDefined();
    expect(PADDING_BUCKETS).toContain((f as MeshFrame).bytes.length);
  });
});

describe('TrafficShaper: cover traffic ramps (no hard toggle)', () => {
  it('ramps the rate up in steps rather than jumping to target', async () => {
    const shaper = new TrafficShaper(ports, mkModel(ports));
    await shaper.enable(resolveConfig(ShieldTier.FULL_GHOST)); // always-on, target 60
    // Immediately after enable it is ramping, not already at full rate.
    expect(shaper.coverRatePerMin).toBeGreaterThan(0);
    expect(shaper.coverRatePerMin).toBeLessThan(60);
    ports.clock.advance(20_000);
    expect(shaper.coverRatePerMin).toBe(60);
  });

  it('emits indistinguishable, bucket-sized, payload-free cover frames', async () => {
    const shaper = new TrafficShaper(ports, mkModel(ports));
    await shaper.enable(resolveConfig(ShieldTier.FULL_GHOST));
    ports.clock.advance(30_000);
    const cover = ports.mesh.sent.filter((f) => f.to === null);
    expect(cover.length).toBeGreaterThan(0);
    for (const f of cover) {
      expect(PADDING_BUCKETS).toContain(f.bytes.length); // same shape as real frames
    }
  });

  it('ramps cover DOWN to zero on disable instead of cutting it', async () => {
    const shaper = new TrafficShaper(ports, mkModel(ports));
    await shaper.enable(resolveConfig(ShieldTier.FULL_GHOST));
    ports.clock.advance(20_000);
    expect(shaper.coverRatePerMin).toBe(60);

    await shaper.disable();
    expect(shaper.coverRatePerMin).toBeGreaterThan(0); // not an instant cut
    ports.clock.advance(20_000);
    expect(shaper.coverRatePerMin).toBe(0);
  });
});

describe('NodeIdRotator: session-safe handoff', () => {
  it('hands off to all active peers BEFORE retiring the old id', async () => {
    const p = createFakePorts({ mesh: { activeSessions: ['p1', 'p2'], nodeId: 'node-real' } });
    const rotator = new NodeIdRotator(p);
    await rotator.enable(resolveConfig(ShieldTier.PHANTOM));

    await rotator.rotate();

    // Both peers got an authenticated old→new handoff.
    expect(p.mesh.handoffs.map((h) => h.peerId).sort()).toEqual(['p1', 'p2']);
    const newId = p.mesh.adopted[0];
    expect(newId).toBeDefined();
    expect(p.mesh.handoffs.every((h) => h.oldId === 'node-real' && h.newId === newId)).toBe(true);

    // New id adopted; old id NOT yet retired (still in grace → no dropped sessions).
    expect(p.mesh.retired).toHaveLength(0);

    // After the grace window, the old id is retired.
    p.clock.advance(resolveConfig(ShieldTier.PHANTOM).nodeIdRotation.handoffGraceMs);
    expect(p.mesh.retired).toEqual(['node-real']);
  });

  it('rotates to a different id each time', async () => {
    const p = createFakePorts({ mesh: { activeSessions: ['p1'], nodeId: 'node-real' } });
    const rotator = new NodeIdRotator(p);
    await rotator.enable(resolveConfig(ShieldTier.FULL_GHOST));
    await rotator.rotate();
    const first = p.mesh.getCurrentNodeId();
    await rotator.rotate();
    const second = p.mesh.getCurrentNodeId();
    expect(first).not.toBe('node-real');
    expect(second).not.toBe(first);
  });
});

describe('DecoyEngine: plausible but unlinkable, no real-id leak', () => {
  it('maintains a 2–4 id pool, none equal to the real id, all distinct', async () => {
    const p = createFakePorts({ mesh: { nodeId: 'node-real' } });
    const engine = new DecoyEngine(p, mkModel(p));
    await engine.enable(resolveConfig(ShieldTier.PHANTOM));

    const ids = engine.decoyIds;
    expect(ids.length).toBeGreaterThanOrEqual(2);
    expect(ids.length).toBeLessThanOrEqual(4);
    for (const id of ids) {
      expect(id).not.toBe('node-real');
      expect(id).not.toContain('node-real');
    }
    expect(new Set(ids).size).toBe(ids.length); // unlinkable: distinct
  });

  it('emits announcements over time, sized from the model, never the real id', async () => {
    const p = createFakePorts({ mesh: { nodeId: 'node-real' } });
    const engine = new DecoyEngine(p, mkModel(p));
    await engine.enable(resolveConfig(ShieldTier.PHANTOM));
    p.clock.advance(60_000);

    expect(p.mesh.decoys.length).toBeGreaterThan(0);
    for (const d of p.mesh.decoys) {
      expect(d.ephemeralId).not.toBe('node-real');
      expect(d.payload.length).toBeGreaterThan(0); // no real payload, but well-formed
      expect(PADDING_BUCKETS).toContain(d.payload.length); // sized from the size model
    }
  });

  it('disable stops the emit + pool loops', async () => {
    const engine = new DecoyEngine(ports, mkModel(ports));
    await engine.enable(resolveConfig(ShieldTier.PHANTOM));
    ports.clock.advance(60_000);
    const before = ports.mesh.decoys.length;
    await engine.disable();
    ports.clock.advance(120_000);
    expect(ports.mesh.decoys.length).toBe(before); // no further announcements
  });
});
