import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ShieldManager, TIER_STORE_KEY } from '../ShieldManager';
import { createFakePorts, type FakePorts } from '../testing';
import {
  ModuleId,
  ShieldTier,
  type CapabilityReport,
  type ShieldConfig,
  type ShieldModule,
  type TierChangedPayload,
} from '../types';

let ports: FakePorts;

beforeEach(() => {
  ports = createFakePorts();
});

describe('state machine transitions', () => {
  it('starts OFF and stable', () => {
    const shield = new ShieldManager(ports);
    const s = shield.getStatus();
    expect(s.tier).toBe(ShieldTier.OFF);
    expect(s.stable).toBe(true);
  });

  it('transitions OFF → STEALTH → GHOST → PHANTOM, activating cumulative modules', async () => {
    const shield = new ShieldManager(ports);

    await shield.setTier(ShieldTier.STEALTH);
    expect(ports.ble.advertising).toBe(false);
    expect(ports.dns.mode).toBe('doh');

    await shield.setTier(ShieldTier.GHOST);
    expect(ports.mesh.transform).not.toBeNull(); // padding installed

    const status = await shield.setTier(ShieldTier.PHANTOM);
    expect(status.tier).toBe(ShieldTier.PHANTOM);
    expect(ports.mesh.minHops).toBeGreaterThan(0);
    const active = status.modules.filter((m) => m.active).map((m) => m.id);
    expect(active).toContain(ModuleId.BleCloak);
    expect(active).toContain(ModuleId.TrafficShaper);
    expect(active).toContain(ModuleId.MeshRouting);
  });

  it('emits tierChanged with from/to', async () => {
    const shield = new ShieldManager(ports);
    const events: TierChangedPayload[] = [];
    shield.on('tierChanged', (p) => events.push(p));

    await shield.setTier(ShieldTier.STEALTH);
    await shield.setTier(ShieldTier.GHOST);

    expect(events.map((e) => [e.from, e.to])).toEqual([
      [ShieldTier.OFF, ShieldTier.STEALTH],
      [ShieldTier.STEALTH, ShieldTier.GHOST],
    ]);
  });

  it('is idempotent: re-applying the same tier emits no tierChanged', async () => {
    const shield = new ShieldManager(ports);
    const events: TierChangedPayload[] = [];
    shield.on('tierChanged', (p) => events.push(p));

    await shield.setTier(ShieldTier.GHOST);
    await shield.setTier(ShieldTier.GHOST);
    expect(events).toHaveLength(1);
  });

  it('stepping down disables higher-tier modules', async () => {
    const shield = new ShieldManager(ports);
    await shield.setTier(ShieldTier.PHANTOM);
    expect(ports.mesh.minHops).toBeGreaterThan(0);

    await shield.setTier(ShieldTier.STEALTH);
    expect(ports.mesh.minHops).toBe(0); // MeshRouting disabled
    expect(ports.mesh.transform).toBeNull(); // TrafficShaper disabled
    // BleCloak still engaged at STEALTH.
    expect(ports.ble.advertising).toBe(false);
  });

  it('serializes concurrent transitions', async () => {
    const shield = new ShieldManager(ports);
    const [a, b, c] = await Promise.all([
      shield.setTier(ShieldTier.STEALTH),
      shield.setTier(ShieldTier.GHOST),
      shield.setTier(ShieldTier.PHANTOM),
    ]);
    expect(a.stable && b.stable && c.stable).toBe(true);
    expect(shield.getStatus().tier).toBe(ShieldTier.PHANTOM);
  });
});

describe('panic', () => {
  it('jumps straight to FULL_GHOST', async () => {
    const shield = new ShieldManager(ports);
    await shield.panic();
    expect(shield.getStatus().tier).toBe(ShieldTier.FULL_GHOST);
    // Always-on cover traffic ramps up.
    ports.clock.advance(60_000);
    expect(ports.mesh.sent.length).toBeGreaterThan(0);
  });
});

describe('persistence + restore', () => {
  it('persists the last stable tier (single key, overwritten)', async () => {
    const shield = new ShieldManager(ports);
    await shield.setTier(ShieldTier.GHOST);
    expect(await ports.store.getItem(TIER_STORE_KEY)).toBe(ShieldTier.GHOST);
    await shield.setTier(ShieldTier.STEALTH);
    expect(await ports.store.getItem(TIER_STORE_KEY)).toBe(ShieldTier.STEALTH);
  });

  it('restores the saved tier on a fresh manager', async () => {
    const first = new ShieldManager(ports);
    await first.setTier(ShieldTier.PHANTOM);

    // New manager, same persisted store.
    const second = new ShieldManager(ports);
    const restored = await second.restore();
    expect(restored.tier).toBe(ShieldTier.PHANTOM);
  });

  it('restore with no saved tier stays OFF', async () => {
    const shield = new ShieldManager(ports);
    const s = await shield.restore();
    expect(s.tier).toBe(ShieldTier.OFF);
  });
});

/** A module whose enable() throws — used to exercise rollback. */
class ExplodingModule implements ShieldModule {
  last: CapabilityReport;
  constructor(readonly id: ModuleId) {
    this.last = { id, requested: false, active: false, degraded: false };
  }
  async enable(_cfg: ShieldConfig): Promise<CapabilityReport> {
    throw new Error('hard failure');
  }
  async disable(): Promise<void> {
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }
  report(): CapabilityReport {
    return this.last;
  }
}

describe('atomic rollback on hard failure', () => {
  it('rolls back to the previous stable tier and emits degraded(rolledBack)', async () => {
    // Replace TrafficShaper (a GHOST module) with one that throws.
    const real = ShieldManager.defaultModules(ports).filter((m) => m.id !== ModuleId.TrafficShaper);
    const modules = [...real, new ExplodingModule(ModuleId.TrafficShaper)];
    const shield = new ShieldManager(ports, { modules });

    const degraded = vi.fn();
    shield.on('degraded', degraded);

    // Reach a good STEALTH baseline first.
    await shield.setTier(ShieldTier.STEALTH);
    expect(shield.getStatus().tier).toBe(ShieldTier.STEALTH);

    // GHOST enables the exploding TrafficShaper → must roll back to STEALTH.
    const status = await shield.setTier(ShieldTier.GHOST);
    expect(status.tier).toBe(ShieldTier.STEALTH);
    expect(status.stable).toBe(true);
    expect(degraded).toHaveBeenCalledTimes(1);
    expect(degraded.mock.calls[0][0].rolledBack).toBe(true);

    // STEALTH invariants are intact after rollback.
    expect(ports.ble.advertising).toBe(false);
    expect(ports.dns.mode).toBe('doh');
  });
});
