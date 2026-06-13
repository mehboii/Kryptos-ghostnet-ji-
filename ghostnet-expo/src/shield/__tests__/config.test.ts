import { describe, expect, it } from 'vitest';
import { modulesForTier, resolveConfig } from '../config';
import { ModuleId, ShieldTier, TIER_RANK } from '../types';

const TIERS = [
  ShieldTier.OFF,
  ShieldTier.STEALTH,
  ShieldTier.GHOST,
  ShieldTier.PHANTOM,
  ShieldTier.FULL_GHOST,
] as const;

describe('tier → config (single source) is cumulative', () => {
  it('module set of each tier is a superset of the tier below', () => {
    for (let i = 1; i < TIERS.length; i++) {
      const below = modulesForTier(TIERS[i - 1]);
      const here = modulesForTier(TIERS[i]);
      for (const id of below) {
        expect(here.has(id), `${TIERS[i]} must include ${id} from ${TIERS[i - 1]}`).toBe(true);
      }
    }
  });

  it('maps each tier to exactly the spec module set', () => {
    expect([...modulesForTier(ShieldTier.OFF)]).toEqual([]);
    expect(new Set(modulesForTier(ShieldTier.STEALTH))).toEqual(
      new Set([ModuleId.BleCloak, ModuleId.DnsGuard]),
    );
    expect(new Set(modulesForTier(ShieldTier.GHOST))).toEqual(
      new Set([ModuleId.BleCloak, ModuleId.DnsGuard, ModuleId.TrafficShaper]),
    );
    expect(new Set(modulesForTier(ShieldTier.PHANTOM))).toEqual(
      new Set([
        ModuleId.BleCloak,
        ModuleId.DnsGuard,
        ModuleId.TrafficShaper,
        ModuleId.MeshRouting,
        ModuleId.DecoyEngine,
        ModuleId.NodeIdRotator,
      ]),
    );
    // FULL_GHOST enables the same modules as PHANTOM (knobs differ, set does not).
    expect(new Set(modulesForTier(ShieldTier.FULL_GHOST))).toEqual(
      new Set(modulesForTier(ShieldTier.PHANTOM)),
    );
  });

  it('OFF disables everything', () => {
    const cfg = resolveConfig(ShieldTier.OFF);
    expect(cfg.ble.silenceAdvertising).toBe(false);
    expect(cfg.dns.mode).toBe('system');
    expect(cfg.traffic.enabled).toBe(false);
    expect(cfg.mesh.enforceMinHops).toBe(false);
    expect(cfg.decoy.enabled).toBe(false);
    expect(cfg.nodeIdRotation.enabled).toBe(false);
  });

  it('STEALTH silences BLE + forces fail-closed DoH only', () => {
    const cfg = resolveConfig(ShieldTier.STEALTH);
    expect(cfg.ble.silenceAdvertising).toBe(true);
    expect(cfg.ble.silenceDiscoveryBeacon).toBe(true);
    expect(cfg.dns.mode).toBe('doh');
    expect(cfg.dns.failClosed).toBe(true);
    expect(cfg.traffic.enabled).toBe(false);
  });

  it('GHOST adds traffic shaping with the spec jitter window and buckets', () => {
    const cfg = resolveConfig(ShieldTier.GHOST);
    expect(cfg.traffic.enabled).toBe(true);
    expect(cfg.traffic.jitterMinMs).toBe(20);
    expect(cfg.traffic.jitterMaxMs).toBe(250);
    expect(cfg.traffic.paddingBuckets).toEqual([256, 512, 1024, 4096]);
    expect(cfg.traffic.coverTraffic).toBe('adaptive');
  });

  it('PHANTOM adds decoys (2–4), id rotation (30–90s), and max hops', () => {
    const cfg = resolveConfig(ShieldTier.PHANTOM);
    expect(cfg.decoy.enabled).toBe(true);
    expect(cfg.decoy.minDecoys).toBe(2);
    expect(cfg.decoy.maxDecoys).toBe(4);
    expect(cfg.nodeIdRotation.minIntervalMs).toBe(30_000);
    expect(cfg.nodeIdRotation.maxIntervalMs).toBe(90_000);
    expect(cfg.mesh.enforceMinHops).toBe(true);
    expect(cfg.mesh.minHops).toBeGreaterThanOrEqual(2);
  });

  it('FULL_GHOST pins every knob at max + cover traffic always-on', () => {
    const cfg = resolveConfig(ShieldTier.FULL_GHOST);
    expect(cfg.traffic.coverTraffic).toBe('always');
    expect(cfg.decoy.minDecoys).toBe(4);
    expect(cfg.decoy.maxDecoys).toBe(4);
    // Aggressive rotation window 10–20s.
    expect(cfg.nodeIdRotation.minIntervalMs).toBe(10_000);
    expect(cfg.nodeIdRotation.maxIntervalMs).toBe(20_000);
  });

  it('respects a custom DoH resolver', () => {
    const cfg = resolveConfig(ShieldTier.STEALTH, { dohResolver: 'https://dns.example/q' });
    expect(cfg.dns.dohResolver).toBe('https://dns.example/q');
  });

  it('tier ranks are strictly increasing', () => {
    for (let i = 1; i < TIERS.length; i++) {
      expect(TIER_RANK[TIERS[i]]).toBeGreaterThan(TIER_RANK[TIERS[i - 1]]);
    }
  });
});
