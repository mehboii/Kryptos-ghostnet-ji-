/**
 * Capability-honesty tests for the WEB and NATIVE platform profiles.
 *
 * These lock in the core contract of this change: the web build must report
 * hardware-dependent capabilities (BLE, on-device detection, attestation) as
 * UNAVAILABLE/UNKNOWN — never active — while the pure-overlay behaviors
 * (node-id rotation, traffic shaping, decoy traffic, DoH) run for real. And
 * there must be NO "MAC rotation" logic or fabricated MAC strings anywhere.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { ShieldManager } from '../ShieldManager';
import { REASON } from '../capabilities';
import { GhostShieldFacade } from '../web/facade';
import { createNativePorts, type NativeBleBridge } from '../web/nativePorts';
import { createWebPorts } from '../web/webPorts';
import { ModuleId, ShieldTier, type CapabilityReport } from '../types';

function reportFor(modules: readonly CapabilityReport[], id: ModuleId): CapabilityReport {
  const r = modules.find((m) => m.id === id);
  if (!r) throw new Error(`no report for ${id}`);
  return r;
}

describe('WEB platform — honest capability reporting', () => {
  it('BleCloak reports UNAVAILABLE (not active) on web, with the no-stack reason', async () => {
    const ports = createWebPorts();
    expect(ports.ble.isAvailable()).toBe(false);

    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.FULL_GHOST);
    const ble = reportFor(status.modules, ModuleId.BleCloak);

    expect(ble.requested).toBe(true);
    expect(ble.active).toBe(false); // never claims BLE is active without a stack
    expect(ble.degraded).toBe(true);
    expect(ble.reason).toBe(REASON.BLE_UNAVAILABLE);
  });

  it('node-id rotation runs for real (active) on web — the real anti-tracking behavior', async () => {
    const ports = createWebPorts();
    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.PHANTOM);

    const rotator = reportFor(status.modules, ModuleId.NodeIdRotator);
    expect(rotator.active).toBe(true); // overlay rotation is achievable on web
    // ...but the BLE advertising-shape randomization bonus is honestly degraded.
    expect(rotator.degraded).toBe(true);
    expect(ports.mesh.supportsNodeIdRotation()).toBe(true);
  });

  it('overlay behaviors (traffic shaping, decoys) are active on web', async () => {
    const ports = createWebPorts();
    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.PHANTOM);

    expect(reportFor(status.modules, ModuleId.TrafficShaper).active).toBe(true);
    expect(reportFor(status.modules, ModuleId.DecoyEngine).active).toBe(true);
  });

  it('DoH is active but honestly degraded (SNI still leaks, no ECH) on web', async () => {
    const ports = createWebPorts({ fetchFn: async () => ({ ok: true }) });
    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.STEALTH);

    const dns = reportFor(status.modules, ModuleId.DnsGuard);
    expect(dns.active).toBe(true);
    expect(dns.degraded).toBe(true);
    expect(dns.reason).toBe(REASON.SNI_LEAK_NO_ECH);
  });

  it('on-device detection + attestation report unavailable/UNKNOWN on web (never "safe")', async () => {
    const ports = createWebPorts();
    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.STEALTH);

    const coRes = reportFor(status.modules, ModuleId.CoResidentGuard);
    expect(coRes.active).toBe(false);
    expect(coRes.reason).toBe(REASON.ONDEVICE_DETECTION_UNSUPPORTED);

    const integ = reportFor(status.modules, ModuleId.DeviceIntegrity);
    expect(integ.degraded).toBe(true); // UNKNOWN verdict, never TRUSTED
    expect(shield.getIntegrityState()?.verdict).toBe('UNKNOWN');
  });
});

describe('NATIVE platform — honest BLE gating', () => {
  it('reports BLE UNAVAILABLE when the native plugin fails to resolve (no bridge)', async () => {
    const ports = createNativePorts({ bleBridge: null });
    expect(ports.ble.isAvailable()).toBe(false);

    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.STEALTH);
    const ble = reportFor(status.modules, ModuleId.BleCloak);
    expect(ble.active).toBe(false);
    expect(ble.reason).toBe(REASON.BLE_UNAVAILABLE);
  });

  it('runs BLE for real (active) when a ready native bridge is wired', async () => {
    const calls: string[] = [];
    const bridge: NativeBleBridge = {
      isReady: () => true,
      supportsAdvertisingControl: () => true,
      supportsAdvertisingParams: () => true,
      stopAdvertising: async () => void calls.push('stop'),
      startAdvertising: async () => void calls.push('start'),
      setDiscoveryBeaconEnabled: async () => void calls.push('beacon'),
      setAdvertisedNodeId: async () => undefined,
      setAdvertisingParameters: async () => undefined,
    };
    const ports = createNativePorts({ bleBridge: bridge });
    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.STEALTH);

    const ble = reportFor(status.modules, ModuleId.BleCloak);
    expect(ble.active).toBe(true);
    expect(ble.degraded).toBe(false);
    expect(calls).toContain('stop');
  });
});

describe('facade — level↔tier mapping and honest stats', () => {
  it('maps cumulative levels and exposes node-id (not MAC) rotation stat', async () => {
    const ports = createWebPorts();
    const manager = new ShieldManager(ports);
    const facade = new GhostShieldFacade(manager, 'web', ports.mesh, { sink: () => undefined });
    try {
      await manager.setTier(ShieldTier.PHANTOM);
      const status = facade.getStatus();

      expect(status.platform).toBe('web');
      expect(status.level).toBe(3);
      expect(status.activeStates).toEqual({ 1: true, 2: true, 3: true });
      // The stat is node-id rotations — there is no macRotations field at all.
      const statKeys = Object.keys(status.stats);
      expect(statKeys).toContain('nodeIdRotations');
      expect(statKeys).not.toContain('macRotations');
    } finally {
      facade.dispose();
    }
  });

  it('FULL_GHOST surfaces the "ALL" badge state', async () => {
    const ports = createWebPorts();
    const manager = new ShieldManager(ports);
    const facade = new GhostShieldFacade(manager, 'web', ports.mesh, { sink: () => undefined });
    try {
      await manager.setTier(ShieldTier.FULL_GHOST);
      expect(facade.getStatus().currentLevel).toBe('ALL');
    } finally {
      facade.dispose();
    }
  });
});

describe('no MAC-rotation / WiFi-probe theater anywhere in the Shield source', () => {
  // Strip comments first: the honesty docs intentionally QUOTE the removed
  // strings ("MAC rotated", "probe suppression") to record that they were
  // deleted. We assert there is no such LOGIC — identifiers and string literals
  // in actual code — not that the words never appear in prose.
  const stripComments = (src: string): string =>
    src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

  it('contains no fabricated MAC-rotation or probe-suppression logic', () => {
    const root = join(__dirname, '..');
    const forbidden = [/macRotation/i, /rotateMac/i, /mac rotated/i, /probe suppression/i, /randomMac/i, /macRotations/i];
    const offenders: string[] = [];

    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const full = join(dir, name);
        if (statSync(full).isDirectory()) {
          walk(full);
          continue;
        }
        if (!name.endsWith('.ts')) continue;
        if (full.includes('__tests__')) continue; // this file names the patterns
        const code = stripComments(readFileSync(full, 'utf8'));
        for (const re of forbidden) {
          if (re.test(code)) offenders.push(`${name} :: ${re}`);
        }
      }
    };
    walk(root);
    expect(offenders).toEqual([]);
  });
});
