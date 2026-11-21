/**
 * Tests for the non-persistent MAC-randomization capability (Android-only).
 *
 * This locks in the honesty contract for the policy flip Kryptos applies to its
 * OWN suggested mesh/relay networks:
 *   - iOS / web build → UNAVAILABLE (active:false), never claimed active.
 *   - Android < 31    → DEGRADED with the "requires Android 12+" reason, not active.
 *   - Android 12+     → active, and only ever for Kryptos-suggested networks.
 *   - No fabricated MAC value appears anywhere in the output.
 */
import { describe, expect, it } from 'vitest';

import { REASON } from '../capabilities';
import { MacRandomizer } from '../modules/MacRandomizer';
import { ShieldManager } from '../ShieldManager';
import { resolveConfig } from '../config';
import { createFakePorts } from '../testing';
import { createNativePorts, type NativeWifiSuggestBridge } from '../web/nativePorts';
import { createWebPorts } from '../web/webPorts';
import { honestReason } from '../web/reasons';
import { ModuleId, ShieldTier, type CapabilityReport } from '../types';

function reportFor(modules: readonly CapabilityReport[], id: ModuleId): CapabilityReport {
  const r = modules.find((m) => m.id === id);
  if (!r) throw new Error(`no report for ${id}`);
  return r;
}

/** A MAC address pattern (XX:XX:XX:XX:XX:XX, hyphen or colon). Must NEVER appear. */
const MAC_RE = /\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/i;

const STEALTH_CFG = resolveConfig(ShieldTier.STEALTH);

describe('MacRandomizer — capability honesty', () => {
  it('reports UNAVAILABLE (not active) when there is no suggestion API (web/iOS)', async () => {
    // available:false models a plain browser OR iOS (no app API at all).
    const ports = createFakePorts({ wifi: { available: false } });
    const mod = new MacRandomizer(ports);

    const report = await mod.enable(STEALTH_CFG);
    expect(report.requested).toBe(true);
    expect(report.active).toBe(false); // never claims the MAC policy is in effect
    expect(report.degraded).toBe(true);
    expect(report.reason).toBe(REASON.MAC_RANDO_UNAVAILABLE);
    // It must not even attempt to act on networks when unavailable.
    expect(ports.wifi.appliedCount).toBe(0);
  });

  it('reports DEGRADED with the version reason on Android < 31 (not active)', async () => {
    const ports = createFakePorts({ wifi: { available: true, supportsNonPersistent: false } });
    const mod = new MacRandomizer(ports);

    const report = await mod.enable(STEALTH_CFG);
    expect(report.requested).toBe(true);
    expect(report.active).toBe(false); // do NOT silently claim active on pre-12
    expect(report.degraded).toBe(true);
    expect(report.reason).toBe(REASON.MAC_RANDO_REQUIRES_ANDROID_12);
    expect(ports.wifi.appliedCount).toBe(0);
  });

  it('is active on Android 12+ and ONLY acts on Kryptos-suggested networks', async () => {
    const ports = createFakePorts({ wifi: { available: true, supportsNonPersistent: true } });
    const mod = new MacRandomizer(ports);

    const report = await mod.enable(STEALTH_CFG);
    expect(report.active).toBe(true);
    expect(report.degraded).toBe(false);
    // Exactly one apply, against Kryptos's own suggestions — never the user's nets.
    expect(ports.wifi.appliedCount).toBe(1);
  });

  it('degrades (not active) when the native apply is rejected on Android 12+', async () => {
    const ports = createFakePorts({
      wifi: { available: true, supportsNonPersistent: true, applyFails: true, applyReason: 'suggestion-rejected-3' },
    });
    const mod = new MacRandomizer(ports);

    const report = await mod.enable(STEALTH_CFG);
    expect(report.active).toBe(false);
    expect(report.degraded).toBe(true);
    expect(report.reason).toBe('suggestion-rejected-3');
  });

  it('disable() withdraws Kryptos suggestions and clears the report', async () => {
    const ports = createFakePorts({ wifi: { available: true, supportsNonPersistent: true } });
    const mod = new MacRandomizer(ports);
    await mod.enable(STEALTH_CFG);

    await mod.disable();
    expect(ports.wifi.clearedCount).toBe(1);
    expect(mod.report()).toEqual({ id: ModuleId.MacRandomizer, requested: false, active: false, degraded: false });
  });

  it('does not enable when the tier does not request it (OFF)', async () => {
    const ports = createFakePorts({ wifi: { available: true, supportsNonPersistent: true } });
    const mod = new MacRandomizer(ports);
    const report = await mod.enable(resolveConfig(ShieldTier.OFF));
    expect(report.requested).toBe(false);
    expect(report.active).toBe(false);
    expect(ports.wifi.appliedCount).toBe(0);
  });
});

describe('MacRandomizer — platform profiles via the real port wiring', () => {
  it('WEB build reports the capability UNAVAILABLE (never active)', async () => {
    const ports = createWebPorts();
    expect(ports.wifi.isAvailable()).toBe(false);

    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.STEALTH);
    const mac = reportFor(status.modules, ModuleId.MacRandomizer);
    expect(mac.active).toBe(false);
    expect(mac.degraded).toBe(true);
    expect(mac.reason).toBe(REASON.MAC_RANDO_UNAVAILABLE);
  });

  it('NATIVE iOS / missing module reports UNAVAILABLE (no bridge wired)', async () => {
    const ports = createNativePorts({ wifiBridge: null });
    expect(ports.wifi.isAvailable()).toBe(false);

    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.STEALTH);
    const mac = reportFor(status.modules, ModuleId.MacRandomizer);
    expect(mac.active).toBe(false);
    expect(mac.reason).toBe(REASON.MAC_RANDO_UNAVAILABLE);
  });

  it('NATIVE Android < 31 reports DEGRADED with the version reason', async () => {
    const bridge: NativeWifiSuggestBridge = {
      isReady: () => true,
      supportsNonPersistentRandomization: () => false, // pre-Android-12
      applyNonPersistentMacRandomization: async () => ({ requested: true, active: false, reason: 'requires-android-12' }),
      clearSuggestions: async () => undefined,
    };
    const ports = createNativePorts({ wifiBridge: bridge });
    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.STEALTH);

    const mac = reportFor(status.modules, ModuleId.MacRandomizer);
    expect(mac.active).toBe(false);
    expect(mac.degraded).toBe(true);
    expect(mac.reason).toBe(REASON.MAC_RANDO_REQUIRES_ANDROID_12);
  });

  it('NATIVE Android 12+ runs the policy for real (active)', async () => {
    let applied = 0;
    const bridge: NativeWifiSuggestBridge = {
      isReady: () => true,
      supportsNonPersistentRandomization: () => true,
      applyNonPersistentMacRandomization: async () => {
        applied++;
        return { requested: true, active: true };
      },
      clearSuggestions: async () => undefined,
    };
    const ports = createNativePorts({ wifiBridge: bridge });
    const shield = new ShieldManager(ports);
    const status = await shield.setTier(ShieldTier.STEALTH);

    const mac = reportFor(status.modules, ModuleId.MacRandomizer);
    expect(mac.active).toBe(true);
    expect(mac.degraded).toBe(false);
    expect(applied).toBe(1);
  });
});

describe('MacRandomizer — never fabricates a MAC value', () => {
  it('no MAC-address string appears in any capability report or its honest message', async () => {
    // Exercise every platform branch and scan the resulting report + rendered reason.
    const cases = [
      createFakePorts({ wifi: { available: false } }),
      createFakePorts({ wifi: { available: true, supportsNonPersistent: false } }),
      createFakePorts({ wifi: { available: true, supportsNonPersistent: true } }),
      createFakePorts({ wifi: { available: true, supportsNonPersistent: true, applyFails: true } }),
    ];
    for (const ports of cases) {
      const mod = new MacRandomizer(ports);
      const report = await mod.enable(STEALTH_CFG);
      const rendered = JSON.stringify(report) + ' ' + honestReason(report, 'native') + ' ' + honestReason(report, 'web');
      expect(MAC_RE.test(rendered)).toBe(false);
      // And there is no app-side rotation counter masquerading as a MAC stat.
      expect(Object.keys(report)).not.toContain('mac');
    }
  });
});
