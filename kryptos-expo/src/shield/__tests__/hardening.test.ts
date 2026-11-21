import { beforeEach, describe, expect, it, vi } from 'vitest';
import { REASON } from '../capabilities';
import { PADDING_BUCKETS, resolveConfig } from '../config';
import { CoResidentGuard } from '../modules/CoResidentGuard';
import { DnsGuard } from '../modules/DnsGuard';
import { NodeIdRotator } from '../modules/NodeIdRotator';
import { ShieldManager } from '../ShieldManager';
import { TrafficModel } from '../traffic-model';
import { createFakePorts, type FakePorts } from '../testing';
import { ShieldTier, type CapabilityReport } from '../types';

let ports: FakePorts;
beforeEach(() => {
  ports = createFakePorts();
});

/** Drain the manager's async transition queue (auto-raise runs there). */
function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

describe('NodeIdRotator: advertising-shape randomization (anti-fingerprint)', () => {
  it('re-randomizes advertising interval + payload length per rotation', async () => {
    const p = createFakePorts({ mesh: { nodeId: 'node-real', activeSessions: ['p1'] } });
    const rotator = new NodeIdRotator(p);
    const rep = await rotator.enable(resolveConfig(ShieldTier.PHANTOM));
    expect(rep.degraded).toBe(false);

    await rotator.rotate();
    expect(p.ble.advertisingParams).toHaveLength(1);
    const params = p.ble.advertisingParams[0];
    // Interval drawn from OS-default values so we blend in with ordinary advertisers.
    expect([100, 250, 1000]).toContain(params.intervalMs);
    expect(params.payloadLength).toBeGreaterThanOrEqual(8);
    expect(params.payloadLength).toBeLessThanOrEqual(31);
  });

  it('stays active but degraded when the platform fixes advertising params (iOS)', async () => {
    const p = createFakePorts({ ble: { supportsAdvertisingParams: false }, mesh: { nodeId: 'node-real' } });
    const rotator = new NodeIdRotator(p);
    const rep = await rotator.enable(resolveConfig(ShieldTier.PHANTOM));
    expect(rep.active).toBe(true); // id rotation still works
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.BLE_ADV_PARAMS_FIXED);

    await rotator.rotate();
    expect(p.ble.advertisingParams).toHaveLength(0); // honestly did not vary them
  });
});

describe('DnsGuard: ECH detection surfaces SNI leakage', () => {
  it('flags SNI leak when DoH works but ECH is unavailable', async () => {
    const p = createFakePorts({ dns: { reachable: true, supportsEch: false } });
    const mod = new DnsGuard(p);
    const rep = await mod.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.active).toBe(true); // DoH is working
    expect(rep.degraded).toBe(true); // but the destination host still leaks via SNI
    expect(rep.reason).toBe(REASON.SNI_LEAK_NO_ECH);
    expect(p.dns.plaintextBlocked).toBe(false);
  });

  it('is clean when both DoH and ECH are available', async () => {
    const p = createFakePorts({ dns: { reachable: true, supportsEch: true } });
    const mod = new DnsGuard(p);
    const rep = await mod.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.degraded).toBe(false);
  });
});

describe('TrafficModel: decoy/cover statistically indistinguishable from real', () => {
  it('reproduces the observed inter-arrival distribution (not a fixed cadence)', () => {
    const p = createFakePorts({ seed: 0xc0ffee });
    const model = new TrafficModel(p.random, { buckets: PADDING_BUCKETS });

    // Train on "real" sends whose gaps come from an exponential (mean ~1000ms).
    let t = 0;
    const realGaps: number[] = [];
    for (let i = 0; i < 400; i++) {
      const u = (p.random.int(1, 1_000_000)) / 1_000_000;
      const gap = Math.max(1, Math.round(-1000 * Math.log(u)));
      realGaps.push(gap);
      t += gap;
      model.observe(512, t);
    }

    // Draw synthetic (decoy/cover) gaps from the model.
    const synth: number[] = [];
    for (let i = 0; i < 400; i++) synth.push(model.sampleGapMs(1000));

    const mean = (xs: number[]): number => xs.reduce((a, b) => a + b, 0) / xs.length;
    const std = (xs: number[]): number => {
      const m = mean(xs);
      return Math.sqrt(mean(xs.map((x) => (x - m) ** 2)));
    };

    const mReal = mean(realGaps);
    const mSynth = mean(synth);
    // Means within 35% — the synthetic stream sits on the real distribution.
    expect(Math.abs(mSynth - mReal) / mReal).toBeLessThan(0.35);
    // NOT a metronome: substantial variance (would be ~0 for a fixed interval).
    expect(std(synth)).toBeGreaterThan(0.3 * mSynth);
  });

  it('a single-threshold classifier cannot separate real from synthetic (≈ chance)', () => {
    const p = createFakePorts({ seed: 0x5eed });
    const model = new TrafficModel(p.random, { buckets: PADDING_BUCKETS });

    let t = 0;
    const real: number[] = [];
    for (let i = 0; i < 300; i++) {
      const u = (p.random.int(1, 1_000_000)) / 1_000_000;
      const gap = Math.max(1, Math.round(-800 * Math.log(u)));
      real.push(gap);
      t += gap;
      model.observe(256, t);
    }
    const synth: number[] = [];
    for (let i = 0; i < 300; i++) synth.push(model.sampleGapMs(800));

    // Best-threshold classifier: sweep thresholds, take the highest accuracy at
    // calling "below = real". If the streams are indistinguishable, even the
    // best threshold is no better than a coin flip.
    const all = [...real.map((g) => [g, 1] as const), ...synth.map((g) => [g, 0] as const)];
    const thresholds = [...new Set(all.map(([g]) => g))].sort((a, b) => a - b);
    let best = 0;
    for (const th of thresholds) {
      let correct = 0;
      for (const [g, label] of all) {
        const guess = g <= th ? 1 : 0;
        if (guess === label) correct++;
      }
      best = Math.max(best, correct / all.length);
    }
    // No strong separation. (A perfect separator would be ~1.0.)
    expect(best).toBeLessThan(0.65);
  });

  it('samples sizes in proportion to the observed size histogram', () => {
    const p = createFakePorts({ seed: 0x1234 });
    const model = new TrafficModel(p.random, { buckets: PADDING_BUCKETS });
    // 70% small (→256), 30% medium (→512).
    for (let i = 0; i < 700; i++) model.observe(200, i);
    for (let i = 0; i < 300; i++) model.observe(500, 1000 + i);

    let small = 0;
    const N = 1000;
    for (let i = 0; i < N; i++) {
      if (model.sampleSizeBytes() === 256) small++;
    }
    // Roughly the observed 70% (tolerant bounds for sampling noise).
    expect(small / N).toBeGreaterThan(0.55);
    expect(small / N).toBeLessThan(0.85);
  });
});

describe('CoResidentGuard: on-device observation detection', () => {
  it('reports degraded when screen capture is active at enable', async () => {
    const p = createFakePorts({ coResident: { screenCaptured: true } });
    const guard = new CoResidentGuard(p);
    const rep = await guard.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.active).toBe(true);
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.SCREEN_CAPTURE_ACTIVE);
  });

  it('notifies out-of-band when capture starts at runtime', async () => {
    const guard = new CoResidentGuard(ports);
    const seen: CapabilityReport[] = [];
    guard.setNotifier((r) => seen.push(r));
    await guard.enable(resolveConfig(ShieldTier.STEALTH));
    expect(guard.report().degraded).toBe(false);

    ports.coResident.emitScreenCapture(true);
    expect(seen).toHaveLength(1);
    expect(seen[0].reason).toBe(REASON.SCREEN_CAPTURE_ACTIVE);
    expect(guard.report().degraded).toBe(true);
  });

  it('reports degraded for an active accessibility service', async () => {
    const p = createFakePorts({ coResident: { accessibilityActive: true } });
    const guard = new CoResidentGuard(p);
    const rep = await guard.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.ACCESSIBILITY_SERVICE_ACTIVE);
  });

  it('honestly degrades when no on-device detection is available', async () => {
    const p = createFakePorts({
      coResident: { supportsScreenCaptureDetection: false, supportsAccessibilityDetection: false },
    });
    const guard = new CoResidentGuard(p);
    const rep = await guard.enable(resolveConfig(ShieldTier.STEALTH));
    expect(rep.active).toBe(false);
    expect(rep.degraded).toBe(true);
    expect(rep.reason).toBe(REASON.ONDEVICE_DETECTION_UNSUPPORTED);
  });

  it('clears the clipboard after the configured delay', async () => {
    const guard = new CoResidentGuard(ports);
    await guard.enable(resolveConfig(ShieldTier.STEALTH));
    guard.protectClipboard();
    const clearMs = resolveConfig(ShieldTier.STEALTH).coResident.clipboardClearMs;

    ports.clock.advance(clearMs - 1);
    expect(ports.coResident.clipboardCleared).toBe(0); // not yet
    ports.clock.advance(2);
    expect(ports.coResident.clipboardCleared).toBe(1); // cleared
  });
});

describe('ShieldManager: co-resident detection wiring', () => {
  it('re-emits a degraded event when a detector fires at runtime', async () => {
    const shield = new ShieldManager(ports);
    const degraded = vi.fn();
    shield.on('degraded', degraded);
    await shield.setTier(ShieldTier.STEALTH);

    ports.coResident.emitScreenCapture(true);
    expect(degraded).toHaveBeenCalledTimes(1);
    expect(degraded.mock.calls[0][0].reports[0].reason).toBe(REASON.SCREEN_CAPTURE_ACTIVE);
    expect(degraded.mock.calls[0][0].rolledBack).toBe(false);
  });

  it('auto-raises the tier on detection when configured', async () => {
    const shield = new ShieldManager(ports, { autoRaiseOnCoResident: ShieldTier.PHANTOM });
    await shield.setTier(ShieldTier.STEALTH);
    expect(shield.getStatus().tier).toBe(ShieldTier.STEALTH);

    ports.coResident.emitScreenCapture(true);
    await flush();
    expect(shield.getStatus().tier).toBe(ShieldTier.PHANTOM);
  });

  it('does NOT change tier on detection when auto-raise is not configured', async () => {
    const shield = new ShieldManager(ports);
    await shield.setTier(ShieldTier.STEALTH);
    ports.coResident.emitScreenCapture(true);
    await flush();
    expect(shield.getStatus().tier).toBe(ShieldTier.STEALTH); // warn-only
  });
});
