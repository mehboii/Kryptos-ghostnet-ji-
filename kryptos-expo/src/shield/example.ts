/**
 * Ghost Shield — usage example.
 *
 * This file is documentation-as-code: it shows how the host React Native app
 * wires Ghost Shield. It uses the in-memory fakes from ./testing so it runs
 * anywhere; the comments mark exactly where you swap in the real platform
 * implementations (react-native-ble-plx, expo-secure-store, the live mesh).
 *
 * It is intentionally not imported by the app at runtime.
 */

import { ShieldManager } from './ShieldManager';
import { createLogger } from './logger';
import { createFakePorts } from './testing';
import { ShieldTier, type ShieldPorts } from './types';

/**
 * In the real app, build `ports` from your platform modules. Each field is an
 * adapter you implement against the interfaces in types.ts, e.g.:
 *
 *   const ports: ShieldPorts = {
 *     ble:   new ReactNativeBleAdapter(blePeripheralModule),   // src/ble/*
 *     dns:   new ExpoDohAdapter(),                             // DoH via fetch
 *     mesh:  new GhostMeshAdapter(meshTransport),              // src/transport
 *     store: ExpoSecureStoreAdapter,                           // expo-secure-store
 *     clock: SystemClock,                                      // wraps global timers
 *     random: WebCryptoRandom,                                 // crypto.getRandomValues
 *     log:   createLogger({ enabled: __DEV__ }),               // opt-in, local-only
 *   };
 *
 * Here we use fakes so the example is runnable:
 */
export async function ghostShieldExample(): Promise<void> {
  const ports: ShieldPorts = createFakePorts({
    // Simulate an iOS-like device with no programmatic BLE advertising control,
    // to demonstrate honest degradation.
    ble: { supportsAdvertisingControl: false },
    logger: createLogger({ enabled: true, sink: (line) => console.log(line) }),
  });

  const shield = new ShieldManager(ports);

  // React to changes for the UI (the seal indicator, degraded banners, etc).
  shield.on('tierChanged', ({ from, to, status }) => {
    console.log(`[shield] ${from} → ${to} (stable=${status.stable}, degraded=${status.degraded})`);
  });
  shield.on('degraded', ({ tier, reports, rolledBack }) => {
    const codes = reports.map((r) => `${r.id}:${r.reason ?? (r.active ? 'partial' : 'inactive')}`);
    console.log(`[shield] degraded at ${tier} (rolledBack=${rolledBack}): ${codes.join(', ')}`);
  });

  // Restore the last tier on launch (no-op the first time).
  await shield.restore();

  // Step up through the tiers.
  await shield.setTier(ShieldTier.STEALTH);
  await shield.setTier(ShieldTier.GHOST);
  await shield.setTier(ShieldTier.PHANTOM);

  // Inspect what is actually active vs degraded right now.
  const status = shield.getStatus();
  for (const r of status.modules) {
    console.log(`  ${r.id}: requested=${r.requested} active=${r.active} degraded=${r.degraded}${r.reason ? ` (${r.reason})` : ''}`);
  }

  // Panic gesture → instant FULL_GHOST.
  await shield.panic();
  console.log(`[shield] after panic: ${shield.getStatus().tier}`);

  // Stand down.
  await shield.setTier(ShieldTier.OFF);
}
