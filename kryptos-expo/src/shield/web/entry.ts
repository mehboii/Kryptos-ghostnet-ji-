/**
 * Ghost Shield — web/WebView bundle entry.
 *
 * This is the SINGLE source compiled into the canonical `ghost-shield.js` the
 * site loads (see scripts/build-shield-web.js). It replaces the old hand-written
 * mock engine. On load it:
 *   1. detects the runtime platform (Capacitor native phone vs plain browser),
 *   2. builds the honest port set for that platform,
 *   3. constructs the REAL ShieldManager from src/shield,
 *   4. exposes a `window.GhostShield` facade for the existing UI.
 *
 * The capability profile is chosen by the platform, never faked: on web the
 * hardware-dependent modules report unavailable; on the phone they run for real
 * when their native bridge resolves.
 */

import { ShieldManager } from '../ShieldManager';
import { createLogger } from '../logger';
import { GhostShieldFacade } from './facade';
import { createNativePorts } from './nativePorts';
import { detectPlatform, type ShieldPlatform } from './runtime';
import { createWebPorts, type ShieldHostPorts } from './webPorts';

export interface InstallOptions {
  readonly platform?: ShieldPlatform;
  /** Print honest [Ghost Shield] capability lines to the console. Default true. */
  readonly verbose?: boolean;
}

/** Build the platform-appropriate ports + manager + facade and return them. */
export function createGhostShield(options: InstallOptions = {}): {
  platform: ShieldPlatform;
  manager: ShieldManager;
  facade: GhostShieldFacade;
} {
  const platform = options.platform ?? detectPlatform();
  const verbose = options.verbose ?? true;
  // The Shield's redacted local logger (debug/warn codes). Separate from the
  // facade's human console lines; both are local-only and identifier-free.
  const log = createLogger({ enabled: verbose, sink: (line) => console.log(`[Ghost Shield] ${line}`) });

  const ports: ShieldHostPorts = platform === 'native' ? createNativePorts({ logger: log }) : createWebPorts({ logger: log });

  const manager = new ShieldManager(ports);
  const facade = new GhostShieldFacade(manager, platform, ports.mesh);
  return { platform, manager, facade };
}

interface ShieldWindow {
  GhostShield?: GhostShieldFacade;
}

/** Install `window.GhostShield` if not already present. Idempotent. */
export function installGhostShield(globalRef: ShieldWindow = globalThis as ShieldWindow): GhostShieldFacade {
  if (globalRef.GhostShield) return globalRef.GhostShield;
  const { facade } = createGhostShield();
  globalRef.GhostShield = facade;
  return facade;
}

// Auto-install when running in a real document context (browser / WebView). The
// assignment is synchronous so the UI (loaded by a later <script>) sees it.
if (typeof document !== 'undefined') {
  installGhostShield();
}
