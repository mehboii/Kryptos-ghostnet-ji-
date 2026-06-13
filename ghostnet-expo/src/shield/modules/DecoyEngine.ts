/**
 * DecoyEngine — injects plausible fake peer announcements into the mesh so an
 * observer counting "GhostNet nodes near this device" sees noise, and so the
 * real node's announcements do not stand out as the only ones.
 *
 * SECURITY REQUIREMENTS:
 *  - Unlinkable: every decoy uses a fresh random ephemeral id, so two decoys (or
 *    a decoy across time) cannot be tied together or to the real node.
 *  - No real-id leak: a decoy NEVER contains the real overlay node id. We assert
 *    this defensively before announcing.
 *  - No payload: decoys carry only a random, well-formed capabilities blob —
 *    never real message payload.
 *
 * Decoys are pure-overlay, so there is no platform capability to degrade against.
 */

import {
  ModuleId,
  type CapabilityReport,
  type DecoyAnnouncement,
  type ShieldConfig,
  type ShieldModule,
  type ShieldPorts,
  type TimerHandle,
} from '../types';

/** Re-pick the decoy population on this cadence so the set churns over time. */
const DECOY_REFRESH_MS = 45_000;
/** Ephemeral decoy id length in bytes (hex-encoded when announced). */
const DECOY_ID_BYTES = 16;

export class DecoyEngine implements ShieldModule {
  readonly id = ModuleId.DecoyEngine;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };
  private refreshTimer: TimerHandle | null = null;
  private cfg: ShieldConfig | null = null;

  constructor(private readonly ports: ShieldPorts) {}

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
    if (!cfg.decoy.enabled) {
      await this.disable();
      return this.last;
    }
    this.cfg = cfg;

    await this.refreshDecoys();
    if (this.refreshTimer === null) {
      this.refreshTimer = this.ports.clock.setInterval(() => {
        void this.refreshDecoys();
      }, DECOY_REFRESH_MS);
    }

    this.last = { id: this.id, requested: true, active: true, degraded: false };
    return this.last;
  }

  async disable(): Promise<void> {
    if (this.refreshTimer) {
      this.ports.clock.clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.cfg = null;
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }

  report(): CapabilityReport {
    return this.last;
  }

  /** Build and announce a fresh batch of decoys. Exposed for testing. */
  async refreshDecoys(): Promise<void> {
    const cfg = this.cfg;
    if (!cfg) return;
    const count = this.ports.random.int(cfg.decoy.minDecoys, cfg.decoy.maxDecoys);
    const realId = this.ports.mesh.getCurrentNodeId();
    for (let i = 0; i < count; i++) {
      const decoy = this.buildDecoy();
      // Defensive: a decoy must never echo the real id.
      if (decoy.ephemeralId === realId) continue;
      await this.ports.mesh.announceDecoyPeer(decoy);
    }
    this.ports.log.debug('decoys_announced', { count });
  }

  /** A single cryptographically-random, payload-free decoy. */
  private buildDecoy(): DecoyAnnouncement {
    const idBytes = this.ports.random.bytes(DECOY_ID_BYTES);
    const ephemeralId = bytesToHex(idBytes);
    // Plausible but meaningless capabilities blob (random, fixed small size).
    const payload = this.ports.random.bytes(24);
    return { ephemeralId, payload };
  }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
