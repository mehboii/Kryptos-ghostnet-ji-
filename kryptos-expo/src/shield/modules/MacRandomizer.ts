/**
 * MacRandomizer — flips the OS MAC-randomization POLICY to NON-PERSISTENT on the
 * Wi-Fi networks Kryptos itself suggests, so the device presents a fresh
 * randomized MAC each time it rejoins a Kryptos mesh/relay network instead of
 * reusing one persistent randomized MAC.
 *
 * HONESTY (read before touching):
 *   - This is NOT app-driven MAC rotation. We do NOT read, set, or rotate the
 *     hardware MAC ourselves, and this module NEVER fabricates or logs a MAC value.
 *     We only ask the OS, via WifiNetworkSuggestion.setMacRandomizationSetting,
 *     to use RANDOMIZATION_NON_PERSISTENT on networks WE add.
 *   - It applies ONLY to Kryptos-suggested networks. It does NOT and CANNOT affect
 *     the user's home/office/cafe Wi-Fi — those stay entirely OS-managed.
 *   - The policy requires Android 12 (API 31). On a build without the suggestion
 *     API (web test, iOS) the module reports UNAVAILABLE; on Android < 31 it reports
 *     DEGRADED with the version reason. It never silently claims active.
 *
 * The adapter is the single source of platform truth: this module simply consults
 * it (sync probes for fast unavailable/degraded paths) and otherwise honors the
 * native module's structured { requested, active, reason } result authoritatively.
 */

import { REASON } from '../capabilities';
import { ModuleId, type CapabilityReport, type ShieldConfig, type ShieldModule, type ShieldPorts } from '../types';

export class MacRandomizer implements ShieldModule {
  readonly id = ModuleId.MacRandomizer;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };

  constructor(private readonly ports: ShieldPorts) {}

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
    if (!cfg.macRandomization.enabled) {
      await this.disable();
      return this.last;
    }

    // No suggestion API at all (web test context, or iOS where the OS manages
    // Private Wi-Fi Address itself). UNAVAILABLE — never claim non-persistent ran.
    if (!this.ports.wifi.isAvailable()) {
      this.last = {
        id: this.id,
        requested: true,
        active: false,
        degraded: true,
        reason: REASON.MAC_RANDO_UNAVAILABLE,
      };
      this.ports.log.warn('mac_rando_unavailable', { reason: REASON.MAC_RANDO_UNAVAILABLE });
      return this.last;
    }

    // Suggestion API exists but the device is below Android 12 → the non-persistent
    // policy does not exist on this OS. DEGRADED with the version reason; not active.
    if (!this.ports.wifi.supportsNonPersistentRandomization()) {
      this.last = {
        id: this.id,
        requested: true,
        active: false,
        degraded: true,
        reason: REASON.MAC_RANDO_REQUIRES_ANDROID_12,
      };
      this.ports.log.warn('mac_rando_requires_android_12', { reason: REASON.MAC_RANDO_REQUIRES_ANDROID_12 });
      return this.last;
    }

    // Android 12+ : actually apply the policy to Kryptos's own networks and honor
    // the native result. We only ever mark active for Kryptos-suggested networks.
    const res = await this.ports.wifi.applyNonPersistentMacRandomization();
    this.last = res.active
      ? { id: this.id, requested: true, active: true, degraded: false }
      : {
          id: this.id,
          requested: true,
          active: false,
          degraded: true,
          reason: res.reason ?? REASON.MAC_RANDO_NOT_APPLIED,
        };
    if (res.active) this.ports.log.debug('mac_rando_on');
    else this.ports.log.warn('mac_rando_not_applied', { reason: this.last.reason ?? '' });
    return this.last;
  }

  async disable(): Promise<void> {
    // Withdraw Kryptos's own suggestions — only if the suggestion API exists.
    if (this.ports.wifi.isAvailable()) {
      await this.ports.wifi.clearSuggestions();
    }
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }

  report(): CapabilityReport {
    return this.last;
  }
}
