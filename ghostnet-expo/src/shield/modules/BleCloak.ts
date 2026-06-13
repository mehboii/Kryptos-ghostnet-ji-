/**
 * BleCloak — silences GhostNet's OWN BLE advertising and active discovery
 * beaconing.
 *
 * HONESTY: this does NOT and CANNOT stop the OS radio's WiFi/BLE probe requests
 * or change the hardware MAC. It stops the *application-level* beacons GhostNet
 * itself emits — the advertisement an observer would otherwise correlate as
 * "a GhostNet node is here". On platforms/builds without programmatic
 * advertising control (e.g. iOS background advertising restrictions, or a build
 * without the BLE peripheral module) it reports `degraded: true` rather than
 * claiming the radio went quiet.
 */

import { REASON } from '../capabilities';
import { ModuleId, type CapabilityReport, type ShieldConfig, type ShieldModule, type ShieldPorts } from '../types';

export class BleCloak implements ShieldModule {
  readonly id = ModuleId.BleCloak;
  private last: CapabilityReport = { id: this.id, requested: false, active: false, degraded: false };

  constructor(private readonly ports: ShieldPorts) {}

  async enable(cfg: ShieldConfig): Promise<CapabilityReport> {
    const requested = cfg.ble.silenceAdvertising || cfg.ble.silenceDiscoveryBeacon;
    if (!requested) {
      await this.disable();
      return this.last;
    }

    if (!this.ports.ble.supportsAdvertisingControl()) {
      // We cannot guarantee silence. Do the achievable subset (stop the
      // discovery beacon, which is app-driven even when peripheral advertising
      // is OS-controlled) and be honest that advertising may continue.
      await this.ports.ble.setDiscoveryBeaconEnabled(false);
      this.last = {
        id: this.id,
        requested: true,
        active: true,
        degraded: true,
        reason: REASON.BLE_ADV_UNSUPPORTED,
      };
      this.ports.log.warn('ble_cloak_degraded', { reason: REASON.BLE_ADV_UNSUPPORTED });
      return this.last;
    }

    if (cfg.ble.silenceAdvertising) await this.ports.ble.stopAdvertising();
    if (cfg.ble.silenceDiscoveryBeacon) await this.ports.ble.setDiscoveryBeaconEnabled(false);
    this.last = { id: this.id, requested: true, active: true, degraded: false };
    this.ports.log.debug('ble_cloak_on');
    return this.last;
  }

  async disable(): Promise<void> {
    // Restore GhostNet's normal presence.
    if (this.ports.ble.supportsAdvertisingControl()) {
      await this.ports.ble.startAdvertising();
    }
    await this.ports.ble.setDiscoveryBeaconEnabled(true);
    this.last = { id: this.id, requested: false, active: false, degraded: false };
  }

  report(): CapabilityReport {
    return this.last;
  }
}
