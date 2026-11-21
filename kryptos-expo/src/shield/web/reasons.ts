/**
 * Ghost Shield — human-readable, platform-aware capability reasons.
 *
 * Turns a module's stable {@link CapabilityReport.reason} code into an honest
 * sentence for the console / UI. The same code can read differently per platform
 * (e.g. "no BLE stack" means "web test context" in a browser vs "native plugin
 * failed to resolve" on the phone), but it is ALWAYS the truth — never a fake
 * "active" claim.
 */

import { REASON } from '../capabilities';
import { INTEGRITY_REASON } from '../modules/DeviceIntegrity';
import type { CapabilityReport } from '../types';
import type { ShieldPlatform } from './runtime';

export function honestReason(report: CapabilityReport, platform: ShieldPlatform): string {
  const web = platform === 'web';
  switch (report.reason) {
    case REASON.BLE_UNAVAILABLE:
      return web
        ? 'BLE unavailable — web test context (no native BLE plugin)'
        : 'BLE unavailable — native plugin failed to resolve';
    case REASON.BLE_ADV_UNSUPPORTED:
      return 'BLE advertising control unsupported on this platform — discovery beacon silenced only';
    case REASON.BLE_ADV_PARAMS_FIXED:
      return web
        ? 'BLE advertising-shape randomization unavailable — no BLE stack in web test context'
        : 'BLE advertising parameters are fixed by this platform';
    case REASON.DOH_UNSUPPORTED:
      return 'DNS-over-HTTPS unsupported on this platform';
    case REASON.DOH_UNREACHABLE_FAILCLOSED:
      return 'DoH resolver unreachable — failing closed (plaintext DNS blocked)';
    case REASON.SNI_LEAK_NO_ECH:
      return 'DNS query hidden via DoH, but TLS SNI still leaks (no ECH control in this build)';
    case REASON.HOP_CONTROL_UNSUPPORTED:
      return 'Mesh min-hop enforcement unavailable — mesh transport not wired';
    case REASON.NODE_ID_ROTATION_UNSUPPORTED:
      return 'Overlay node-id rotation unsupported by this mesh build';
    case REASON.NO_ACTIVE_SESSIONS:
      return 'No active sessions to hand off';
    case REASON.SCREEN_CAPTURE_ACTIVE:
      return 'Screen is being captured/recorded';
    case REASON.ACCESSIBILITY_SERVICE_ACTIVE:
      return 'A third-party accessibility service is active';
    case REASON.ONDEVICE_DETECTION_UNSUPPORTED:
      return web
        ? 'On-device observation detection unavailable in web test context'
        : 'On-device observation detection unavailable — no native bridge wired';
    case INTEGRITY_REASON.COMPROMISED:
      return 'Device integrity: COMPROMISED (attestation failed)';
    case INTEGRITY_REASON.SUSPECT:
      return 'Device integrity: SUSPECT (local tamper indicators high)';
    case INTEGRITY_REASON.UNKNOWN:
      return web
        ? 'Device integrity: UNKNOWN — attestation unavailable in web test context'
        : 'Device integrity: UNKNOWN — could not attest';
    case REASON.MAC_RANDO_UNAVAILABLE:
      return web
        ? 'Non-persistent MAC randomization unavailable — web test context (no Wi-Fi suggestion API)'
        : 'Non-persistent MAC randomization unavailable — no app API (iOS OS-managed Private Wi-Fi Address) or native module not resolved';
    case REASON.MAC_RANDO_REQUIRES_ANDROID_12:
      return 'Non-persistent MAC randomization requires Android 12+ — registered with OS-default randomization only';
    case REASON.MAC_RANDO_NOT_APPLIED:
      return 'Non-persistent MAC randomization could not be applied to Kryptos-suggested networks';
    default:
      return report.reason ?? (report.active ? 'running a reduced subset' : 'inactive');
  }
}
