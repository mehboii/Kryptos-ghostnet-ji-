/**
 * Ghost Shield — runtime platform capability probe.
 *
 * This is the honesty layer. Before a tier promises anything, we ask the
 * platform adapters what is actually achievable on THIS device/build, and we
 * surface a {@link CapabilitySet}. Modules consult it (or re-probe) and degrade
 * with a reason rather than pretending. Nothing here changes device state — it
 * only inspects.
 *
 * Reminder of the hard limits this layer encodes (see types.ts): on unprivileged
 * iOS / non-rooted Android we cannot touch the hardware MAC or the OS radio's
 * probe requests. "BLE advertising control" means control of *GhostNet's own*
 * advertisement, and even that is platform-gated (iOS strips service data and
 * restricts background advertising).
 */

import type { ShieldPorts } from './types';

export interface CapabilitySet {
  /** Is there any BLE stack at all on this build (false on a plain web build)? */
  readonly bleAvailable: boolean;
  /** Can we programmatically stop/start GhostNet's own BLE advertising? */
  readonly bleAdvertisingControl: boolean;
  /** Can we vary the advertising interval + payload length (anti-fingerprint)? */
  readonly bleAdvertisingParams: boolean;
  /** Can we route DNS through an app-controlled DoH resolver? */
  readonly doh: boolean;
  /** Is Encrypted Client Hello available (so TLS SNI does not leak)? */
  readonly ech: boolean;
  /** Can the mesh enforce a minimum outbound hop count? */
  readonly meshHopControl: boolean;
  /** Can the mesh advertise a rotated overlay node id with session handoff? */
  readonly nodeIdRotation: boolean;
  /** Can we observe screen-capture / recording state? */
  readonly screenCaptureDetection: boolean;
  /** Can we observe active accessibility services? */
  readonly accessibilityDetection: boolean;
  /** Is server-backed attestation (Play Integrity / App Attest) available? */
  readonly attestation: boolean;
  /** Cover traffic / padding / jitter / decoys are pure-overlay behaviors that
   *  the app fully controls, so they are always achievable. Listed for symmetry. */
  readonly trafficShaping: boolean;
  readonly decoys: boolean;
}

/** Stable reason codes a module emits when a capability is missing. */
export const REASON = {
  /** No BLE stack at all (plain web build, or native plugin failed to resolve).
   *  The host turns this into a platform-aware message, e.g.
   *  "BLE unavailable — web test context (no native plugin)". */
  BLE_UNAVAILABLE: 'ble_unavailable_no_local_stack',
  BLE_ADV_UNSUPPORTED: 'ble_advertising_control_unsupported',
  BLE_ADV_PARAMS_FIXED: 'ble_advertising_params_fixed_platform',
  DOH_UNSUPPORTED: 'doh_unsupported_on_platform',
  DOH_UNREACHABLE_FAILCLOSED: 'doh_unreachable_failclosed',
  SNI_LEAK_NO_ECH: 'sni_leak_no_ech',
  HOP_CONTROL_UNSUPPORTED: 'mesh_hop_control_unsupported',
  NODE_ID_ROTATION_UNSUPPORTED: 'node_id_rotation_unsupported',
  NO_ACTIVE_SESSIONS: 'no_active_sessions_to_hand_off',
  SCREEN_CAPTURE_ACTIVE: 'screen_capture_active',
  ACCESSIBILITY_SERVICE_ACTIVE: 'accessibility_service_active',
  ONDEVICE_DETECTION_UNSUPPORTED: 'ondevice_detection_unsupported',
  DEVICE_COMPROMISED: 'device_compromised',
  DEVICE_SUSPECT: 'device_suspect',
  INTEGRITY_UNKNOWN: 'integrity_unknown',
} as const;

/**
 * Probe the platform. Synchronous capability flags come from the adapters'
 * `supports*()` methods (cheap, no I/O). DoH *reachability* is intentionally
 * NOT probed here — that is a live network check the DnsGuard does at enable
 * time so it can fail-closed; here we only report whether DoH is supported at all.
 */
export function probeCapabilities(ports: ShieldPorts): CapabilitySet {
  const set: CapabilitySet = {
    bleAvailable: ports.ble.isAvailable(),
    bleAdvertisingControl: ports.ble.supportsAdvertisingControl(),
    bleAdvertisingParams: ports.ble.supportsAdvertisingParams(),
    doh: ports.dns.supportsDoh(),
    ech: ports.dns.supportsEch(),
    meshHopControl: ports.mesh.supportsHopControl(),
    nodeIdRotation: ports.mesh.supportsNodeIdRotation(),
    screenCaptureDetection: ports.coResident.supportsScreenCaptureDetection(),
    accessibilityDetection: ports.coResident.supportsAccessibilityDetection(),
    attestation: ports.integrity.provider.isSupported(),
    trafficShaping: true,
    decoys: true,
  };
  ports.log.debug('capabilities', {
    bleStack: set.bleAvailable,
    ble: set.bleAdvertisingControl,
    advParams: set.bleAdvertisingParams,
    doh: set.doh,
    ech: set.ech,
    hops: set.meshHopControl,
    rotate: set.nodeIdRotation,
    screencap: set.screenCaptureDetection,
    a11y: set.accessibilityDetection,
    attestation: set.attestation,
  });
  return set;
}
