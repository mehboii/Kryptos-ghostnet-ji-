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
  /** Can we programmatically stop/start GhostNet's own BLE advertising? */
  readonly bleAdvertisingControl: boolean;
  /** Can we route DNS through an app-controlled DoH resolver? */
  readonly doh: boolean;
  /** Can the mesh enforce a minimum outbound hop count? */
  readonly meshHopControl: boolean;
  /** Can the mesh advertise a rotated overlay node id with session handoff? */
  readonly nodeIdRotation: boolean;
  /** Cover traffic / padding / jitter / decoys are pure-overlay behaviors that
   *  the app fully controls, so they are always achievable. Listed for symmetry. */
  readonly trafficShaping: boolean;
  readonly decoys: boolean;
}

/** Stable reason codes a module emits when a capability is missing. */
export const REASON = {
  BLE_ADV_UNSUPPORTED: 'ble_advertising_control_unsupported',
  DOH_UNSUPPORTED: 'doh_unsupported_on_platform',
  DOH_UNREACHABLE_FAILCLOSED: 'doh_unreachable_failclosed',
  HOP_CONTROL_UNSUPPORTED: 'mesh_hop_control_unsupported',
  NODE_ID_ROTATION_UNSUPPORTED: 'node_id_rotation_unsupported',
  NO_ACTIVE_SESSIONS: 'no_active_sessions_to_hand_off',
} as const;

/**
 * Probe the platform. Synchronous capability flags come from the adapters'
 * `supports*()` methods (cheap, no I/O). DoH *reachability* is intentionally
 * NOT probed here — that is a live network check the DnsGuard does at enable
 * time so it can fail-closed; here we only report whether DoH is supported at all.
 */
export function probeCapabilities(ports: ShieldPorts): CapabilitySet {
  const set: CapabilitySet = {
    bleAdvertisingControl: ports.ble.supportsAdvertisingControl(),
    doh: ports.dns.supportsDoh(),
    meshHopControl: ports.mesh.supportsHopControl(),
    nodeIdRotation: ports.mesh.supportsNodeIdRotation(),
    trafficShaping: true,
    decoys: true,
  };
  ports.log.debug('capabilities', {
    ble: set.bleAdvertisingControl,
    doh: set.doh,
    hops: set.meshHopControl,
    rotate: set.nodeIdRotation,
  });
  return set;
}
