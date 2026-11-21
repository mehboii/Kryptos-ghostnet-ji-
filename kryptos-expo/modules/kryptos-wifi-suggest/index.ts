/**
 * kryptos-wifi-suggest — non-persistent MAC randomization for Kryptos networks.
 *
 * ANDROID 12+ ONLY by platform reality. Android lets an app set the MAC
 * randomization *policy* on the Wi-Fi networks it suggests via
 * WifiNetworkSuggestion. We ask the OS to present a FRESH randomized MAC each time
 * the device rejoins a Kryptos mesh/relay network (RANDOMIZATION_NON_PERSISTENT),
 * instead of reusing one persistent randomized MAC.
 *
 * This is NOT app-driven MAC rotation: we never read, set, or rotate the hardware
 * MAC ourselves, and never fabricate a MAC value. It applies ONLY to networks
 * Kryptos itself adds — it cannot affect the user's home/office/cafe Wi-Fi.
 *
 *   - iOS: no app API (OS-managed Private Wi-Fi Address) → reports unavailable.
 *   - Android < 31: the non-persistent policy is unavailable → reports the version
 *     reason; never claims active.
 *   - Web / Expo Go / unlinked build: the optional require returns null → callers
 *     degrade to "unavailable in this build".
 */
import { requireOptionalNativeModule } from 'expo-modules-core';

/** A Kryptos-owned mesh/relay network to suggest. Never the user's networks. */
export interface MeshNetworkSpec {
  /** SSID of a Kryptos mesh/relay network. */
  ssid: string;
  /** WPA2 passphrase, if the relay network is protected. Omit for open. */
  passphrase?: string;
}

/** Structured result of attempting to apply the policy. Mirrors the native shape. */
export interface MacRandomizationResult {
  /** Did we ask the OS for non-persistent randomization? */
  requested: boolean;
  /** Is non-persistent randomization actually in effect for our networks? */
  active: boolean;
  /**
   * Honest reason when not active. Stable codes:
   * 'requires-android-12' | 'ios-os-managed-private-wifi' | 'wifi-unavailable' |
   * 'no-mesh-networks' | 'permission-denied' | 'suggestion-rejected-*' | error
   */
  reason?: string;
}

const Native = requireOptionalNativeModule('KryptosWifiSuggest');

/** True only on a build where the native module is linked (dev client / EAS). */
export const isAvailable = Native != null;

/** Android 12+ check, async (native). False on iOS, web, and Android < 31. */
export async function supportsNonPersistentRandomization(): Promise<boolean> {
  if (!Native) return false;
  try {
    return !!(await Native.supportsNonPersistentRandomization());
  } catch {
    return false;
  }
}

/**
 * Apply NON_PERSISTENT MAC randomization to Kryptos's OWN suggested mesh/relay
 * networks. Always resolves (never throws) so a missing module / denied permission
 * / old OS degrades gracefully instead of crashing.
 */
export async function applyMeshNetworkMacRandomization(
  networks: MeshNetworkSpec[],
): Promise<MacRandomizationResult> {
  if (!Native) {
    return { requested: true, active: false, reason: 'module-not-installed' };
  }
  try {
    const res = await Native.applyMeshNetworkMacRandomization(networks);
    return {
      requested: !!res.requested,
      active: !!res.active,
      reason: res.reason ?? undefined,
    };
  } catch (e: any) {
    return { requested: true, active: false, reason: e?.message || 'suggestion-failed' };
  }
}

/** Withdraw Kryptos's network suggestions (Shield tier lowered / OFF). */
export async function clearMeshNetworkSuggestions(): Promise<MacRandomizationResult> {
  if (!Native) {
    return { requested: false, active: false, reason: 'module-not-installed' };
  }
  try {
    const res = await Native.clearMeshNetworkSuggestions();
    return {
      requested: !!res.requested,
      active: !!res.active,
      reason: res.reason ?? undefined,
    };
  } catch (e: any) {
    return { requested: false, active: false, reason: e?.message || 'clear-failed' };
  }
}
