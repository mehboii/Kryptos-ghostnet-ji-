/**
 * kryptos-wifi-scan — nearby WiFi access-point scan for Ghost Radar.
 *
 * ANDROID ONLY by platform reality: Android exposes the list of nearby WiFi
 * access points (SSID/BSSID/signal) via WifiManager. iOS does NOT permit an app
 * to enumerate surrounding access points at all (no public API), so the iOS half
 * of this module deliberately reports `available = false` rather than faking a
 * result. The JS/UI layer hides the WiFi section on iOS accordingly.
 *
 * This lists ROUTERS / HOTSPOTS, never other phones — the caller labels it
 * "nearby networks", not "devices".
 *
 * Fails soft: if the native module isn't present (Expo Go / web), the optional
 * require returns null and callers degrade to "unavailable in this build".
 */
import { requireOptionalNativeModule } from 'expo-modules-core';

export interface WifiAccessPoint {
  /** Network name. Empty string when the SSID is hidden/cloaked. */
  ssid: string;
  /** AP hardware address (router identity). */
  bssid: string;
  /** Signal strength in dBm (e.g. -45 close, -85 far). */
  rssi: number;
  /** Channel centre frequency in MHz. */
  frequency: number;
  /** Raw capability string (e.g. "[WPA2-PSK-CCMP][ESS]"). */
  capabilities: string;
}

export interface WifiScanResult {
  available: boolean;
  /** 'ok' | 'ios-unsupported' | 'permission-denied' | 'wifi-disabled' | 'throttled' | error message */
  reason?: string;
  accessPoints: WifiAccessPoint[];
}

const Native = requireOptionalNativeModule('KryptosWifiScan');

/** True only on a build where the native module is linked (dev client / EAS). */
export const isAvailable = Native != null;

/**
 * Scan for nearby access points. Always resolves (never throws) so a denied
 * permission or a throttled scan degrades gracefully instead of crashing.
 */
export async function scan(): Promise<WifiScanResult> {
  if (!Native) {
    return { available: false, reason: 'module-not-installed', accessPoints: [] };
  }
  try {
    const res = await Native.scan();
    return {
      available: !!res.available,
      reason: res.reason,
      accessPoints: Array.isArray(res.accessPoints) ? res.accessPoints : [],
    };
  } catch (e: any) {
    return { available: false, reason: e?.message || 'scan-failed', accessPoints: [] };
  }
}
