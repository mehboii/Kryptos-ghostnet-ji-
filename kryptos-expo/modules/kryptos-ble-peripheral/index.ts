/**
 * kryptos-ble-peripheral — the BLE *peripheral* role for Proximity Connect.
 *
 * react-native-ble-plx (used on the central side) is CENTRAL-ONLY: it can scan
 * and connect but cannot advertise or run a GATT server. This local Expo module
 * supplies the missing half so a phone can be DISCOVERABLE at the same time it
 * is scanning:
 *   - advertises the shared rendezvous Service UUID (+ a rotating pseudonym byte
 *     in Android service data — iOS strips it, which is fine),
 *   - runs a GATT server exposing the Kryptos service so a connecting central
 *     can read our nodeId / identity key and drive the handshake over CHAR_DATA.
 *
 * Doing advertising here (rather than adding react-native-ble-advertiser) keeps
 * the dependency surface minimal: the GATT server already requires native code,
 * so advertising rides along in the same module.
 *
 * All methods fail soft: if advertising/peripheral is unsupported (older Android
 * radios, simulators), `isPeripheralSupported()` returns false and the caller
 * degrades to scan-only instead of crashing.
 */
import { EventEmitter, requireOptionalNativeModule } from 'expo-modules-core';

export type PeripheralEvents = {
  /** A connected central wrote a handshake/session frame to CHAR_DATA. */
  onCentralWrite: (e: { deviceId: string; base64: string }) => void;
  onCentralConnected: (e: { deviceId: string }) => void;
  onCentralDisconnected: (e: { deviceId: string }) => void;
  /** Adapter/advertiser/GATT-server state transitions and fatal errors. */
  onStateChange: (e: { state: string }) => void;
  onError: (e: { message: string; phase?: string }) => void;
};

export interface StartAdvertisingOptions {
  /** Rendezvous service UUID every Kryptos client advertises + scans for. */
  serviceUuid: string;
  /** Rotating ephemeral pseudonym (hex). NEVER a stable identifier. */
  pseudonymHex?: string;
}

export interface PeripheralCharacteristicValues {
  /** Our nodeId, returned on a read of CHAR_PEER_ID. */
  peerId: string;
  /** Our identity public key (hex), returned on a read of CHAR_PUB_KEY. */
  publicKeyHex: string;
  charPeerIdUuid: string;
  charPubKeyUuid: string;
  charDataUuid: string;
}

// requireOptionalNativeModule → returns null instead of throwing when the native
// module isn't present (e.g. running in Expo Go or before a dev build). The JS
// orchestrator checks this and degrades to scan-only.
const Native = requireOptionalNativeModule('KryptosBlePeripheral');

export const isAvailable = Native != null;

const emitter = Native ? new EventEmitter(Native as any) : null;

export function addListener<T extends keyof PeripheralEvents>(
  event: T,
  listener: PeripheralEvents[T]
) {
  if (!emitter) return { remove() {} };
  return emitter.addListener(event as string, listener as any);
}

/** True only when the radio can advertise AND run a GATT server. */
export async function isPeripheralSupported(): Promise<boolean> {
  if (!Native) return false;
  try {
    return await Native.isPeripheralSupported();
  } catch {
    return false;
  }
}

/** Configure the static values the GATT server returns on characteristic reads. */
export async function configure(values: PeripheralCharacteristicValues): Promise<void> {
  if (!Native) return;
  await Native.configure(values);
}

/** Start advertising the rendezvous UUID + open the GATT server. */
export async function startAdvertising(options: StartAdvertisingOptions): Promise<boolean> {
  if (!Native) return false;
  return await Native.startAdvertising(options);
}

/** Refresh only the advertised rotating pseudonym without tearing down the server. */
export async function updatePseudonym(pseudonymHex: string): Promise<void> {
  if (!Native) return;
  await Native.updatePseudonym(pseudonymHex);
}

/** Stop advertising and close the GATT server. */
export async function stopAdvertising(): Promise<void> {
  if (!Native) return;
  await Native.stopAdvertising();
}

/** Push a handshake/session frame (base64) to connected central(s) via notify. */
export async function notifyData(base64: string): Promise<void> {
  if (!Native) return;
  await Native.notifyData(base64);
}
