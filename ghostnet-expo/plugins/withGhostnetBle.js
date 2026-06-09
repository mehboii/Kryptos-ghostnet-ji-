/**
 * Expo config plugin for GhostNet Proximity Connect BLE.
 *
 * Sets up the native permission/manifest/plist surface that the central
 * (react-native-ble-plx) and the local peripheral module need. Applied on every
 * `expo prebuild`, so the committed android/ project and a fresh ios/ project
 * both come out correct.
 *
 * Android (API 31+): BLUETOOTH_SCAN (with android:usesPermissionFlags=
 * "neverForLocation" so fine-location is NOT required), BLUETOOTH_ADVERTISE,
 * BLUETOOTH_CONNECT as runtime permissions. Pre-31 path: legacy BLUETOOTH /
 * BLUETOOTH_ADMIN + ACCESS_FINE_LOCATION (capped at maxSdkVersion 30) for scan.
 *
 * iOS: NSBluetoothAlwaysUsageDescription + bluetooth-central / bluetooth-peripheral
 * background modes (foreground is the real target; modes let the OS keep the
 * session alive briefly when backgrounded).
 */
const {
  AndroidConfig,
  withAndroidManifest,
  withInfoPlist,
} = require('@expo/config-plugins');

const BT_PERMISSION_DESCRIPTION =
  'GhostNet uses Bluetooth to discover and securely connect to nearby devices in the offline mesh.';

function ensureUsesPermission(manifest, name, extraAttrs = {}) {
  manifest['uses-permission'] = manifest['uses-permission'] || [];
  const existing = manifest['uses-permission'].find(
    (p) => p.$ && p.$['android:name'] === name
  );
  const attrs = { 'android:name': name, ...extraAttrs };
  if (existing) {
    Object.assign(existing.$, attrs);
  } else {
    manifest['uses-permission'].push({ $: attrs });
  }
}

const withGhostnetAndroidBle = (config) =>
  withAndroidManifest(config, (cfg) => {
    const manifest = cfg.modResults.manifest;

    // API 31+ runtime permissions.
    ensureUsesPermission(manifest, 'android.permission.BLUETOOTH_SCAN', {
      'android:usesPermissionFlags': 'neverForLocation',
    });
    ensureUsesPermission(manifest, 'android.permission.BLUETOOTH_ADVERTISE');
    ensureUsesPermission(manifest, 'android.permission.BLUETOOTH_CONNECT');

    // Pre-31 legacy permissions (ignored on 31+ via maxSdkVersion).
    ensureUsesPermission(manifest, 'android.permission.BLUETOOTH', {
      'android:maxSdkVersion': '30',
    });
    ensureUsesPermission(manifest, 'android.permission.BLUETOOTH_ADMIN', {
      'android:maxSdkVersion': '30',
    });
    ensureUsesPermission(manifest, 'android.permission.ACCESS_FINE_LOCATION', {
      'android:maxSdkVersion': '30',
    });

    return cfg;
  });

const withGhostnetIosBle = (config) =>
  withInfoPlist(config, (cfg) => {
    cfg.modResults.NSBluetoothAlwaysUsageDescription =
      cfg.modResults.NSBluetoothAlwaysUsageDescription || BT_PERMISSION_DESCRIPTION;
    cfg.modResults.NSBluetoothPeripheralUsageDescription =
      cfg.modResults.NSBluetoothPeripheralUsageDescription || BT_PERMISSION_DESCRIPTION;

    const modes = new Set(cfg.modResults.UIBackgroundModes || []);
    modes.add('bluetooth-central');
    modes.add('bluetooth-peripheral');
    cfg.modResults.UIBackgroundModes = Array.from(modes);

    return cfg;
  });

module.exports = function withGhostnetBle(config) {
  config = withGhostnetAndroidBle(config);
  config = withGhostnetIosBle(config);
  return config;
};
