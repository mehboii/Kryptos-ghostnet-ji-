# Bluetooth Troubleshooting Guide

If you are experiencing issues with Bluetooth scanning or connectivity in GhostNet, please follow these steps.

## Common Issues on Windows

### 1. Adapter Conflict (Scanning vs Advertising)
On Windows, the Bluetooth adapter cannot be used by two different applications simultaneously in different modes.

- **Scenario A (Recommended)**: Run `ble-peripheral.js` on your **PC** to advertise. Use your **Phone** (Chrome/Bluefy) to scan and connect.
  - PC acts as a GhostNet Node.
  - Phone acts as a Client.
  
- **Scenario B (Not Supported)**: Trying to run `ble-peripheral.js` AND scan from Chrome on the **same PC**.
  - The `ble-peripheral.js` script (using `bleno`) takes exclusive control of the adapter (requires Zadig driver).
  - Chrome (using Windows native stack) loses access to the adapter.
  - Result: Chrome finds no devices.

**Solution**: Stop `ble-peripheral.js` if you want to scan from Chrome on the same machine. Or use a separate USB Bluetooth dongle for one of them.

### 2. "Device Connected but Service Not Found"
- This means you connected to a device that is NOT running GhostNet.
- Ensure the other device is running the GhostNet app and is actively advertising.
- If using `ble-peripheral.js`, ensure it says "Advertising started".

### 3. "NotFoundError" or "User cancelled"
- This means no device was selected in the browser picker, or no devices were found.
- Ensure Bluetooth is ON.
- Ensure the other device is advertising.
- Android: Ensure Location Services are ON (required for BLE scanning).

### 4. Zadig Driver (For Node.js scripts only)
- If running `node ble-peripheral.js` or `node ghostnet-ble.js`, you likely need to replace the Bluetooth driver with `WinUSB` using Zadig.
- **Warning**: This breaks standard Windows Bluetooth functionality (like connecting mice/keyboards) until you uninstall the driver.
- **Recommendation**: Create a dedicated GhostNet station (Raspberry Pi or old laptop) or use a USB dongle.

## Testing Setup
1. **PC (PowerShell)**:
   ```bash
   node ble-peripheral.js
   ```
   (Must see "Advertising started")

2. **Phone (Chrome)**:
   - Go to `chrome://flags` and enable `#unsafely-treat-insecure-origin-as-secure`.
   - Add `http://<YOUR_PC_IP>:8080` to the list.
   - Relaunch Chrome.
   - Visit `http://<YOUR_PC_IP>:8080`.
   - Click "Enable Mesh" / "Scan Network".
   - You should see "GhostNode" in the list.
