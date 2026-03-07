# GhostNet BLE Transport Layer

This module (`ghostnet-ble.js`) adds native Bluetooth Mesh capabilities to GhostNet.

## Architecture

- **Browser**: Uses Web Bluetooth API (`navigator.bluetooth`) to scan and connect to GhostNet nodes.
- **Node.js**: Uses `@abandonware/noble` to scan and connect.

## Usage

The `TransportManager` in `simulation.js` automatically initializes the BLE layer.

### Discovery
To discover BLE peers:
1. Go to the **Nodes** tab in the UI.
2. Click **Scan BLE Mesh**.
3. Select a matching device (Service UUID: `ghostnet-mesh`).

### Auto-Routing
The `TransportManager` automatically selects the best transport:
- If a peer is connected via BLE, messages are routed over BLE.
- Otherwise, it falls back to IP/WebSocket (simulated).

## Prerequisites

### Local Testing (Node.js)
Install dependencies:
```bash
npm install @abandonware/noble
```

### Browser Testing
- Requires a browser with Web Bluetooth support (Chrome, Edge, Opera).
- Must be served over **HTTPS** (or localhost).
- **Note**: Browsers generally cannot *advertise* BLE services (Peripheral role) without experimental flags. This implementation allows the browser to act as a Central (Client) to connect to existing BLE nodes (e.g., ESP32, Raspberry Pi, or Node.js instances running `bleno`).

## Integration
The transport layer is integrated into `simulation.js` via `TransportManager`.
```javascript
app.transport.send(payload, peerId);
```
