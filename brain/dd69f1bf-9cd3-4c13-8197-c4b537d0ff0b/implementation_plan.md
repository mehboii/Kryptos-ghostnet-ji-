# Kryptos Functionality Repair & Mesh Enhancement Plan

## Goal
Restore full interactivity to the new "Ahost Net" UI and implement a convincing Bluetooth Mesh experience that simulates multi-hop decentralized communication.

## User Review Required
> [!NOTE]
> True background Bluetooth Mesh (scanning and advertising simultaneously) is not fully supported by standard browser APIs (Web Bluetooth is Central-only and requires user gestures). We will use the real API for "Entry Point" connection and simulate the Mesh/Multi-hop aspect visually.

## Proposed Changes

### Logic Layer (`script.js`)
#### [MODIFY] [script.js](file:///C:/Users/novtw/.gemini/antigravity/scratch/kryptos-client/script.js)
- **DOM Selector Updates**:
    - Update Nav selectors from `.nav-links li` to `.nav-item`.
    - Update Tab selectors from `.tab-content` to `.view-panel`.
    - Fix Auth layer transition (hiding `.auth-overlay` instead of toggling `active` on non-existent `app-layer`).
- **Bluetooth Logic**:
    - Enhance `startBleScan` to visualize "finding" peers after the initial connection.
    - Add "Mesh Hop" routing lines on the Radar canvas (new feature).
- **Dashboard Visualization**:
    - Ensure the Network Map canvas resizes correctly in the new grid layout.

## Verification Plan
### Manual Verification
- **Click Navigation**: Verify all tabs (Network, Chat, BLE, Vault, Browser) switch correctly.
- **Auth Flow**: Verify "Connect" button dismisses opacity layer and reveals dashboard.
- **Bluetooth**: Click "Broadcast Beacon" -> Browser Permission Prompt -> Select Device -> See it appear in list -> Watch radar visualize "hops" to distant nodes.
