# Implementation Plan - Kryptos Bug Fixes

This plan addresses five critical bugs in the Kryptos application related to session management, identity preservation, and API communication.

## Proposed Changes

### 1. Unified Session Clearing and Loop Prevention (`ui.js`)

#### [MODIFY] [ui.js](file:///c:/Users/novtw/.gemini/antigravity/ui.js)
- Add a guard flag `isClearingSession` to `UI.clearSession` to prevent infinite recursion.
- Stop using `localStorage.clear()` and `sessionStorage.clear()`.
- Explicitly clear only session-related keys: `kryptos_token`, `kryptos_jwt`, `kryptos_node_id`, `kryptos_vault_unlocked`, etc.
- Preserve identity keys like `kryptos_identity`, `kryptos_identity_vault`, `kryptos_vault_index`, and `kryptos_ble_devices`.

### 2. Payload Size Reduction (`index.html` and `kryptos-server.js`)

#### [MODIFY] [kryptos-server.js](file:///c:/Users/novtw/.gemini/antigravity/kryptos-server.js)
- Increase `MAX_BODY_SIZE` from `64kb` to `1mb` to accommodate avatars and other larger payloads (up to the 512KB clip limit for avatars).

#### [MODIFY] [index.html](file:///c:/Users/novtw/.gemini/antigravity/index.html)
- Ensure avatars are downsampled or limited in size before being sent to the server (though increasing the server limit might be sufficient if they are already clipped to 512KB).

### 3. Vault Key Route Fix (`kryptos-file-vault.js`)

#### [MODIFY] [kryptos-file-vault.js](file:///c:/Users/novtw/.gemini/antigravity/kryptos-file-vault.js)
- Update `VaultKeyManager.getOrGenerateKey` and `VaultKeyManager.generateNew` to fetch from the correct endpoint. The server expects `GET /vault/key` and `POST /vault/key`.
- Ensure the URL assembly correctly targets these routes on the Railway backend.

### 4. Seed Phrase Restore Flow (`crypto-identity.js`)

#### [MODIFY] [crypto-identity.js](file:///c:/Users/novtw/.gemini/antigravity/crypto-identity.js)
- Ensure `restoreFromMnemonic` can proceed even if a partial identity or session existed previously.
- Validate that it doesn't get blocked by the "No identity found" state if an identity is actually present but just locked.

## Verification Plan

### Automated Tests
- I'll check if there are existing tests for identity and session management.
- I'll run `node test-identity.js` if available to check identity logic.

### Manual Verification
- **Session Clear Loop**: Manually trigger signout and observe if the infinite loop is gone.
- **Identity Preservation**: Sign out and check `localStorage` to ensure `kryptos_identity` is still there.
- **Payload Size**: Register a node with a large avatar and confirm it doesn't hit the 413 error.
- **Vault Key**: Test opening the vault and confirm the 404 error is resolved.
