# Vault Login/Logout — Walkthrough

## What Changed

### [ghostnet-file-vault.js](file:///c:/Users/novtw/.gemini/antigravity/ghostnet-file-vault.js)

Two new functions added and exposed on the `GhostVault` API:

| Function | Purpose |
|---|---|
| `clearVaultState()` | **Logout** — wipes in-memory `vaultIndex`, removes `ghostnet_vault_index` from localStorage, clears session keys via `lockVault()`, and resets `VaultKeyManager.key`. Does **NOT** delete server/IPFS files. |
| `refreshVaultForUser()` | **Login** — fetches the authenticated user's files from `VAULT_API/files/{owner}`, updates in-memory + localStorage index, returns the file list. |

render_diffs(file:///c:/Users/novtw/.gemini/antigravity/ghostnet-file-vault.js)

---

### [ui.js](file:///c:/Users/novtw/.gemini/antigravity/ui.js)

| Hook | What it does |
|---|---|
| `logout` handler (line ~224) | Calls `GhostVault.clearVaultState()` + `UI.vaultRenderFiles([])` to empty the vault file cards |
| `identity:updated` listener (line ~302) | Calls `GhostVault.init()` → `UI.vaultLoadFiles()` to re-fetch and render the new user's files |

render_diffs(file:///c:/Users/novtw/.gemini/antigravity/ui.js)

## Verification

- ✅ Both files pass `node -c` syntax check (no parse errors)
- ✅ `clearVaultState` — Only clears local state (in-memory array, localStorage key, session), never calls server DELETE endpoints
- ✅ `refreshVaultForUser` — Uses same `_secureHeaders()` (auth token) and same owner-based URL pattern as existing `listFiles()`
- ✅ File cards continue to show: filename, size, date, SHA-256 hash, and Stored/Confirmed badge (rendering via existing `vaultRenderFiles`)
