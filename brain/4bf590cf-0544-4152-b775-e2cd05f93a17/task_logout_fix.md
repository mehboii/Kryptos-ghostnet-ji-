# Unified Logout & Session Cleanup

## Tasks
- [x] Research navigation and overflow logic in `ui.js`
- [x] Research in-memory state in `app.js` and `ui.js`
- [x] Define `UI.clearSession()` in `ui.js`
- [x] Implement `clearSession()`:
    - [x] `localStorage.clear()` & `sessionStorage.clear()`
    - [x] Reset `AppState` and `window.app` identity/auth state
    - [x] Call `GhostVault.clearVaultState()`
    - [x] Reset `body`/`html` overflow
    - [x] Remove all modals/overlays
    - [x] Navigate to identity/login section
- [x] Hook `clearSession()` to all logout buttons
- [x] Prevent back-navigation (replace state)
- [x] Verify fix for Bug 1 (Identity info cleared)
- [x] Verify fix for Bug 2 (Vault cleared)
- [x] Verify fix for Bug 3 (Scroll restored)
- [x] Final Walkthrough
- [x] Push changes to GitHub
