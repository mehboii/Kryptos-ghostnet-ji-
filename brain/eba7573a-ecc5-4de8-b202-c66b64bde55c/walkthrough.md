# Auth Token Infinite Loop Fix — Full Walkthrough

## Root Cause Analysis

The infinite loop after signout was caused by **three compounding issues**:

### 1. Token Key Name Mismatch (Critical)
- **Login** (`index.html`): Stored token in `sessionStorage.setItem('ghostnet_token', token)` only
- **Auth check** (`ui.js:32`): Read from `localStorage.getItem('ghostnet_token')` FIRST, then `sessionStorage`
- **After page reload**: `sessionStorage` is cleared → token appears missing even though it was valid

### 2. `getAuthHeaders()` triggered `clearSession()` on missing token
- Every API call (loadProfile, fetchGhostCode, fetchRealData, vault, conversations) called `getAuthHeaders()`
- When no token found, it called `UI.clearSession()` via `setTimeout()`
- This created **multiple overlapping `clearSession()` calls** — the existing guard `_isClearingSession` reset after 1 second, allowing the next queued call to fire

### 3. No skip for unauthenticated state
- `UI.init()` always called `loadProfile()`, `startGhostCodeWatcher()`, and `fetchRealData()` even when no token existed (e.g., fresh page load on the identity screen)
- Each of those made API calls → got 401 → triggered `getAuthHeaders()` → triggered `clearSession()` loop

---

## Fixes Applied

### Fix 1: Token stored in BOTH storages (`index.html`)

**Before** (both login paths):
```js
sessionStorage.setItem('ghostnet_token', token);
```

**After**:
```js
sessionStorage.setItem('ghostnet_token', token);
localStorage.setItem('ghostnet_token', token);
```

This ensures the token survives tab reloads and is always findable by `ui.js`.

---

### Fix 2: `getAuthHeaders()` NEVER calls `clearSession()` (`ui.js`)

**Before**:
```js
const getAuthHeaders = () => {
    const token = localStorage.getItem('ghostnet_token') || sessionStorage.getItem('ghostnet_token');
    if (!token) {
        console.warn("[Auth] Token missing or expired. Redirecting to login...");
        setTimeout(() => {
            if (window.UI && UI.clearSession) UI.clearSession();
        }, 100);
        return {};
    }
    return { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };
};
```

**After**:
```js
function _readToken() {
    return sessionStorage.getItem('ghostnet_token')
        || localStorage.getItem('ghostnet_token')
        || localStorage.getItem('ghostnet_jwt')
        || '';
}

function hasAuthToken() {
    return !!_readToken();
}

const getAuthHeaders = () => {
    const token = _readToken();
    if (!token) return {};  // No side effects — just return empty
    return { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };
};
```

Key change: `getAuthHeaders()` is now a **pure function**. No redirects, no clearSession calls.

---

### Fix 3: One-time guard on `clearSession()` (`ui.js`)

**Before**:
```js
clearSession: (isDestroy = false) => {
    if (window._isClearingSession) return;
    window._isClearingSession = true;
    // ... cleanup ...
    setTimeout(() => { window._isClearingSession = false; }, 1000);
},
```

**After**:
```js
let _authRedirectFired = false;  // module-level, permanent per page load

clearSession: (isDestroy = false) => {
    if (_authRedirectFired || window._isClearingSession) return;
    window._isClearingSession = true;
    _authRedirectFired = true;  // PERMANENT — blocks ALL future calls this page load
    // ... cleanup ...
    setTimeout(() => { window._isClearingSession = false; }, 1000);
},
```

`_authRedirectFired` is reset ONLY on the `identity:updated` event (i.e., a successful new login).

---

### Fix 4: Skip API calls when unauthenticated (`ui.js`)

**Before**: `UI.init()` always called `loadProfile()`, `startGhostCodeWatcher()`, etc.

**After**:
```js
if (hasAuthToken()) {
    UI.loadProfile();
}
// ...
if (hasAuthToken()) {
    UI.startGhostCodeWatcher(false);
}
```

Same for `fetchRealData()`, `fetchGhostCode()`, and `loadProfile()` — they all now check `hasAuthToken()` before making network requests.

---

### Fix 5: `POST /register-node` only fires after valid token (`index.html`)

**Before**:
```js
fetch('.../register-node', {
    headers: { 'X-Auth-Token': sessionStorage.getItem('ghostnet_token') || '' },
    // ...
});
```

**After**:
```js
const _regToken = sessionStorage.getItem('ghostnet_token');
if (_regToken) {
    fetch('.../register-node', {
        headers: { 'Authorization': `Bearer ${_regToken}` },
        // ...
    });
}
```

---

### Fix 6: Debug logging for `POST /auth/node` 400 error (`index.html`)

Added payload logging before the fetch:
```js
const authPayload = { nodeId: stored.nodeId };
console.log('[Auth] POST /auth/node payload:', authPayload);
```

And error body logging:
```js
} else {
    console.error('[Auth] /auth/node returned', authRes.status, await authRes.text());
}
```

The 400 error from `/auth/node` occurs when `nodeId` is `undefined` or doesn't match the `0x[hex]` pattern expected by `validateNodeId()`. The logging will reveal the actual payload sent.

---

### Fix 7: SignOut clears ONLY session tokens (`ui.js`)

Confirmed the `sessionKeys` list contains only temporary keys:
```js
const sessionKeys = [
    'ghostnet_token', 'ghostnet_jwt', 'ghostnet_node_id',
    'ghostnet_vault_unlocked', 'ghostnet_session_key', 'ghostnet_last_convo'
];
```

Identity keys (`ghostnet_identity`, `ghostnet_seed_words`, etc.) are ONLY removed when `isDestroy === true` (full identity wipe), never during normal signout.

---

## Files Modified

| File | Lines | Change |
|------|-------|--------|
| `ui.js` | 31-70 | Rewrote `getAuthHeaders()` as pure function + `_readToken()` + `hasAuthToken()` |
| `ui.js` | 285-332 | Guard `mockData`, `loadProfile`, `startGhostCodeWatcher` behind `hasAuthToken()` |
| `ui.js` | 334-354 | Reset `_authRedirectFired` on `identity:updated`; gate post-login calls |
| `ui.js` | 375-500 | Added `_authRedirectFired` permanent guard to `clearSession()` |
| `ui.js` | 700-710 | Guard `fetchRealData` behind `hasAuthToken()` |
| `ui.js` | 1806-1820 | Guard `loadProfile` server fetch behind `hasAuthToken()` |
| `ui.js` | 2367 | Guard `fetchGhostCode` behind `hasAuthToken()` |
| `index.html` | 1425-1465 | Fix token storage (both storages), auth/node logging, register-node guard |
| `index.html` | 1532-1570 | Same fix for PIN unlock flow |
