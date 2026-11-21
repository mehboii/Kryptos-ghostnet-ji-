# 🧪 Kryptos Manual Test Checklist — Core Flows

> **Date:** 2026-04-03  
> **Tester:** _______________  
> **Build/Commit:** _______________  
> **Backend URL:** `https://kryptos-ji-production.up.railway.app` _or_ `localhost:8080`  
> **Frontend:** Vercel deployment _or_ `index.html` (local)

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Browser A** | Chrome (latest) — primary device, fresh profile or incognito |
| **Browser B** | Chrome (separate profile or incognito) — peer device |
| **DevTools** | Network tab open on both (filter `WS` for WebSocket frames) |
| **Email** | Two valid email addresses (or single email + Ethereal dev preview) |
| **Storage** | `localStorage` and `sessionStorage` cleared on both profiles before start |

> [!IMPORTANT]
> Execute all phases **sequentially** — each phase depends on state from the previous one.

---

## Phase 1 — Sign Up

> **Source:** [auth.routes.js](file:///c:/Users/novtw/.gemini/antigravity/auth/auth.routes.js) · `POST /auth/signup` → `POST /auth/verify`

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| 1.1 | Open fresh app | Navigate to app URL, clear all storage | Welcome / onboarding screen appears. No stale identity loaded. | | |
| 1.2 | Navigate to Sign Up | Click "Login / Signup" | Registration form shows email + password fields | | |
| 1.3 | Submit empty form | Click submit with no input | Error: "Email and password are required." | | |
| 1.4 | Submit weak password | Enter valid email + password `abc` | Error: "Password must be at least 8 characters." | | |
| 1.5 | Submit password without uppercase | Enter password `abcdefg1!` | Error: "Password must contain at least one uppercase letter." | | |
| 1.6 | Submit password without special char | Enter password `Abcdefg1` | Error: "Password must contain at least one special character." | | |
| 1.7 | Submit valid credentials | Enter valid email + strong password (e.g., `GhostN3t!2026`) | 201 response. UI shows "Check your email for verification code." `requiresVerification: true` | | |
| 1.8 | Check rate limiting | Repeat signup 5+ times rapidly | Rate limited: "Too many signup attempts. Please try again later." (5 per 10 min) | | |
| 1.9 | Retrieve verification code | Check email inbox (or console for `[DEV]` / Ethereal preview link) | 6-digit numeric code received | | |
| 1.10 | Submit wrong verification code | `POST /auth/verify` with incorrect 6-digit code | Error: code mismatch or expired | | |
| 1.11 | Submit correct verification code | Enter the correct 6-digit code | `verified: true`, JWT token returned. Identity setup flow begins. | | |
| 1.12 | Verify JWT structure | Inspect returned token (decode at jwt.io) | Payload contains `userId` and `tv` (tokenVersion = 0) | | |
| 1.13 | Duplicate signup prevention | Try to sign up again with the same email | Returns generic 200: "If this email is not already registered…" (no account enumeration leak) | | |

---

## Phase 2 — Create Identity (BIP39 Seed)

> **Source:** [crypto-identity.js](file:///c:/Users/novtw/.gemini/antigravity/crypto-identity.js) · `generateIdentity()`

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| 2.1 | Enter Display Name | Type a display name (e.g., "AlphaNode") | Name accepted, identity generation begins | | |
| 2.2 | Identity generation | Wait for `ethers.Wallet.createRandom()` to complete | No UI freeze. Loading indicator shows progress. | | |
| 2.3 | Seed phrase displayed | Verify the mnemonic phrase shown on screen | **12-word BIP39 mnemonic** displayed. Each word is from the BIP39 English wordlist. | | |
| 2.4 | **⚠️ SAVE SEED PHRASE** | Copy / write down the 12 words exactly | Needed for Phase 8 (recovery). Record here: `________________________` | | |
| 2.5 | Ed25519 keypair generated | Check identity object in memory (DevTools console) | Object contains `publicKey` (0x-prefixed hex), `address`, `nodeId` (Keccak256 hash, 66 hex chars with 0x prefix). `privateKey` present but NOT persisted yet. | | |
| 2.6 | NodeId derivation is deterministic | Verify `nodeId` uses length-prefixed canonical input | `nodeId = ethers.id("<pkLen>:<pk>|<nameLen>:<name>")` — collision-safe per [FIX F] | | |
| 2.7 | Existing identity check | If `kryptos_identity` already in localStorage, verify generation is skipped | Returns existing identity without overwriting seed | | |

---

## Phase 3 — Set PIN

> **Source:** [crypto-identity.js](file:///c:/Users/novtw/.gemini/antigravity/crypto-identity.js) · `_encryptWithPin()` + `saveNewIdentity()`

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| 3.1 | Enter short PIN | Enter PIN with < 6 characters (e.g., "1234") | Error: "PIN must be at least 6 characters." [FIX E] | | |
| 3.2 | Enter valid PIN | Enter a 6+ character PIN (e.g., "Gh0st!") | PIN accepted | | |
| 3.3 | Confirm PIN | Re-enter the same PIN | Confirmation matches | | |
| 3.4 | Private key encrypted | After PIN set, check `localStorage.getItem('kryptos_enc_pk')` | Base64-encoded blob present. Structure: salt(16B) + iv(12B) + ciphertext. **No plaintext private key anywhere in storage.** | | |
| 3.5 | PBKDF2 iteration count | Verify in source or via timing (~0.5-2s for PIN derivation) | 600,000 iterations (OWASP compliant) [FIX D] | | |
| 3.6 | Identity saved to localStorage | Check `localStorage.getItem('kryptos_identity')` | JSON object with `encryptedPK`, `publicKey`, `address`, `displayName`, `nodeId`. **No `privateKey` or `mnemonic` field.** | | |
| 3.7 | Session created | Check `sessionStorage.getItem('kryptos_session_key')` | Base64-encoded 256-bit session key present (tab-scoped). [FIX A] | | |
| 3.8 | Dashboard access | After PIN setup completes | App redirects to main dashboard. GhostCode loads. All tabs accessible. | | |
| 3.9 | Node registered | Verify `POST /register-node` or `POST /auth/node` was called | Node ID registered on server. Appears in mesh. | | |
| 3.10 | GhostCode assigned | Check UI or `GET /user/shortcode` | Short alphanumeric code displayed (not "Loading...") | | |

---

## Phase 4 — Send Message

> **Source:** [kryptos-chat.js](file:///c:/Users/novtw/.gemini/antigravity/kryptos-chat.js) · [kryptos-server.js](file:///c:/Users/novtw/.gemini/antigravity/kryptos-server.js) `POST /message`

> [!NOTE]
> Before this phase, set up **Browser B** by completing Phases 1–3 with a second account. Share GhostCodes or Node IDs between devices to initiate a chat.

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| 4.1 | Setup Device B | Complete Phases 1–3 in Browser B with a separate email | Second identity created. Both devices have distinct nodeIds. | | |
| 4.2 | Initiate chat | On Device A: search for Device B's GhostCode or enter Node ID | Chat window opens. Message input enabled. | | |
| 4.3 | Send plaintext message | Type "Eagle has landed" and hit Send on Device A | Message appears in Device A's chat feed with sent status. | | |
| 4.4 | Verify wire encryption (DevTools) | Inspect WebSocket frame in Device A's Network tab | Payload contains ONLY `iv` (base64) + `data` (base64 ciphertext). **NO `body` field. NO plaintext.** | | |
| 4.5 | Verify HMAC present | Inspect outbound WS frame for `hmac` field | 64-character hex HMAC-SHA256 string present | | |
| 4.6 | Verify ciphertext is random | Base64-decode the `data` field | Decoded bytes are unintelligible random data. Not the original message. | | |
| 4.7 | Message stored server-side | Check `POST /message` response | Returns `{ success: true, message: { id, convoId, timestamp } }` | | |
| 4.8 | Delivery receipt | Check WS frames | Device A receives `{ type: 'receipt', status: 'delivered', msgId }` if B is online, or `status: 'queued'` if offline | | |

---

## Phase 5 — Receive Message

> **Source:** [kryptos-server.js](file:///c:/Users/novtw/.gemini/antigravity/kryptos-server.js) WebSocket `CHAT_MESSAGE` handler

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| 5.1 | Real-time delivery | Observe Browser B's chat feed | Message "Eagle has landed" appears within **< 2 seconds** via WebSocket. | | |
| 5.2 | Decryption success | Verify displayed text on Device B | Plaintext matches exactly: "Eagle has landed" | | |
| 5.3 | Sender identity verified | Check message metadata on Device B | Correct sender name, nodeId, and timestamp displayed | | |
| 5.4 | Reply message | Send a reply from Device B to Device A | Device A receives the reply in real-time. Same encryption guarantees apply. | | |
| 5.5 | Offline message delivery | Disconnect Device B (close tab), send message from A, reopen B | Queued message arrives on reconnect. Content decrypts correctly. | | |
| 5.6 | Conversation history | Navigate away and back to the chat | `GET /history?convoId=X` returns paginated messages. Only messages from this conversation. | | |
| 5.7 | Cross-user isolation | On Device A, try `GET /conversations` and verify | Returns ONLY Device A's conversations. No data from other users. `userId` forced from JWT. | | |
| 5.8 | History access control | On Device A, try `GET /history?convoId=<Device_B_only_convo>` | Returns `403 Access denied` — cannot read conversations you're not a participant in. | | |

---

## Phase 6 — Enable Ghost Mode

> **Source:** [ghost-shield.js](file:///c:/Users/novtw/.gemini/antigravity/ghost-shield.js) · `GhostShieldEngine`

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| 6.1 | Navigate to Shield tab | Open the "Shield" tab on Device A | Shield UI renders. All 3 tiers shown as inactive. | | |
| 6.2 | **Level 1: Stealth — Enable** | Toggle Stealth ON | UI shows Stealth active. Console logs: `[Ghost Shield] Activated Level 1` | | |
| 6.3 | Verify DNS-over-HTTPS | Check console logs + fetch interceptor | `_dohActive = true`. Fetch calls route through DoH resolver (Cloudflare). Console: "DNS-over-HTTPS active via..." | | |
| 6.4 | Verify BLE suppression | Check console logs | "Stopped BLE advertising" or "BLE toggle skipped — plugin unavailable" (expected in browser, real on native) | | |
| 6.5 | **Level 2: Ghost — Enable** | Toggle Ghost ON (on top of Stealth) | Both Level 1 + 2 active. Console: `Activated Level 2` | | |
| 6.6 | Verify traffic padding | Send a message, inspect WS frame | Outbound JSON contains `_pad` field with random base64 padding data | | |
| 6.7 | Verify timing obfuscation | Send multiple messages, check delivery timing | Messages have random jitter delay (not instant). Visible in Network timing. | | |
| 6.8 | Verify dummy packet injection | Watch WS frames for ~30s | Periodic `{ type: 'cover', data: '__DUMMY__...' }` frames visible | | |
| 6.9 | **Level 3: Phantom — Enable** | Toggle Phantom ON (all 3 tiers active) | Console: "Full Ghost Protocol activated — all levels running simultaneously" | | |
| 6.10 | Verify MAC rotation | Check console logs / `ghostShield:macRotated` events | `MAC rotated → XX:XX:XX:XX:XX:XX` messages appear periodically. `stats.macRotations` incrementing. | | |
| 6.11 | Verify decoy BLE profiles | Check SignalIntelligence feed in UI (if available) | Decoy devices with names like "AirPods Pro", "Galaxy Watch" appear with `isDecoy: true`. | | |
| 6.12 | Messaging still works | Send a message from A to B with all tiers active | Message delivered and decrypted correctly despite padding + timing + noise. | | |
| 6.13 | State persists | Refresh the page (F5) | Ghost Shield restores all 3 active tiers from `localStorage`. `_restoreState()` fires. | | |
| 6.14 | Disable tiers | Toggle each tier OFF (3 → 2 → 1) | Each deactivates cleanly. Console confirms. After all disabled: `active = false`, no lingering intervals. | | |

---

## Phase 7 — Logout

> **Source:** [auth.routes.js](file:///c:/Users/novtw/.gemini/antigravity/auth/auth.routes.js) `POST /auth/logout` · [crypto-identity.js](file:///c:/Users/novtw/.gemini/antigravity/crypto-identity.js) `clearSession()`

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| 7.1 | Open Profile/Settings | Navigate to profile or settings area | Logout button visible | | |
| 7.2 | Click Logout | Click the Logout button | API call: `POST /auth/logout` fires | | |
| 7.3 | Server-side token invalidation | Check server response | `{ success: true, message: "Logged out. All tokens invalidated." }`. Server logs: `tokenVersion bumped to N+1` | | |
| 7.4 | JWT cleared from storage | Check `sessionStorage` and `localStorage` | `kryptos_token` removed. `kryptos_session_key` removed from sessionStorage. `kryptos_session_key_blob` removed from localStorage. | | |
| 7.5 | UI reset | Observe the app | Returns to welcome/login screen. No authenticated content visible. | | |
| 7.6 | Old JWT rejected — HTTP | Manually try `GET /auth/me` with the old JWT | Returns `401 Unauthorized` — tokenVersion mismatch rejects stale token | | |
| 7.7 | Old JWT rejected — WebSocket | Try to connect WS with old JWT: `/ws?token=<old_jwt>` | WebSocket connection destroyed immediately. `socket.destroy()` called. | | |
| 7.8 | No residual data leak | Inspect `localStorage` for `kryptos_*` keys | `kryptos_identity` and `kryptos_enc_pk` **may persist** (they hold the encrypted identity, not the session). But session keys are gone — identity cannot be unlocked without PIN. | | |

---

## Phase 8 — Recover with Seed Phrase

> **Source:** [crypto-identity.js](file:///c:/Users/novtw/.gemini/antigravity/crypto-identity.js) · `restoreFromMnemonic()`

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| 8.1 | Navigate to recovery | On the welcome screen, click "Restore Identity" / "Recover with seed phrase" | Seed phrase input screen appears | | |
| 8.2 | Enter wrong seed phrase | Enter 12 random words | Error: "Invalid seed phrase. Please check your words." | | |
| 8.3 | Enter correct seed phrase | Enter the 12 words saved from Phase 2 (Step 2.4) | Identity restoration begins. `ethers.Wallet.fromPhrase()` succeeds. | | |
| 8.4 | Re-enter display name | Enter the same display name used in Phase 2 | Display name accepted | | |
| 8.5 | Same keys regenerated | Compare `publicKey` and `nodeId` with Phase 2 values | **Exact match.** Same public key, same address, same nodeId (deterministic derivation). | | |
| 8.6 | Set new PIN | Enter a PIN (same or different from Phase 3) | Private key re-encrypted under new PIN. Stored in `kryptos_enc_pk`. | | |
| 8.7 | Dashboard access restored | After PIN setup | Main dashboard loads. Identity shows same GhostCode / Node ID as before logout. | | |
| 8.8 | GhostCode resolves | Verify via UI or `GET /user/shortcode` | Returns the same GhostCode assigned in Phase 3 | | |
| 8.9 | Previous chats accessible | Open the chat with Device B | Encrypted messages from earlier sessions decrypt correctly with the restored keys. | | |
| 8.10 | Node re-registered | Verify `POST /register-node` was called | Same nodeId re-registered on server. Mesh peers can see this device again. | | |

---

## PIN Lockout (Edge Case — Run After Phase 8)

> **Source:** [crypto-identity.js](file:///c:/Users/novtw/.gemini/antigravity/crypto-identity.js) · `_recordFailedAttempt()` [FIX B]

| # | Step | Action | Expected Result | ✅/❌ | Notes |
|---|------|--------|-----------------|:-----:|-------|
| E.1 | Enter wrong PIN 4 times | Attempt to unlock identity with incorrect PIN, 4 times | Errors: "Wrong PIN. N attempts remaining." Counter decrements: 4 → 3 → 2 → 1 | | |
| E.2 | 5th wrong attempt — lockout | Enter wrong PIN a 5th time | Error: "Too many failed attempts. Identity locked." `_locked = true` | | |
| E.3 | Verify lockout persists | Try entering the correct PIN | Error: "Identity locked. Please restore from seed phrase." | | |
| E.4 | Lockout bypass impossible | Open DevTools, try `localStorage.setItem('kryptos_locked', 'false')` | **No effect.** Lockout is in-memory only. [FIX B] | | |
| E.5 | Recovery after lockout | Restore from seed phrase (repeat Phase 8 steps) | Full recovery succeeds. Lockout state reset on page reload. | | |

---

## Test Summary Scorecard

| Phase | Description | Total Steps | Passed | Failed | Blocked |
|-------|-------------|:-----------:|:------:|:------:|:-------:|
| **1** | Sign Up (Email + Verification) | 13 | | | |
| **2** | Create Identity (BIP39 Seed) | 7 | | | |
| **3** | Set PIN (PBKDF2 Encryption) | 10 | | | |
| **4** | Send Message (E2E Encrypted) | 8 | | | |
| **5** | Receive Message (WebSocket) | 8 | | | |
| **6** | Enable Ghost Mode (3-Tier Shield) | 14 | | | |
| **7** | Logout (Token Invalidation) | 8 | | | |
| **8** | Recover with Seed Phrase | 10 | | | |
| **E** | PIN Lockout (Edge Case) | 5 | | | |
| | **TOTAL** | **83** | | | |

---

> **Sign-off**
>
> | Role | Name | Date | Signature |
> |------|------|------|-----------|
> | Tester | | | |
> | Reviewer | | | |

