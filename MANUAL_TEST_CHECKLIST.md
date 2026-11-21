# Kryptos Manual Test Checklist

> **Last updated:** 2026-04-03
> **Backend:** `kryptos-server.js` (port 8080)
> **Build:** Capacitor Android (`capacitor.config.json` appId: `dev.n11x.kryptos`)

---

## 1. CRITICAL — Sign Up > Identity > Message > Recovery Flow

Full end-to-end user journey. Every step must pass.

### 1.1 Sign Up & Identity Creation

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 1.1.1 | Open app fresh (clear data) | Boot modal / onboarding screen appears | | |
| 1.1.2 | `POST /auth/signup` with valid email | 200 OK, 6-digit verification code sent to email | | |
| 1.1.3 | `POST /auth/verify` with correct code | 200 OK, JWT token returned | | |
| 1.1.4 | Submit with invalid/expired code | Rejected with error, not authenticated | | |
| 1.1.5 | Identity generation triggers (`crypto-identity.js:generateIdentity()`) | BIP39-style seed phrase generated, Ed25519 keypair created | | |
| 1.1.6 | Seed phrase displayed to user | 12/24 words shown, user prompted to back up | | |
| 1.1.7 | Set PIN (4-6 digits) | PIN accepted, key derived via PBKDF2 (600K iterations) | | |
| 1.1.8 | Verify PIN lockout: enter wrong PIN 5 times | Account locks, no bypass via localStorage manipulation | | |
| 1.1.9 | After setup, `POST /auth/node` issues node JWT | Node registered, token stored in sessionStorage | | |
| 1.1.10 | `POST /register-node` with JWT | Node appears in mesh, nodeId validated (hex, 64 chars) | | |
| 1.1.11 | GhostCode assigned (`GET /user/shortcode`) | Short code displayed in UI (not stuck on "Loading...") | | |

### 1.2 Send & Receive Messages

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 1.2.1 | Open Chat view, select a peer | Chat window opens, message input enabled | | |
| 1.2.2 | Type and send a message | `POST /message` succeeds, message appears in sender's chat | | |
| 1.2.3 | Recipient device receives message via WebSocket | Message appears on recipient in <2s | | |
| 1.2.4 | Verify message payload has NO plaintext `body` field | Network capture shows only `iv` + `data` (ciphertext) | | |
| 1.2.5 | Verify HMAC present on message payload | `hmac` field exists and is 64-char hex | | |
| 1.2.6 | Send message to offline peer | Message queued, delivered when peer reconnects | | |
| 1.2.7 | Delete a sent message | DELETE authenticated via HMAC, removed from both devices | | |
| 1.2.8 | Send ephemeral message (if TTL supported) | Message auto-deletes after TTL expires | | |
| 1.2.9 | `GET /history?convoId=X` returns only own messages | No cross-user data leakage | | |
| 1.2.10 | `GET /conversations` returns only own conversations | userId forced from JWT, not query param | | |

### 1.3 Ghost Mode (Enable/Disable)

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 1.3.1 | Enable Ghost Mode from UI | Shield UI reflects active state | | |
| 1.3.2 | Verify BLE broadcast stops (if on native) | No BLE advertisements from device | | |
| 1.3.3 | Verify network behavior changes (not just UI) | Traffic padding or DNS-over-HTTPS active | | |
| 1.3.4 | Disable Ghost Mode | All protections deactivated, normal traffic resumes | | |

### 1.4 Logout & Seed Recovery

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 1.4.1 | Tap Logout | Session cleared, token removed from sessionStorage + localStorage | | |
| 1.4.2 | Verify no auth tokens remain in storage | Manual check: `sessionStorage` and `localStorage` empty of `kryptos_token` | | |
| 1.4.3 | Re-open app, choose "Recover with seed phrase" | Seed input screen appears | | |
| 1.4.4 | Enter correct seed phrase | Identity restored, same nodeId/public key regenerated | | |
| 1.4.5 | Enter incorrect seed phrase | Rejected with clear error | | |
| 1.4.6 | After recovery, verify previous messages accessible | Encrypted messages decrypt correctly with restored keys | | |
| 1.4.7 | Verify GhostCode resolves after recovery | `GET /user/shortcode` returns same code | | |

---

## 2. HIGH — Android Device Testing (Capacitor Build)

Test on **3+ real Android devices**. Log every crash with device model, Android version, and stack trace.

### 2.1 Build & Install

| # | Step | Expected Result | Device 1 (Your Phone) | Device 2 (Budget: Redmi/Realme) | Device 3 (Older Android 10+) |
|---|------|----------------|----------------------|-------------------------------|------------------------------|
| 2.1.1 | `npx cap sync android` | Build completes without errors | | | |
| 2.1.2 | Install APK on device | App installs and opens | | | |
| 2.1.3 | Splash screen displays | Dark background (#020428) shown | | | |
| 2.1.4 | App loads to Home/onboarding | No white screen, no crash | | | |

### 2.2 Core Functionality Per Device

| # | Test | Device 1 | Device 2 | Device 3 |
|---|------|----------|----------|----------|
| 2.2.1 | Sign up flow completes | | | |
| 2.2.2 | Identity generated without freeze | | | |
| 2.2.3 | Send message (WebSocket connects) | | | |
| 2.2.4 | Receive message in <3s | | | |
| 2.2.5 | Navigate all tabs (Home, Nodes, Wallet, Chat, Vault, Profile, Shield) | | | |
| 2.2.6 | Ghost Shield toggle works | | | |
| 2.2.7 | App survives background/foreground cycle | | | |
| 2.2.8 | App survives screen rotation | | | |
| 2.2.9 | KeepAwake plugin active (no sleep disconnect) | | | |
| 2.2.10 | Mesh canvas renders without lag | | | |

### 2.3 Crash Log Template

| Device | Model | Android Version | Crash Description | Steps to Reproduce | Stack Trace |
|--------|-------|-----------------|-------------------|--------------------| ------------|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

---

## 3. CRITICAL — Encryption Integrity Verification

### 3.1 Message Encryption (AES-256-GCM)

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 3.1.1 | Device A sends message to Device B | Message sent successfully | | |
| 3.1.2 | Intercept WebSocket frame (use Chrome DevTools > Network > WS) | Raw frame visible | | |
| 3.1.3 | Inspect payload: `body` field must NOT exist | Only `iv` (base64) + `data` (base64) present | | |
| 3.1.4 | Copy ciphertext, attempt to base64-decode `data` | Decoded bytes are random/unintelligible (not plaintext) | | |
| 3.1.5 | On Device B, message decrypts and displays correctly | Plaintext matches what Device A sent | | |
| 3.1.6 | On Device C (not the recipient), attempt to decrypt same payload | Decryption fails — wrong key, no plaintext recovered | | |

### 3.2 HMAC Authentication

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 3.2.1 | Inspect outbound message for `hmac` field | 64-char hex HMAC present | | |
| 3.2.2 | Modify any byte of intercepted payload, replay to recipient | Recipient silently discards (HMAC mismatch) | | |
| 3.2.3 | Forge a DELETE packet with wrong HMAC | DELETE rejected, message NOT removed | | |
| 3.2.4 | Forge a message with spoofed `from` field but wrong HMAC | Message rejected at recipient | | |

### 3.3 Key Derivation

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 3.3.1 | Verify PBKDF2 uses 600,000 iterations (check `crypto-identity.js`) | Code confirms 600K | | |
| 3.3.2 | Verify shared secret uses HKDF (check `kryptos-chat.js`) | `_deriveSharedSecret()` uses HKDF-SHA-256 | | |
| 3.3.3 | Verify nodeId is full SHA-256 (64 hex chars) | `validateNodeId()` enforces `/^[a-f0-9]{64}$/` | | |

### 3.4 Storage Security

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 3.4.1 | After sending messages, inspect localStorage | NO plaintext message bodies stored | | |
| 3.4.2 | Only encrypted blobs (iv + data) in persisted chat data | Confirmed | | |
| 3.4.3 | Private key NOT stored on GhostChat object | `this.myIdentity` has only `pub` + `nodeId` | | |

---

## 4. HIGH — Ghost Shield Tier Switching

Test each tier **actually changes network behavior**, not just UI state.

### 4.1 Level 1: Stealth

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 4.1.1 | Enable Level 1 (Stealth) | UI shows Stealth active | | |
| 4.1.2 | Verify BLE broadcast disabled | `_activateStealth()` calls BLE plugin to stop advertising | | |
| 4.1.3 | Verify WiFi probe suppression active | WiFi scan requests suppressed (native plugin) | | |
| 4.1.4 | Verify DNS-over-HTTPS enabled | DNS queries go to DoH resolver, not system DNS | | |
| 4.1.5 | Check `ghost-shield.js` stats: `packetsProtected` incrementing | Counter increases over time | | |

### 4.2 Level 2: Ghost

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 4.2.1 | Enable Level 2 (Ghost) on top of Level 1 | Both Level 1 + 2 active | | |
| 4.2.2 | Verify traffic padding active | Outbound packets have random padding bytes | | |
| 4.2.3 | Verify timing obfuscation | Message send times have random jitter (not instant) | | |
| 4.2.4 | Verify dummy packet injection | Capture traffic: periodic dummy packets visible alongside real traffic | | |

### 4.3 Level 3: Phantom

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 4.3.1 | Enable Level 3 (Phantom) on top of Level 1 + 2 | All three levels active | | |
| 4.3.2 | Verify fake BLE decoy profiles active | `_decoyProfiles` array populated, decoy BLE advertisements broadcasting | | |
| 4.3.3 | Verify MAC rotation active | `stats.macRotations` counter incrementing | | |
| 4.3.4 | Verify forced max mesh hops | Mesh routing uses max hop count | | |

### 4.4 Full Ghost Protocol (All Tiers)

| # | Step | Expected Result | Pass/Fail | Notes |
|---|------|----------------|-----------|-------|
| 4.4.1 | Enable all 3 tiers simultaneously | All `activeStates` = true | | |
| 4.4.2 | Messages still send and receive correctly | Encryption + padding + timing don't break delivery | | |
| 4.4.3 | Disable tiers one by one (3 > 2 > 1) | Each tier deactivates cleanly, no lingering intervals | | |
| 4.4.4 | After full disable, verify no intervals remain | `_intervals` arrays empty, `active` = false | | |
| 4.4.5 | State persists across app restart | Re-open app, shield restores previous state (`_restoreState()`) | | |

---

## 5. MEDIUM — Backend API Load Test

### 5.1 Auth Endpoints

| # | Endpoint | Method | Rate Limit | Test | Expected | Pass/Fail |
|---|----------|--------|------------|------|----------|-----------|
| 5.1.1 | `/auth/signup` | POST | Strict | 10 rapid requests same email | Rate limited after threshold | |
| 5.1.2 | `/auth/verify` | POST | Strict | 10 rapid wrong codes | Rate limited, no brute force | |
| 5.1.3 | `/auth/node` | POST | nodeAuthLimiter | 20 rapid requests | Rate limited | |
| 5.1.4 | `/auth/login` | POST | Strict | 10 rapid wrong passwords | Rate limited | |

### 5.2 Core API Endpoints (Authenticated)

| # | Endpoint | Method | Test | Expected | Pass/Fail |
|---|----------|--------|------|----------|-----------|
| 5.2.1 | `/register-node` | POST | 50 concurrent registrations | All return 200 or rate limit, no crash | |
| 5.2.2 | `/message` | POST | 100 messages in 10s | Messages queued, server stable, no OOM | |
| 5.2.3 | `/conversations` | GET | 50 concurrent requests | Returns correct data, <500ms avg | |
| 5.2.4 | `/history?convoId=X` | GET | 50 concurrent requests | Paginated results, no full DB dump | |
| 5.2.5 | `/users` | GET | 20 concurrent requests | Returns user list, auth enforced | |
| 5.2.6 | `/status` | GET | 100 rapid requests (no auth) | Always 200, server info returned | |
| 5.2.7 | `/health` | GET | 100 rapid requests | Always 200, uptime correct | |

### 5.3 Vault Endpoints

| # | Endpoint | Method | Test | Expected | Pass/Fail |
|---|----------|--------|------|----------|-----------|
| 5.3.1 | `/vault/upload` | POST | Upload 10 files concurrently (each <5MB) | All succeed, no data corruption | |
| 5.3.2 | `/vault/download/:fileId` | GET | Download same file 20x concurrently | Consistent file returned | |
| 5.3.3 | `/vault/verify/:fileId` | GET | 20 concurrent verify requests | Integrity hash matches | |
| 5.3.4 | `/vault/file/:fileId` | DELETE | Delete with valid + invalid HMAC | Only valid HMAC deletes | |
| 5.3.5 | `/vault/keys` | GET/POST | 20 concurrent requests | Key storage consistent | |

### 5.4 WebSocket Load

| # | Test | Expected | Pass/Fail |
|---|------|----------|-----------|
| 5.4.1 | Connect 50 WS clients simultaneously | All authenticate and receive HELLO | |
| 5.4.2 | Each client sends HEARTBEAT every 30s for 5min | No disconnects, server memory stable | |
| 5.4.3 | Broadcast MSG to all 50 clients | All receive within 2s | |
| 5.4.4 | Disconnect 25 clients abruptly | Server cleans up, remaining 25 unaffected | |
| 5.4.5 | Reconnect with expired JWT | Connection rejected, 401 | |

### 5.5 Security Under Load

| # | Test | Expected | Pass/Fail |
|---|------|----------|-----------|
| 5.5.1 | Send request with body >64KB | Rejected (body size limit) | |
| 5.5.2 | Send request with `__proto__` as nodeId | Rejected by `validateNodeId()` | |
| 5.5.3 | Request `/vault/download/../../.env` | Rejected by `validateFileId()` | |
| 5.5.4 | Request with `Origin` not in allowlist | CORS blocked | |
| 5.5.5 | Access any authenticated endpoint without JWT | 401 Unauthorized | |

### 5.6 Load Test Tools

```bash
# Quick API load test with curl loop
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" \
    -H "Authorization: Bearer $TOKEN" \
    https://kryptos-ji-production.up.railway.app/status &
done
wait

# WebSocket load test (install wscat: npm i -g wscat)
for i in $(seq 1 20); do
  wscat -c "wss://kryptos-ji-production.up.railway.app?token=$TOKEN" \
    -x '{"type":"HELLO","nodeId":"test'$i'"}' &
done
wait

# Recommended: use k6 or artillery for proper load testing
# npm i -g artillery
# artillery quick --count 50 --num 100 https://kryptos-ji-production.up.railway.app/status
```

---

## Test Summary

| Section | Priority | Total Tests | Passed | Failed | Blocked |
|---------|----------|-------------|--------|--------|---------|
| 1. Core Flow (Sign Up > Message > Recovery) | CRITICAL | 28 | | | |
| 2. Android Device Testing | HIGH | 13+ per device | | | |
| 3. Encryption Integrity | CRITICAL | 14 | | | |
| 4. Ghost Shield Tiers | HIGH | 18 | | | |
| 5. Backend API Load | MEDIUM | 24 | | | |
| **TOTAL** | | **97+** | | | |

**Tested by:** _______________
**Date:** _______________
**Build version:** _______________
**Backend commit:** _______________
