# 🧪 GhostNet Manual Test Checklist — Core Flows

This focused checklist covers the **Core End-to-End User Journey**. Execute these steps sequentially to ensure the critical paths are fully operational.

> **Testing Environment**
> - **Platform**: Web / Local Dev
> - **Requirements**: Two browser profiles (or incognito) to simulate two devices (Device A and Device B).

---

## Part 1: Registration & Identity Creation
**Device A**

- [ ] **1. Sign Up**
  - Launch the app.
  - Select "Login / Signup" and enter a valid email address.
  - Submit the verification code received via email.
  - **Expected**: Authentication succeeds, and the identity setup flow begins.

- [ ] **2. Create Identity (BIP39 Seed)**
  - Enter a Display Name.
  - Wait for identity generation (Ed25519 keypair).
  - Verify that a 12- or 24-word BIP39 seed phrase is displayed.
  - **Save this seed phrase securely** (you will need it for Part 4).
  - **Expected**: Keypair is generated, and prompt safely displays the seed.

- [ ] **3. Set PIN**
  - Enter a secure PIN (4-6 digits).
  - Confirm the PIN.
  - **Expected**: Identity encryption completes via PBKDF2. App redirects to the main dashboard. GhostCode logic initializes.

---

## Part 2: Peer-to-Peer Messaging
**Device A & Device B**

- [ ] **4. Setup Device B**
  - In a separate browser/incognito window, repeat steps 1-3 for "Device B".
  - Share GhostCards or manually enter the GhostCode / Node ID to initiate a chat between Device A and Device B.

- [ ] **5. Send Message (Device A)**
  - Open the chat with Device B.
  - Type a text message (e.g., "Eagle has landed") and hit send.
  - **Expected**: Message appears in the local chat feed.

- [ ] **6. Receive Message (Device B)**
  - Observe the chat feed on Device B.
  - **Expected**: Message arrives in real-time (via WebSocket) and decrypts successfully.

---

## Part 3: Active Protections (Ghost Mode)
**Device A**

- [ ] **7. Enable Ghost Mode**
  - Navigate to the "Shield" tab on Device A.
  - Toggle "Ghost Mode" functionality (Stealth / Ghost / Phantom tiers).
  - **Expected**: UI visibly reflects active protection. (If checking via network tab: traffic padding/jitter should become active. Native platforms will suppress BLE). 

---

## Part 4: Session Teardown & Recovery
**Device A**

- [ ] **8. Logout**
  - Open Profile settings.
  - Click "Logout" (or safety wipe).
  - **Expected**: Session tokens (`ghostnet_token`) are cleared. App returns to the welcome/login screen.

- [ ] **9. Recover with Seed Phrase**
  - On the welcome screen, click "Restore Identity" or "Recover with seed phrase".
  - Enter the BIP39 seed phrase saved from Step 2.
  - Select your display name again.
  - **Expected**: Identity is fully restored. The same Node ID / Public Key is regenerated. You regain access to the dashboard and any persistent data tied to this key.
