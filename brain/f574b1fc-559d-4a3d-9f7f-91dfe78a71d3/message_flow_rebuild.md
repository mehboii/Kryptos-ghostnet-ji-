# Kryptos Message Flow — Complete Rebuild

## Root Cause
The `sendMessage` function in `app.js` only sent messages via GhostChat WebSocket encryption and **never called the HTTP POST `/message` endpoint**. This meant:
- Messages were never stored in the database
- Offline recipients never received messages
- Conversations were never created/updated
- The WS handler returned "Recipient offline" errors, further blocking delivery

## All Changes Made

### 1. `kryptos-server.js` (4 fixes)

**Fix 1.1 — `/validate-node` endpoint**
- Separated online/offline check from existence check
- `valid: true` if node exists in registry (even if offline)
- `valid: false` only if node ID doesn't exist at all
- Returns `online: true/false` as info, not as a blocker

**Fix 1.2 — `POST /message` endpoint**
- Changed error from "Node not found or offline" → "Node not found" 
- Only rejects if node ID is completely unregistered
- Auto-registers sender in node registry if not present
- Added `delivered: false` field to messages for tracking
- Marks `delivered: true` after successful WS delivery

**Fix 1.3 — WebSocket `'message'` handler**
- Removed the "Recipient offline" error response to sender
- Still stores message to DB when recipient is offline
- Added `delivered` status tracking for offline queue

**Fix 1.4 — Pending message delivery on connect**
- New `deliverPendingMessages()` function
- When a user registers via WebSocket, checks DB for undelivered messages
- Delivers all pending messages instantly via `CHAT_MESSAGE` WS events
- Also sends `NEW_CONVERSATION` notifications
- Marks messages as `delivered: true` after sending
- Auto-registers connecting nodes in registry

### 2. `app.js` (2 fixes)

**Fix 2.1 — `sendMessage` function (THE CRITICAL FIX)**
- Old: Sent via GhostChat encryption → WS only, never called HTTP persist
- New: Always calls `persistMessage()` (HTTP POST `/message`) as primary path
- Server handles everything: DB storage, WS real-time delivery, offline queuing
- Falls back to WS-only if HTTP fails (server down)

**Fix 2.2 — `persistMessage` function**  
- Changed `content` from wrapped object `{body, from, to, ts, type}` → plain string
- Messages now stored as clean readable text in DB
- Uses `nodeId` instead of generic `id` for sender identification
- Uses display name for contactName instead of raw target ID
- Shows specific error message in chat for 404 errors

### 3. `ui.js` (2 fixes)

**Fix 3.1 — `submitNewChat` validation**
- Error message: "Node not found or offline" → "Node not found"
- Chat now allowed with offline nodes (only blocked if fake/unregistered)

**Fix 3.2 — `setupChat` fallback**  
- Uses `nodeId` for identification instead of generic `id`
- Sends plain text as content instead of wrapped object

## Message Flow (After Fix)

```
User types message → clicks SEND
    ↓
app.js sendMessage() runs
    ↓
persistMessage() → HTTP POST /message to backend
    ↓
Server receives, validates recipient exists in registry
    ↓
Creates/updates conversation + saves message to DB
    ↓
├── Recipient ONLINE → Server forwards via WS (CHAT_MESSAGE)
│   → Recipient sees it instantly in real-time
│   → Message marked delivered=true
│
└── Recipient OFFLINE → Message saved with delivered=false
    → When recipient connects → deliverPendingMessages()
    → All pending messages delivered instantly
```

## Files Modified
- [kryptos-server.js](file:///c:/Users/novtw/.gemini/antigravity/scratch/kryptos-server.js) — Server-side message handling
- [app.js](file:///c:/Users/novtw/.gemini/antigravity/scratch/app.js) — Frontend send flow
- [ui.js](file:///c:/Users/novtw/.gemini/antigravity/scratch/ui.js) — UI validation
