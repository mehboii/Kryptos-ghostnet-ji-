# GhostTag Username System — Implementation Plan

## Background

GhostTag is the human-readable username system for GhostNet identities. Currently, the frontend **already has** a GhostTag input field during registration and displays it on the identity dashboard, but:

1. **No server-side uniqueness enforcement** — the tag is only saved locally in `localStorage`. Two users can claim the same tag.
2. **No case normalization** — `@Alice` and `@alice` are treated as different tags.
3. **No reservation/claim API** — the server has no `/ghosttag` endpoint or database table.
4. **No lookup by tag** — you can't find a user by their `@username`, only by nodeId.
5. **No sharing mechanism** — the invite link (`ghostnet.n11x.dev/invite/@username`) exists in the UI but has no backend resolution.

## Proposed Changes

### Server — `ghostnet-server.js`

#### [MODIFY] [ghostnet-server.js](file:///c:/Users/novtw/.gemini/antigravity/ghostnet-server.js)

Add a `ghosttags.json` data file and three new endpoints:

1. **`POST /ghosttag/claim`** (requireAuth)
   - Body: `{ tag: "username", nodeId: "0x...", publicKey: "0x..." }`
   - Normalizes to lowercase, validates `^[a-z0-9_]{3,20}$`
   - Checks `ghosttags.json` for duplicates (case-insensitive)
   - Returns `409` with suggestions if taken, `200 { success, tag }` if claimed
   - Binds the tag to the authenticated user's nodeId + publicKey

2. **`GET /ghosttag/check/:tag`** (public, rate-limited)
   - Returns `{ available: true/false }` — used for real-time availability checks in the UI
   - Case-insensitive lookup

3. **`GET /ghosttag/resolve/:tag`** (requireAuth)
   - Resolves `@username` → `{ nodeId, publicKey, displayName }` 
   - Used by chat to look up a user by their GhostTag instead of raw nodeId

Data structure in `ghosttags.json`:
```json
{
  "alice": { "nodeId": "0x...", "publicKey": "0x...", "ownerId": "...", "claimedAt": 1234567890 }
}
```

> [!IMPORTANT]
> GhostTags are **immutable** once claimed — to prevent impersonation attacks where an attacker claims a vacated tag. A user cannot change or release their tag.

---

### Client — `index.html`

#### [MODIFY] [index.html](file:///c:/Users/novtw/.gemini/antigravity/index.html)

1. **Registration flow (`submitName`)**: Before proceeding to key generation, call `POST /ghosttag/claim` to reserve the tag server-side. If `409` (taken), show error with suggestions inline — do NOT proceed to key gen.

2. **Real-time availability check**: Add a debounced `input` event listener on `#id-ghost-tag` that calls `GET /ghosttag/check/:tag` and shows a ✓ or ✗ indicator next to the field as the user types.

3. **Dashboard display**: After login, verify the tag is still bound server-side (graceful — if server is unreachable, show local value). No functional change needed; the `@tag` display already works.

4. **Invite link sharing**: Add a "Share" button that copies `ghostnet.n11x.dev/invite/@tag` or uses the Web Share API on mobile.

5. **Chat: Start by GhostTag**: In `openNewChat()`, allow typing `@username` in the contact field. Resolve via `GET /ghosttag/resolve/:tag` to get the nodeId for encryption.

---

### Identity — `crypto-identity.js`

#### [MODIFY] [crypto-identity.js](file:///c:/Users/novtw/.gemini/antigravity/crypto-identity.js)

No changes needed — it already stores and retrieves `ghostTag` in the identity object. The existing plumbing is sufficient.

---

## Open Questions

> [!IMPORTANT]
> **Tag immutability**: Should GhostTags be permanently locked once claimed, or should users be able to change them (with a cooldown)? Current plan: **permanent** (safest against impersonation).

> [!IMPORTANT]  
> **Offline-first behavior**: If the server is unreachable during registration, should we:
> - (A) Block registration until the tag can be verified server-side, or
> - (B) Allow local-only registration and attempt to claim the tag later?
> Current plan: **(A)** — block, because allowing (B) means two offline users could pick the same tag.

## Verification Plan

### Automated Tests
- Run the server locally and hit the three new endpoints via `curl` / `fetch`:
  - Claim a tag → 200
  - Claim same tag again → 409 with suggestions
  - Check availability → `{ available: false }`
  - Resolve tag → returns nodeId + publicKey

### Manual Verification
- Register a new identity in the app and verify:
  - The GhostTag field shows real-time availability (✓/✗)
  - A taken tag shows error + suggestions
  - The dashboard displays the claimed tag
  - The invite link is copyable/shareable
  - Starting a chat with `@username` resolves to the correct contact
