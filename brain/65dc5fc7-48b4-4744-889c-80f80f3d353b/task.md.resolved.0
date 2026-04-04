# GhostTag Username System — Task Tracker

## Server (`ghostnet-server.js`)
- [ ] Add `ghosttags.json` data file + load/save helpers
- [ ] `POST /ghosttag/claim` — case-insensitive uniqueness, binds to nodeId
- [ ] `GET /ghosttag/check/:tag` — public availability check
- [ ] `GET /ghosttag/resolve/:tag` — resolve tag → nodeId/publicKey
- [ ] Release tag on account/identity deletion (`clearIdentity` path)

## Client (`index.html`)
- [ ] Real-time availability indicator on `#id-ghost-tag` (debounced)
- [ ] `submitName()` — claim server-side before keygen (offline fallback to localStorage)
- [ ] Pending tag sync on app startup (offline-first: sync when server comes back)
- [ ] Chat: resolve `@username` via `/ghosttag/resolve`

## Verification
- [ ] Test: claim a tag → 200
- [ ] Test: claim same tag → 409 + suggestions
- [ ] Test: delete identity → tag released
- [ ] Test: offline registration → local save → sync on reconnect
