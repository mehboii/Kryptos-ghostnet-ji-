# Task Checklist

- [x] Add `messageQueue` and `safeSend` helper to `kryptos-mesh.js`
- [x] Replace `ws.send` calls with `safeSend` in `kryptos-mesh.js`
- [x] Implement queue flushing in `onopen` handler
- [x] Verify fix by checking logs and ensuring no `InvalidStateError` occurs
