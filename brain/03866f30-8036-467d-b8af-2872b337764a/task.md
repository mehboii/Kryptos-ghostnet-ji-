# Task Checklist

- [x] Add `messageQueue` and `safeSend` helper to `ghostnet-mesh.js`
- [x] Replace `ws.send` calls with `safeSend` in `ghostnet-mesh.js`
- [x] Implement queue flushing in `onopen` handler
- [x] Verify fix by checking logs and ensuring no `InvalidStateError` occurs
