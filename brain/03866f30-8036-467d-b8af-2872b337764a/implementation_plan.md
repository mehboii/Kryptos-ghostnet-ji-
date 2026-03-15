# Fix WebSocket Race Condition

The goal is to resolve the `InvalidStateError: Failed to execute 'send' on 'WebSocket': Still in CONNECTING state` error that occurs when a message is sent before the WebSocket connection is fully established.

## Proposed Changes

### ghostnet-mesh.js

- [MODIFY] [ghostnet-mesh.js](file:///c:/Users/novtw/.gemini/antigravity/ghostnet-mesh.js)
  - Add a module-level `messageQueue` array at the top of the file.
  - Add a `safeSend(ws, data)` helper function that checks `ws.readyState` and queues messages if the state is not `OPEN`.
  - Replace all instances of `this.ws.send()` with `safeSend(this.ws, ...)`.
  - In the `onopen` callback, flush the `messageQueue` after setting `this.wsReady = true`.

## Verification Plan

### Manual Verification
- Reproduce the startup flow where the mesh is initialized.
- Observe the console for the absence of `InvalidStateError`.
- Verify that the `register` message and any other early messages are correctly sent once the connection opens.
