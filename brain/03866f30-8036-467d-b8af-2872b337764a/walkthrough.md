# Walkthrough - WebSocket Race Condition Fix

I have implemented a fix for the `InvalidStateError` that occurred when attempting to send data over a WebSocket before it was in the `OPEN` state.

## Changes Made

### ghostnet-mesh.js

I introduced a module-level `messageQueue` and a `safeSend` utility function to buffer messages until the connection is ready.

```javascript
let messageQueue = [];

function safeSend(ws, data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(data);
    } else {
        messageQueue.push(data);
    }
}
```

- All `ws.send()` calls were replaced with `safeSend(this.ws, ...)`.
- The `onopen` handler now flushes any queued messages:

```javascript
this.ws.onopen = () => {
    // ...
    this.wsReady = true;

    // Flush queue
    messageQueue.forEach(msg => {
        if (this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(msg);
        }
    });
    messageQueue = [];
    // ...
};
```

## Verification Results

- Errors like `InvalidStateError: Failed to execute 'send' on 'WebSocket'` are now prevented.
- Initial registration and early broadcast/direct messages are queued and delivered as soon as the connection is established.
