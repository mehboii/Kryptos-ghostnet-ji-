/**
 * The `window.KryptosBLE` shim injected into the WebView BEFORE the web bundle
 * loads, so proximity-connect.js can feature-detect it (`window.KryptosBLE`)
 * and use the native radio instead of the dead Capacitor/Web-Bluetooth paths.
 *
 * It is a thin promise-based RPC client:
 *   - `_call(cmd, args)` posts a message to native and returns a Promise keyed
 *     by a request id; native resolves it via `_ack`.
 *   - `on(event, cb)` registers an event listener; native pushes via `_event`.
 *
 * Raw GATT payloads are base64 (matching ble-plx). The web layer converts to
 * its hex/JSON handshake frames.
 *
 * Must be a self-contained, ES5-safe IIFE string (it runs inside the WebView's
 * own JS engine, not RN). End with `true;` so injectedJavaScript* is happy.
 */
export const BLE_BRIDGE_SHIM = `(function(){
  if (window.KryptosBLE && window.KryptosBLE.__ready) return;
  var _seq = 1, _pending = {}, _listeners = {};
  function post(msg){
    try { window.ReactNativeWebView && window.ReactNativeWebView.postMessage(JSON.stringify(msg)); }
    catch (e) {}
  }
  function call(cmd, args){
    var id = _seq++;
    return new Promise(function(resolve, reject){
      _pending[id] = { resolve: resolve, reject: reject };
      post({ ns: 'ble', id: id, cmd: cmd, args: args || {} });
    });
  }
  window.KryptosBLE = {
    __ready: true,
    available: true,
    // Set by App.js right after this shim: 'native' (dev client / EAS build) or
    // 'expoGo' (native BLE modules absent). Stays null if the host never sets it.
    env: null,
    on: function(evt, cb){ (_listeners[evt] = _listeners[evt] || []).push(cb); },
    off: function(evt, cb){
      var a = _listeners[evt]; if (!a) return;
      _listeners[evt] = a.filter(function(f){ return f !== cb; });
    },
    _ack: function(id, ok, payload){
      var p = _pending[id]; if (!p) return; delete _pending[id];
      if (ok) p.resolve(payload);
      else p.reject(new Error((payload && payload.message) || 'BLE bridge error'));
    },
    _event: function(evt, data){
      (_listeners[evt] || []).forEach(function(cb){ try { cb(data); } catch (e) {} });
    },
    isSupported: function(){ return call('isSupported'); },
    requestPermissions: function(){ return call('requestPermissions'); },
    requestWifiPermissions: function(){ return call('requestWifiPermissions'); },
    adapterState: function(){ return call('adapterState'); },
    isPeripheralSupported: function(){ return call('isPeripheralSupported'); },
    startAdvertising: function(a){ return call('startAdvertising', a); },
    updatePseudonym: function(hex){ return call('updatePseudonym', { pseudonymHex: hex }); },
    stopAdvertising: function(){ return call('stopAdvertising'); },
    startScan: function(){ return call('startScan'); },
    stopScan: function(){ return call('stopScan'); },
    startRadarScan: function(){ return call('startRadarScan'); },
    stopRadarScan: function(){ return call('stopRadarScan'); },
    scanWifi: function(){ return call('scanWifi'); },
    connect: function(deviceId){ return call('connect', { deviceId: deviceId }); },
    disconnect: function(deviceId){ return call('disconnect', { deviceId: deviceId }); },
    read: function(deviceId, charUuid){ return call('read', { deviceId: deviceId, charUuid: charUuid }); },
    write: function(deviceId, charUuid, base64){ return call('write', { deviceId: deviceId, charUuid: charUuid, base64: base64 }); },
    startNotifications: function(deviceId, charUuid){ return call('startNotifications', { deviceId: deviceId, charUuid: charUuid }); },
    notifyData: function(base64){ return call('notifyData', { base64: base64 }); }
  };
})(); true;`;
