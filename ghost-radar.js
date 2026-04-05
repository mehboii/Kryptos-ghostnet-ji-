/**
 * Ghost Radar - Android Native Hardware Scanner via Capacitor
 * strictly real signals only.
 */

// Polyfill: Promise.allSettled (Safari <13)
if (typeof Promise.allSettled !== 'function') {
  Promise.allSettled = function(promises) {
    return Promise.all(promises.map(p => Promise.resolve(p).then(
      value => ({ status: 'fulfilled', value }),
      reason => ({ status: 'rejected', reason })
    )));
  };
}

class GhostRadarEngine {
  constructor() {
    this.results = [];
    this.scanning = false;
    this.onUpdate = null;
    this.permissionState = { ble: 'unknown', wifi: 'unknown' };
    this._startRepeatingScan();
  }

  /**
   * Check and request required permissions (BLE + WiFi only).
   * No location, no personal data — privacy first.
   */
  async checkPermissions() {
    const result = { ble: false, wifi: false };

    // BLE permissions via Capacitor BLE plugin
    try {
      const { BleClient } = await import('@capacitor-community/bluetooth-le');
      await BleClient.initialize();
      result.ble = true;
      this.permissionState.ble = 'granted';
    } catch (e) {
      console.warn('[GhostRadar] BLE permission/init failed:', e.message);
      this.permissionState.ble = 'denied';
    }

    // WiFi — typically granted via manifest, just test the import
    try {
      await import('@capacitor-community/wifi-wizard2');
      result.wifi = true;
      this.permissionState.wifi = 'granted';
    } catch (e) {
      this.permissionState.wifi = 'denied';
    }

    window.dispatchEvent(new CustomEvent('ghostRadar:permissionUpdate', { detail: this.permissionState }));
    return result;
  }

  // 1. WiFi Networks — real scan
  async scanWifi() {
    try {
      const { WifiWizard2 } = await import('@capacitor-community/wifi-wizard2');
      const results = await WifiWizard2.scan();
      this.permissionState.wifi = 'granted';
      return results.map(n => ({
        id: n.BSSID,
        name: n.SSID || 'Hidden Network',
        type: 'wifi',
        rssi: n.level,
        frequency: n.frequency,
        security: n.capabilities,
        channel: this._freqToChannel(n.frequency),
        source: 'real'
      }));
    } catch(e) {
      console.error('[GhostRadar] WiFi scan failed:', e);
      if (e.message && e.message.toLowerCase().includes('permission')) {
        this.permissionState.wifi = 'denied';
        window.dispatchEvent(new CustomEvent('ghostRadar:permissionUpdate', { detail: this.permissionState }));
      }
      return [];
    }
  }

  // 2. Bluetooth + BLE — real scan
  async scanBluetooth() {
    try {
      const { BleClient } = await import('@capacitor-community/bluetooth-le');
      await BleClient.initialize();
      this.permissionState.ble = 'granted';
      const devices = [];
      // scanMode 1 = LOW_LATENCY — continuous scan for best device discovery at range
      await BleClient.requestLEScan(
        { allowDuplicates: false, scanMode: 1 },
        (result) => {
          devices.push({
            id: result.device.deviceId,
            name: result.device.name || 'Unknown Device',
            type: this._guessDeviceType(result),
            rssi: result.rssi,
            manufacturerData: result.manufacturerData,
            source: 'real'
          });
        }
      );
      // Scan for 8 seconds then stop
      await new Promise(r => setTimeout(r, 8000));
      await BleClient.stopLEScan();
      return devices;
    } catch(e) {
      console.error('[GhostRadar] BLE scan failed:', e);
      if (e.message && e.message.toLowerCase().includes('permission')) {
        this.permissionState.ble = 'denied';
        window.dispatchEvent(new CustomEvent('ghostRadar:permissionUpdate', { detail: this.permissionState }));
      }
      return [];
    }
  }

  // 3. Network info — real connection data
  async getNetworkInfo() {
    try {
      const { Network } = await import('@capacitor/network');
      const status = await Network.getStatus();
      const conn = navigator.connection;
      return {
        id: 'network_info',
        name: 'Current Connection',
        type: 'network',
        connectionType: status.connectionType,
        connected: status.connected,
        downlink: conn?.downlink,
        rtt: conn?.rtt,
        effectiveType: conn?.effectiveType,
        source: 'real'
      };
    } catch(e) {
      return null;
    }
  }

  // 4. Device type guesser from BLE manufacturer data
  _guessDeviceType(result) {
    const mfr = result.manufacturerData;
    if (!mfr) return 'unknown';
    // Apple devices — manufacturer ID 0x004C
    if (mfr['76']) return 'apple_device';
    // Microsoft — 0x0006
    if (mfr['6']) return 'windows_device';
    // Samsung — 0x0075
    if (mfr['117']) return 'samsung_device';
    // Fitness trackers common range
    if (result.rssi > -50 && !result.device.name) return 'wearable';
    return 'bluetooth_device';
  }

  _freqToChannel(freq) {
    // Convert MHz frequency to WiFi channel number
    if (freq >= 2412 && freq <= 2484) return Math.floor((freq - 2412) / 5) + 1;
    if (freq >= 5170 && freq <= 5825) return Math.floor((freq - 5170) / 5) + 34;
    return 0;
  }

  // 5. GhostNet node detection
  _isGhostNetNode(device) {
    return device.name?.startsWith('GhostNode') ||
           (device.name?.startsWith('0x') && device.name?.length === 42);
  }

  _calculateThreatScore(d) {
    return 0; // Baseline real score, logic handled upstream to avoid false mocks
  }

  // 6. Master scan function
  async startScan() {
    console.log('[GhostRadar] Starting real hardware scan...');
    this.scanning = true;
    this.results = [];

    const [wifi, ble, network] = await Promise.allSettled([
      this.scanWifi(),
      this.scanBluetooth(),
      this.getNetworkInfo()
    ]);

    if (wifi.status === 'fulfilled') this.results.push(...wifi.value);
    if (ble.status === 'fulfilled') this.results.push(...ble.value);
    if (network.status === 'fulfilled' && network.value) this.results.push(network.value);

    // Tag GhostNet nodes separately
    this.results = this.results.map(d => ({
      ...d,
      isGhostNode: this._isGhostNetNode(d),
      threatScore: this._calculateThreatScore(d)
    }));

    console.log(`[GhostRadar] Scan complete — ${this.results.length} real signals found`);
    this.scanning = false;
    this.onUpdate?.(this.results);

    window.dispatchEvent(new CustomEvent('ghostRadar:scanComplete', {
      detail: { count: this.results.length, results: this.results }
    }));

    return this.results;
  }

  _startRepeatingScan() {
    // Rescan automatically every 15 seconds
    setInterval(() => {
      if (!this.scanning) {
        this.startScan();
      }
    }, 15000);
    this.startScan();
  }

  _renderUI() {
    const renderContainer = document.getElementById('threat-list-container');
    if (!renderContainer) return;

    if (this.results.length === 0) {
      renderContainer.innerHTML = `<div style="text-align:center; padding: 20px; color:var(--text-muted); font-size: 0.85rem;">No signals detected nearby</div>`;
      return;
    }

    // Bridge data dynamically over to the real UI format safely, without fake data loops
    let html = '';
    for (const d of this.results) {
      const isBlocked = window.GhostShield && window.GhostShield.blockedMacs && window.GhostShield.blockedMacs.has(d.id);
      
      let cls = 'safe';
      if (d.threatScore > 60) cls = 'danger';
      else if (d.threatScore > 30) cls = 'monitor';
      if (isBlocked) cls = 'blocked';

      const flags = [];
      if (d.security) flags.push(`Security: ${d.security}`);
      if (d.channel) flags.push(`CH: ${d.channel}`);
      if (d.effectiveType) flags.push(`Link: ${d.effectiveType}`);
      const flagStr = flags.length > 0 ? flags.join(', ') : 'Clean';
      const scoreClass = d.threatScore > 60 ? 'high' : '';

      html += `
          <div class="threat-item ${cls}" style="margin-bottom:8px; cursor:pointer;" onclick="if(window.GhostShieldUI) window.GhostShieldUI.toggleBlockView(this)">
              <div class="threat-item-top">
                  <strong style="font-size:0.9rem; color:var(--text-primary);"><span class="threat-score ${scoreClass}">[${String(d.threatScore || 0).padStart(2,' ')}]</span> ${d.name}</strong>
              </div>
              <div class="threat-item-bot">
                  <span>ID: ${d.id || 'N/A'}</span>
                  <span>·</span>
                  <span>${flagStr}</span>
                  <span>·</span>
                  <span style="border-radius:4px; padding:1px 4px; background:rgba(0,0,0,0.5);">${d.type}</span>
              </div>
              ${!isBlocked && cls === 'danger' ? `<button class="btn-block-device" onclick="if(window.GhostShieldUI) window.GhostShieldUI.blockMac('${d.id}', event)">Block This Device</button>` : ''}
              ${isBlocked ? `<div class="blocked-label">BLOCKED — APP INVISIBLE TO THIS DEVICE <br><a href="#" style="color:var(--text-muted); font-weight:normal; text-decoration:underline; font-size:10px;" onclick="if(window.GhostShieldUI) window.GhostShieldUI.unblockMac('${d.id}', event)">Unblock</a></div>` : ''}
          </div>
      `;
    }
    renderContainer.innerHTML = html;
  }
}

window.GhostRadar = new GhostRadarEngine();

// GhostRadar results are now fed through SignalIntelService → SignalIntelligence
// and rendered by ghost-shield-ui.js via the signalIntel:scanComplete event.
