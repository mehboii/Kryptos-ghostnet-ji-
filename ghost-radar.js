/**
 * Ghost Radar
 * Real-world signal detection engine.
 * No mock data allowed.
 */

class GhostRadarEngine {
  constructor() {
    this.signals = [];
  }

  // 1. Real Network Info (works on web + Android)
  async getRealNetworkInfo() {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!conn) return null;
    return {
      type: conn.type,           // wifi, cellular, ethernet
      effectiveType: conn.effectiveType,  // 4g, 3g, 2g
      downlink: conn.downlink,   // Mbps
      rtt: conn.rtt,             // latency ms
      saveData: conn.saveData,
      source: 'real'
    };
  }

  // 2. Real IP + Location Info (works on web)
  async getRealIPInfo() {
    try {
      const res = await fetch('https://ipapi.co/json/');
      const data = await res.json();
      return {
        ip: data.ip,
        isp: data.org,
        city: data.city,
        country: data.country_name,
        isVPN: data.threat?.is_vpn || false,
        isProxy: data.threat?.is_proxy || false,
        isTor: data.threat?.is_tor || false,
        source: 'real'
      };
    } catch (e) {
      return null;
    }
  }

  // 3. Real local network scan via WebRTC (works on web)
  async getLocalNetworkDevices() {
    const pc = new RTCPeerConnection({iceServers: []});
    pc.createDataChannel('');
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    return new Promise(resolve => {
      const ips = new Set();
      pc.onicecandidate = e => {
        if (!e.candidate) {
          resolve([...ips].map(ip => ({ip, source: 'real', type: 'local_device'})));
          return;
        }
        const match = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
        if (match) ips.add(match[1]);
      };
      setTimeout(() => resolve([...ips].map(ip => ({ip, source: 'real', type: 'local_device'}))), 3000);
    });
  }

  // 4. Real BLE scan (web, requires user gesture)
  async startRealBLEScan() {
    if (!navigator.bluetooth) return [];
    try {
      const device = await navigator.bluetooth.requestDevice({
        acceptAllDevices: true,
        optionalServices: []
      });
      return [{
        name: device.name || 'Unknown BLE Device',
        id: device.id,
        source: 'real',
        type: 'bluetooth'
      }];
    } catch(e) {
      return [];
    }
  }

  // 5. For Android APK via Capacitor — real WiFi scan
  async getRealWifiNetworks() {
    if (!window.Capacitor) return [];
    try {
      const { WifiWizard2 } = await import('wifiwizard2');
      const networks = await WifiWizard2.scan();
      return networks.map(n => ({
        ssid: n.SSID,
        bssid: n.BSSID,
        rssi: n.level,
        frequency: n.frequency,
        security: n.capabilities,
        source: 'real',
        type: 'wifi'
      }));
    } catch(e) {
      return [];
    }
  }

  // Empty state handler
  getEmptyStateUI() {
    return `<div style="text-align:center; padding: 20px; color:var(--text-muted); font-size: 0.85rem;">
      No signals detected. Enable Bluetooth or install Android APK for full scanning.
    </div>`;
  }
}

window.GhostRadar = new GhostRadarEngine();

// Force the UI to show the real empty state without modifying ghost-shield-ui.js
document.addEventListener('DOMContentLoaded', () => {
    // We delay slightly to ensure GhostShieldUI is attached
    setTimeout(() => {
        if (window.GhostShieldUI) {
            window.GhostShieldUI.renderThreats = function() {
                const container = document.getElementById('threat-list-container');
                if(!container) return;
                
                if (!window.SignalIntelligence) return;
                const signals = window.SignalIntelligence.getSignalReport();
                
                if (signals.length === 0) {
                    container.innerHTML = `<div style="text-align:center; padding: 20px; color:var(--text-muted); font-size: 0.85rem;">No signals detected. Enable Bluetooth or install Android APK for full scanning.</div>`;
                    return;
                }
                
                let html = '';
                for (const sig of signals) {
                    const isBlocked = window.GhostShield.blockedMacs.has(sig.mac);
                    let cls = 'safe';
                    if (sig.threatLevel === 'THREAT') cls = 'danger';
                    else if (sig.threatLevel === 'MONITOR') cls = 'monitor';
                    
                    if (isBlocked) cls = 'blocked';

                    const flags = (sig.interferenceFlags || []).join(', ') || 'Normal behavior';
                    const scoreClass = sig.threatScore > 60 ? 'high' : '';

                    html += `
                        <div class="threat-item ${cls}" onclick="GhostShieldUI.toggleBlockView(this)">
                            <div class="threat-item-top">
                                <strong style="font-size:0.9rem; color:var(--text-primary);"><span class="threat-score ${scoreClass}">[${String(sig.threatScore).padStart(2,' ')}]</span> ${sig.type || sig.name || 'Unknown Device'}</strong>
                            </div>
                            <div class="threat-item-bot">
                                <span>MAC: ${sig.isRandomizedMac ? 'Randomized' : sig.mac}</span>
                                <span>·</span>
                                <span>${flags}</span>
                            </div>
                            ${!isBlocked && sig.threatLevel === 'THREAT' ? `<button class="btn-block-device" onclick="GhostShieldUI.blockMac('${sig.mac}', event)">Block This Device</button>` : ''}
                            ${isBlocked ? `<div class="blocked-label"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:4px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>BLOCKED — APP INVISIBLE TO THIS DEVICE <br><a href="#" style="color:var(--text-muted); font-weight:normal; text-decoration:underline; font-size:10px;" onclick="GhostShieldUI.unblockMac('${sig.mac}', event)">Unblock</a></div>` : ''}
                        </div>
                    `;
                }
                container.innerHTML = html;
            }
        }
    }, 100);
});
