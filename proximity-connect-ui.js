/**
 * Proximity Connect UI
 * BLE discovery screen — scan, pair, verify, connect.
 */

document.addEventListener('DOMContentLoaded', () => {
    const mainContent = document.getElementById('main-content');
    if (!mainContent) return;

    // ── Styles ──────────────────────────────────────────────────
    const style = document.createElement('style');
    style.textContent = `
        .prox-container { padding: 24px; max-width: 800px; margin: 0 auto; }

        /* State card */
        .prox-state-card {
            text-align: center; padding: 40px 20px; margin-bottom: 24px;
            border-radius: 16px; border: 1px solid var(--border);
            background: linear-gradient(180deg, rgba(20,20,30,0.8) 0%, rgba(10,10,15,0.9) 100%);
            position: relative; overflow: hidden;
        }
        .prox-state-icon { margin-bottom: 16px; }
        .prox-state-title {
            font-size: 1.3rem; font-weight: 800; letter-spacing: 1px;
            font-family: 'Space Grotesk', sans-serif; margin-bottom: 8px;
        }
        .prox-state-desc { font-size: 0.85rem; color: var(--text-muted); max-width: 400px; margin: 0 auto; }

        /* Pulse animation for scanning */
        .prox-pulse-ring {
            position: absolute; top: 50%; left: 50%;
            width: 120px; height: 120px; border-radius: 50%;
            transform: translate(-50%, -50%);
            border: 2px solid rgba(139,92,246,0.3);
            animation: proxPulse 2s ease-out infinite;
            pointer-events: none;
        }
        .prox-pulse-ring:nth-child(2) { animation-delay: 0.6s; }
        .prox-pulse-ring:nth-child(3) { animation-delay: 1.2s; }
        @keyframes proxPulse {
            0% { width: 80px; height: 80px; opacity: 1; }
            100% { width: 260px; height: 260px; opacity: 0; }
        }
        .prox-state-card:not(.scanning) .prox-pulse-ring { display: none; }

        /* Action buttons */
        .prox-actions { display: flex; gap: 12px; justify-content: center; margin-top: 20px; flex-wrap: wrap; }
        .prox-btn {
            padding: 12px 24px; border-radius: 12px; font-weight: 700;
            cursor: pointer; transition: all 0.2s; font-size: 0.85rem;
            letter-spacing: 0.5px; border: 1px solid var(--border);
            background: rgba(139,92,246,0.1); color: #a78bfa;
        }
        .prox-btn:hover { background: rgba(139,92,246,0.2); }
        .prox-btn.primary { background: #8b5cf6; color: #fff; border-color: #8b5cf6; }
        .prox-btn.primary:hover { background: #7c3aed; }
        .prox-btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .prox-btn.danger { background: rgba(239,68,68,0.1); color: #ef4444; border-color: rgba(239,68,68,0.3); }

        /* Device list */
        .prox-device-list {
            display: flex; flex-direction: column; gap: 10px;
            margin-bottom: 24px;
        }
        .prox-device-item {
            background: rgba(0,0,0,0.2); border-radius: 10px; padding: 14px 16px;
            display: flex; justify-content: space-between; align-items: center;
            border: 1px solid var(--border); cursor: pointer; transition: all 0.2s;
        }
        .prox-device-item:hover { background: rgba(139,92,246,0.08); border-color: rgba(139,92,246,0.3); }
        .prox-device-left { display: flex; align-items: center; gap: 12px; }
        .prox-device-icon {
            width: 40px; height: 40px; border-radius: 50%;
            background: rgba(139,92,246,0.15); display: flex;
            align-items: center; justify-content: center; color: #a78bfa;
        }
        .prox-device-name { font-weight: 600; font-size: 0.9rem; color: var(--text-primary); }
        .prox-device-id { font-size: 0.7rem; color: var(--text-muted); font-family: monospace; margin-top: 2px; }
        .prox-device-rssi {
            font-family: monospace; font-size: 0.75rem; color: var(--text-muted);
            background: rgba(255,255,255,0.06); padding: 3px 8px; border-radius: 6px;
        }

        /* Verification code */
        .prox-verify-box {
            background: rgba(0,0,0,0.3); border: 2px dashed rgba(139,92,246,0.4);
            border-radius: 16px; padding: 30px; text-align: center; margin-bottom: 24px;
        }
        .prox-verify-label { font-size: 0.8rem; color: var(--text-muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
        .prox-verify-code {
            font-size: 2.5rem; font-family: 'Space Grotesk', monospace;
            font-weight: 900; letter-spacing: 12px; color: #a78bfa;
            text-shadow: 0 0 20px rgba(139,92,246,0.5);
        }
        .prox-verify-hint { font-size: 0.75rem; color: var(--text-muted); margin-top: 12px; }

        /* Connected card */
        .prox-connected-card {
            background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.3);
            border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 24px;
        }
        .prox-connected-card .peer-name { font-size: 1.1rem; font-weight: 700; color: #10b981; margin-bottom: 4px; }
        .prox-connected-card .peer-status { font-size: 0.8rem; color: var(--text-muted); }

        /* Log */
        .prox-log {
            background: rgba(0,0,0,0.3); border-radius: 8px; padding: 12px;
            font-family: monospace; font-size: 0.7rem; color: var(--text-muted);
            max-height: 150px; overflow-y: auto; line-height: 1.6;
        }
        .prox-log .log-line { opacity: 0.7; }
        .prox-log .log-line.success { color: #10b981; opacity: 1; }
        .prox-log .log-line.error { color: #ef4444; opacity: 1; }

        @media (max-width: 600px) {
            .prox-verify-code { font-size: 1.8rem; letter-spacing: 8px; }
        }
    `;
    document.head.appendChild(style);

    // ── HTML ────────────────────────────────────────────────────
    const section = document.createElement('section');
    section.id = 'view-proximity';
    section.className = 'view-section';
    section.innerHTML = `
        <div class="home-hero" style="margin-bottom: 24px; padding: 0 24px; margin-top:20px;">
            <div class="home-hero-left">
                <h1 class="home-title">Proximity Connect</h1>
                <p class="home-subtitle">Offline BLE discovery and pairing</p>
            </div>
            <div class="home-hero-right">
                <span class="home-badge" style="border-color:#8b5cf6; color:#8b5cf6;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M6.5 6.5l11 11"/><path d="m21 21-4.35-4.35"/><path d="M15 7h4v4"/>
                        <path d="m3 3 4.35 4.35"/><path d="M9 17H5v-4"/>
                    </svg>
                    NO INTERNET
                </span>
            </div>
        </div>

        <div class="prox-container">
            <!-- State Card -->
            <div class="prox-state-card" id="prox-state-card">
                <div class="prox-pulse-ring"></div>
                <div class="prox-pulse-ring"></div>
                <div class="prox-pulse-ring"></div>
                <div class="prox-state-icon" id="prox-state-icon">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="1.5" stroke-linecap="round">
                        <path d="M5 12.55a11 11 0 0 1 14.08 0"/>
                        <path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
                        <circle cx="12" cy="20" r="1"/>
                    </svg>
                </div>
                <h2 class="prox-state-title" id="prox-state-title" style="color:var(--text-muted);">Ready to Connect</h2>
                <p class="prox-state-desc" id="prox-state-desc">Scan for nearby GhostNet devices over Bluetooth. No internet required.</p>
                <div class="prox-actions" id="prox-actions">
                    <button class="prox-btn primary" id="prox-btn-scan" onclick="ProximityUI.startScan()">Scan Nearby</button>
                </div>
            </div>

            <!-- Device List (hidden by default) -->
            <div id="prox-device-section" style="display:none;">
                <h3 style="margin:0 0 12px; font-size:0.95rem;">Nearby Devices</h3>
                <div class="prox-device-list" id="prox-device-list"></div>
            </div>

            <!-- Verification Box (hidden by default) -->
            <div id="prox-verify-section" style="display:none;">
                <div class="prox-verify-box">
                    <div class="prox-verify-label">Verification Code</div>
                    <div class="prox-verify-code" id="prox-verify-code">------</div>
                    <div class="prox-verify-hint">Both devices should show the same code. If they don't, cancel immediately.</div>
                </div>
                <div class="prox-actions">
                    <button class="prox-btn primary" id="prox-btn-confirm" onclick="ProximityUI.confirmPairing()">Codes Match</button>
                    <button class="prox-btn danger" onclick="ProximityUI.cancelPairing()">Cancel</button>
                </div>
            </div>

            <!-- Connected Card (hidden by default) -->
            <div id="prox-connected-section" style="display:none;">
                <div class="prox-connected-card">
                    <div style="margin-bottom:8px;">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2" stroke-linecap="round">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                    </div>
                    <div class="peer-name" id="prox-peer-name">Connected</div>
                    <div class="peer-status">Encrypted BLE session active — forward secrecy enabled</div>
                </div>
                <div class="prox-actions">
                    <button class="prox-btn primary" onclick="ProximityUI.addAsContact()">Add as Contact</button>
                    <button class="prox-btn danger" onclick="ProximityUI.disconnect()">Disconnect</button>
                </div>
            </div>

            <!-- Log -->
            <div class="prox-log" id="prox-log"></div>
        </div>
    `;
    mainContent.appendChild(section);

    // ── UI Logic ────────────────────────────────────────────────
    const esc = (str) => { const d = document.createElement('div'); d.textContent = String(str); return d.innerHTML; };

    window.ProximityUI = {
        _logLines: [],

        log(msg, cls) {
            const el = document.getElementById('prox-log');
            if (!el) return;
            this._logLines.push({ msg, cls });
            if (this._logLines.length > 50) this._logLines.shift();
            el.innerHTML = this._logLines.map(l =>
                `<div class="log-line ${l.cls || ''}">${esc(l.msg)}</div>`
            ).join('');
            el.scrollTop = el.scrollHeight;
        },

        async startScan() {
            const pc = window.ProximityConnect;
            if (!pc) { this.log('ProximityConnect not loaded', 'error'); return; }

            // Init with current identity
            const identity = window.AppState?.identity;
            if (!identity || !identity.nodeId) {
                this.log('Sign in to GhostNet first', 'error');
                return;
            }

            try {
                await pc.init(identity);
            } catch (e) {
                this.log('Init failed: ' + e.message, 'error');
                return;
            }

            // Wire up events
            pc.on('deviceFound', (d) => this._addDevice(d));
            pc.on('scanComplete', (r) => this._onScanComplete(r));
            pc.on('stateChange', (s) => this._updateState(s));
            pc.on('connected', (d) => this._onConnected(d));
            pc.on('pairingRequest', (d) => this._onPairingRequest(d));
            pc.on('error', (e) => this.log(`Error [${e.phase}]: ${e.message}`, 'error'));

            // Update UI
            const card = document.getElementById('prox-state-card');
            card.classList.add('scanning');
            document.getElementById('prox-state-title').textContent = 'Scanning...';
            document.getElementById('prox-state-title').style.color = '#a78bfa';
            document.getElementById('prox-state-desc').textContent = 'Looking for nearby GhostNet devices over Bluetooth...';
            document.getElementById('prox-btn-scan').disabled = true;
            document.getElementById('prox-btn-scan').textContent = 'Scanning...';
            document.getElementById('prox-device-section').style.display = 'block';
            document.getElementById('prox-device-list').innerHTML = '';

            this.log('Starting BLE scan...');
            await pc.startScan();
        },

        _addDevice(device) {
            const list = document.getElementById('prox-device-list');
            if (!list) return;

            const shortId = (device.deviceId || '').substring(0, 12);
            const item = document.createElement('div');
            item.className = 'prox-device-item';
            item.innerHTML = `
                <div class="prox-device-left">
                    <div class="prox-device-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                            <rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>
                        </svg>
                    </div>
                    <div>
                        <div class="prox-device-name">${esc(device.name)}</div>
                        <div class="prox-device-id">${esc(shortId)}</div>
                    </div>
                </div>
                <div class="prox-device-rssi">${device.rssi} dBm</div>
            `;
            item.addEventListener('click', () => this._connectToDevice(device));
            list.appendChild(item);
            this.log('Found: ' + device.name + ' (' + shortId + ')');
        },

        _onScanComplete(result) {
            const card = document.getElementById('prox-state-card');
            card.classList.remove('scanning');
            document.getElementById('prox-btn-scan').disabled = false;
            document.getElementById('prox-btn-scan').textContent = 'Scan Again';

            if (result.count === 0) {
                document.getElementById('prox-state-title').textContent = 'No Devices Found';
                document.getElementById('prox-state-title').style.color = 'var(--text-muted)';
                document.getElementById('prox-state-desc').textContent = 'Make sure the other device has GhostNet running and Bluetooth enabled.';
                this.log('Scan complete — no devices found');
            } else {
                document.getElementById('prox-state-title').textContent = result.count + ' Device' + (result.count > 1 ? 's' : '') + ' Found';
                document.getElementById('prox-state-title').style.color = '#a78bfa';
                document.getElementById('prox-state-desc').textContent = 'Tap a device below to start the secure handshake.';
                this.log('Scan complete — ' + result.count + ' device(s) found', 'success');
            }
        },

        async _connectToDevice(device) {
            this.log('Connecting to ' + device.name + '...');
            document.getElementById('prox-state-title').textContent = 'Handshaking...';
            document.getElementById('prox-state-title').style.color = '#f59e0b';
            document.getElementById('prox-state-desc').textContent = 'Exchanging ephemeral keys and verifying identity...';

            const pc = window.ProximityConnect;
            const result = await pc.connectTo(device.deviceId);

            if (!result) {
                document.getElementById('prox-state-title').textContent = 'Handshake Failed';
                document.getElementById('prox-state-title').style.color = '#ef4444';
                document.getElementById('prox-state-desc').textContent = 'Could not establish a secure connection. Try again.';
                document.getElementById('prox-btn-scan').disabled = false;
                document.getElementById('prox-btn-scan').textContent = 'Scan Again';
            }
        },

        _onPairingRequest(data) {
            document.getElementById('prox-verify-section').style.display = 'block';
            document.getElementById('prox-verify-code').textContent = data.verificationCode;
            document.getElementById('prox-state-title').textContent = 'Verify Pairing';
            document.getElementById('prox-state-title').style.color = '#a78bfa';
            document.getElementById('prox-state-desc').textContent = 'Check the code below matches the other device.';
            this.log('Verification code: ' + data.verificationCode, 'success');
        },

        _onConnected(data) {
            // Show verification code first
            document.getElementById('prox-verify-section').style.display = 'block';
            document.getElementById('prox-verify-code').textContent = data.verificationCode;
            document.getElementById('prox-state-title').textContent = 'Verify & Connect';
            document.getElementById('prox-state-title').style.color = '#10b981';
            document.getElementById('prox-state-desc').textContent = 'Handshake complete. Verify the code matches the other device.';

            this.log('Session established — verify code: ' + data.verificationCode, 'success');

            // Store peer info for contact adding
            this._connectedPeer = data.peer;
        },

        confirmPairing() {
            document.getElementById('prox-verify-section').style.display = 'none';
            document.getElementById('prox-connected-section').style.display = 'block';
            document.getElementById('prox-device-section').style.display = 'none';

            const card = document.getElementById('prox-state-card');
            card.classList.remove('scanning');
            document.getElementById('prox-state-title').textContent = 'Securely Connected';
            document.getElementById('prox-state-title').style.color = '#10b981';
            document.getElementById('prox-state-desc').textContent = 'Encrypted BLE session active with forward secrecy.';
            document.getElementById('prox-state-icon').innerHTML = `
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="1.5" stroke-linecap="round">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
            `;

            const peerName = this._connectedPeer?.peerId || 'Unknown Peer';
            document.getElementById('prox-peer-name').textContent = peerName;
            document.getElementById('prox-actions').style.display = 'none';

            this.log('Pairing confirmed by user', 'success');
        },

        cancelPairing() {
            document.getElementById('prox-verify-section').style.display = 'none';
            window.ProximityConnect?.disconnect();
            this._resetUI();
            this.log('Pairing cancelled by user');
        },

        addAsContact() {
            const peer = this._connectedPeer;
            if (!peer) return;

            // Auto-fill new chat dialog with peer info
            if (typeof UI !== 'undefined' && UI.openNewChat) {
                UI.openNewChat();
                setTimeout(() => {
                    const pk = document.getElementById('chat-pubkey');
                    const nm = document.getElementById('chat-name');
                    if (pk) pk.value = peer.peerId;
                    if (nm) nm.value = peer.peerId;
                }, 100);
            }

            this.log('Added ' + peer.peerId + ' as contact', 'success');
        },

        disconnect() {
            window.ProximityConnect?.disconnect();
            this._resetUI();
            this.log('Disconnected');
        },

        _updateState(s) {
            this.log('State: ' + s);
        },

        _resetUI() {
            const card = document.getElementById('prox-state-card');
            card.classList.remove('scanning');
            document.getElementById('prox-state-title').textContent = 'Ready to Connect';
            document.getElementById('prox-state-title').style.color = 'var(--text-muted)';
            document.getElementById('prox-state-desc').textContent = 'Scan for nearby GhostNet devices over Bluetooth. No internet required.';
            document.getElementById('prox-state-icon').innerHTML = `
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="1.5" stroke-linecap="round">
                    <path d="M5 12.55a11 11 0 0 1 14.08 0"/>
                    <path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
                    <circle cx="12" cy="20" r="1"/>
                </svg>
            `;
            document.getElementById('prox-btn-scan').disabled = false;
            document.getElementById('prox-btn-scan').textContent = 'Scan Nearby';
            document.getElementById('prox-actions').style.display = 'flex';
            document.getElementById('prox-device-section').style.display = 'none';
            document.getElementById('prox-verify-section').style.display = 'none';
            document.getElementById('prox-connected-section').style.display = 'none';
            document.getElementById('prox-device-list').innerHTML = '';
            this._connectedPeer = null;
        }
    };
});
