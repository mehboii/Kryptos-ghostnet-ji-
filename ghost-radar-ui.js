/**
 * Ghost Radar UI
 * Dedicated radar view with animated sweep, live device list,
 * permission prompts, and empty-state handling.
 */

document.addEventListener('DOMContentLoaded', () => {
    const mainContent = document.getElementById('main-content');
    if (!mainContent) return;

    // ── Styles ──────────────────────────────────────────────────
    const style = document.createElement('style');
    style.textContent = `
        .radar-view-container {
            padding: 24px;
            max-width: 800px;
            margin: 0 auto;
        }

        /* Radar Visual */
        .ghost-radar-wrap {
            display: flex;
            justify-content: center;
            margin-bottom: 28px;
        }
        .ghost-radar-visual {
            position: relative;
            width: 220px;
            height: 220px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(16,185,129,0.06) 0%, rgba(0,0,0,0.4) 70%);
            border: 1px solid rgba(16,185,129,0.25);
            overflow: hidden;
        }
        .ghost-radar-visual .radar-ring {
            position: absolute;
            border-radius: 50%;
            border: 1px solid rgba(16,185,129,0.12);
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
        }
        .ghost-radar-visual .radar-ring.r1 { width: 33%; height: 33%; }
        .ghost-radar-visual .radar-ring.r2 { width: 66%; height: 66%; }
        .ghost-radar-visual .radar-ring.r3 { width: 100%; height: 100%; }
        .ghost-radar-visual .radar-crosshair-h,
        .ghost-radar-visual .radar-crosshair-v {
            position: absolute;
            background: rgba(16,185,129,0.1);
        }
        .ghost-radar-visual .radar-crosshair-h {
            width: 100%; height: 1px; top: 50%; left: 0;
        }
        .ghost-radar-visual .radar-crosshair-v {
            width: 1px; height: 100%; top: 0; left: 50%;
        }
        .ghost-radar-visual .radar-sweep {
            position: absolute;
            width: 50%; height: 50%;
            top: 50%; left: 50%;
            transform-origin: 0 0;
            background: conic-gradient(from 0deg, rgba(16,185,129,0.35), transparent 60deg);
            animation: radarSweep 3s linear infinite;
            border-radius: 0 100% 0 0;
        }
        @keyframes radarSweep {
            0%   { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .ghost-radar-visual.paused .radar-sweep {
            animation-play-state: paused;
            opacity: 0.3;
        }
        .ghost-radar-visual .radar-center-dot {
            position: absolute;
            width: 8px; height: 8px;
            background: #10b981;
            border-radius: 50%;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            box-shadow: 0 0 10px rgba(16,185,129,0.7);
            z-index: 3;
        }
        /* Blips on radar */
        .ghost-radar-visual .radar-blip {
            position: absolute;
            width: 6px; height: 6px;
            border-radius: 50%;
            transform: translate(-50%, -50%);
            z-index: 2;
            animation: blipPulse 2s ease-in-out infinite;
        }
        .radar-blip.safe { background: #10b981; box-shadow: 0 0 6px rgba(16,185,129,0.6); }
        .radar-blip.monitor { background: #f59e0b; box-shadow: 0 0 6px rgba(245,158,11,0.6); }
        .radar-blip.threat { background: #ef4444; box-shadow: 0 0 6px rgba(239,68,68,0.6); }
        .radar-blip.ghost-node { background: #8b5cf6; box-shadow: 0 0 8px rgba(139,92,246,0.7); width: 8px; height: 8px; }
        @keyframes blipPulse {
            0%, 100% { opacity: 1; transform: translate(-50%,-50%) scale(1); }
            50% { opacity: 0.6; transform: translate(-50%,-50%) scale(1.4); }
        }

        /* Scan status bar */
        .radar-status-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
            font-size: 0.8rem;
        }
        .radar-status-bar .scan-indicator {
            display: flex; align-items: center; gap: 8px;
            color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .radar-status-bar .scan-indicator .dot {
            width: 8px; height: 8px; border-radius: 50%; background: #10b981;
            animation: dotBlink 1.5s infinite;
        }
        .radar-status-bar .scan-indicator .dot.idle { background: #6b7280; animation: none; }
        @keyframes dotBlink { 0%,100%{ opacity:1; } 50%{ opacity:0.3; } }
        .radar-status-bar .scan-count {
            color: var(--text-primary); font-weight: 700; font-family: monospace;
        }

        /* Permission banner */
        .radar-permission-banner {
            background: rgba(245,158,11,0.1);
            border: 1px solid rgba(245,158,11,0.3);
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 20px;
            display: none;
        }
        .radar-permission-banner.visible { display: block; }
        .radar-permission-banner h4 {
            margin: 0 0 8px;
            color: #f59e0b;
            font-size: 0.9rem;
            display: flex; align-items: center; gap: 8px;
        }
        .radar-permission-banner p {
            margin: 0 0 12px;
            color: var(--text-muted);
            font-size: 0.8rem;
            line-height: 1.5;
        }
        .radar-permission-banner .perm-items {
            display: flex; flex-direction: column; gap: 6px;
        }
        .radar-permission-banner .perm-item {
            display: flex; align-items: center; gap: 8px;
            font-size: 0.8rem; color: var(--text-muted);
        }
        .radar-permission-banner .perm-item .perm-status {
            width: 18px; height: 18px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 0.65rem; font-weight: bold;
        }
        .perm-status.granted { background: rgba(16,185,129,0.2); color: #10b981; }
        .perm-status.denied  { background: rgba(239,68,68,0.2); color: #ef4444; }
        .perm-status.unknown { background: rgba(107,114,128,0.2); color: #6b7280; }
        .btn-grant-permissions {
            margin-top: 12px;
            padding: 8px 16px;
            background: rgba(245,158,11,0.15);
            border: 1px solid rgba(245,158,11,0.4);
            color: #f59e0b;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            font-size: 0.8rem;
            transition: background 0.2s;
        }
        .btn-grant-permissions:hover { background: rgba(245,158,11,0.25); }

        /* Device list */
        .radar-device-board {
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }
        .radar-device-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid var(--border);
        }
        .radar-device-header h3 { margin: 0; font-family: 'Inter', sans-serif; font-size: 1rem; }
        .radar-device-list {
            display: flex; flex-direction: column; gap: 8px;
            max-height: 350px; overflow-y: auto;
        }

        /* Empty state */
        .radar-empty-state {
            text-align: center; padding: 40px 20px;
        }
        .radar-empty-state .empty-icon {
            margin-bottom: 16px; opacity: 0.3;
        }
        .radar-empty-state .empty-title {
            font-size: 1rem; font-weight: 600; color: var(--text-muted); margin-bottom: 6px;
        }
        .radar-empty-state .empty-desc {
            font-size: 0.8rem; color: var(--text-muted); opacity: 0.7; max-width: 300px; margin: 0 auto;
        }

        /* Device items (reuses threat-item styles from shield) */
        .radar-device-item {
            background: rgba(0,0,0,0.2); border-radius: 8px; padding: 12px;
            display: flex; flex-direction: column;
            border-left: 4px solid var(--border);
            transition: all 0.2s;
        }
        .radar-device-item.safe   { border-left-color: #10b981; }
        .radar-device-item.monitor { border-left-color: #f59e0b; }
        .radar-device-item.threat  { border-left-color: #ef4444; }
        .radar-device-item.ghost-node { border-left-color: #8b5cf6; }
        .radar-device-item .dev-top {
            display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;
        }
        .radar-device-item .dev-name {
            font-size: 0.9rem; color: var(--text-primary); font-weight: 600;
        }
        .radar-device-item .dev-rssi {
            font-family: monospace; font-size: 0.75rem; color: var(--text-muted);
            background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px;
        }
        .radar-device-item .dev-bottom {
            font-size: 0.72rem; color: var(--text-muted); display: flex; gap: 10px; flex-wrap: wrap;
        }
        .radar-device-item .dev-badge {
            font-size: 0.65rem; padding: 1px 6px; border-radius: 4px;
            background: rgba(255,255,255,0.06); text-transform: uppercase; letter-spacing: 0.5px;
        }

        @media (max-width: 600px) {
            .ghost-radar-visual { width: 180px; height: 180px; }
            .radar-status-bar { flex-direction: column; gap: 8px; text-align: center; }
        }
    `;
    document.head.appendChild(style);

    // ── HTML Section ────────────────────────────────────────────
    const section = document.createElement('section');
    section.id = 'view-radar';
    section.className = 'view-section';
    section.innerHTML = `
        <div class="home-hero" style="margin-bottom: 24px; padding: 0 24px; margin-top:20px;">
            <div class="home-hero-left">
                <h1 class="home-title">Ghost Radar</h1>
                <p class="home-subtitle">Passive BLE & WiFi signal scanner</p>
            </div>
            <div class="home-hero-right">
                <span class="home-badge" style="border-color:#10b981; color:#10b981;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                    </svg>
                    PASSIVE SCAN
                </span>
            </div>
        </div>

        <div class="radar-view-container">

            <!-- PERMISSION BANNER -->
            <div class="radar-permission-banner" id="radar-perm-banner">
                <h4>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Permissions Required
                </h4>
                <p>Ghost Radar needs access to Bluetooth and Location to detect nearby devices. No data is sent or stored externally.</p>
                <div class="perm-items">
                    <div class="perm-item">
                        <span class="perm-status unknown" id="perm-ble-dot">?</span>
                        <span>Bluetooth / BLE Scanning</span>
                    </div>
                    <div class="perm-item">
                        <span class="perm-status unknown" id="perm-loc-dot">?</span>
                        <span>Location (required for BLE on Android)</span>
                    </div>
                    <div class="perm-item">
                        <span class="perm-status unknown" id="perm-wifi-dot">?</span>
                        <span>WiFi Network Scanning</span>
                    </div>
                </div>
                <button class="btn-grant-permissions" id="btn-grant-perms" onclick="GhostRadarUI.requestPermissions()">Grant Permissions</button>
            </div>

            <!-- RADAR VISUAL -->
            <div class="ghost-radar-wrap">
                <div class="ghost-radar-visual" id="radar-visual">
                    <div class="radar-ring r1"></div>
                    <div class="radar-ring r2"></div>
                    <div class="radar-ring r3"></div>
                    <div class="radar-crosshair-h"></div>
                    <div class="radar-crosshair-v"></div>
                    <div class="radar-sweep"></div>
                    <div class="radar-center-dot"></div>
                </div>
            </div>

            <!-- SCAN STATUS -->
            <div class="radar-status-bar">
                <div class="scan-indicator">
                    <span class="dot" id="radar-scan-dot"></span>
                    <span id="radar-scan-label">Scanning nearby...</span>
                </div>
                <div>
                    <span class="scan-count" id="radar-device-count">0</span>
                    <span style="color:var(--text-muted); font-size:0.75rem; margin-left:4px;">devices</span>
                </div>
            </div>

            <!-- DEVICE LIST -->
            <div class="radar-device-board">
                <div class="radar-device-header">
                    <h3>Nearby Devices</h3>
                    <button style="background:none; border:1px solid var(--border); color:var(--text-muted); padding:4px 10px; border-radius:6px; font-size:0.7rem; cursor:pointer; font-weight:600; letter-spacing:0.5px;" onclick="GhostRadarUI.manualScan()">RESCAN</button>
                </div>
                <div class="radar-device-list" id="radar-device-list">
                    <div class="radar-empty-state" id="radar-empty">
                        <div class="empty-icon">
                            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
                                <path d="M5 12.55a11 11 0 0 1 14.08 0"/>
                                <path d="M1.42 9a16 16 0 0 1 21.16 0"/>
                                <path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
                                <circle cx="12" cy="20" r="1"/>
                            </svg>
                        </div>
                        <div class="empty-title">No devices found</div>
                        <div class="empty-desc">Scanning for BLE and WiFi signals nearby. Make sure Bluetooth and Location are enabled.</div>
                    </div>
                </div>
            </div>

        </div>
    `;
    mainContent.appendChild(section);

    // ── UI Logic ────────────────────────────────────────────────
    window.GhostRadarUI = {

        _esc(str) {
            const d = document.createElement('div');
            d.textContent = String(str);
            return d.innerHTML;
        },

        async requestPermissions() {
            const radar = window.GhostRadar;
            if (!radar) return;
            await radar.checkPermissions();
            this.updatePermissionBanner();
        },

        updatePermissionBanner() {
            const radar = window.GhostRadar;
            if (!radar) return;

            const ps = radar.permissionState;
            const allGranted = ps.ble === 'granted' && ps.location === 'granted';
            const anyDenied = ps.ble === 'denied' || ps.location === 'denied';

            const banner = document.getElementById('radar-perm-banner');
            if (allGranted) {
                banner.classList.remove('visible');
            } else if (anyDenied) {
                banner.classList.add('visible');
            }

            // Update dots
            this._setPermDot('perm-ble-dot', ps.ble);
            this._setPermDot('perm-loc-dot', ps.location);
            this._setPermDot('perm-wifi-dot', ps.wifi);

            // Hide the grant button if everything is denied permanently
            // (user must go to system settings)
            const btn = document.getElementById('btn-grant-perms');
            if (anyDenied && ps.ble !== 'unknown') {
                btn.textContent = 'Open Settings to Grant';
            }
        },

        _setPermDot(id, state) {
            const el = document.getElementById(id);
            if (!el) return;
            el.className = 'perm-status ' + (state === 'granted' ? 'granted' : state === 'denied' ? 'denied' : 'unknown');
            el.textContent = state === 'granted' ? '\u2713' : state === 'denied' ? '\u2717' : '?';
        },

        async manualScan() {
            const radar = window.GhostRadar;
            if (!radar || radar.scanning) return;
            await radar.startScan();
        },

        /**
         * Place blips on the radar visual based on RSSI and device type.
         */
        renderBlips(results) {
            const visual = document.getElementById('radar-visual');
            if (!visual) return;

            // Remove old blips
            visual.querySelectorAll('.radar-blip').forEach(b => b.remove());

            if (!results || results.length === 0) return;

            const cx = 110, cy = 110, maxR = 100; // center and max radius

            for (let i = 0; i < results.length; i++) {
                const d = results[i];
                // Map RSSI (-30 close to -100 far) to distance from center
                const rssi = Math.max(-100, Math.min(-20, d.rssi || -80));
                const dist = ((Math.abs(rssi) - 20) / 80) * maxR;

                // Spread devices around the circle using a deterministic angle from ID
                let hash = 0;
                const idStr = String(d.id || i);
                for (let c = 0; c < idStr.length; c++) hash = ((hash << 5) - hash) + idStr.charCodeAt(c);
                const angle = (Math.abs(hash) % 360) * (Math.PI / 180);

                const x = cx + dist * Math.cos(angle);
                const y = cy + dist * Math.sin(angle);

                const cfg = window.ShieldConfig;
                const blockedAt = cfg ? cfg.signalIntel.thresholdBlocked : 75;
                const warningAt = cfg ? cfg.signalIntel.thresholdWarning : 50;

                const blip = document.createElement('div');
                blip.className = 'radar-blip';
                if (d.isGhostNode) {
                    blip.classList.add('ghost-node');
                } else if (d.threatScore > blockedAt) {
                    blip.classList.add('threat');
                } else if (d.threatScore >= warningAt) {
                    blip.classList.add('monitor');
                } else {
                    blip.classList.add('safe');
                }
                blip.style.left = x + 'px';
                blip.style.top = y + 'px';
                blip.title = this._esc(d.name || d.id || 'Unknown');
                visual.appendChild(blip);
            }
        },

        /**
         * Render the device list from GhostRadar results.
         */
        renderDeviceList(results) {
            const container = document.getElementById('radar-device-list');
            const countEl = document.getElementById('radar-device-count');
            if (!container) return;

            if (!results || results.length === 0) {
                container.innerHTML = `
                    <div class="radar-empty-state" id="radar-empty">
                        <div class="empty-icon">
                            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
                                <path d="M5 12.55a11 11 0 0 1 14.08 0"/>
                                <path d="M1.42 9a16 16 0 0 1 21.16 0"/>
                                <path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
                                <circle cx="12" cy="20" r="1"/>
                            </svg>
                        </div>
                        <div class="empty-title">No devices found</div>
                        <div class="empty-desc">Scanning for BLE and WiFi signals nearby. Make sure Bluetooth and Location are enabled.</div>
                    </div>`;
                if (countEl) countEl.textContent = '0';
                return;
            }

            if (countEl) countEl.textContent = results.length;

            // Sort: GhostNodes first, then by RSSI descending
            const sorted = [...results].sort((a, b) => {
                if (a.isGhostNode && !b.isGhostNode) return -1;
                if (!a.isGhostNode && b.isGhostNode) return 1;
                return (b.rssi || -100) - (a.rssi || -100);
            });

            const cfg = window.ShieldConfig;
            const blockedAt = cfg ? cfg.signalIntel.thresholdBlocked : 75;
            const warningAt = cfg ? cfg.signalIntel.thresholdWarning : 50;

            let html = '';
            for (const d of sorted) {
                const score = Number(d.threatScore) || 0;
                let cls = 'safe';
                let badgeLabel = 'ALLOWED';
                if (d.isGhostNode) { cls = 'ghost-node'; badgeLabel = 'NODE'; }
                else if (score > blockedAt) { cls = 'threat'; badgeLabel = 'BLOCKED'; }
                else if (score >= warningAt) { cls = 'monitor'; badgeLabel = 'WARNING'; }

                const name = this._esc(d.name || 'Unknown Device');
                const rssiLabel = d.rssi != null ? d.rssi + ' dBm' : '--';
                const typeLabel = this._esc(d.type || 'unknown');

                const extras = [];
                if (d.channel) extras.push('CH ' + d.channel);
                if (d.security) extras.push(this._esc(d.security));
                if (d.connectionType) extras.push(this._esc(d.connectionType));
                if (d.isGhostNode) extras.push('GhostNet Node');

                html += `
                    <div class="radar-device-item ${cls}">
                        <div class="dev-top">
                            <span class="dev-name">${name} <span style="font-size:0.7rem; font-family:monospace; opacity:0.7;">[${score}]</span></span>
                            <span class="dev-rssi">${rssiLabel}</span>
                        </div>
                        <div class="dev-bottom">
                            <span class="dev-badge">${typeLabel}</span>
                            <span class="dev-badge" style="${score > blockedAt ? 'color:#ef4444;' : score >= warningAt ? 'color:#f59e0b;' : 'color:#10b981;'}">${badgeLabel}</span>
                            <span>ID: ${this._esc((d.id || 'N/A').substring(0, 20))}</span>
                            ${extras.length ? '<span>\u00B7</span><span>' + extras.join(' \u00B7 ') + '</span>' : ''}
                        </div>
                    </div>`;
            }
            container.innerHTML = html;
        },

        /**
         * Full UI refresh from current GhostRadar state.
         */
        refresh() {
            const radar = window.GhostRadar;
            if (!radar) return;

            const results = radar.results || [];
            const scanDot = document.getElementById('radar-scan-dot');
            const scanLabel = document.getElementById('radar-scan-label');
            const radarVisual = document.getElementById('radar-visual');

            if (radar.scanning) {
                if (scanDot) scanDot.classList.remove('idle');
                if (scanLabel) scanLabel.textContent = 'Scanning nearby...';
                if (radarVisual) radarVisual.classList.remove('paused');
            } else {
                if (scanDot) scanDot.classList.add('idle');
                if (scanLabel) scanLabel.textContent = results.length > 0
                    ? 'Scan complete \u2014 next in 15s'
                    : 'Idle \u2014 waiting for signals';
                if (radarVisual && results.length === 0) radarVisual.classList.add('paused');
                else if (radarVisual) radarVisual.classList.remove('paused');
            }

            this.renderBlips(results);
            this.renderDeviceList(results);
            this.updatePermissionBanner();
        },

        init() {
            // Listen for scan completions from GhostRadar
            window.addEventListener('ghostRadar:scanComplete', (e) => {
                this.refresh();
            });

            // Listen for permission updates
            window.addEventListener('ghostRadar:permissionUpdate', () => {
                this.updatePermissionBanner();
            });

            // Also listen for signalIntel completions (enriched data)
            window.addEventListener('signalIntel:scanComplete', () => {
                this.refresh();
            });

            // Periodic refresh fallback
            setInterval(() => this.refresh(), 5000);

            // Initial render
            this.refresh();
        }
    };

    window.GhostRadarUI.init();
});
