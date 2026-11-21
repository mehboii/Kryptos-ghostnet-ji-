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
            width: 240px;
            height: 240px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(16,185,129,0.04) 0%, rgba(0,0,0,0.45) 70%);
            border: 1px solid rgba(16,185,129,0.18);
            overflow: hidden;
            box-shadow: 0 0 30px rgba(16,185,129,0.06), inset 0 0 40px rgba(0,0,0,0.3);
        }
        .ghost-radar-visual .radar-ring {
            position: absolute;
            border-radius: 50%;
            border: 1px solid rgba(16,185,129,0.08);
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
        }
        .ghost-radar-visual .radar-ring.r1 { width: 33%; height: 33%; }
        .ghost-radar-visual .radar-ring.r2 { width: 66%; height: 66%; }
        .ghost-radar-visual .radar-ring.r3 { width: 100%; height: 100%; border-color: rgba(16,185,129,0.12); }
        .ghost-radar-visual .radar-crosshair-h,
        .ghost-radar-visual .radar-crosshair-v {
            position: absolute;
            background: rgba(16,185,129,0.06);
        }
        .ghost-radar-visual .radar-crosshair-h {
            width: 100%; height: 1px; top: 50%; left: 0;
        }
        .ghost-radar-visual .radar-crosshair-v {
            width: 1px; height: 100%; top: 0; left: 50%;
        }
        /* Sweep arm — smooth gradient with soft afterglow trail */
        .ghost-radar-visual .radar-sweep {
            position: absolute;
            width: 50%; height: 50%;
            top: 50%; left: 50%;
            transform-origin: 0 0;
            background: conic-gradient(
                from 0deg,
                rgba(16,185,129,0.40) 0deg,
                rgba(16,185,129,0.18) 20deg,
                rgba(16,185,129,0.06) 40deg,
                transparent 55deg
            );
            animation: radarSweep 4s cubic-bezier(0.4, 0, 0.2, 1) infinite;
            border-radius: 0 100% 0 0;
            will-change: transform;
        }
        /* Afterglow trail — faint secondary cone behind the main sweep */
        .ghost-radar-visual .radar-afterglow {
            position: absolute;
            width: 50%; height: 50%;
            top: 50%; left: 50%;
            transform-origin: 0 0;
            background: conic-gradient(
                from 0deg,
                rgba(16,185,129,0.08) 0deg,
                transparent 90deg
            );
            animation: radarSweep 4s cubic-bezier(0.4, 0, 0.2, 1) infinite;
            animation-delay: -0.3s;
            border-radius: 0 100% 0 0;
            will-change: transform;
            pointer-events: none;
        }
        @keyframes radarSweep {
            0%   { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .ghost-radar-visual.paused .radar-sweep,
        .ghost-radar-visual.paused .radar-afterglow {
            animation-play-state: paused;
            opacity: 0.2;
        }
        .ghost-radar-visual .radar-center-dot {
            position: absolute;
            width: 8px; height: 8px;
            background: #10b981;
            border-radius: 50%;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            box-shadow: 0 0 8px rgba(16,185,129,0.6), 0 0 20px rgba(16,185,129,0.15);
            z-index: 3;
        }

        /* ── Blips ─────────────────────────────────────── */
        .ghost-radar-visual .radar-blip {
            position: absolute;
            width: 6px; height: 6px;
            border-radius: 50%;
            transform: translate(-50%, -50%) scale(0);
            z-index: 2;
            opacity: 0;
            animation: blipEnter 0.5s ease-out forwards;
        }
        /* Entrance: fade-in + scale-up from nothing */
        @keyframes blipEnter {
            0%   { opacity: 0; transform: translate(-50%,-50%) scale(0); }
            60%  { opacity: 1; transform: translate(-50%,-50%) scale(1.5); }
            100% { opacity: 1; transform: translate(-50%,-50%) scale(1); }
        }
        /* Idle pulse — subtle breathe for safe / monitor / ghost */
        .radar-blip.safe {
            background: #10b981;
            box-shadow: 0 0 5px rgba(16,185,129,0.5);
            animation: blipEnter 0.5s ease-out forwards, blipBreathe 3s ease-in-out 0.5s infinite;
        }
        .radar-blip.monitor {
            background: #f59e0b;
            box-shadow: 0 0 5px rgba(245,158,11,0.5);
            animation: blipEnter 0.5s ease-out forwards, blipBreathe 3s ease-in-out 0.5s infinite;
        }
        .radar-blip.ghost-node {
            background: #8b5cf6;
            box-shadow: 0 0 6px rgba(139,92,246,0.6);
            width: 7px; height: 7px;
            animation: blipEnter 0.5s ease-out forwards, blipBreathe 3s ease-in-out 0.5s infinite;
        }
        /* Threat — aggressive red glow pulse */
        .radar-blip.threat {
            background: #ef4444;
            box-shadow: 0 0 6px rgba(239,68,68,0.7), 0 0 14px rgba(239,68,68,0.3);
            animation: blipEnter 0.5s ease-out forwards, threatGlow 1.4s ease-in-out 0.5s infinite;
        }
        @keyframes blipBreathe {
            0%, 100% { opacity: 0.85; transform: translate(-50%,-50%) scale(1); }
            50%      { opacity: 1;    transform: translate(-50%,-50%) scale(1.15); }
        }
        @keyframes threatGlow {
            0%, 100% {
                opacity: 1;
                transform: translate(-50%,-50%) scale(1);
                box-shadow: 0 0 6px rgba(239,68,68,0.7), 0 0 14px rgba(239,68,68,0.3);
            }
            50% {
                opacity: 1;
                transform: translate(-50%,-50%) scale(1.35);
                box-shadow: 0 0 10px rgba(239,68,68,0.9), 0 0 22px rgba(239,68,68,0.45);
            }
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

        /* Device items */
        .radar-device-item {
            background: rgba(0,0,0,0.2); border-radius: 8px; padding: 12px;
            display: flex; flex-direction: column;
            border-left: 4px solid var(--border);
            transition: background 0.25s, border-color 0.25s;
        }
        .radar-device-item.safe   { border-left-color: #10b981; }
        .radar-device-item.monitor { border-left-color: #f59e0b; }
        .radar-device-item.threat  {
            border-left-color: #ef4444;
            background: rgba(239,68,68,0.05);
            box-shadow: inset 0 0 20px rgba(239,68,68,0.04);
        }
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

        /* Device meta row: vendor / category / proximity */
        .radar-device-item .dev-proximity {
            font-size: 0.65rem; padding: 1px 6px; border-radius: 4px;
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        .dev-proximity.very.close, .dev-proximity.very-close { background: rgba(16,185,129,0.15); color: #10b981; }
        .dev-proximity.nearby { background: rgba(245,158,11,0.12); color: #f59e0b; }
        .dev-proximity.far { background: rgba(107,114,128,0.15); color: #9ca3af; }
        .dev-proximity.unknown { background: rgba(107,114,128,0.12); color: #6b7280; }

        /* "Notable" chip — rare, always paired with a plain-language reason */
        .radar-device-item.notable {
            border-left-color: #f59e0b;
            background: rgba(245,158,11,0.05);
        }
        .dev-notable {
            margin-top: 6px; font-size: 0.7rem; color: #f59e0b;
            display: flex; align-items: center; gap: 6px;
        }
        .dev-unknown-name { color: var(--text-muted); font-style: italic; }

        /* WiFi (nearby networks) board */
        .radar-wifi-board {
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-top: 16px;
        }
        .radar-wifi-board h3 { margin: 0 0 4px; font-size: 1rem; }
        .radar-wifi-sub { font-size: 0.72rem; color: var(--text-muted); margin: 0 0 14px; }
        .radar-wifi-note {
            font-size: 0.78rem; color: var(--text-muted); line-height: 1.5;
            padding: 12px; border: 1px dashed var(--border); border-radius: 8px;
            background: rgba(0,0,0,0.2);
        }
        .radar-wifi-item {
            background: rgba(0,0,0,0.2); border-radius: 8px; padding: 10px 12px;
            display: flex; justify-content: space-between; align-items: center;
            border-left: 4px solid rgba(34,211,238,0.4); margin-bottom: 8px;
        }
        .radar-wifi-item.notable { border-left-color: #f59e0b; }
        .radar-wifi-item .wifi-name { font-size: 0.85rem; color: var(--text-primary); font-weight: 600; }
        .radar-wifi-item .wifi-meta { font-size: 0.7rem; color: var(--text-muted); margin-top: 2px; }
        .radar-wifi-item .wifi-rssi {
            font-family: monospace; font-size: 0.72rem; color: var(--text-muted);
            background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px;
        }

        /* Unsupported-environment (web / Expo Go) state */
        .radar-unsupported {
            text-align: center; padding: 36px 20px;
            border: 1px solid rgba(139,92,246,0.3); border-radius: 12px;
            background: linear-gradient(180deg, rgba(34,211,238,0.04) 0%, rgba(139,92,246,0.06) 100%);
        }
        .radar-unsupported .ru-title { font-size: 1rem; font-weight: 700; color: #a78bfa; margin-bottom: 8px; }
        .radar-unsupported .ru-desc { font-size: 0.82rem; color: var(--text-muted); max-width: 360px; margin: 0 auto; line-height: 1.5; }

        @media (max-width: 600px) {
            .ghost-radar-visual { width: 200px; height: 200px; }
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
                <p>Ghost Radar needs Bluetooth and WiFi access to detect nearby signals. No location, identity, or personal data is ever collected or stored.</p>
                <div class="perm-items">
                    <div class="perm-item">
                        <span class="perm-status unknown" id="perm-ble-dot">?</span>
                        <span>Bluetooth / BLE Scanning</span>
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
                    <div class="radar-afterglow"></div>
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

            <!-- UNSUPPORTED ENVIRONMENT (web / Expo Go) -->
            <div id="radar-unsupported" style="display:none;"></div>

            <!-- DEVICE LIST -->
            <div class="radar-device-board" id="radar-device-board">
                <div class="radar-device-header">
                    <h3>Nearby Devices (BLE)</h3>
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
                        <div class="empty-desc">Scanning for BLE signals nearby. Make sure Bluetooth is enabled.</div>
                    </div>
                </div>
            </div>

            <!-- WIFI (NEARBY NETWORKS — Android only) -->
            <div class="radar-wifi-board" id="radar-wifi-board">
                <h3>Nearby Networks (WiFi)</h3>
                <p class="radar-wifi-sub">Routers and hotspots in range — not phones or people.</p>
                <div id="radar-wifi-body"></div>
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
            const denied = ps.ble === 'denied';

            const banner = document.getElementById('radar-perm-banner');
            // Only nag when BLE is actually denied AND the radio could otherwise work.
            if (banner) {
                if (denied && radar.env === 'native') banner.classList.add('visible');
                else banner.classList.remove('visible');
            }

            this._setPermDot('perm-ble-dot', ps.ble);
            this._setPermDot('perm-wifi-dot', ps.wifi);

            const btn = document.getElementById('btn-grant-perms');
            if (btn && denied && ps.ble !== 'unknown') btn.textContent = 'Open Settings to Grant';
        },

        _setPermDot(id, state) {
            const el = document.getElementById(id);
            if (!el) return;
            el.className = 'perm-status ' + (state === 'granted' ? 'granted' : state === 'denied' ? 'denied' : 'unknown');
            el.textContent = state === 'granted' ? '\u2713' : state === 'denied' ? '\u2717' : '?';
        },

        _wifi: { supported: false, available: false, reason: 'unknown', networks: [] },

        async manualScan() {
            const radar = window.GhostRadar;
            if (!radar) return;
            if (typeof GhostAnalytics !== 'undefined') GhostAnalytics.trackFeature('radar:scan');
            await radar.start();
        },

        // ── Unsupported-environment gate (browser / Expo Go) ────────
        _showUnsupported(env) {
            const box = document.getElementById('radar-unsupported');
            const board = document.getElementById('radar-device-board');
            const wifiBoard = document.getElementById('radar-wifi-board');
            const banner = document.getElementById('radar-perm-banner');
            const visual = document.getElementById('radar-visual');
            if (!box) return;
            const where = env === 'web' ? 'a web browser' : 'Expo Go';
            box.style.display = 'block';
            box.innerHTML = `
                <div class="radar-unsupported">
                    <div class="ru-title">Open in the Kryptos App</div>
                    <div class="ru-desc">Ghost Radar scans the Bluetooth radio directly, which only works in the installed Kryptos app — not in ${where}. Bluetooth and WiFi scanning need the native app to reach your phone's hardware.</div>
                </div>`;
            if (board) board.style.display = 'none';
            if (wifiBoard) wifiBoard.style.display = 'none';
            if (banner) banner.classList.remove('visible');
            if (visual) visual.classList.add('paused');
            const label = document.getElementById('radar-scan-label');
            if (label) label.textContent = 'Unavailable in this environment';
            const dot = document.getElementById('radar-scan-dot');
            if (dot) dot.classList.add('idle');
        },

        _hideUnsupported() {
            const box = document.getElementById('radar-unsupported');
            const board = document.getElementById('radar-device-board');
            if (box) box.style.display = 'none';
            if (board) board.style.display = 'block';
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

            const size = visual.offsetWidth || 220;
            const cx = size / 2, cy = size / 2, maxR = (size / 2) - 10;

            for (let i = 0; i < results.length; i++) {
                const d = results[i];
                // Map RSSI (-20 close to -100 far) to distance from center.
                const rssi = Math.max(-100, Math.min(-20, d.rssi || -80));
                const dist = ((Math.abs(rssi) - 20) / 80) * maxR;

                // Deterministic angle from the id so a device keeps its position.
                let hash = 0;
                const idStr = String(d.id || i);
                for (let c = 0; c < idStr.length; c++) hash = ((hash << 5) - hash) + idStr.charCodeAt(c);
                const angle = (Math.abs(hash) % 360) * (Math.PI / 180);

                const x = cx + dist * Math.cos(angle);
                const y = cy + dist * Math.sin(angle);

                const blip = document.createElement('div');
                blip.className = 'radar-blip';
                // Restrained colour: ghost node (purple), notable (amber), else safe (green).
                if (d.isGhostNode) blip.classList.add('ghost-node');
                else if (d.notable) blip.classList.add('monitor');
                else blip.classList.add('safe');
                blip.style.left = x + 'px';
                blip.style.top = y + 'px';
                blip.style.animationDelay = (i * 0.08) + 's, ' + (0.5 + i * 0.08) + 's';
                blip.title = this._esc(d.name || d.category || d.id || 'Unknown');
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
                        <div class="empty-desc">Scanning for BLE and WiFi signals nearby. Make sure Bluetooth is enabled.</div>
                    </div>`;
                if (countEl) countEl.textContent = '0';
                return;
            }

            if (countEl) countEl.textContent = results.length;

            // Engine already sorts (ghost node, then notable, then RSSI).
            let html = '';
            for (const d of results) {
                let cls = 'safe';
                if (d.isGhostNode) cls = 'ghost-node';
                else if (d.notable) cls = 'notable';

                // Never invent a name: fall back to the inferred category in muted text.
                const nameHtml = d.name
                    ? this._esc(d.name)
                    : '<span class="dev-unknown-name">' + this._esc(d.category || 'Unknown device') + '</span>';
                const rssiLabel = d.rssi != null ? d.rssi + ' dBm' : '--';
                const proxClass = (d.proximity || 'unknown').replace(/\s+/g, '-');

                const meta = [];
                if (d.vendor) meta.push(this._esc(d.vendor));
                if (d.category && (d.name || d.vendor)) meta.push(this._esc(d.category));
                if (d.isGhostNode) meta.push('Kryptos node');

                html += `
                    <div class="radar-device-item ${cls}">
                        <div class="dev-top">
                            <span class="dev-name">${nameHtml}</span>
                            <span class="dev-rssi">${rssiLabel}</span>
                        </div>
                        <div class="dev-bottom">
                            <span class="dev-proximity ${proxClass}">${this._esc(d.proximity || 'unknown')}</span>
                            ${meta.length ? '<span>' + meta.join(' \u00B7 ') + '</span>' : ''}
                            <span>ID: ${this._esc((d.id || 'N/A').substring(0, 17))}</span>
                        </div>
                        ${d.notable ? '<div class="dev-notable">' +
                            '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>' +
                            ' Notable: ' + this._esc(d.notableReason || 'strong, persistent signal') + '</div>' : ''}
                    </div>`;
            }
            container.innerHTML = html;
        },

        /** Render the WiFi "nearby networks" board \u2014 Android only, else honest note. */
        renderWifi(wifi) {
            const board = document.getElementById('radar-wifi-board');
            const body = document.getElementById('radar-wifi-body');
            if (!board || !body) return;
            const radar = window.GhostRadar;

            // iOS: hide behind a one-line note (the OS forbids AP scanning).
            if (wifi && wifi.reason === 'ios-unsupported') {
                board.style.display = 'block';
                body.innerHTML = '<div class="radar-wifi-note">iOS does not permit apps to scan nearby WiFi networks, so this is unavailable on iPhone/iPad. (Android only.)</div>';
                return;
            }
            // Native module not in this build: honest, not faked.
            if (!wifi || (!wifi.available && (wifi.reason === 'module-not-installed' || wifi.reason === 'unsupported'))) {
                board.style.display = 'block';
                body.innerHTML = '<div class="radar-wifi-note">Nearby-network scanning needs the native WiFi module, which is not included in this build.</div>';
                return;
            }
            if (!wifi.available) {
                board.style.display = 'block';
                const why = wifi.reason === 'permission-denied' ? 'Location/WiFi permission is required to list nearby networks.'
                    : wifi.reason === 'wifi-disabled' ? 'Turn on WiFi to list nearby networks.'
                    : 'Nearby networks are currently unavailable (' + this._esc(wifi.reason || 'unknown') + ').';
                body.innerHTML = '<div class="radar-wifi-note">' + why + '</div>';
                return;
            }

            board.style.display = 'block';
            if (!wifi.networks || wifi.networks.length === 0) {
                body.innerHTML = '<div class="radar-wifi-note">No access points in range.</div>';
                return;
            }
            let html = '';
            for (const n of wifi.networks) {
                const name = n.hidden ? '<span class="dev-unknown-name">Hidden network</span>' : this._esc(n.ssid);
                const rssiLabel = n.rssi != null ? n.rssi + ' dBm' : '--';
                const meta = [];
                if (n.security) meta.push(this._esc(n.security));
                if (n.channel) meta.push('CH ' + n.channel);
                if (n.bssid) meta.push(this._esc(n.bssid));
                html += `
                    <div class="radar-wifi-item ${n.notable ? 'notable' : ''}">
                        <div>
                            <div class="wifi-name">${name}</div>
                            <div class="wifi-meta">${meta.join(' \u00B7 ')}${n.notable ? ' \u00B7 \u26A0 ' + this._esc(n.notableReason || 'notable') : ''}</div>
                        </div>
                        <span class="wifi-rssi">${rssiLabel}</span>
                    </div>`;
            }
            body.innerHTML = html;
        },

        /**
         * Full UI refresh from current GhostRadar state.
         */
        refresh(detail) {
            const radar = window.GhostRadar;
            if (!radar) return;

            // Environment gate first: browser / Expo Go get the honest disabled UI.
            const env = (radar.env && radar.env !== 'unknown') ? radar.env : radar.detectEnvironment();
            if (env !== 'native') { this._showUnsupported(env); return; }
            this._hideUnsupported();

            const results = radar.results || [];
            const wifi = (detail && detail.wifi) || radar.wifi || this._wifi;
            this._wifi = wifi;

            const scanDot = document.getElementById('radar-scan-dot');
            const scanLabel = document.getElementById('radar-scan-label');
            const radarVisual = document.getElementById('radar-visual');

            if (radar.scanning) {
                if (scanDot) scanDot.classList.remove('idle');
                if (scanLabel) scanLabel.textContent = 'Scanning nearby...';
                if (radarVisual) radarVisual.classList.remove('paused');
            } else {
                if (scanDot) scanDot.classList.add('idle');
                if (scanLabel) scanLabel.textContent = results.length > 0 ? 'Paused' : 'Idle \u2014 waiting for signals';
                if (radarVisual) radarVisual.classList.add('paused');
            }

            this.renderBlips(results);
            this.renderDeviceList(results);
            this.renderWifi(wifi);
            this.updatePermissionBanner();
        },

        // Start scanning when the radar view is shown; stop when it is hidden
        // (battery + privacy \u2014 the radio must not run on other screens).
        _bindVisibility() {
            const section = document.getElementById('view-radar');
            if (!section) return;
            const sync = () => {
                const active = section.classList.contains('active');
                const radar = window.GhostRadar;
                if (!radar) return;
                if (active && !this._active) {
                    this._active = true;
                    Promise.resolve(radar.start()).then(() => this.refresh()).catch(() => this.refresh());
                } else if (!active && this._active) {
                    this._active = false;
                    Promise.resolve(radar.stop()).catch(() => {});
                }
            };
            new MutationObserver(sync).observe(section, { attributes: true, attributeFilter: ['class'] });
            sync(); // handle radar already being the active view at load
        },

        init() {
            window.addEventListener('ghostRadar:scanComplete', (e) => this.refresh(e.detail));
            window.addEventListener('ghostRadar:permissionUpdate', () => this.updatePermissionBanner());
            window.addEventListener('ghostRadar:error', (e) => {
                const label = document.getElementById('radar-scan-label');
                if (label && e.detail && e.detail.message) label.textContent = e.detail.message;
            });

            this._bindVisibility();
            this.refresh();
        }
    };

    window.GhostRadarUI.init();
});
