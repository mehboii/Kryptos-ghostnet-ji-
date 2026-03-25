/**
 * Ghost Shield UI
 * Dynamic injection of the Ghost Shield view into GhostNet.
 */

document.addEventListener('DOMContentLoaded', () => {
    const mainContent = document.getElementById('main-content');
    if (!mainContent) return;

    // 1. Inject Styles
    const style = document.createElement('style');
    style.textContent = `
        /* Ghost Shield specific styles */
        .shield-view-container {
            padding: 24px;
            max-width: 800px;
            margin: 0 auto;
            position: relative;
        }
        
        /* Top Section: Shield Status */
        .shield-status-box {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin-bottom: 30px;
            padding: 40px;
            border-radius: 16px;
            background: linear-gradient(180deg, rgba(20,20,30,0.8) 0%, rgba(10,10,15,0.9) 100%);
            border: 1px solid var(--border);
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .shield-icon-wrap {
            width: 120px;
            height: 120px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            margin-bottom: 20px;
            transition: all 0.5s ease;
            position: relative;
            z-index: 2;
        }

        .shield-icon-bg {
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            border-radius: 50%;
            z-index: 0;
            transition: all 0.5s ease;
        }

        .shield-icon-inner {
            z-index: 2;
            color: var(--text-muted);
            transition: all 0.5s ease;
        }

        /* Level 0: OFF */
        .shield-level-0 .shield-icon-wrap { border: 2px dashed #4b5563; }
        .shield-level-0 .shield-icon-inner { color: #6b7280; }
        .shield-level-0 .shield-status-text { color: #9ca3af; }

        /* Level 1: STEALTH */
        .shield-level-1 .shield-icon-wrap { border: 2px solid #0d9488; box-shadow: 0 0 30px rgba(13, 148, 136, 0.4); }
        .shield-level-1 .shield-icon-inner { color: #2dd4bf; }
        .shield-level-1 .shield-status-text { color: #2dd4bf; text-shadow: 0 0 10px rgba(45, 212, 191, 0.6); }

        /* Level 2: GHOST */
        .shield-level-2 .shield-icon-wrap { border: 2px solid #7e22ce; box-shadow: 0 0 40px rgba(126, 34, 206, 0.5); animation: pulseGhost 2s infinite; }
        .shield-level-2 .shield-icon-inner { color: #c084fc; fill: #7e22ce;}
        .shield-level-2 .shield-status-text { color: #c084fc; text-shadow: 0 0 15px rgba(192, 132, 252, 0.6); }

        /* Level 3: PHANTOM */
        .shield-level-3 .shield-icon-wrap { border: 2px solid #d97706; box-shadow: 0 0 50px rgba(217, 119, 6, 0.6); animation: pulsePhantom 0.8s infinite alternate;}
        .shield-level-3 .shield-icon-bg { border: 2px dashed #f59e0b; animation: spinRing 4s linear infinite; }
        .shield-level-3 .shield-icon-inner { color: #fcd34d; fill: #d97706; }
        .shield-level-3 .shield-status-text { color: #fbbf24; text-shadow: 0 0 20px rgba(251, 191, 36, 0.8); }

        @keyframes pulseGhost { 0% { transform: scale(1); } 50% { transform: scale(1.05); } 100% { transform: scale(1); } }
        @keyframes pulsePhantom { 0% { transform: scale(0.95); } 100% { transform: scale(1.1); } }
        @keyframes spinRing { 100% { transform: rotate(360deg); } }

        .shield-status-title {
            font-size: 1.5rem;
            font-weight: 800;
            letter-spacing: 2px;
            margin-bottom: 8px;
            font-family: 'Space Grotesk', sans-serif;
            transition: all 0.3s ease;
        }

        .shield-status-desc {
            font-size: 0.9rem;
            color: var(--text-muted);
            max-width: 400px;
        }

        /* Middle section: Level selector */
        .shield-level-cards {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }

        .level-card {
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }

        .level-card:hover { background: rgba(255,255,255,0.05); }
        .level-card.active { border-color: var(--accent); background: rgba(139, 92, 246, 0.1); }

        .level-card .lvl-icon { margin-bottom: 12px; display: inline-block; }
        .level-card .lvl-title { font-weight: 700; margin-bottom: 8px; font-size: 1.1rem; }
        .level-card .lvl-desc { font-size: 0.75rem; color: var(--text-muted); line-height: 1.4; }

        /* Active Badge for Level Card */
        .level-card .active-badge {
            display: none;
            position: absolute; top: 8px; right: 8px;
            background: var(--accent); color: #fff;
            font-size: 0.6rem; font-weight: bold;
            padding: 2px 6px; border-radius: 10px;
            animation: pulse-slow 2s infinite;
        }
        .level-card.active .active-badge { display: block; }
        
        .btn-full-ghost {
            width: 100%;
            margin-bottom: 30px;
            padding: 16px;
            border-radius: 12px;
            font-family: monospace;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            cursor: pointer;
            transition: all 0.3s ease;
            background: rgba(226, 75, 74, 0.1);
            border: 1px solid #e24b4a;
            color: #e24b4a;
        }
        .btn-full-ghost.active {
            background: rgba(226, 75, 74, 0.3);
            border: 2px solid #e24b4a;
            color: #ffdddd;
            box-shadow: 0 0 20px rgba(226, 75, 74, 0.5);
            animation: pulse-red 2s infinite;
        }
        @keyframes pulse-red {
            0% { box-shadow: 0 0 20px rgba(226, 75, 74, 0.5); }
            50% { box-shadow: 0 0 40px rgba(226, 75, 74, 0.8); }
            100% { box-shadow: 0 0 20px rgba(226, 75, 74, 0.5); }
        }
        
        .btn-disable-shield {
            background: rgba(239, 68, 68, 0.1);
            color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3);
            width: 100%; padding: 12px; margin-bottom: 30px;
            border-radius: 8px; font-weight: bold; letter-spacing: 1px;
            cursor: pointer; transition: 0.2s;
        }
        .btn-disable-shield:hover { background: rgba(239, 68, 68, 0.2); }

        /* Bottom Section: Threat Board */
        .threat-board {
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .threat-header {
            display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;
            padding-bottom: 10px; border-bottom: 1px solid var(--border);
        }

        .threat-list { display: flex; flex-direction: column; gap: 10px; max-height: 300px; overflow-y: auto; }

        .threat-item {
            background: rgba(0,0,0,0.2); border-radius: 8px; padding: 12px;
            display: flex; flex-direction: column;
            border-left: 4px solid var(--border);
            transition: all 0.2s;
        }
        
        .threat-item.safe { border-left-color: #10b981; }
        .threat-item.monitor { border-left-color: #f59e0b; }
        .threat-item.danger { border-left-color: #ef4444; cursor: pointer; }
        .threat-item.danger:hover { background: rgba(239, 68, 68, 0.1); }
        .threat-item.blocked { border-left-color: #6b7280; opacity: 0.6; }

        .threat-item-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
        .threat-item-bot { font-size: 0.75rem; color: var(--text-muted); display:flex; gap:10px;}

        .threat-score { font-family: monospace; font-weight: bold; background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; }
        .threat-score.high { color: #ef4444; background: rgba(239, 68, 68, 0.2); }

        .btn-block-device {
            display: none; width: 100%; margin-top: 10px; background: #ef4444; color: white;
            border: none; padding: 6px; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 0.8rem;
        }
        .threat-item.danger.expanded .btn-block-device { display: block; }
        .threat-item.blocked .btn-block-device { display: none; }
        .blocked-label { display: none; margin-top: 8px; color: #ef4444; font-size: 0.8rem; font-weight: bold; text-align: center; }
        .threat-item.blocked .blocked-label { display: block; }

        /* Stats Bar */
        .shield-stats {
            display: flex; justify-content: space-between;
            font-size: 0.75rem; color: var(--text-muted); background: rgba(0,0,0,0.4);
            padding: 12px 20px; border-radius: 8px; text-transform: uppercase; letter-spacing: 1px;
            font-weight: bold;
        }
        .shield-stats span strong { color: var(--text-primary); margin-left: 5px; font-size: 0.85rem;}

        @media (max-width: 600px) {
            .shield-level-cards { grid-template-columns: 1fr; }
            .shield-stats { flex-direction: column; gap: 8px; text-align: center; }
        }
    `;
    document.head.appendChild(style);

    // 2. Inject HTML Section
    const section = document.createElement('section');
    section.id = 'view-shield';
    section.className = 'view-section'; // standard hide/show class in GhostNet
    section.innerHTML = `
        <div class="home-hero" style="margin-bottom: 24px; padding: 0 24px; margin-top:20px;">
            <div class="home-hero-left">
                <h1 class="home-title">Ghost Shield</h1>
                <p class="home-subtitle">App cloaking and network defense</p>
            </div>
            <div class="home-hero-right">
                <span class="home-badge" style="border-color:#ef4444; color:#ef4444;" id="shield-header-badge">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    DEFENSIVE ONLY
                </span>
            </div>
        </div>

        <div class="shield-view-container">
            
            <!-- SHIELD STATUS BOX -->
            <div class="shield-status-box shield-level-0" id="shield-status-box">
                <div class="shield-icon-wrap">
                    <div class="shield-icon-bg"></div>
                    <svg class="shield-icon-inner" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    </svg>
                </div>
                <h2 class="shield-status-title shield-status-text" id="shield-main-text">GHOST SHIELD OFFLINE</h2>
                <p class="shield-status-desc">Activate a cloaking level to hide your app's presence from physical surveillance and network scanners.</p>
            </div>

            <!-- LEVEL SELECTOR -->
            <div class="shield-level-cards">
                <div class="level-card" onclick="GhostShieldUI.activateLevel(1)" id="card-lvl-1">
                    <div class="active-badge">ACTIVE</div>
                    <div class="lvl-icon" style="color:#0d9488;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/></svg>
                    </div>
                    <div class="lvl-title" style="color:#2dd4bf;">STEALTH</div>
                    <div class="lvl-desc">Stops BLE broadcasting, suppresses probe requests, enables secure DNS.</div>
                </div>

                <div class="level-card" onclick="GhostShieldUI.activateLevel(2)" id="card-lvl-2">
                    <div class="active-badge">ACTIVE</div>
                    <div class="lvl-icon" style="color:#7e22ce;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m12 12 4-4"/><path d="m12 12-4 4"/></svg>
                    </div>
                    <div class="lvl-title" style="color:#c084fc;">GHOST</div>
                    <div class="lvl-desc">Stealth + Encrypts & pads traffic sizes. Defeats timing analysis with delays.</div>
                </div>

                <div class="level-card" onclick="GhostShieldUI.activateLevel(3)" id="card-lvl-3">
                    <div class="active-badge">ACTIVE</div>
                    <div class="lvl-icon" style="color:#d97706;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    </div>
                    <div class="lvl-title" style="color:#fcd34d;">PHANTOM</div>
                    <div class="lvl-desc">Ghost + Fake device decoys, rapid MAC rotation, maximum mesh routing hops.</div>
                </div>
            </div>
            
            <button class="btn-full-ghost" id="btn-full-ghost" onclick="GhostShieldUI.toggleEnableAll()">
                ⚡ FULL GHOST PROTOCOL
            </button>

            <button class="btn-disable-shield" id="btn-disable-shield" onclick="GhostShieldUI.disable()" style="display:none;">
                DISABLE GHOST SHIELD
            </button>

            <!-- THREAT BOARD -->
            <div class="threat-board">
                <div class="threat-header">
                    <h3 style="margin:0; font-family:'Inter', sans-serif;">Signal Intelligence</h3>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span class="home-pulse" style="background:#10b981;"></span>
                        <span style="font-size:0.75rem; color:var(--text-muted); font-weight:bold;">SCANNING NEARBY</span>
                    </div>
                </div>
                <div class="threat-list" id="threat-list-container">
                    <div style="text-align:center; padding: 20px; color:var(--text-muted); font-size: 0.85rem;">
                        Scanning for signals...
                    </div>
                </div>
            </div>

            <!-- STATS BAR -->
            <div class="shield-stats">
                <span>Protected <strong id="stat-pkts">0</strong></span>
                <span>Blocked <strong id="stat-blocked">0</strong></span>
                <span>MAC Rotations <strong id="stat-macs">0</strong></span>
                <span>Uptime <strong id="stat-up">0s</strong></span>
            </div>

        </div>
    `;
    mainContent.appendChild(section);

    // 3. UI logic
    window.GhostShieldUI = {
        scanInterval: null,

        toggleEnableAll() {
            const status = window.GhostShield.getStatus();
            if (status.currentLevel === 'ALL') {
                window.GhostShield.disableAll();
            } else {
                window.GhostShield.enableAll();
            }
            this.updateView();
        },

        activateLevel(lvl) {
            window.GhostShield.enable(lvl);
            this.updateView();
        },

        disable() {
            window.GhostShield.disable();
            this.updateView();
        },

        updateView() {
            const status = window.GhostShield.getStatus();
            const box = document.getElementById('shield-status-box');
            const mainText = document.getElementById('shield-main-text');
            const disableBtn = document.getElementById('btn-disable-shield');
            
            box.className = `shield-status-box shield-level-${status.level}`;
            
            [1,2,3].forEach(l => {
                document.getElementById(`card-lvl-${l}`).classList.toggle('active', status.activeStates[l] === true);
            });
            
            const fullGhostBtn = document.getElementById('btn-full-ghost');
            if (status.currentLevel === 'ALL') {
                fullGhostBtn.classList.add('active');
                fullGhostBtn.innerText = '🔴 FULL PROTOCOL ACTIVE — TAP TO DISABLE';
            } else {
                fullGhostBtn.classList.remove('active');
                fullGhostBtn.innerText = '⚡ FULL GHOST PROTOCOL';
            }

            if (status.level === 0) {
                mainText.textContent = 'GHOST SHIELD OFFLINE';
                disableBtn.style.display = 'none';
            } else {
                mainText.textContent = `GHOST SHIELD ACTIVE — LEVEL ${status.level}`;
                if (status.currentLevel === 'ALL') {
                    mainText.textContent = 'GHOST SHIELD ACTIVE — MAX LEVEL';
                }
                disableBtn.style.display = 'block';
            }
        },

        toggleBlockView(el) {
            if (el.classList.contains('blocked')) return;
            el.classList.toggle('expanded');
        },

        blockMac(mac, event) {
            event.stopPropagation();
            window.GhostShield.blockDevice(mac);
            this.renderThreats();
        },

        unblockMac(mac, event) {
            event.stopPropagation();
            window.GhostShield.unblockDevice(mac);
            this.renderThreats();
        },

        formatUptime(sec) {
            if (sec < 60) return sec + 's';
            const m = Math.floor(sec / 60);
            return m + 'm ' + (sec % 60) + 's';
        },

        updateStats() {
            const status = window.GhostShield.getStatus();
            document.getElementById('stat-pkts').textContent = status.stats.packetsProtected;
            document.getElementById('stat-blocked').textContent = status.stats.devicesBlocked;
            document.getElementById('stat-macs').textContent = status.stats.macRotations;
            document.getElementById('stat-up').textContent = this.formatUptime(status.stats.uptime);
        },

        renderThreats() {
            const container = document.getElementById('threat-list-container');
            if(!container) return;

            if (!window.SignalIntelligence) return;

            const signals = window.SignalIntelligence.getSignalReport();
            
            if (signals.length === 0) {
                container.innerHTML = `<div style="text-align:center; padding: 20px; color:var(--text-muted); font-size: 0.85rem;">No devices detected.</div>`;
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
        },

        init() {
            this.updateView();
            // register listeners for live updates
            window.addEventListener('ghostShield:statsUpdated', () => this.updateStats());

            // Listen for real scan completions from SignalIntelService
            window.addEventListener('signalIntel:scanComplete', () => {
                this.renderThreats();
                this.updateStats();
            });

            // Render threats periodically (fallback if no scan events)
            this.scanInterval = setInterval(() => {
                this.renderThreats();
                this.updateStats();
            }, 3000);

            // Auto-start Signal Intelligence service if available
            if (window.SignalIntelService && !window.SignalIntelService.isActive()) {
                window.SignalIntelService.start();
            }
        }
    };

    window.GhostShieldUI.init();
});
