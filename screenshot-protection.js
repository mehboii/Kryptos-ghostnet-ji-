/**
 * GhostNet Screenshot & Privacy Protection
 * Isolated module to prevent unauthorized captures and interactions on sensitive screens.
 */

(function() {
    'use strict';

    const SENSITIVE_IDS = ['view-chat', 'view-vault', 'view-profile', 'id-screen-sync_export'];
    
    // ─── STYLES Injection ──────────────────────────────────────────────────
    const style = document.createElement('style');
    style.textContent = `
        /* Disable long-press and selection on sensitive areas for mobile */
        .view-section-protected {
            -webkit-touch-callout: none !important;
            -webkit-user-select: none !important;
            -khtml-user-select: none !important;
            -moz-user-select: none !important;
            -ms-user-select: none !important;
            user-select: none !important;
        }

        /* Screen Capture Alert Overlay */
        #ghostnet-privacy-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(13, 17, 23, 0.98);
            z-index: 99999;
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: #ff3e3e;
            font-family: 'SF Mono', 'Fira Code', monospace;
            text-align: center;
            backdrop-filter: blur(10px);
        }

        .privacy-icon {
            margin-bottom: 20px;
            filter: drop-shadow(0 0 15px rgba(255, 62, 62, 0.5));
        }

        .privacy-text {
            font-weight: 800;
            letter-spacing: 2px;
            font-size: 1.2rem;
            text-transform: uppercase;
        }
    `;
    document.head.appendChild(style);

    // ─── UI ELEMENTS ────────────────────────────────────────────────────────
    const overlay = document.createElement('div');
    overlay.id = 'ghostnet-privacy-overlay';
    overlay.innerHTML = `
        <div class="privacy-icon">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                <line x1="12" y1="8" x2="12" y2="12"/>
                <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
        </div>
        <div class="privacy-text">SECURITY PROTOCOL TRIGGERED</div>
        <div style="margin-top:10px; color:var(--text-muted); font-size:0.8rem;">SCREEN CAPTURE DETECTED OR UNAUTHORIZED ACTION</div>
        <button onclick="this.parentElement.style.display='none'" style="margin-top:30px; background:transparent; border:1px solid #ff3e3e; color:#ff3e3e; padding:8px 20px; border-radius:4px; cursor:pointer; font-weight:bold;">DISMISS</button>
    `;
    document.body.appendChild(overlay);

    // ─── PROTECTION LOGIC ──────────────────────────────────────────────────
    
    function isSensitiveActive() {
        return SENSITIVE_IDS.some(id => {
            const el = document.getElementById(id);
            return el && el.style.display !== 'none' && getComputedStyle(el).display !== 'none';
        });
    }

    function triggerAlert() {
        overlay.style.display = 'flex';
        // Auto-hide after 3 seconds
        setTimeout(() => {
            overlay.style.display = 'none';
        }, 3000);
    }

    // 1. Right-Click Protection
    document.addEventListener('contextmenu', (e) => {
        if (isSensitiveActive()) {
            e.preventDefault();
            triggerAlert();
        }
    }, false);

    // 2. Print Screen / Capture Detection (Desktop)
    window.addEventListener('keyup', (e) => {
        if (e.key === 'PrintScreen' || e.keyCode === 44) {
            navigator.clipboard.writeText('GhostNet Protection: Screen capture disabled for sensitive content.');
            triggerAlert();
        }
    });

    // 3. Command+Shift+3/4 (Mac) / Win+Shift+S (Win) detection attempt
    // Note: Browsers can't fully block these, but we can detect keys
    document.addEventListener('keydown', (e) => {
        const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0;
        const cmdKey = isMac ? e.metaKey : e.ctrlKey;
        
        // Detection for common screenshot shortcuts
        if ((cmdKey && e.shiftKey && (e.key === '3' || e.key === '4' || e.key === 's')) || 
            (e.key === 'PrintScreen')) {
            if (isSensitiveActive()) {
                triggerAlert();
            }
        }
    });

    // 4. Mobile Long-Press / Drag Protection
    // We add a class to sensitive sections to use the CSS protection
    function applyMobileProtection() {
        SENSITIVE_IDS.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('view-section-protected');
        });
    }

    // Init protection
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyMobileProtection);
    } else {
        applyMobileProtection();
    }

    console.log('🛡️ GhostNet Screenshot Protection Active');
})();
