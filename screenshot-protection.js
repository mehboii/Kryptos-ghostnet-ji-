/**
 * GhostNet Screenshot Prevention Module
 * Isolated feature for cross-platform content protection.
 */

const style = document.createElement('style')
style.innerHTML = `
  .ghost-protected {
    -webkit-touch-callout: none;
    -webkit-user-select: none;
    user-select: none;
  }
  .ghost-blur-overlay {
    position: fixed;
    inset: 0;
    backdrop-filter: blur(20px);
    z-index: 9999;
    display: none;
  }
  .ghost-blur-overlay.active {
    display: block;
  }
`
document.head.appendChild(style)

/**
 * Initializes screenshot and content protection.
 * @param {string[]} sensitiveSelectors Array of CSS selectors to protect.
 */
export function initScreenshotProtection(sensitiveSelectors = ['.chat-message', '.vault-file']) {
  // 1. Desktop: Print Screen detection & Clipboard Clearing
  window.addEventListener('keyup', (e) => {
    if (e.key === 'PrintScreen') {
      try {
        navigator.clipboard.writeText('');
      } catch (err) {
        // Fallback for browsers that block clipboard write on keyup
        console.warn('[Security] Clipboard clearing failed', err);
      }
    }
  });

  // 2. Desktop: Right-click protection on sensitive elements
  document.addEventListener('contextmenu', (e) => {
    const isSensitive = sensitiveSelectors.some(selector => e.target.closest(selector));
    if (isSensitive) {
      e.preventDefault();
    }
  });

  // 3. Desktop & iOS: Blur Overlay when inactive
  const blurOverlay = document.createElement('div');
  blurOverlay.className = 'ghost-blur-overlay';
  document.body.appendChild(blurOverlay);

  const toggleOverlay = (active) => {
    if (active) blurOverlay.classList.add('active');
    else blurOverlay.classList.remove('active');
  };

  // Blur when window loses focus (Desktop)
  window.addEventListener('blur', () => toggleOverlay(true));
  window.addEventListener('focus', () => toggleOverlay(false));

  // Blur when tab becomes hidden (iOS / Desktop)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      toggleOverlay(true);
    } else {
      toggleOverlay(false);
    }
  });

  // 4. Mobile: Disable long-press and selection
  // Apply protection class to sensitive elements
  const applyProtection = () => {
    sensitiveSelectors.forEach(selector => {
      document.querySelectorAll(selector).forEach(el => {
        if (!el.classList.contains('ghost-protected')) {
          el.classList.add('ghost-protected');
        }
      });
    });
  };

  // Observer to handle dynamically added messages
  const observer = new MutationObserver(applyProtection);
  observer.observe(document.body, { childList: true, subtree: true });
  applyProtection();
}
