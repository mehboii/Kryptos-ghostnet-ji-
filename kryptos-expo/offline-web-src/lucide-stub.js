(function () {
  'use strict';

  function renderIcon(name) {
    return (
      '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<circle cx="12" cy="12" r="9"></circle>' +
      `<text x="12" y="15" text-anchor="middle" font-size="7" fill="currentColor" stroke="none">${String(name || '?').slice(0, 1).toUpperCase()}</text>` +
      '</svg>'
    );
  }

  window.lucide = {
    createIcons() {
      document.querySelectorAll('[data-lucide]').forEach((el) => {
        const iconName = el.getAttribute('data-lucide');
        el.innerHTML = renderIcon(iconName);
      });
    }
  };
})();
