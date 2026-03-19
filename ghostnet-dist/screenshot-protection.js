// screenshot-protection.js
(function() {
  // all screenshot protection logic here
  // no export, no import

  const style = document.createElement('style')
  style.innerHTML = `
    .ghost-protected { -webkit-touch-callout: none; -webkit-user-select: none; user-select: none; }
    .ghost-blur-overlay { position: fixed; inset: 0; backdrop-filter: blur(20px); z-index: 9999; display: none; }
    .ghost-blur-overlay.active { display: block; }
  `
  document.head.appendChild(style)

  document.addEventListener('keyup', function(e) {
    if (e.key === 'PrintScreen') navigator.clipboard?.writeText('')
  })

  document.addEventListener('contextmenu', function(e) {
    if (e.target.closest('.chat-message, .vault-file')) e.preventDefault()
  })

  document.addEventListener('visibilitychange', function() {
    const overlay = document.getElementById('ghost-blur-overlay')
    if (overlay) overlay.classList.toggle('active', document.hidden)
  })

  // Desktop blur on loss of focus
  window.addEventListener('blur', function() {
    const overlay = document.getElementById('ghost-blur-overlay')
    if (overlay) overlay.classList.add('active')
  })
  window.addEventListener('focus', function() {
    const overlay = document.getElementById('ghost-blur-overlay')
    if (overlay) overlay.classList.remove('active')
  })

  // Create overlay element
  const overlay = document.createElement('div')
  overlay.id = 'ghost-blur-overlay'
  overlay.className = 'ghost-blur-overlay'
  document.body.appendChild(overlay)
  
  console.log('🛡️ GhostNet Screenshot Protection Active');
})()
