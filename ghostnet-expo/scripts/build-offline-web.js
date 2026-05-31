const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..', '..');
const expoRoot = path.resolve(__dirname, '..');
const srcRoot = path.join(expoRoot, 'offline-web-src');
const outRoot = path.join(expoRoot, 'offline-web');
const outputFile = path.join(outRoot, 'index.html');

// GN_MODE=online builds a bundle that talks to the live backend (real-time WS,
// cross-device messaging). Default = offline standalone (localStorage shim).
const ONLINE = process.env.GN_MODE === 'online';

const scriptFiles = [
  'ghostnet-chat.js',
  'ghostnet-mesh.js',
  'ghostnet-file-vault.js',
  'ghosttag.js',
  'ghostnet-sync.js',
  'ghostnet-nat.js',
  'app.js',
  'shieldConfig.js',
  'signal-intelligence.js',
  'ghost-radar.js',
  'ghost-shield.js',
  'signalIntel.js',
  'ghost-shield-ui.js',
  'ghost-radar-ui.js',
  'mesh-hardening.js',
  'proximity-connect.js',
  'proximity-connect-ui.js',
  'crypto-identity.js',
  'jsQR.js',
  'qrcode.min.js',
  'screenshot-protection.js',
  'ui.js'
];

function read(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

function escapeInlineScript(text) {
  return text.replace(/<\/script/gi, '<\\/script');
}

function inlineScriptTag(text) {
  return `<script>\n${escapeInlineScript(text)}\n</script>`;
}

function transformScript(name, text) {
  // Online build: keep the original sources as-is. They already point at the
  // live backend (Railway), and the offline guards (window.__GHOSTNET_OFFLINE__)
  // stay inert because the offline-bridge that sets that flag is not injected.
  if (ONLINE) return text;

  let output = text;

  if (name === 'app.js') {
    output = output
      .replace(/var BACKEND = \{[\s\S]*?\};/, [
        'var BACKEND = {',
        "    http: (window.__GHOSTNET_BACKEND__ || 'https://ghostnet-offline.local'),",
        "    ws: 'wss://ghostnet-offline.local/ws',",
        "    url: (path) => `${window.__GHOSTNET_BACKEND__ || 'https://ghostnet-offline.local'}${path}`",
        '};'
      ].join('\n'))
      .replace(
        /if \(window\.location\.protocol === 'file:'\) \{[\s\S]*?\n    \}/,
        "if (window.__GHOSTNET_OFFLINE__) {\n        console.log('[GhostNet] Offline standalone mode active.');\n    }"
      );
  }

  if (name === 'ui.js') {
    output = output
      .replace(
        "const BACKEND_URL = 'https://ghostnet-ji-production.up.railway.app';",
        "const BACKEND_URL = window.__GHOSTNET_BACKEND__ || 'https://ghostnet-offline.local';"
      )
      .replace(
        /setInterval\(\(\) => \{\n            if \(navigator\.onLine\) \{\n                fetch\('https:\/\/ghostnet-ji-production\.up\.railway\.app\/health', \{ method: 'GET' \}\)\n                    \.catch\(\(\) => \{\}\);\n            \}\n        \}, 4 \* 60 \* 1000\);/,
        "setInterval(() => {\n            if (!window.__GHOSTNET_OFFLINE__ && navigator.onLine) {\n                fetch(`${BACKEND_URL}/health`, { method: 'GET' }).catch(() => {});\n            }\n        }, 4 * 60 * 1000);"
      );
  }

  if (name === 'ghostnet-mesh.js') {
    output = output.replace(
      /buildWsUrl\(\) \{[\s\S]*?return 'wss:\/\/ghostnet-ji-production\.up\.railway\.app\/ws';\n    \}/,
      [
        'buildWsUrl() {',
        '        if (window.__GHOSTNET_OFFLINE__) return null;',
        "        const meta = document.querySelector('meta[name=\"ghostnet-ws-url\"]');",
        '        if (meta && meta.content) return meta.content;',
        "        return 'wss://ghostnet-ji-production.up.railway.app/ws';",
        '    }'
      ].join('\n')
    ).replace(
      /const token = this\.authToken \|\| this\.getAuthToken\(\);\n        if \(token\) \{\n            this\.connectWebSocket\(\);\n        \} else \{\n            console\.log\('🔌 Mesh: Standing by for authentication before connecting\.'\);\n        \}/,
      "const token = this.authToken || this.getAuthToken();\n        if (window.__GHOSTNET_OFFLINE__) {\n            this.wsReady = false;\n            this.onStatusChange({ state: 'offline', transport: 'local' });\n        } else if (token) {\n            this.connectWebSocket();\n        } else {\n            console.log('🔌 Mesh: Standing by for authentication before connecting.');\n        }"
    );
  }

  return output;
}

let html = read(path.join(repoRoot, 'index.html'));
const uiCss = read(path.join(repoRoot, 'ui.css'));
const ethersLocal = read(path.join(repoRoot, 'ethers.umd.min.js'));
const offlineBridge = read(path.join(srcRoot, 'offline-bridge.js'));
// Prefer the real Lucide icon library (bundled offline). Fall back to the
// placeholder stub only if the package isn't installed.
const lucideRealPath = path.join(expoRoot, 'node_modules', 'lucide', 'dist', 'umd', 'lucide.js');
const lucideLib = fs.existsSync(lucideRealPath)
  ? read(lucideRealPath)
  : read(path.join(srcRoot, 'lucide-stub.js'));
if (!fs.existsSync(lucideRealPath)) {
  console.warn('[build] WARNING: real lucide not found — using placeholder stub icons.');
}

html = html.replace(/<link rel="preconnect" href="https:\/\/ghostnet-ji-production\.up\.railway\.app">\s*/g, '');
html = html.replace(/<link rel="dns-prefetch" href="https:\/\/ghostnet-ji-production\.up\.railway\.app">\s*/g, '');
html = html.replace(/<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com">\s*/g, '');
html = html.replace(/<link rel="preconnect" href="https:\/\/fonts\.gstatic\.com" crossorigin>\s*/g, '');
html = html.replace(/<link\s+href="https:\/\/fonts\.googleapis\.com[^>]+>\s*/g, '');
html = html.replace(/<link rel="icon" type="image\/x-icon" href="\/favicon\.ico">\s*/g, '');
html = html.replace(/<link rel="apple-touch-icon" href="\/favicon\.ico">\s*/g, '');
if (!ONLINE) {
  html = html.replace(
    '<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">',
    '<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">\n    <meta name="ghostnet-offline" content="true">'
  );
}
html = html.replace(
  /<link rel="stylesheet" href="ui\.css">/,
  `<style>\nbody { font-family: "Segoe UI", sans-serif; }\n${uiCss}\n</style>`
);

html = html.replace(
  /<meta http-equiv="Content-Security-Policy"[^>]*>/,
  `<meta http-equiv="Content-Security-Policy"
      content="default-src * 'unsafe-inline' 'unsafe-eval' data: blob: file:; script-src * 'unsafe-inline' 'unsafe-eval' file:; style-src * 'unsafe-inline' file:; font-src * data: file:; img-src * data: blob: file:; connect-src * wss: ws: data: blob: file:; worker-src * blob: file:; object-src 'none'; frame-ancestors 'none';">`
);

html = html.replace(
  /<!-- Core Libraries -->[\s\S]*?<script\s+src="https:\/\/unpkg\.com\/lucide@0\.344\.0"[\s\S]*?<\/script>/,
  () => {
    const libs = [
      '<!-- Core Libraries (bundled) -->',
      inlineScriptTag(ethersLocal),
      inlineScriptTag(lucideLib)
    ];
    // Offline shim only in offline mode; online mode talks to the real backend.
    if (!ONLINE) libs.push(inlineScriptTag(offlineBridge));
    return libs.join('\n');
  }
);

for (const fileName of scriptFiles) {
  const sourcePath = path.join(repoRoot, fileName);
  const script = transformScript(fileName, read(sourcePath));
  const tagPattern = new RegExp(`<script src="${fileName.replace(/\./g, '\\.')}"><\\/script>`, 'g');
  html = html.replace(tagPattern, () => inlineScriptTag(script));
}

fs.mkdirSync(outRoot, { recursive: true });
fs.writeFileSync(outputFile, html, 'utf8');
console.log(`${ONLINE ? 'ONLINE' : 'Offline'} bundle written to ${outputFile}`);
