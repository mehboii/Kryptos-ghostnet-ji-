const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..', '..');
const expoRoot = path.resolve(__dirname, '..');
const srcRoot = path.join(expoRoot, 'offline-web-src');
const outRoot = path.join(expoRoot, 'offline-web');
const outputFile = path.join(outRoot, 'index.html');

const scriptFiles = [
  'ghostnet-chat.js',
  'ghostnet-mesh.js',
  'ghostnet-file-vault.js',
  'ghosttag.js',
  'ghostnet-sync.js',
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
const lucideStub = read(path.join(srcRoot, 'lucide-stub.js'));

html = html.replace(/<link rel="preconnect" href="https:\/\/ghostnet-ji-production\.up\.railway\.app">\s*/g, '');
html = html.replace(/<link rel="dns-prefetch" href="https:\/\/ghostnet-ji-production\.up\.railway\.app">\s*/g, '');
html = html.replace(/<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com">\s*/g, '');
html = html.replace(/<link rel="preconnect" href="https:\/\/fonts\.gstatic\.com" crossorigin>\s*/g, '');
html = html.replace(/<link\s+href="https:\/\/fonts\.googleapis\.com[^>]+>\s*/g, '');
html = html.replace(/<link rel="icon" type="image\/x-icon" href="\/favicon\.ico">\s*/g, '');
html = html.replace(/<link rel="apple-touch-icon" href="\/favicon\.ico">\s*/g, '');
html = html.replace(
  '<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">',
  '<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">\n    <meta name="ghostnet-offline" content="true">'
);
html = html.replace(
  /<link rel="stylesheet" href="ui\.css">/,
  `<style>\nbody { font-family: "Segoe UI", sans-serif; }\n${uiCss}\n</style>`
);

html = html.replace(
  /<!-- Core Libraries -->[\s\S]*?<script\s+src="https:\/\/unpkg\.com\/lucide@0\.344\.0"[\s\S]*?<\/script>/,
  [
    '<!-- Core Libraries (bundled for offline mode) -->',
    inlineScriptTag(ethersLocal),
    inlineScriptTag(lucideStub),
    inlineScriptTag(offlineBridge)
  ].join('\n')
);

for (const fileName of scriptFiles) {
  const sourcePath = path.join(repoRoot, fileName);
  const script = transformScript(fileName, read(sourcePath));
  const tagPattern = new RegExp(`<script src="${fileName.replace(/\./g, '\\.')}"><\\/script>`, 'g');
  html = html.replace(tagPattern, inlineScriptTag(script));
}

fs.mkdirSync(outRoot, { recursive: true });
fs.writeFileSync(outputFile, html, 'utf8');
console.log(`Offline bundle written to ${outputFile}`);
