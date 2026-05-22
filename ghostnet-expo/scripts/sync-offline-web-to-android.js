const fs = require('fs');
const path = require('path');

const expoRoot = path.resolve(__dirname, '..');
const srcDir = path.join(expoRoot, 'offline-web');
const destDir = path.join(expoRoot, 'android', 'app', 'src', 'main', 'assets', 'offline-web');

function copyRecursive(src, dest) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      copyRecursive(path.join(src, entry), path.join(dest, entry));
    }
    return;
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}

if (!fs.existsSync(srcDir)) {
  throw new Error(`Offline web bundle not found at ${srcDir}`);
}

fs.rmSync(destDir, { recursive: true, force: true });
copyRecursive(srcDir, destDir);

console.log(`Synced offline web bundle to ${destDir}`);
