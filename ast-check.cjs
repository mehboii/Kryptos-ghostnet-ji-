const fs = require('fs');
const content = fs.readFileSync('kryptos-server.js', 'utf8');
try {
  const acorn = require('./node_modules/acorn/dist/acorn.js');
  acorn.parse(content, { ecmaVersion: 2022, sourceType: 'module' });
} catch (e) {
  console.log('Error found: ', e.message, e.loc);
}
