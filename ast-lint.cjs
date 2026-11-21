const { ESLint } = require('./node_modules/eslint');

(async function main() {
  const eslint = new ESLint({
    useEslintrc: false,
    overrideConfig: {
      env: { es2022: true, node: true },
      parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
      rules: { 'no-undef': 'error', 'no-redeclare': 'error' }
    }
  });

  const results = await eslint.lintFiles(['kryptos-server.js']);
  const formatter = await eslint.loadFormatter('stylish');
  console.log(formatter.format(results));
})().catch(err => {
  console.error(err);
});
