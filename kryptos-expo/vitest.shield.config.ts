import { defineConfig } from 'vitest/config';

// Scoped Vitest config for the Ghost Shield module only, so it does not try to
// run under the React Native / Metro test environment.
// Run: npx vitest run --config vitest.shield.config.ts
export default defineConfig({
  test: {
    include: ['src/shield/**/*.test.ts'],
    environment: 'node',
    globals: false,
  },
});
