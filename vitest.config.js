import { defineConfig } from 'vitest/config';

// Task 7 adds a second project that runs tests/worker/index.test.js inside the
// Workers runtime; all other tests run in plain Node.
export default defineConfig({
  test: {
    include: ['tests/**/*.test.js'],
    exclude: ['tests/e2e/**', 'node_modules/**'],
  },
});
