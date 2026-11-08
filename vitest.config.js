import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-plugin';

// Two projects: plain Node for everything, and the Workers runtime (workerd via
// Miniflare) for the Worker entry test, which needs Cache API and SELF.fetch.
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'node',
          include: ['tests/**/*.test.js'],
          exclude: ['tests/e2e/**', 'tests/worker/index.test.js', 'node_modules/**'],
        },
      },
      {
        plugins: [cloudflareTest({ wrangler: { configPath: './wrangler.jsonc' } })],
        test: {
          name: 'workers',
          include: ['tests/worker/index.test.js'],
        },
      },
    ],
  },
});
