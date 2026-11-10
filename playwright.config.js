import { defineConfig, devices } from '@playwright/test';

const PORT = 8787;

// `npm run test:e2e` builds, serves dist/ plus the Worker with `wrangler dev`
// (so the real _headers CSP applies), and drives Chromium against it.
export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  retries: 0,
  use: { baseURL: `http://127.0.0.1:${PORT}`, ...devices['Desktop Chrome'] },
  webServer: {
    command: `npx wrangler dev --port ${PORT} --ip 127.0.0.1`,
    url: `http://127.0.0.1:${PORT}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: { WRANGLER_SEND_METRICS: 'false' },
  },
});
