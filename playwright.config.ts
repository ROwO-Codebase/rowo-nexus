import { defineConfig, devices } from '@playwright/test';

import { RP_A_ORIGIN } from './tests/browser-e2e/origins.js';

export default defineConfig({
  testDir: './tests/browser-e2e',
  outputDir: './test-results/browser-e2e',
  fullyParallel: false,
  workers: 1,
  retries: process.env['CI'] === undefined ? 0 : 1,
  reporter: process.env['CI'] === undefined ? 'list' : [['line'], ['html', { open: 'never' }]],
  timeout: 90_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: RP_A_ORIGIN,
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        ...(process.env['CI'] === undefined ? { channel: 'chrome' as const } : {}),
      },
    },
  ],
  webServer: {
    command: 'pnpm exec tsx tests/browser-e2e/fixture-server.ts',
    url: `${RP_A_ORIGIN}/api/health`,
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
