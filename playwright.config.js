import { defineConfig, devices } from '@playwright/test';
export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: true,
  workers: 2,
  timeout: 60_000,
  use: { baseURL: process.env.LIVE_URL || 'http://127.0.0.1:4173', acceptDownloads: true },
  webServer: process.env.LIVE_URL ? undefined : {
    command: 'node tools/serve.mjs', url: 'http://127.0.0.1:4173', reuseExistingServer: false,
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
});
