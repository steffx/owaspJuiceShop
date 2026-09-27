import { defineConfig } from '@playwright/test';

const BASE_URL = process.env.JUICE_SHOP_URL || 'http://localhost:3000';

export default defineConfig({
  testDir: './tests',
  globalSetup: './src/global-setup.js',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ['list'],
    ['html', { open: 'never' }],
    ['json', { outputFile: 'results/results.json' }],
    ['junit', { outputFile: 'results/junit.xml' }],
  ],
  use: {
    baseURL: BASE_URL,
    ignoreHTTPSErrors: true,
    extraHTTPHeaders: { Accept: 'application/json' },
  },
  projects: [
    // Pure-logic checks of the helpers: no Juice Shop needed, always runnable.
    { name: 'unit', testDir: './tests/unit' },
    // The rest need a running Juice Shop at JUICE_SHOP_URL.
    { name: 'functional', testDir: './tests/functional', dependencies: [] },
    { name: 'security', testDir: './tests/security' },
    { name: 'coverage', testDir: './tests/coverage', dependencies: ['security'] },
  ],
});
