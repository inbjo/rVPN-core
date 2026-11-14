import { defineConfig } from '@playwright/test'
// Keep local test traffic direct even on developer machines using a proxy.
process.env.NO_PROXY = [
  process.env.NO_PROXY,
  process.env.no_proxy,
  '127.0.0.1',
  'localhost',
]
  .filter(Boolean)
  .join(',')
process.env.no_proxy = process.env.NO_PROXY
export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  use: {
    baseURL: 'http://127.0.0.1:5173',
    browserName: 'chromium',
    launchOptions: {
      executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    },
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'npm run dev -- --port 5173 --strictPort',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: !process.env.CI,
  },
})
