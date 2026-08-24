// @ts-check
const { defineConfig, devices } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests/visual",
  timeout: 30000,
  expect: {
    toHaveScreenshot: {
      // Allow up to 2% pixel difference before failing (anti-aliasing/font rendering tolerance)
      maxDiffPixelRatio: 0.02,
    },
  },
  reporter: [["html", { outputFolder: "playwright-report", open: "never" }]],
  use: {
    baseURL: process.env.VAP_TEST_URL || "http://127.0.0.1:8000",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  // Disable parallel execution for consistent screenshot comparison
  workers: 1,
});
