// Visual regression tests across mobile, tablet, and desktop breakpoints.
// Run via: npx playwright test tests/visual/
// Baseline screenshots are stored in tests/visual/snapshots/.

const { test, expect } = require("@playwright/test");

const BASE_URL = process.env.VAP_TEST_URL || "http://127.0.0.1:8000";

const VIEWPORTS = [
  { name: "mobile", width: 375, height: 812 },
  { name: "tablet", width: 768, height: 1024 },
  { name: "desktop", width: 1280, height: 800 },
  { name: "wide", width: 1920, height: 1080 },
];

const PAGES = [
  { name: "homepage", path: "/" },
  { name: "scans-list", path: "/scans" },
];

for (const viewport of VIEWPORTS) {
  for (const page of PAGES) {
    test(`${page.name} at ${viewport.name} (${viewport.width}x${viewport.height})`, async ({
      browser,
    }) => {
      const ctx = await browser.newContext({
        viewport: { width: viewport.width, height: viewport.height },
      });
      const browserPage = await ctx.newPage();

      await browserPage.goto(`${BASE_URL}${page.path}`, {
        waitUntil: "networkidle",
        timeout: 15000,
      });

      // Ensure critical structural elements are visible before snapshot
      await browserPage.waitForSelector("main", { timeout: 5000 });

      // Layout assertions: no horizontal overflow at any breakpoint
      const bodyWidth = await browserPage.evaluate(
        () => document.body.scrollWidth
      );
      expect(bodyWidth).toBeLessThanOrEqual(
        viewport.width + 2,
        `Horizontal overflow detected at ${viewport.name} breakpoint on ${page.name}`
      );

      // Screenshot snapshot for visual diff
      await expect(browserPage).toHaveScreenshot(
        `${page.name}-${viewport.name}.png`,
        {
          fullPage: true,
          maxDiffPixelRatio: 0.02,
        }
      );

      await ctx.close();
    });
  }
}

// Additional structural checks on homepage
test("homepage has no CDN Tailwind script tag", async ({ page }) => {
  await page.goto(`${BASE_URL}/`, { waitUntil: "networkidle" });
  const cdnScript = await page.$('script[src*="cdn.tailwindcss.com"]');
  expect(cdnScript).toBeNull();
});

test("homepage loads local tailwind.min.css", async ({ page }) => {
  await page.goto(`${BASE_URL}/`, { waitUntil: "networkidle" });
  const localCss = await page.$(
    'link[href*="tailwind.min.css"]'
  );
  expect(localCss).not.toBeNull();
});

test("homepage accessibility: skip link present", async ({ page }) => {
  await page.goto(`${BASE_URL}/`, { waitUntil: "networkidle" });
  const skipLink = await page.$('a.sr-only');
  expect(skipLink).not.toBeNull();
});

test("homepage main landmark present", async ({ page }) => {
  await page.goto(`${BASE_URL}/`, { waitUntil: "networkidle" });
  const main = await page.$("main");
  expect(main).not.toBeNull();
});
