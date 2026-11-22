// Regression: local HTTP policy + unavailable CDNs must not trap startup.
// PLAYWRIGHT_MODULE=/path/to/playwright node tools/check-local-startup.cjs
const assert = require('node:assert/strict');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage();
    // Never send test traffic to production APIs or websocket peers.
    await page.route('**/*', route => new URL(route.request().url()).origin === 'http://localhost:8080' ? route.continue() : route.abort());
    await page.routeWebSocket(/.*/, socket => socket.close());
    let navigations = 0;
    const errors = [];
    page.on('framenavigated', frame => { if (frame === page.mainFrame()) navigations++; });
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://localhost:8080/', { waitUntil: 'domcontentloaded' });
    await page.locator('#kryptos-splash-overlay').waitFor({ state: 'detached', timeout: 3000 });
    await page.locator('.brand-emblem img').evaluate(image => image.decode());
    assert(await page.locator('.nav-btn svg').count() >= 9, 'navigation icons load without CDN access');
    await page.locator('#onboard-skip-btn').click();
    await page.locator('.nav-btn[data-target="home"]').click();
    assert(await page.locator('#view-home').isVisible());
    await page.locator('.nav-btn[data-target="profile"]').click();
    await page.getByRole('button', { name: 'Create New Identity', exact: true }).click();
    await page.locator('#id-display-name').fill('Startup check');
    await page.waitForTimeout(2200);
    assert.equal(await page.locator('#id-display-name').inputValue(), 'Startup check');
    assert.equal(navigations, 1, 'CDN failure must not trigger reloads');
    assert.deepEqual(errors, [], 'no uncaught startup errors');
    console.log('PASS: splash dismissal, onboarding, navigation, inline identity action, no reload loop, no uncaught errors; external requests blocked.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
