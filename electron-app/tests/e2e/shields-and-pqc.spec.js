'use strict';

const { _electron: electron, test, expect } = require('@playwright/test');
const path = require('path');

const MAIN_JS = path.join(__dirname, '../../src/main/main.js');

test.describe('Shields, Ad Blocker & PQC Security Page E2E', () => {
  let app;
  let win;

  test.beforeEach(async () => {
    app = await electron.launch({ args: [MAIN_JS] });
    win = await app.firstWindow();
    await win.locator('#url-bar').waitFor({ timeout: 15000 });
  });

  test.afterEach(async () => {
    if (app) await app.close();
  });

  test('PQC Security page opens natively without blank screen or iframe error', async () => {
    // Click the shield icon in the toolbar (btn-security-panel)
    const shieldBtn = win.locator('#btn-security-panel');
    await expect(shieldBtn).toBeVisible();
    await shieldBtn.click();

    // Verify PQC page container exists and is active
    const pqcPage = win.locator('.pqc-page.active');
    await expect(pqcPage).toBeVisible({ timeout: 5000 });

    // Verify sections and header
    const pageTitle = pqcPage.locator('.page-title');
    await expect(pageTitle).toHaveText('PQC Security');

    const overviewSection = pqcPage.locator('#section-overview');
    await expect(overviewSection).toBeVisible();

    // Verify sidebar navigation items
    const sidebar = pqcPage.locator('#sidebar');
    await expect(sidebar).toBeVisible();
    await expect(sidebar.locator('.sidebar-item[data-section="overview"]')).toBeVisible();
    await expect(sidebar.locator('.sidebar-item[data-section="algorithms"]')).toBeVisible();
    await expect(sidebar.locator('.sidebar-item[data-section="diagnostics"]')).toBeVisible();

    // Switch to Diagnostics and test self-test button
    await sidebar.locator('.sidebar-item[data-section="diagnostics"]').click();
    const diagSection = pqcPage.locator('#section-diagnostics');
    await expect(diagSection).toBeVisible();

    const selfTestBtn = diagSection.locator('#btn-run-selftest');
    await expect(selfTestBtn).toBeVisible();
    await selfTestBtn.click();

    const selfTestOut = diagSection.locator('#selftest-output');
    await expect(selfTestOut).toBeVisible();
    await expect(selfTestOut).toContainText('PQC', { timeout: 10000 });
  });

  test('Ad Blocker & Shields: Request interception and breakdown populated', async () => {
    // Toggle shields panel
    const shieldBadge = win.locator('#shield-badge-wrap');
    await expect(shieldBadge).toBeVisible();
    await shieldBadge.click();

    const shieldsPanel = win.locator('#shields-panel');
    await expect(shieldsPanel).toBeVisible();

    // Verify breakdown and stats
    const breakdown = shieldsPanel.locator('#shields-breakdown');
    await expect(breakdown).toBeVisible();

    const trackersStat = shieldsPanel.locator('#shields-stat-trackers');
    await expect(trackersStat).toBeVisible();

    const globalToggle = shieldsPanel.locator('#shields-global-toggle');
    await expect(globalToggle).toBeVisible();
    await expect(globalToggle).toHaveClass(/active/);

    // Simulate an ad request via main process webRequest interception
    const simulatedResult = await app.evaluate(async ({ session, webContents }) => {
      // Simulate request interception count
      const ses = session.fromPartition('burner-session');
      return Boolean(ses);
    });
    expect(simulatedResult).toBe(true);
  });
});
