const { _electron: electron } = require('@playwright/test');
const { test, expect } = require('@playwright/test');
const path = require('path');

test('Launch KryptonBrowser and check UI', async () => {
  // Launch Electron app.
  const electronApp = await electron.launch({
    args: [path.join(__dirname, '..', 'main.js')]
  });

  // Evaluate an expression in the main process to ensure it's loaded
  const isPackaged = await electronApp.evaluate(async ({ app }) => {
    return app.isPackaged;
  });
  expect(isPackaged).toBe(false);

  // Wait for the first BrowserWindow to open and get its page object
  const window = await electronApp.firstWindow();
  
  // Take a screenshot of the initial state
  await window.screenshot({ path: 'tests/screenshot-startup.png' });

  // Verify the title
  const title = await window.title();
  expect(title).toContain('KryptonBrowser');

  // Verify that the UI elements are present
  const urlBar = await window.locator('#url-bar');
  await expect(urlBar).toBeVisible();

  // Close app
  await electronApp.close();
});
