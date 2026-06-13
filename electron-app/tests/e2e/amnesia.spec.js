const { _electron: electron } = require('@playwright/test');
const { test, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

test.describe('Krypton Ephemeral Burner Session', () => {
  test('Amnesia: ensures volatile directory is completely shredded on exit', async () => {
    // Launch Electron app.
    const electronApp = await electron.launch({
      args: [path.join(__dirname, '../../src/main', 'main.js')],
    });

    // Wait for the first window
    const window = await electronApp.firstWindow();

    // Ensure the app has fully initialized and the path is set
    await window.locator('#url-bar').waitFor();

    // Retrieve the userData path from the main process
    const userDataPath = await electronApp.evaluate(async ({ app }) => {
      return app.getPath('userData');
    });

    // Verify it is a burner directory
    expect(userDataPath).toContain('krypton-burner-');
    expect(fs.existsSync(userDataPath)).toBe(true);

    // Write a dummy file to the directory to simulate session activity
    const dummyFile = path.join(userDataPath, 'test-cookie-simulation.db');
    fs.writeFileSync(dummyFile, 'dummy data');
    expect(fs.existsSync(dummyFile)).toBe(true);

    // Close the app gracefully
    await electronApp.close();

    // Verify forensic shredding: the directory should no longer exist
    expect(fs.existsSync(userDataPath)).toBe(false);
  });

  test('Panic Button: is globally registered', async () => {
    const electronApp = await electron.launch({
      args: [path.join(__dirname, '../../src/main', 'main.js')],
    });
    
    const window = await electronApp.firstWindow();
    await window.locator('#url-bar').waitFor();

    // In Playwright we cannot easily simulate OS-level global shortcuts.
    // We verify the shortcut is registered.
    const isRegistered = await electronApp.evaluate(({ globalShortcut }) => {
      return globalShortcut.isRegistered('CommandOrControl+Shift+Escape');
    });

    expect(isRegistered).toBe(true);

    await electronApp.close();
  });
});
