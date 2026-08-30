'use strict';
const { session } = require('electron');
const fs = require('fs');
const log = require('electron-log');
const { getConfigSync, setConfigSync } = require('../config/allowed-keys');
const { triggerPanic } = require('../main'); // Not accessible directly like this if triggerPanic isn't exported. Let's see how triggerPanic is implemented. I should probably get it from somewhere or move it.
// Oh wait, `set-panic-shortcut` needs to register `triggerPanic`. I'll have to export `triggerPanic` from `main.js` or define it inside the handler, or pass it via services. The prompt says "triggerPanic() function" must be kept in main.js, so I need to pass it via services or something? Wait, the prompt says "triggerPanic() function" DO NOT move. So I will add it to the services object in main.js. Let's check what services are passed:
// The prompt says: "The services object shape you used in `registerAllHandlers` call". So I will add `triggerPanic` to the services object.

module.exports = function registerSessionHandlers(ipcMain, services) {
  const {
    pqcEngine,
    pqcSessionService,
    pqcCertValidator,
    mainWindowGetter,
    globalShortcut,
    dialog,
    shell,
    app,
    triggerPanic,
  } = services;

  // PQC Session Log — now backed by SQLite via pqcEngine delegation
  ipcMain.handle('pqc-get-sessions', async () => pqcEngine.getSessionLog(100));

  ipcMain.handle('pqc-get-stats', async () => pqcEngine.getSessionStats());

  // PQC OCSP Status for current domain
  ipcMain.handle('pqc-get-ocsp-status', async (e, domain) => {
    if (typeof domain !== 'string' || domain.length === 0 || domain.length > 253) {
      return { result: 'unknown', warning: true, message: 'Invalid domain' };
    }
    return pqcCertValidator.checkOCSP(domain);
  });

  // Session / Private mode
  ipcMain.handle('clear-session-data', async () => {
    try {
      const ses = session.fromPartition('burner-session');
      await ses.clearStorageData({ storages: ['cookies', 'cachestorage', 'serviceworkers'] });
      await ses.clearCache();
      return true;
    } catch {
      return false;
    }
  });

  // History Export
  ipcMain.handle('export-history', async (e, historyJsonString) => {
    try {
      const mainWindow = mainWindowGetter();
      const { filePath } = await dialog.showSaveDialog(mainWindow, {
        title: 'Export History',
        defaultPath: 'krypton_history.json',
        filters: [{ name: 'JSON', extensions: ['json'] }],
      });
      if (filePath) {
        await fs.promises.writeFile(filePath, historyJsonString, 'utf-8');
        return true;
      }
      return false;
    } catch (err) {
      log.error('[History] Export failed:', err.message);
      return false;
    }
  });

  ipcMain.handle('set-panic-shortcut', async (e, shortcutStr) => {
    if (typeof shortcutStr !== 'string' || shortcutStr.length > 64) return false;
    const oldShortcut = getConfigSync('krypton_panic_shortcut', 'CommandOrControl+Shift+Escape');
    globalShortcut.unregister(oldShortcut);
    try {
      const success = globalShortcut.register(shortcutStr, triggerPanic);
      if (!success) throw new Error('Failed to register shortcut');
      setConfigSync('krypton_panic_shortcut', shortcutStr);
      return true;
    } catch (err) {
      globalShortcut.register(oldShortcut, triggerPanic);
      return false;
    }
  });
};
