'use strict';
const { session } = require('electron');
const fs = require('fs');
const log = require('electron-log');
const { getConfigSync, setConfigSync } = require('../config/allowed-keys');

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
