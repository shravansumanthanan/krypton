'use strict';

const { getConfigSync, setConfigSync, ALLOWED_CONFIG_KEYS } = require('../config/allowed-keys');

module.exports = function registerConfigHandlers(ipcMain, services) {
  const { configPath } = services;

  // Config sync
  ipcMain.handle('get-config', async (e, key, def) => {
    if (typeof key !== 'string' || key.length > 64) return def;
    return getConfigSync(key, def);
  });

  ipcMain.handle('set-config', async (e, key, val) => {
    if (typeof key !== 'string' || !ALLOWED_CONFIG_KEYS.has(key)) return false;
    if (typeof val !== 'string' || val.length > 256) return false;
    setConfigSync(key, val);
    return true;
  });
};
