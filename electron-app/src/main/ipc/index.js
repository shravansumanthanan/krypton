'use strict';

const registerConfig = require('./config.ipc');
const registerPqc = require('./pqc.ipc');
const registerSession = require('./session.ipc');
const registerSecurity = require('./security.ipc');
const registerDownloads = require('./downloads.ipc');
const registerShields = require('./shields.ipc');
const registerTokens = require('./token.ipc');
const registerBenchmarks = require('./benchmark.ipc');

function registerAllHandlers(ipcMain, services) {
  registerConfig(ipcMain, services);
  registerPqc(ipcMain, services);
  registerSession(ipcMain, services);
  registerSecurity(ipcMain, services);
  registerDownloads(ipcMain, services);
  registerShields(ipcMain, services);
  registerTokens(ipcMain, services);
  registerBenchmarks(ipcMain, services);
}

module.exports = { registerAllHandlers };
