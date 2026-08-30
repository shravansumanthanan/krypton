'use strict';
const path = require('path');

module.exports = function registerDownloadsHandlers(ipcMain, services) {
  const { downloadsMapGetter, shell, dialog, app, mainWindowGetter } = services;

  ipcMain.handle('get-downloads', async () => downloadsMapGetter());

  // Validate download paths — must be under the downloads directory to prevent path traversal
  function isValidDownloadPath(p) {
    if (typeof p !== 'string' || p.length === 0) return false;
    const resolved = path.resolve(p);
    const downloadsDir = path.resolve(app.getPath('downloads'));

    // Prevent directory traversal: must be inside the downloadsDir exactly
    const isInsideDownloads =
      resolved === downloadsDir || resolved.startsWith(downloadsDir + path.sep);
    const downloads = downloadsMapGetter();
    return isInsideDownloads || downloads.some((d) => d.savePath === resolved);
  }

  ipcMain.handle('open-download', async (e, p) => {
    if (!isValidDownloadPath(p)) return;
    try {
      shell.openPath(path.resolve(p));
    } catch {}
  });

  ipcMain.handle('show-download-in-folder', async (e, p) => {
    if (!isValidDownloadPath(p)) return;
    try {
      shell.showItemInFolder(path.resolve(p));
    } catch {}
  });

  ipcMain.handle('open-downloads-folder', async () => {
    try {
      shell.openPath(app.getPath('downloads'));
    } catch {}
  });

  ipcMain.handle('choose-download-path', async () => {
    const mainWindow = mainWindowGetter();
    const r = await dialog.showOpenDialog(mainWindow, {
      properties: ['openDirectory'],
      title: 'Choose Download Location',
    });
    return r.canceled ? null : r.filePaths[0];
  });
};
