// KryptonBrowser — Browser Chrome Preload Script
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kryptonBrowser', {
    platform: process.platform,
    version: '1.0.0',
    electronVersion: process.versions.electron,
    chromeVersion: process.versions.chrome,

    // ── Security info ──
    getCertificateInfo: (url) => ipcRenderer.invoke('get-certificate-info', url),
    getSecurityInfo: (url) => ipcRenderer.invoke('get-security-info', url),

    // ── Blocking stats ──
    getBlockingStats: () => ipcRenderer.invoke('get-blocking-stats'),
    getSiteBlockCount: (pageUrl) => ipcRenderer.invoke('get-site-block-count', pageUrl),
    getAllSiteStats: () => ipcRenderer.invoke('get-all-site-stats'),

    // ── Config sync (main process enforces) ──
    getConfig: (key, def) => ipcRenderer.invoke('get-config', key, def),
    setConfig: (key, val) => ipcRenderer.invoke('set-config', key, val),

    // ── PQC Engine ──
    pqcSelfTest: () => ipcRenderer.invoke('pqc-selftest'),
    pqcKeygen: () => ipcRenderer.invoke('pqc-keygen'),
    pqcEncapsulate: (pk) => ipcRenderer.invoke('pqc-encapsulate', pk),
    pqcDsaKeygen: () => ipcRenderer.invoke('pqc-dsa-keygen'),
    pqcGetSessions: () => ipcRenderer.invoke('pqc-get-sessions'),
    pqcGetStats: () => ipcRenderer.invoke('pqc-get-stats'),

    // ── Downloads ──
    getDownloads: () => ipcRenderer.invoke('get-downloads'),
    openDownload: (p) => ipcRenderer.invoke('open-download', p),
    showDownloadInFolder: (p) => ipcRenderer.invoke('show-download-in-folder', p),
    openDownloadsFolder: () => ipcRenderer.invoke('open-downloads-folder'),
    chooseDownloadPath: () => ipcRenderer.invoke('choose-download-path'),

    // ── Private mode ──
    clearSessionData: () => ipcRenderer.invoke('clear-session-data'),

    // ── Main → Renderer events ──
    onNavigateTo: (cb) => ipcRenderer.on('navigate-to', (e, url) => cb(url)),
    onNewTab: (cb) => ipcRenderer.on('new-tab', () => cb()),
    onCloseTab: (cb) => ipcRenderer.on('close-tab', () => cb()),
    onFocusUrlBar: (cb) => ipcRenderer.on('focus-url-bar', () => cb()),
    onReloadPage: (cb) => ipcRenderer.on('reload-page', () => cb()),
    onShowSecurityInfo: (cb) => ipcRenderer.on('show-security-info', () => cb()),
    onOpenUrlInNewTab: (cb) => ipcRenderer.on('open-url-in-new-tab', (e, url) => cb(url)),
    onToggleFindBar: (cb) => ipcRenderer.on('toggle-find-bar', () => cb()),
    onDownloadStarted: (cb) => ipcRenderer.on('download-started', (e, info) => cb(info)),
    onDownloadUpdated: (cb) => ipcRenderer.on('download-updated', (e, info) => cb(info)),
    onDownloadDone: (cb) => ipcRenderer.on('download-done', (e, info) => cb(info)),
    onPermissionRequest: (cb) => ipcRenderer.on('permission-request', (e, d) => cb(d)),
    onClearBrowsingData: (cb) => ipcRenderer.on('clear-browsing-data', () => cb()),
    onMenuAction: (cb) => ipcRenderer.on('menu-action', (e, action) => cb(action)),
});
