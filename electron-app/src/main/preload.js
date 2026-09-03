// KryptonBrowser — Browser Chrome Preload Script
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

let webviewPreloadPath = 'preload-webview.js';
try {
  const arg = process.argv && process.argv.find((a) => a.startsWith('--webview-preload-path='));
  if (arg) {
    webviewPreloadPath = 'file://' + arg.split('=').slice(1).join('=');
  }
} catch {
  /* ignore */
}

contextBridge.exposeInMainWorld('kryptonBrowser', {
  platform: process.platform,
  version: '1.0.0',
  electronVersion: process.versions.electron,
  chromeVersion: process.versions.chrome,
  webviewPreloadPath,

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
  // PQC extended (Phase 2–5 integrations)
  pqcGetOcspStatus: (domain) => ipcRenderer.invoke('pqc-get-ocsp-status', domain),
  pqcGetKeyPool: (count) => ipcRenderer.invoke('pqc-get-key-pool', count),
  pqcGetLiboqsVersion: () => ipcRenderer.invoke('pqc-get-liboqs-version'),

  // PQC crypto-agility
  pqcKeygenAgile: (algorithm) => ipcRenderer.invoke('pqc-keygen-agile', algorithm),
  pqcEncapsulateAgile: (algorithm, pk) =>
    ipcRenderer.invoke('pqc-encapsulate-agile', algorithm, pk),
  pqcDecapsulateAgile: (algorithm, ct, sk) =>
    ipcRenderer.invoke('pqc-decapsulate-agile', algorithm, ct, sk),
  pqcDsaKeygenAgile: (algorithm) => ipcRenderer.invoke('pqc-dsa-keygen-agile', algorithm),
  pqcGetAlgorithms: () => ipcRenderer.invoke('pqc-get-algorithms'),

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
  onShieldBlockedUpdate: (cb) => ipcRenderer.on('shield-blocked-update', (e, data) => cb(data)),

  // ── History ──

  // ── Fingerprint protection ──
  setFingerprintPolicy: (level) => ipcRenderer.invoke('set-fingerprint-policy', level),
  getFingerprintPolicy: () => ipcRenderer.invoke('get-fingerprint-policy'),

  // ── Anonymous tokens (ML-DSA-65 blind signatures) ──
  // Security: only nonce + signature cross IPC. sessionId stays in main process.
  anonTokenIssue: () => ipcRenderer.invoke('anon-token-issue'),
  anonTokenRedeem: (nonce, sig) => ipcRenderer.invoke('anon-token-redeem', nonce, sig),
  anonTokenCount: () => ipcRenderer.invoke('anon-token-count'),

  // ── PQC Benchmark (server-side hrtime.bigint() precision) ──
  pqcBenchmarkRunAll: (opts) => ipcRenderer.invoke('pqc-benchmark-run-all', opts),
  pqcBenchmarkRunOne: (alg, runs) => ipcRenderer.invoke('pqc-benchmark-run-one', alg, runs),
  pqcBenchmarkGetLatest: () => ipcRenderer.invoke('pqc-benchmark-get-latest'),
  pqcBenchmarkGetHistory: (limit) => ipcRenderer.invoke('pqc-benchmark-get-history', limit),
});
