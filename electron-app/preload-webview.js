// KryptonBrowser — Webview Preload Script
// Runs inside each <webview> guest page context.
// Provides a minimal bridge for webview-specific functionality.

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kryptonWebview', {
    // Report page metrics back to the host
    reportMetrics: (metrics) => ipcRenderer.sendToHost('page-metrics', metrics),

    // Request PQC certificate info for the current page
    getCertificateInfo: (url) => ipcRenderer.invoke('get-certificate-info', url),
});
