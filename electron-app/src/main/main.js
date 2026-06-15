// KryptonBrowser — Electron Main Process
// PQC-enabled browser with hybrid X25519+ML-KEM-768 TLS.
// Post-quantum secure browsing for sensitive network operations.

'use strict';

const {
  app,
  BrowserWindow,
  ipcMain,
  session,
  Menu,
  shell,
  webContents,
  dialog,
  globalShortcut,
} = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const log = require('electron-log');

// ═══ Burner Session Initialization ═══
const burnerTempDir = path.join(
  os.tmpdir(),
  `krypton-burner-${crypto.randomBytes(8).toString('hex')}`,
);
fs.mkdirSync(burnerTempDir, { recursive: true });
app.setPath('userData', burnerTempDir);

let isShredded = false;
let shredPromise = null;

async function secureWipeFilesAsync(dirPath) {
  if (!fs.existsSync(dirPath)) return;
  const stat = await fs.promises.stat(dirPath);
  if (stat.isDirectory()) {
    const files = await fs.promises.readdir(dirPath);
    for (const file of files) {
      await secureWipeFilesAsync(path.join(dirPath, file));
    }
  } else {
    try {
      const fd = await fs.promises.open(dirPath, 'r+');
      const size = stat.size;

      // Pass 1: Zeros
      let buffer = Buffer.alloc(size, 0);
      await fd.write(buffer, 0, size, 0);
      await fd.datasync();

      // Pass 2: Ones
      buffer = Buffer.alloc(size, 255);
      await fd.write(buffer, 0, size, 0);
      await fd.datasync();

      // Pass 3: Random
      buffer = crypto.randomBytes(size);
      await fd.write(buffer, 0, size, 0);
      await fd.datasync();

      await fd.close();

      // Rename to random string before deletion
      const randomName = crypto.randomBytes(16).toString('hex');
      const newPath = path.join(path.dirname(dirPath), randomName);
      await fs.promises.rename(dirPath, newPath);
    } catch (e) {
      // ignore
    }
  }
}

async function shredSessionDataAsync() {
  if (isShredded) return;
  if (shredPromise) return shredPromise;

  if (fs.existsSync(burnerTempDir)) {
    shredPromise = (async () => {
      try {
        log.info(`[KryptonBrowser] Forensic wipe starting for burner session at ${burnerTempDir}`);
        await secureWipeFilesAsync(burnerTempDir);
        fs.rmSync(burnerTempDir, { recursive: true, force: true });
        isShredded = true;
        log.info('[KryptonBrowser] Forensic wipe complete.');
      } catch (e) {
        log.error(`[KryptonBrowser] Failed to shred session data: ${e.message}`);
      }
    })();
    await shredPromise;
  }
}

function sendToActiveWindow(channel, ...args) {
  const focused = BrowserWindow.getFocusedWindow();
  if (focused) {
    focused.webContents.send(channel, ...args);
  } else {
    const windows = BrowserWindow.getAllWindows();
    if (windows.length > 0) {
      windows[0].webContents.send(channel, ...args);
    }
  }
}

// ═══ PQC Engine ═══
const pqcEngine = require('./pqc-engine');

// ═══ PQC Services (Session Persistence + Handshake FSM + OCSP) ═══
const PQCSessionService = require('./pqc-session-service');
const { PQCHandshakeService } = require('./pqc-handshake-service');
const PQCCertificateValidator = require('./pqc-certificate-validator');

// ═══ Enable PQC/ML-KEM in Chromium's TLS stack ═══
// Chromium 124+ supports ML-KEM-768 for TLS key exchange natively.
app.commandLine.appendSwitch('enable-features', 'PostQuantumKeyAgreement,UseMLKEM');
app.commandLine.appendSwitch('enable-quic');
// app.commandLine.appendSwitch('site-per-process'); // Causes SIGTRAP with webview
// Enforce minimum TLS 1.3 to prevent downgrade attacks and ensure PQC can be negotiated
app.commandLine.appendSwitch('ssl-version-min', 'tls1.3');

let mainWindow;

// ═══ Load Real Blocklist from blocklist.json ═══
let BLOCK_SET = new Set();
let BLOCK_PATTERNS = [];
// Per-category Sets for O(1) classification in recordSiteBlock
const CATEGORY_SETS = {}; // { ads: Set, trackers: Set, fingerprinting: Set, ... }

function loadBlocklist() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, '../../blocklist.json'), 'utf-8');
    const data = JSON.parse(raw);

    // Flatten all category arrays into one Set for O(1) hostname lookup
    const categories = [
      'ads',
      'trackers',
      'fingerprinting',
      'cryptominers',
      'malware',
      'social_tracking',
      'telemetry',
    ];
    const catAlias = { social_tracking: 'social' };
    for (const cat of categories) {
      const alias = catAlias[cat] || cat;
      if (!CATEGORY_SETS[alias]) CATEGORY_SETS[alias] = new Set();
      if (Array.isArray(data[cat])) {
        for (const domain of data[cat]) {
          const d = domain.toLowerCase().trim();
          BLOCK_SET.add(d);
          CATEGORY_SETS[alias].add(d);
        }
      }
    }

    // Load URL pattern strings and compile to RegExp
    if (Array.isArray(data.url_patterns)) {
      BLOCK_PATTERNS = data.url_patterns
        .map((p) => {
          try {
            return new RegExp(p, 'i');
          } catch {
            return null;
          }
        })
        .filter(Boolean);
    }

    log.info(
      `[KryptonBrowser] Blocklist loaded: ${BLOCK_SET.size} domains, ${BLOCK_PATTERNS.length} patterns`,
    );
  } catch (e) {
    log.error('[KryptonBrowser] Failed to load blocklist:', e.message);
  }
}

function isDomainBlocked(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if (BLOCK_SET.has(hostname)) return true;
    // Check if any parent domain is in the blocklist (e.g. cdn.doubleclick.net)
    const parts = hostname.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      if (BLOCK_SET.has(parts.slice(i).join('.'))) return true;
    }
    return false;
  } catch {
    return false;
  }
}

function isPatternBlocked(url) {
  return BLOCK_PATTERNS.some((p) => p.test(url));
}

// ═══ Stats ═══
let blockedRequestCount = 0;
let trackersBlockedCount = 0;
let httpsUpgradedCount = 0;
let pqcSessionCount = 0;

// Per-site block counts — Map<hostname, { total, ads, trackers, fingerprinting, cryptominers, malware, social, telemetry, patterns }>
const siteBlockCounts = new Map();

function recordSiteBlock(requestUrl, category) {
  try {
    const hostname = new URL(requestUrl).hostname.toLowerCase();
    if (!siteBlockCounts.has(hostname)) {
      // Evict oldest if map grows too large to prevent memory leak
      if (siteBlockCounts.size >= 1000) {
        const oldest = siteBlockCounts.keys().next().value;
        siteBlockCounts.delete(oldest);
      }
      siteBlockCounts.set(hostname, {
        total: 0,
        ads: 0,
        trackers: 0,
        fingerprinting: 0,
        cryptominers: 0,
        malware: 0,
        social: 0,
        telemetry: 0,
        patterns: 0,
      });
    }
    const entry = siteBlockCounts.get(hostname);
    entry.total++;
    if (category in entry) entry[category]++;
  } catch {
    /* ignore invalid URLs */
  }
}

// Classify a blocked URL into its category using pre-built CATEGORY_SETS (O(1))
function classifyBlockedUrl(url) {
  try {
    const h = new URL(url).hostname.toLowerCase();
    const parts = h.split('.');
    const candidates = [h];
    for (let i = 1; i < parts.length - 1; i++) candidates.push(parts.slice(i).join('.'));
    for (const [cat, set] of Object.entries(CATEGORY_SETS)) {
      if (candidates.some((c) => set.has(c))) return cat;
    }
  } catch {
    /* ignore */
  }
  return 'trackers';
}

// ═══ Main Window ═══
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 800,
    minHeight: 500,
    title: 'KryptonBrowser',
    backgroundColor: '#16181f',
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 12, y: 12 },
    webPreferences: {
      partition: 'burner-session',
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,
      sandbox: true,
      webSecurity: true,
      enableBlinkFeatures: '',
    },
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, '../../build/index.html'));
  mainWindow.once('ready-to-show', () => mainWindow.show());

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  mainWindow.webContents.on('console-message', (event, level, message) => {
    const tags = ['LOG', 'WARN', 'ERROR'];
    if (level > 0) log.info(`[Renderer ${tags[level] || 'INFO'}] ${message}`);
  });

  // Intercept new window opens → send to renderer as a new tab
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const parsedUrl = new URL(url);
      if (['http:', 'https:', 'krypton:', 'about:'].includes(parsedUrl.protocol)) {
        if (mainWindow) mainWindow.webContents.send('open-url-in-new-tab', url);
      } else {
        log.warn(
          `[KryptonBrowser] Blocked window open for disallowed protocol: ${parsedUrl.protocol}`,
        );
      }
    } catch {
      // Invalid URL
    }
    return { action: 'deny' };
  });

  setupRequestInterception(mainWindow.webContents.session);
}

// ═══ Request Interception ═══
function setupRequestInterception(ses) {
  // 1. Block ads, trackers, fingerprinting, cryptominers, malware
  ses.webRequest.onBeforeRequest({ urls: ['*://*/*'] }, (details, callback) => {
    const url = details.url;

    const blockAds = getConfig('krypton_ad_block', 'true') === 'true';
    if (blockAds) {
      if (isDomainBlocked(url)) {
        blockedRequestCount++;
        trackersBlockedCount++;
        // Classify via O(1) CATEGORY_SETS lookup (populated at startup)
        const cat = classifyBlockedUrl(url);
        const pageUrl = details.referrer || url;
        recordSiteBlock(pageUrl, cat);
        callback({ cancel: true });
        return;
      }
      if (isPatternBlocked(url)) {
        blockedRequestCount++;
        const pageUrl2 = details.referrer || url;
        recordSiteBlock(pageUrl2, 'patterns');
        callback({ cancel: true });
        return;
      }
    }

    // Block browser plugins/objects (legacy attack vectors)
    if (['object', 'plugin'].includes(details.resourceType)) {
      callback({ cancel: true });
      return;
    }

    // HTTPS upgrade
    if (
      getConfig('krypton_https_upgrade', 'true') === 'true' &&
      url.startsWith('http://') &&
      !url.startsWith('http://localhost') &&
      !url.startsWith('http://127.')
    ) {
      httpsUpgradedCount++;
      callback({ redirectURL: url.replace(/^http:\/\//, 'https://') });
      return;
    }

    callback({});
  });

  // 2. Inject DNT / Sec-GPC headers + KryptonBrowser User-Agent suffix
  ses.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, callback) => {
    const headers = details.requestHeaders;
    if (getConfig('krypton_send_dnt', 'true') === 'true') {
      headers['DNT'] = '1';
      headers['Sec-GPC'] = '1';
    }
    if (headers['User-Agent']) {
      headers['User-Agent'] = headers['User-Agent'].replace(
        /\s*$/,
        ' KryptonBrowser/1.0 PQC-Enabled',
      );
    }
    callback({ requestHeaders: headers });
  });

  // 3. Strip tracking response headers + inject security headers
  ses.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, callback) => {
    const headers = details.responseHeaders || {};
    delete headers['X-FB-Debug'];
    delete headers['X-Powered-By'];
    headers['X-Content-Type-Options'] = ['nosniff'];
    headers['X-Frame-Options'] = ['SAMEORIGIN'];
    headers['Referrer-Policy'] = ['strict-origin-when-cross-origin'];

    // Enforce strict CSP for local files (the main UI)
    if (details.url.startsWith('file://')) {
      headers['Content-Security-Policy'] = [
        "default-src 'self'; script-src 'self'; img-src 'self' https: data: blob:; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; connect-src 'self' https:;",
      ];
    }

    callback({ responseHeaders: headers });
  });

  // 4. Permission handler — deny sensitive permissions by default
  ses.setPermissionRequestHandler((wc, permission, callback, details) => {
    const denied = [
      'camera',
      'microphone',
      'geolocation',
      'notifications',
      'midi',
      'pointerLock',
      'serial',
      'bluetooth',
      'hid',
      'usb',
    ];
    if (denied.includes(permission)) {
      if (mainWindow)
        mainWindow.webContents.send('permission-request', {
          permission,
          origin: details?.requestingUrl || 'unknown',
        });
      callback(false);
      return;
    }
    callback(['clipboard-read', 'clipboard-sanitized-write'].includes(permission));
  });

  // 5. Certificate verification — record PQC sessions + async OCSP
  ses.setCertificateVerifyProc((request, callback) => {
    if (request.verificationResult === 'net::OK') {
      pqcSessionCount++;
      const domain = request.hostname;

      // Drive the handshake state machine (sync part)
      pqcHandshakeService.onCertVerified(domain, { success: true });

      // Async OCSP check runs in the background (fail-open — does not block TLS)
      pqcCertValidator
        .checkOCSP(domain, {
          issuerName: request.certificate?.issuer?.commonName || '',
          ocspUrls: [],
        })
        .then((ocspResult) => {
          if (ocspResult.warning) {
            log.warn(`[OCSP] Fail-open for ${domain}: ${ocspResult.message}`);
          }
        })
        .catch((err) => {
          log.warn(`[OCSP] Async check error for ${domain}:`, err.message);
        });
    } else {
      // Failed verification — record as failed handshake
      pqcHandshakeService.onCertVerified(request.hostname, { success: false });
    }
    callback(-3); // Use Chromium default verification
  });
}

// ═══ File-Based Config ═══
const persistentDataPath = path.join(app.getPath('appData'), 'KryptonBrowser');
if (!fs.existsSync(persistentDataPath)) fs.mkdirSync(persistentDataPath, { recursive: true });
const CONFIG_FILE = path.join(persistentDataPath, 'krypton_config.json');
let _configCache = null;

function loadConfigFile() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      _configCache = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
    } else {
      _configCache = {};
    }
  } catch {
    _configCache = {};
  }
  return _configCache;
}

function getConfig(key, defaultVal) {
  const cfg = _configCache || loadConfigFile();
  return cfg[key] !== undefined ? cfg[key] : defaultVal;
}

function setConfig(key, value) {
  const cfg = _configCache || loadConfigFile();
  cfg[key] = value;
  _configCache = cfg;
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
  } catch (e) {
    log.error(e);
  }
}

// ═══ IPC Handlers ═══

// Allowed config keys (prevent arbitrary key injection)
const ALLOWED_CONFIG_KEYS = new Set([
  'krypton_ad_block',
  'krypton_https_upgrade',
  'krypton_send_dnt',
  'krypton_block_cookies',
  'krypton_ask_download_loc',
  'krypton_panic_shortcut',
]);

// Config sync
ipcMain.handle('get-config', async (e, key, def) => {
  if (typeof key !== 'string' || key.length > 64) return def;
  return getConfig(key, def);
});
ipcMain.handle('set-config', async (e, key, val) => {
  if (typeof key !== 'string' || !ALLOWED_CONFIG_KEYS.has(key)) return false;
  if (typeof val !== 'string' || val.length > 256) return false;
  setConfig(key, val);
  return true;
});

// Blocking stats
ipcMain.handle('get-blocking-stats', async () => ({
  blockedRequests: blockedRequestCount,
  trackersBlocked: trackersBlockedCount,
  httpsUpgraded: httpsUpgradedCount,
  pqcSessions: pqcSessionCount,
}));

// Per-site shield stats
ipcMain.handle('get-site-block-count', async (e, pageUrl) => {
  if (!pageUrl) return null;
  try {
    const hostname = new URL(pageUrl).hostname.toLowerCase();
    return (
      siteBlockCounts.get(hostname) || {
        total: 0,
        ads: 0,
        trackers: 0,
        fingerprinting: 0,
        cryptominers: 0,
        malware: 0,
        social: 0,
        telemetry: 0,
        patterns: 0,
      }
    );
  } catch {
    return null;
  }
});

// Full site block map (for shields summary)
ipcMain.handle('get-all-site-stats', async () => {
  const result = [];
  for (const [host, counts] of siteBlockCounts.entries()) {
    result.push({ host, ...counts });
  }
  return result.sort((a, b) => b.total - a.total).slice(0, 50);
});

// PQC Engine — Self-Test
ipcMain.handle('pqc-selftest', async () => {
  return pqcEngine.runSelfTest();
});

// PQC Engine — Real Keygen
ipcMain.handle('pqc-keygen', async () => {
  const result = pqcEngine.kemKeygen();
  return {
    publicKeyHex: result.publicKeyHex,
    publicKeyBytes: result.publicKeyBytes,
    secretKeyBytes: result.secretKeyBytes,
    ms: result.ms,
  };
});

// PQC Engine — Encapsulate
ipcMain.handle('pqc-encapsulate', async (e, publicKeyHex) => {
  if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]+$/.test(publicKeyHex)) {
    throw new Error('Invalid public key: must be a hex string');
  }
  // ML-KEM-768 public key is 1184 bytes = 2368 hex chars
  if (publicKeyHex.length !== 2368) {
    throw new Error('Invalid public key length for ML-KEM-768');
  }
  const result = pqcEngine.kemEncapsulate(publicKeyHex);
  return {
    cipherTextHex: result.cipherTextHex,
    sharedSecretHex: result.sharedSecretHex,
    cipherTextBytes: result.cipherTextBytes,
    ms: result.ms,
  };
});

// PQC Engine — DSA Keygen
ipcMain.handle('pqc-dsa-keygen', async () => {
  const result = pqcEngine.dsaKeygen();
  return {
    publicKeyHex: result.publicKeyHex,
    publicKeyBytes: result.publicKeyBytes,
    secretKeyBytes: result.secretKeyBytes,
    ms: result.ms,
  };
});

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

// PQC Hybrid Key Pool (pre-generate keypairs for 0-RTT)
ipcMain.handle('pqc-get-key-pool', async (e, count) => {
  const n = Math.min(parseInt(count) || 5, 10);
  return pqcEngine.hybridKeygenPool(n);
});

// PQC liboqs version
ipcMain.handle('pqc-get-liboqs-version', async () => pqcEngine.getLiboqsVersion());

// Certificate info
ipcMain.handle('get-certificate-info', async (e, url) => {
  try {
    const { net } = require('electron');
    const dns = require('dns');

    if (typeof url !== 'string' || url.length === 0) return { error: 'Invalid URL' };

    const parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
      return { error: 'Invalid protocol for certificate info' };
    }

    // SSRF Prevention: Block requests to local/private networks
    const hostname = parsedUrl.hostname.toLowerCase();

    try {
      const addresses = await dns.promises.lookup(hostname, { all: true });
      for (const addr of addresses) {
        const ip = addr.address;
        if (
          ip === '127.0.0.1' ||
          ip === '0.0.0.0' ||
          ip === '::1' ||
          ip.startsWith('192.168.') ||
          ip.startsWith('10.') ||
          /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
          ip.startsWith('169.254.') ||
          ip.startsWith('fc00:') ||
          ip.startsWith('fe80:')
        ) {
          return { error: 'Private IP resolution not allowed for certificate info' };
        }
      }
    } catch (err) {
      return { error: `DNS lookup failed: ${err.message}` };
    }

    return await new Promise((resolve) => {
      const req = net.request(url);
      req.on('response', (res) => {
        resolve({ statusCode: res.statusCode, url });
        req.abort();
      });
      req.on('error', (err) => resolve({ error: err.message, url }));
      req.end();
    });
  } catch (err) {
    return { error: err.message };
  }
});

ipcMain.handle('get-security-info', async (e, urlStr) => {
  try {
    const url = new URL(urlStr);
    if (url.protocol !== 'https:') return { secure: false };

    const session = pqcEngine.getSessionByDomain(url.hostname);

    if (session && session.status === 'COMPLETED') {
      return {
        secure: true,
        pqcActive: true,
        protocol: 'TLS 1.3',
        kem: session.kem,
        cipher: 'AES-256-GCM',
        sig: session.sig,
      };
    }

    return {
      secure: true,
      pqcActive: false,
      protocol: 'TLS 1.2/1.3',
      kem: 'Standard (ECDHE/RSA)',
      cipher: 'Standard',
      sig: 'Standard',
    };
  } catch (err) {
    return { error: err.message };
  }
});

// Downloads
const downloads = [];

function setupDownloadManager() {
  session.fromPartition('burner-session').on('will-download', (e, item) => {
    const askLocation = getConfig('krypton_ask_download_loc', 'false') === 'true';
    const fileName = item.getFilename();
    if (!askLocation) {
      item.setSavePath(path.join(app.getPath('downloads'), fileName));
    }

    const id = Date.now().toString();
    const info = {
      id,
      filename: fileName,
      url: item.getURL(),
      savePath: item.getSavePath(),
      totalBytes: item.getTotalBytes(),
      receivedBytes: 0,
      state: 'progressing',
      startTime: Date.now(),
      speed: 0,
    };
    downloads.push(info);
    if (mainWindow) mainWindow.webContents.send('download-started', info);

    item.on('updated', (e, state) => {
      info.receivedBytes = item.getReceivedBytes();
      info.totalBytes = item.getTotalBytes();
      info.state = state;
      info.savePath = item.getSavePath();
      const elapsed = (Date.now() - info.startTime) / 1000;
      info.speed = elapsed > 0 ? info.receivedBytes / elapsed : 0;
      if (mainWindow) mainWindow.webContents.send('download-updated', info);
    });

    item.once('done', (e, state) => {
      info.state = state;
      info.receivedBytes = item.getReceivedBytes();
      info.savePath = item.getSavePath();
      if (mainWindow) mainWindow.webContents.send('download-done', info);
    });
  });
}

ipcMain.handle('get-downloads', async () => downloads);

// Validate download paths — must be under the downloads directory to prevent path traversal
function isValidDownloadPath(p) {
  if (typeof p !== 'string' || p.length === 0) return false;
  const resolved = path.resolve(p);
  const downloadsDir = path.resolve(app.getPath('downloads'));

  // Prevent directory traversal: must be inside the downloadsDir exactly
  const isInsideDownloads =
    resolved === downloadsDir || resolved.startsWith(downloadsDir + path.sep);
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
  const r = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory'],
    title: 'Choose Download Location',
  });
  return r.canceled ? null : r.filePaths[0];
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

// ═══ App Menu ═══
function createMenu() {
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      {
        label: 'KryptonBrowser',
        submenu: [
          { label: 'About Krypton', role: 'about' },
          { type: 'separator' },
          {
            label: 'PQC Security Panel',
            accelerator: 'CmdOrCtrl+Shift+P',
            click: () => sendToActiveWindow('navigate-to', 'krypton://pqc-security'),
          },
          { type: 'separator' },
          { role: 'hide' },
          { role: 'hideOthers' },
          { type: 'separator' },
          { role: 'quit' },
        ],
      },
      {
        label: 'File',
        submenu: [
          {
            label: 'New Tab',
            accelerator: 'CmdOrCtrl+T',
            click: () => sendToActiveWindow('new-tab'),
          },
          {
            label: 'New Private Window',
            accelerator: 'CmdOrCtrl+Shift+N',
            click: () => sendToActiveWindow('menu-action', 'private-window'),
          },
          {
            label: 'Close Tab',
            accelerator: 'CmdOrCtrl+W',
            click: () => sendToActiveWindow('close-tab'),
          },
          { type: 'separator' },
          {
            label: 'Open Location',
            accelerator: 'CmdOrCtrl+L',
            click: () => sendToActiveWindow('focus-url-bar'),
          },
          { type: 'separator' },
          {
            label: 'Find in Page',
            accelerator: 'CmdOrCtrl+F',
            click: () => sendToActiveWindow('toggle-find-bar'),
          },
        ],
      },
      {
        label: 'Edit',
        submenu: [
          { role: 'undo' },
          { role: 'redo' },
          { type: 'separator' },
          { role: 'cut' },
          { role: 'copy' },
          { role: 'paste' },
          { role: 'selectAll' },
        ],
      },
      {
        label: 'View',
        submenu: [
          {
            label: 'Reload',
            accelerator: 'CmdOrCtrl+R',
            click: () => sendToActiveWindow('reload-page'),
          },
          { type: 'separator' },
          {
            label: 'Toggle Sidebar',
            accelerator: 'CmdOrCtrl+B',
            click: () => sendToActiveWindow('menu-action', 'toggle-sidebar'),
          },
          {
            label: 'Reader Mode',
            accelerator: 'CmdOrCtrl+Shift+R',
            click: () => sendToActiveWindow('menu-action', 'reader-mode'),
          },
          {
            label: 'Shields Panel',
            accelerator: 'CmdOrCtrl+Shift+S',
            click: () => sendToActiveWindow('menu-action', 'toggle-shields'),
          },
          { type: 'separator' },
          { role: 'toggleDevTools' },
          { type: 'separator' },
          { role: 'resetZoom' },
          { role: 'zoomIn' },
          { role: 'zoomOut' },
          { type: 'separator' },
          { role: 'togglefullscreen' },
        ],
      },
      {
        label: 'Security',
        submenu: [
          {
            label: 'PQC Security Panel',
            accelerator: 'CmdOrCtrl+Shift+P',
            click: () => sendToActiveWindow('navigate-to', 'krypton://pqc-security'),
          },
          { type: 'separator' },
          {
            label: 'View Connection Security',
            click: () => sendToActiveWindow('show-security-info'),
          },
          { type: 'separator' },
          {
            label: 'Clear Browsing Data',
            accelerator: 'CmdOrCtrl+Shift+Delete',
            click: () => sendToActiveWindow('clear-browsing-data'),
          },
        ],
      },
      {
        label: 'Window',
        submenu: [{ role: 'minimize' }, { role: 'zoom' }, { type: 'separator' }, { role: 'front' }],
      },
    ]),
  );
}

// ═══ Service Instances (initialized in app.whenReady) ═══
// These are module-level references, initialized after app is ready.
let pqcSessionService = null;
let pqcHandshakeService = null;
let pqcCertValidator = null;

// ═══ App Lifecycle ═══
let isQuitting = false;

function triggerPanic() {
  log.warn('[KryptonBrowser] PANIC BUTTON TRIGGERED!');
  BrowserWindow.getAllWindows().forEach((win) => {
    if (!win.isDestroyed()) win.destroy();
  });
  shredSessionDataAsync().then(() => {
    isQuitting = true;
    app.quit();
  });
}

ipcMain.handle('set-panic-shortcut', async (e, shortcutStr) => {
  if (typeof shortcutStr !== 'string' || shortcutStr.length > 64) return false;
  const oldShortcut = getConfig('krypton_panic_shortcut', 'CommandOrControl+Shift+Escape');
  globalShortcut.unregister(oldShortcut);
  try {
    const success = globalShortcut.register(shortcutStr, triggerPanic);
    if (!success) throw new Error('Failed to register shortcut');
    setConfig('krypton_panic_shortcut', shortcutStr);
    return true;
  } catch (err) {
    globalShortcut.register(oldShortcut, triggerPanic);
    return false;
  }
});

app.whenReady().then(async () => {
  await pqcEngine.init(); // Load native PQC addon before anything else

  // ── Init PQC Services ──────────────────────────────────────────
  // DB lives in persistentDataPath, NOT in burnerTempDir (it is NOT wiped on quit)
  pqcSessionService = new PQCSessionService(path.join(persistentDataPath, 'pqc_sessions.db'));
  const dbReady = pqcSessionService.init();
  if (dbReady) {
    pqcEngine.setSessionService(pqcSessionService);
    log.info(
      '[KryptonBrowser] PQC session DB initialized at',
      path.join(persistentDataPath, 'pqc_sessions.db'),
    );
  } else {
    log.warn('[KryptonBrowser] PQC session DB failed to init — falling back to in-memory log');
  }

  pqcCertValidator = new PQCCertificateValidator();
  pqcHandshakeService = new PQCHandshakeService(pqcSessionService, pqcCertValidator);
  // ──────────────────────────────────────────────────────

  loadBlocklist();
  loadConfigFile();
  createMenu();
  createWindow();
  setupDownloadManager();

  // Register Panic Button
  const panicShortcut = getConfig('krypton_panic_shortcut', 'CommandOrControl+Shift+Escape');
  globalShortcut.register(panicShortcut, triggerPanic);

  // Check for updates
  autoUpdater.checkForUpdatesAndNotify();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('will-quit', () => {
  globalShortcut.unregisterAll();
});

app.on('before-quit', (e) => {
  if (isQuitting) return; // Allow quit
  e.preventDefault(); // Prevent immediate quit
  shredSessionDataAsync().then(() => {
    // Close SQLite DB gracefully before quit
    if (pqcSessionService) {
      pqcSessionService.close();
      log.info('[KryptonBrowser] PQC session DB closed.');
    }
    isQuitting = true;
    app.quit();
  });
});

// ═══ Global Error Handlers ═══
process.on('uncaughtException', (err) => {
  log.error('[KryptonBrowser] CRITICAL: Uncaught Exception:', err);
  dialog.showErrorBox('Critical Error', 'A critical error occurred. Check the logs for details.');
  shredSessionDataAsync().then(() => {
    isQuitting = true;
    app.quit();
  });
});

process.on('unhandledRejection', (reason, promise) => {
  log.error('[KryptonBrowser] CRITICAL: Unhandled Rejection at:', promise, 'reason:', reason);
});
