// KryptonBrowser — Electron Main Process
// PQC-enabled browser with hybrid X25519+ML-KEM-768 TLS.
// Post-quantum secure browsing for sensitive network operations.

'use strict';

const {
  app,
  BrowserWindow,
  ipcMain,
  session,
  webContents,
  Menu,
  shell,
  dialog,
  globalShortcut,
} = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const log = require('electron-log');

const {
  initConfig,
  getConfigSync,
  setConfigSync,
  ALLOWED_CONFIG_KEYS,
} = require('./config/allowed-keys');
const { registerAllHandlers } = require('./ipc');

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

// ═══ Fingerprint Enforcement Service ═══
const fingerprintEnforcer = require('./fingerprint-enforcer');

// ═══ Anonymous Token Provider (ML-DSA-65 signed tokens) ═══
const anonTokenProvider = require('./anon-token-provider');

// ═══ PQC Benchmark Service ═══
const pqcBenchmarkService = require('./pqc-benchmark-service');

// ═══ Enable PQC/ML-KEM in Chromium's TLS stack ═══
// Chromium 124+ supports ML-KEM-768 for TLS key exchange natively.
app.commandLine.appendSwitch(
  'enable-features',
  'PostQuantumKeyAgreement,UseMLKEM,PlatformHEVCDecoderSupport',
);
app.commandLine.appendSwitch('enable-quic');
app.commandLine.appendSwitch('ignore-gpu-blocklist');
app.commandLine.appendSwitch('enable-zero-copy');
// app.commandLine.appendSwitch('site-per-process'); // Causes SIGTRAP with webview
// Enforce minimum TLS 1.3 to prevent downgrade attacks and ensure PQC can be negotiated
app.commandLine.appendSwitch('ssl-version-min', 'tls1.3');
// Hardware video decoding and media playback flags for smooth rendering
app.commandLine.appendSwitch('enable-accelerated-video-decode');
app.commandLine.appendSwitch('enable-accelerated-mjpeg-decode');
app.commandLine.appendSwitch('enable-gpu-rasterization');
app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');

let mainWindow;

// ═══ Load Real Blocklist from blocklist.json ═══
let BLOCK_SET = new Set();
let BLOCK_PATTERNS = [];
// Per-category Sets for O(1) classification in recordSiteBlock
const CATEGORY_SETS = {}; // { ads: Set, trackers: Set, fingerprinting: Set, ... }

// Guaranteed YouTube and Google ad network endpoints
const YOUTUBE_AD_DOMAINS = new Set([
  'googleads.g.doubleclick.net',
  'static.doubleclick.net',
  'pagead2.googlesyndication.com',
  'ad.doubleclick.net',
  'pubads.g.doubleclick.net',
  'securepubads.g.doubleclick.net',
  'adservice.google.com',
  'adservice.google.de',
  'video-stats.l.google.com',
  'tpc.googlesyndication.com',
  's0.2mdn.net',
  'googleadservices.com',
]);

const YOUTUBE_AD_PATTERNS = [
  /youtube\.com\/api\/stats\/ads/i,
  /youtube\.com\/pagead\//i,
  /youtube\.com\/ptracking/i,
  /youtube\.com\/api\/stats\/qoe\?.*adformat/i,
  /youtube\.com\/youtubei\/v1\/player\/ad_break/i,
  /googlevideo\.com\/videoplayback\?.*[&?]adformat=/i,
  /googleads\.g\.doubleclick\.net/i,
  /pubads\.g\.doubleclick\.net/i,
  /static\.doubleclick\.net/i,
  /youtube\.com\/get_midroll_info/i,
  /youtube\.com\/api\/stats\/playback\?.*adformat/i,
  /youtube\.com\/api\/stats\/watchtime\?.*adformat/i,
];

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

    // Ensure all guaranteed YouTube & Google ad domains are in BLOCK_SET & CATEGORY_SETS
    if (!CATEGORY_SETS['ads']) CATEGORY_SETS['ads'] = new Set();
    for (const d of YOUTUBE_AD_DOMAINS) {
      BLOCK_SET.add(d);
      CATEGORY_SETS['ads'].add(d);
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
    if (YOUTUBE_AD_DOMAINS.has(hostname)) return true;
    if (BLOCK_SET.has(hostname)) return true;
    // Check if any parent domain is in the blocklist (e.g. cdn.doubleclick.net)
    const parts = hostname.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join('.');
      if (YOUTUBE_AD_DOMAINS.has(parent) || BLOCK_SET.has(parent)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

function isPatternBlocked(url) {
  if (YOUTUBE_AD_PATTERNS.some((p) => p.test(url))) return true;
  return BLOCK_PATTERNS.some((p) => p.test(url));
}

// ═══ Stats ═══
let blockedRequestCount = 0;
let trackersBlockedCount = 0;
let httpsUpgradedCount = 0;
let pqcSessionCount = 0;

// Verified certificates map — Map<hostname, { issuer, subject, validStart, validExpiry }>
const verifiedCertificates = new Map();

// Per-site block counts — Map<hostname, { total, ads, trackers, fingerprinting, cryptominers, malware, social, telemetry, patterns, scripts }>
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
        scripts: 0,
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
    if (YOUTUBE_AD_PATTERNS.some((p) => p.test(url))) return 'ads';
    const h = new URL(url).hostname.toLowerCase();
    if (YOUTUBE_AD_DOMAINS.has(h)) return 'ads';
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
      additionalArguments: [`--webview-preload-path=${path.join(__dirname, 'preload-webview.js')}`],
    },
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, '../../build/index.html'));
  mainWindow.once('ready-to-show', () => mainWindow.show());

  // Wire fingerprint enforcement injection into the main renderer process
  fingerprintEnforcer.injectIntoWebContents(mainWindow.webContents);

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

  const burnerSession = session.fromPartition('burner-session');
  setupRequestInterception(burnerSession);
  setupRequestInterception(session.defaultSession);
}

// Ensure any new webContents (including guest webviews) have interception and fingerprint protection
app.on('web-contents-created', (event, contents) => {
  if (contents.session) {
    setupRequestInterception(contents.session);
  }
  fingerprintEnforcer.injectIntoWebContents(contents);
});

// ═══ Request Interception ═══
const interceptedSessions = new WeakSet();

function setupRequestInterception(ses) {
  if (!ses || interceptedSessions.has(ses)) return;
  interceptedSessions.add(ses);

  try {
    const rawUa = ses.getUserAgent();
    if (rawUa) {
      ses.setUserAgent(rawUa.replace(/Electron\/[0-9.]+\s*/i, ''));
    }
  } catch {
    /* ignore */
  }

  // 1. Block ads, trackers, fingerprinting, cryptominers, malware
  ses.webRequest.onBeforeRequest({ urls: ['*://*/*'] }, (details, callback) => {
    const url = details.url;
    const getPageUrl = () => {
      try {
        if (details.webContentsId) {
          const wc = webContents.fromId(details.webContentsId);
          if (wc && typeof wc.getURL === 'function' && wc.getURL()) {
            return wc.getURL();
          }
        }
      } catch {
        /* ignore */
      }
      return details.referrer || url;
    };

    const blockAds = getConfigSync('krypton_ad_block', 'true') === 'true';
    if (blockAds) {
      if (isDomainBlocked(url)) {
        blockedRequestCount++;
        trackersBlockedCount++;
        // Classify via O(1) CATEGORY_SETS lookup (populated at startup)
        const cat = classifyBlockedUrl(url);
        const pageUrl = getPageUrl();
        recordSiteBlock(pageUrl, cat);
        callback({ cancel: true });
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('shield-blocked-update', {
            url,
            category: cat,
            pageUrl,
            blockedRequestCount,
            trackersBlockedCount,
          });
        }
        return;
      }
      if (isPatternBlocked(url)) {
        blockedRequestCount++;
        trackersBlockedCount++;
        const cat = classifyBlockedUrl(url);
        const pageUrl2 = getPageUrl();
        recordSiteBlock(pageUrl2, cat);
        callback({ cancel: true });
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('shield-blocked-update', {
            url,
            category: cat,
            pageUrl: pageUrl2,
            blockedRequestCount,
            trackersBlockedCount,
          });
        }
        return;
      }
    }

    // Block browser plugins/objects (legacy attack vectors)
    if (['object', 'plugin'].includes(details.resourceType)) {
      callback({ cancel: true });
      return;
    }

    // Script blocking (enforced when krypton_block_scripts=true)
    if (
      details.resourceType === 'script' &&
      getConfigSync('krypton_block_scripts', 'false') === 'true'
    ) {
      blockedRequestCount++;
      const pageUrl = getPageUrl();
      recordSiteBlock(pageUrl, 'scripts');
      callback({ cancel: true });
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('shield-blocked-update', {
          url,
          category: 'scripts',
          pageUrl,
          blockedRequestCount,
          trackersBlockedCount,
        });
      }
      return;
    }

    // HTTPS upgrade
    if (
      getConfigSync('krypton_https_upgrade', 'true') === 'true' &&
      url.startsWith('http://') &&
      !url.startsWith('http://localhost') &&
      !url.startsWith('http://127.0.0.1')
    ) {
      httpsUpgradedCount++;
      const secureUrl = url.replace(/^http:\/\//i, 'https://');
      callback({ redirectURL: secureUrl });
      return;
    }

    // Block third-party cookies if krypton_block_cookies=strict
    if (getConfigSync('krypton_block_cookies', 'standard') === 'strict') {
      const isThirdParty = (reqUrl, ref) => {
        try {
          if (!ref) return false;
          return new URL(reqUrl).hostname !== new URL(ref).hostname;
        } catch {
          return false;
        }
      };
      if (isThirdParty(url, details.referrer)) {
        delete details.requestHeaders?.['Cookie'];
      }
    }

    callback({});
  });

  // 2. Inject DNT / Sec-GPC headers + clean User-Agent
  ses.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, callback) => {
    const headers = details.requestHeaders;
    if (getConfigSync('krypton_send_dnt', 'true') === 'true') {
      headers['DNT'] = '1';
      headers['Sec-GPC'] = '1';
    }
    if (headers['User-Agent']) {
      let ua = headers['User-Agent'].replace(/Electron\/[0-9.]+\s*/i, '');
      const isGoogleOrMedia =
        /youtube\.com|googlevideo\.com|google\.com|gstatic\.com|googleapis\.com/i.test(details.url);
      if (isGoogleOrMedia) {
        ua = ua
          .replace(/sterlingsuman\/[0-9.]+\s*/gi, '')
          .replace(/KryptonBrowser\/[0-9.]+\s*/gi, '');
      } else {
        ua = ua.replace(/\s*$/, ' KryptonBrowser/1.0 PQC-Enabled');
      }
      headers['User-Agent'] = ua.trim();
    }
    callback({ requestHeaders: headers });
  });

  // 3. Strip tracking response headers + inject security headers
  ses.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, callback) => {
    const headers = details.responseHeaders || {};
    delete headers['X-FB-Debug'];
    delete headers['X-Powered-By'];
    headers['X-Content-Type-Options'] = ['nosniff'];
    headers['Referrer-Policy'] = ['strict-origin-when-cross-origin'];

    // Enforce strict CSP and frame options only for local files (the main UI)
    if (details.url.startsWith('file://')) {
      headers['X-Frame-Options'] = ['SAMEORIGIN'];
      headers['Content-Security-Policy'] = [
        "default-src 'self'; script-src 'self'; img-src 'self' https: data: blob:; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; connect-src 'self' https:;",
      ];
    }

    // Apply fingerprint-enforcer headers (Permissions-Policy, COEP, ETag stripping)
    fingerprintEnforcer.applyHeaders(headers, details.url);

    callback({ responseHeaders: headers });
  });

  // 4. Permission handler — deny sensitive permissions by default, allow media & clipboard
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
    const allowed = [
      'clipboard-read',
      'clipboard-sanitized-write',
      'fullscreen',
      'media',
      'protected-media-identifier',
    ];
    callback(allowed.includes(permission));
  });

  // 5. Certificate verification — record PQC sessions + async OCSP
  ses.setCertificateVerifyProc((request, callback) => {
    if (request.verificationResult === 'net::OK') {
      pqcSessionCount++;
      const domain = request.hostname;
      const cert = request.certificate;
      const issuer =
        cert?.issuerName || cert?.issuer?.commonName || cert?.issuer?.organizationName || '';
      verifiedCertificates.set(domain.toLowerCase(), {
        issuer,
        subject: cert?.subjectName || cert?.subject?.commonName || '',
        validStart: cert?.validStart,
        validExpiry: cert?.validExpiry,
      });

      // Drive the handshake state machine (sync part)
      pqcHandshakeService.onCertVerified(domain, {
        success: true,
        issuingCa: issuer,
      });

      // Async OCSP check runs in the background (fail-open — does not block TLS)
      pqcCertValidator
        .checkOCSP(domain, {
          issuerName: issuer,
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
const configPath = CONFIG_FILE;

// Downloads
const downloads = [];

function setupDownloadManager() {
  session.fromPartition('burner-session').on('will-download', (e, item) => {
    const askLocation = getConfigSync('krypton_ask_download_loc', 'false') === 'true';
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

  // Init anonymous token provider (needs PQCEngine + session service ready)
  anonTokenProvider.init(pqcEngine, pqcSessionService);

  // Init benchmark service (needs PQCEngine ready)
  pqcBenchmarkService.init(pqcEngine);
  // ──────────────────────────────────────────────────────

  loadBlocklist();
  initConfig(configPath);
  registerAllHandlers(ipcMain, {
    pqcEngine,
    pqcSessionService,
    pqcHandshakeService,
    pqcCertValidator,
    anonTokenProvider,
    pqcBenchmarkService,
    configPath,
    mainWindowGetter: () => mainWindow,
    downloadsMapGetter: () => downloads,
    statsGetter: () => ({
      blockedRequests: blockedRequestCount,
      blockedRequestCount,
      trackersBlockedCount,
      httpsUpgradedCount,
      pqcSessionCount,
    }),
    siteBlockCountsGetter: () => siteBlockCounts,
    verifiedCertificatesGetter: () => verifiedCertificates,
    globalShortcut,
    dialog,
    shell,
    app,
    triggerPanic,
  });
  createMenu();
  createWindow();
  setupDownloadManager();

  // Register Panic Button
  const panicShortcut = getConfigSync('krypton_panic_shortcut', 'CommandOrControl+Shift+Escape');
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
