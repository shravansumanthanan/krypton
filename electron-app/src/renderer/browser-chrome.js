// KryptonBrowser — Browser Chrome Controller
// Tabs, navigation, bookmarks, extensions, menu, PQC security.

import {
  sanitizeHTML,
  getGreeting,
  getTimeString,
  pick,
  formatBytes,
  formatSpeed,
  getFileIcon,
} from './js/utils.js';

// ═══ State ═══
const tabs = [];
let activeTabId = null;
let tabCounter = 0;
let clockInterval = null;
let zoomLevel = 100;

// Find-in-page state
let findBarVisible = false;
let findCurrentTabId = null;

// Per-tab blocked request counts (populated from IPC)
let shieldTotalBlocked = 0;

// Downloads
const downloadItems = {}; // id → info

// Bookmarks stored in memory (persisted to localStorage)
let bookmarks = JSON.parse(localStorage.getItem('krypton_bookmarks') || '[]');

// Built-in extensions
const extensions = [
  {
    id: 'pqc-shield',
    name: 'PQC Shield',
    desc: 'Quantum-safe connection monitor',
    icon: '🛡️',
    color: 'rgba(251,146,60,0.15)',
    enabled: true,
  },
  {
    id: 'ad-guard',
    name: 'KryptonShield',
    desc: 'Block ads, trackers & fingerprinting',
    icon: '🚫',
    color: 'rgba(248,113,113,0.15)',
    enabled: true,
  },
  {
    id: 'dark-reader',
    name: 'Dark Reader',
    desc: 'Dark mode for every website',
    icon: '🌙',
    color: 'rgba(96,165,250,0.15)',
    enabled: true,
  },
  {
    id: 'password-mgr',
    name: 'Password Manager',
    desc: 'Auto-fill passwords securely',
    icon: '🔑',
    color: 'rgba(52,211,153,0.15)',
    enabled: false,
  },
  {
    id: 'speedreader',
    name: 'Speedreader',
    desc: 'Declutter pages for focused reading',
    icon: '📖',
    color: 'rgba(167,139,250,0.15)',
    enabled: true,
  },
  {
    id: 'translate',
    name: 'Translate',
    desc: 'Private in-browser translation',
    icon: '🌐',
    color: 'rgba(34,211,238,0.15)',
    enabled: true,
  },
];

const INTERNAL_PAGES = {
  'krypton://pqc-security': { title: 'PQC Security', file: 'pages/pqc_security.html' },
  'krypton://newtab': { title: 'New Tab', internal: true },
  'krypton://history': { title: 'History', internal: true },
  'krypton://settings': { title: 'Settings', internal: true },
  'krypton://extensions': { title: 'Extensions', internal: true },
};

// NTP wallpapers — CSS gradients (offline-safe; no external image requests)
const WALLPAPERS = [
  { type: 'gradient', value: 'linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%)' },
  { type: 'gradient', value: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)' },
  { type: 'gradient', value: 'linear-gradient(160deg, #0d1b2a 0%, #1b2838 40%, #1d3557 100%)' },
  { type: 'gradient', value: 'linear-gradient(145deg, #16181f 0%, #1a2035 50%, #0e1628 100%)' },
  { type: 'gradient', value: 'linear-gradient(135deg, #0a0a1a 0%, #1a0a2e 50%, #2d1b69 100%)' },
  { type: 'gradient', value: 'linear-gradient(135deg, #0d1117 0%, #161b22 50%, #21262d 100%)' },
];

const QUOTES = [
  { text: 'The only way to do great work is to love what you do.', author: 'Steve Jobs' },
  { text: 'Security is not a product, but a process.', author: 'Bruce Schneier' },
  { text: 'In the middle of difficulty lies opportunity.', author: 'Albert Einstein' },
  {
    text: "Privacy is not something that I'm merely entitled to, it's an absolute prerequisite.",
    author: 'Marlon Brando',
  },
  { text: 'Technology is best when it brings people together.', author: 'Matt Mullenweg' },
  { text: 'The price of freedom is eternal vigilance.', author: 'Thomas Jefferson' },
  {
    text: 'Encryption works. Properly implemented strong crypto systems are one of the few things you can rely on.',
    author: 'Edward Snowden',
  },
];

// NTP Shortcuts — built dynamically from user bookmarks

// Reading list (persisted)
let readingList = JSON.parse(localStorage.getItem('krypton_reading_list') || '[]');

// Sidebar state
let sidebarOpen = false;

// Private mode state
let isPrivateMode = false;

// Reader mode state
let readerFontSize = 17;
let readerLightTheme = false;

// ═══ DOM Refs ═══
const $tabsContainer = document.getElementById('tabs-container');
const $webviewContainer = document.getElementById('webview-container');
const $urlInput = document.getElementById('url-input');
const $securityIndicator = document.getElementById('security-indicator');
const $lockIcon = document.getElementById('lock-icon');
const $pqcBadge = document.getElementById('pqc-badge');
const $loadingBar = document.getElementById('loading-bar');
const $loadingProgress = document.getElementById('loading-progress');
const $securityPopup = document.getElementById('security-popup');
const $reloadIcon = document.getElementById('reload-icon');
const $bookmarkBtn = document.getElementById('btn-bookmark');
const $bookmarkIcon = document.getElementById('bookmark-icon');
const $bookmarksList = document.getElementById('bookmarks-list');
const $browserMenu = document.getElementById('browser-menu');
const $extensionsPanel = document.getElementById('extensions-panel');

// New element refs
const $findBar = document.getElementById('find-bar');
const $findInput = document.getElementById('find-input');
const $findCount = document.getElementById('find-count');
const $shieldCount = document.getElementById('shield-count');
const $shieldBadgeWrap = document.getElementById('shield-badge-wrap');
const $downloadsPanel = document.getElementById('downloads-panel');
const $dlList = document.getElementById('dl-list');
const $ctxMenu = document.getElementById('ctx-menu');
const $permOverlay = document.getElementById('permission-overlay');

// ═══ Helpers removed and imported from utils.js ═══

// ═══ History ═══
// Clean up stale entries on startup (entries where title is just the URL)
(function cleanStaleHistory() {
  try {
    let hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
    // Remove entries where title is the same as the URL (never got a real title)
    hist = hist.filter((entry) => entry.title && entry.title !== entry.url);
    localStorage.setItem('krypton_history', JSON.stringify(hist));
  } catch (e) {
    /* ignore */
  }
})();

function recordHistory(url, title, favicon, timestamp) {
  if (isPrivateMode) return; // Don't record history in private mode
  if (!url || url.startsWith('krypton://') || url.startsWith('file://')) return;
  try {
    let hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
    hist.unshift({
      url,
      title: title || url,
      favicon: favicon || null,
      timestamp: timestamp || Date.now(),
    });
    // Keep last 500 entries
    if (hist.length > 500) hist = hist.slice(0, 500);
    localStorage.setItem('krypton_history', JSON.stringify(hist));
  } catch (e) {
    /* storage full or unavailable */
  }
}

function updateHistoryEntry(timestamp, updates) {
  if (!timestamp) return;
  try {
    let hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
    const entry = hist.find((h) => h.timestamp === timestamp);
    if (entry) {
      if (updates.title) entry.title = updates.title;
      if (updates.favicon) entry.favicon = updates.favicon;
      localStorage.setItem('krypton_history', JSON.stringify(hist));
    }
  } catch (e) {
    /* ignore */
  }
}

// ═══ Bookmarks ═══
function saveBookmarks() {
  localStorage.setItem('krypton_bookmarks', JSON.stringify(bookmarks));
  renderBookmarksBar();
}

function isBookmarked(url) {
  return bookmarks.some((b) => b.url === url);
}

function toggleBookmark() {
  const tab = getActiveTab();
  if (!tab || tab.isNewTab) return;

  const url = tab.url;
  if (!url) return;

  if (isBookmarked(url)) {
    bookmarks = bookmarks.filter((b) => b.url !== url);
  } else {
    bookmarks.push({
      url: url,
      title: tab.title || url,
      favicon: tab.favicon || null,
      addedAt: Date.now(),
    });
  }
  saveBookmarks();
  updateBookmarkButton();
}

function updateBookmarkButton() {
  const tab = getActiveTab();
  if (!tab || tab.isNewTab || !tab.url) {
    $bookmarkBtn.classList.remove('bookmarked');
    $bookmarkIcon.textContent = 'bookmark_border';
    return;
  }
  if (isBookmarked(tab.url)) {
    $bookmarkBtn.classList.add('bookmarked');
    $bookmarkIcon.textContent = 'bookmark';
  } else {
    $bookmarkBtn.classList.remove('bookmarked');
    $bookmarkIcon.textContent = 'bookmark_border';
  }
}

function renderBookmarksBar() {
  $bookmarksList.innerHTML = '';
  bookmarks.forEach((bm) => {
    const el = document.createElement('button');
    el.className = 'bookmark-item';
    const safeTitle = (bm.title || '').replace(/[<>"&]/g, '');
    const faviconHtml = bm.favicon
      ? `<img src="${encodeURI(bm.favicon)}" data-fallback="bookmark">`
      : '<span class="material-icons-outlined">bookmark</span>';
    const displayTitle = safeTitle.length > 20 ? safeTitle.substring(0, 20) + '…' : safeTitle;
    el.innerHTML = `${faviconHtml}${displayTitle}`;
    el.title = bm.url;
    el.addEventListener('click', () => navigateActiveTab(bm.url));
    // Right-click to remove
    el.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      bookmarks = bookmarks.filter((b) => b.url !== bm.url);
      saveBookmarks();
      updateBookmarkButton();
    });
    $bookmarksList.appendChild(el);
  });
}

// ═══ Tab Management ═══
function createTab(url = 'krypton://newtab') {
  const id = 'tab-' + ++tabCounter;
  const isInternal = url.startsWith('krypton://');
  const isNewTab = url === 'krypton://newtab';
  const isHistory = url === 'krypton://history';
  const isSettings = url === 'krypton://settings';
  const isExtensions = url === 'krypton://extensions';
  const isInAppPage = isHistory || isSettings || isExtensions;

  // Determine favicon and title
  let faviconIcon = 'language';
  let initialTitle = 'Loading...';
  if (isNewTab) {
    faviconIcon = 'security';
    initialTitle = 'New Tab';
  } else if (isHistory) {
    faviconIcon = 'history';
    initialTitle = 'History';
  } else if (isSettings) {
    faviconIcon = 'settings';
    initialTitle = 'Settings';
  } else if (isExtensions) {
    faviconIcon = 'extension';
    initialTitle = 'Extensions';
  } else if (url === 'krypton://pqc-security') {
    faviconIcon = 'shield';
  }

  const tabEl = document.createElement('div');
  tabEl.className = 'tab';
  tabEl.id = id;

  tabEl.innerHTML = `
    <div class="tab-favicon">
      <span class="material-icons-outlined">${faviconIcon}</span>
    </div>
    <span class="tab-title">${initialTitle}</span>
    <button class="tab-close" title="Close tab">×</button>
  `;

  tabEl.querySelector('.tab-close').addEventListener('click', (e) => {
    e.stopPropagation();
    closeTab(id);
  });
  tabEl.addEventListener('click', () => activateTab(id));

  // Tab context menu (right-click)
  tabEl.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    e.stopPropagation();
    showTabContextMenu(id, e.clientX, e.clientY);
  });

  // Tab drag-and-drop for reordering
  tabEl.setAttribute('draggable', 'true');
  tabEl.addEventListener('dragstart', (e) => {
    e.dataTransfer.setData('text/plain', id);
    tabEl.classList.add('dragging');
  });
  tabEl.addEventListener('dragend', () => {
    tabEl.classList.remove('dragging');
    document.querySelectorAll('.tab.drag-over').forEach((t) => t.classList.remove('drag-over'));
  });
  tabEl.addEventListener('dragover', (e) => {
    e.preventDefault();
    const dragging = document.querySelector('.tab.dragging');
    if (dragging && dragging !== tabEl) {
      tabEl.classList.add('drag-over');
    }
  });
  tabEl.addEventListener('dragleave', () => {
    tabEl.classList.remove('drag-over');
  });
  tabEl.addEventListener('drop', (e) => {
    e.preventDefault();
    tabEl.classList.remove('drag-over');
    const draggedId = e.dataTransfer.getData('text/plain');
    reorderTabs(draggedId, id);
  });

  const newTabBtn = document.getElementById('btn-new-tab');
  $tabsContainer.insertBefore(tabEl, newTabBtn);

  let webview = null;
  let newTabPage = null;
  let inAppPage = null;

  if (isNewTab) {
    newTabPage = createNewTabPage(id);
    $webviewContainer.appendChild(newTabPage);
  } else if (isHistory) {
    inAppPage = createHistoryPage(id);
    $webviewContainer.appendChild(inAppPage);
  } else if (isSettings) {
    inAppPage = createSettingsPage(id);
    $webviewContainer.appendChild(inAppPage);
  } else if (isExtensions) {
    inAppPage = createExtensionsInAppPage(id);
    $webviewContainer.appendChild(inAppPage);
  } else if (!isInAppPage) {
    webview = createWebview(id, url);
    $webviewContainer.appendChild(webview);
  }

  const tab = {
    id,
    tabEl,
    webview,
    newTabPage,
    inAppPage,
    url,
    title: initialTitle,
    isNewTab,
    isInAppPage,
    favicon: null,
    pinned: false,
    muted: false,
  };
  tabs.push(tab);

  activateTab(id);

  // For internal pages that use a webview (e.g. pqc-security with a file), navigate
  if (isInternal && !isNewTab && !isInAppPage) navigateInternalPage(id, url);
  return tab;
}

function createNewTabPage(tabId) {
  const div = document.createElement('div');
  div.className = 'new-tab-page';
  div.dataset.tabId = tabId;
  const wallpaper = pick(WALLPAPERS);
  const showWallpaper = localStorage.getItem('krypton_show_wallpaper') !== 'false';
  // Use the gradient value directly; no external image fetch
  const wallpaperStyle = showWallpaper
    ? `background: ${wallpaper.value}`
    : 'background: var(--bg-chrome)';

  // Build shortcuts HTML from user bookmarks only
  let shortcutsHtml = '';
  bookmarks.slice(0, 8).forEach((bm) => {
    const safeTitle = (bm.title || '').replace(/[<>"&]/g, '');
    const label = safeTitle.length > 10 ? safeTitle.substring(0, 10) + '…' : safeTitle;
    const faviconHtml = bm.favicon
      ? `<img src="${encodeURI(bm.favicon)}" data-fallback="language">`
      : '<span class="material-icons-outlined">language</span>';
    shortcutsHtml += `<button class="ntp-shortcut" data-url="${encodeURI(bm.url)}" title="${safeTitle}"><div class="ntp-shortcut-icon">${faviconHtml}</div><span class="ntp-shortcut-label">${label}</span></button>`;
  });

  div.innerHTML = `
    <div class="ntp-wallpaper" style="${wallpaperStyle}"></div>
    <div class="ntp-overlay" style="${showWallpaper ? '' : 'background: transparent'}"></div>
    <div class="ntp-top-bar">
      <div class="ntp-top-left">
        <button class="ntp-icon-btn" id="ntp-pqc-${tabId}" title="PQC Security">
          <span class="material-icons-outlined">shield</span>
          <span class="ntp-icon-label">Security</span>
        </button>
        <button class="ntp-icon-btn" id="ntp-history-${tabId}" title="History">
          <span class="material-icons-outlined">history</span>
          <span class="ntp-icon-label">History</span>
        </button>
      </div>
      <div class="ntp-top-right">
        <div class="ntp-stat"><span class="material-icons-outlined">verified_user</span><span>PQC Active</span></div>
        <div class="ntp-stat"><span class="material-icons-outlined">security</span><span>ML-KEM-768</span></div>
      </div>
    </div>
    <div class="ntp-center">
      <div class="ntp-clock" id="ntp-clock-${tabId}">${getTimeString()}</div>
      <div class="ntp-greeting" id="ntp-greeting-${tabId}">${getGreeting()}.</div>
    </div>
    <!-- Stats Widget (Brave Rewards style) -->
    <div class="ntp-stats-widget">
      <div class="ntp-stats-item">
        <span class="ntp-stats-num" id="ntp-stat-blocked-${tabId}">${shieldTotalBlocked}</span>
        <span class="ntp-stats-label">Trackers Blocked</span>
      </div>
      <div class="ntp-stats-item">
        <span class="ntp-stats-num" id="ntp-stat-https-${tabId}">0</span>
        <span class="ntp-stats-label">HTTPS Upgraded</span>
      </div>
      <div class="ntp-stats-item">
        <span class="ntp-stats-time" id="ntp-stat-time-${tabId}">0</span>
        <span class="ntp-stats-label">Minutes Saved</span>
      </div>
    </div>
    <div class="ntp-search-wrap">
      <div class="ntp-search" id="ntp-search-${tabId}">
        <span class="material-icons-outlined">search</span><span>Search or enter web address</span>
      </div>
    </div>
    <!-- Shortcuts Grid -->
    <div class="ntp-shortcuts-grid">${shortcutsHtml}</div>
    <div class="ntp-bottom-bar">
       <div class="ntp-bottom-left"><span class="ntp-badge-text">KryptonBrowser · Quantum-Secure · ${isPrivateMode ? 'Private Mode' : 'Protected'}</span></div>
      <div class="ntp-quote" id="ntp-quote-${tabId}"></div>
    </div>
  `;

  startClock(tabId);
  div.querySelector(`#ntp-search-${tabId}`).addEventListener('click', () => {
    $urlInput.focus();
    $urlInput.select();
  });
  div
    .querySelector(`#ntp-pqc-${tabId}`)
    .addEventListener('click', () => createTab('krypton://pqc-security'));
  div
    .querySelector(`#ntp-history-${tabId}`)
    .addEventListener('click', () => createTab('krypton://history'));

  // Set quote text via JS
  const quote = pick(QUOTES);
  const quoteEl = div.querySelector(`#ntp-quote-${tabId}`);
  if (quoteEl)
    quoteEl.innerHTML = `"${quote.text}"<span class="ntp-quote-author">— ${quote.author}</span>`;

  // Shortcut clicks
  div.querySelectorAll('.ntp-shortcut').forEach((btn) => {
    btn.addEventListener('click', () => navigateActiveTab(btn.dataset.url));
  });

  // Refresh stats from main process — update live every 5s
  function refreshNtpStats() {
    if (!window.kryptonBrowser) return;
    window.kryptonBrowser
      .getBlockingStats()
      .then((stats) => {
        if (!stats) return;
        const blocked = div.querySelector(`#ntp-stat-blocked-${tabId}`);
        const https = div.querySelector(`#ntp-stat-https-${tabId}`);
        const time = div.querySelector(`#ntp-stat-time-${tabId}`);
        if (blocked) blocked.textContent = (stats.blockedRequests || 0).toLocaleString();
        if (https) https.textContent = (stats.httpsUpgraded || 0).toLocaleString();
        // Estimate time saved: ~50ms per blocked request → minutes
        const mins = Math.round((((stats.blockedRequests || 0) * 0.05) / 60) * 10) / 10;
        if (time) time.textContent = mins || '0';
      })
      .catch(() => {});
  }
  refreshNtpStats();
  const ntpStatsInterval = setInterval(() => {
    // Stop refreshing if this NTP page is no longer in the DOM
    if (!div.isConnected) {
      clearInterval(ntpStatsInterval);
      return;
    }
    refreshNtpStats();
  }, 5000);

  return div;
}

function startClock(tabId) {
  if (clockInterval) clearInterval(clockInterval);
  clockInterval = setInterval(() => {
    const c = document.getElementById(`ntp-clock-${tabId}`);
    const g = document.getElementById(`ntp-greeting-${tabId}`);
    if (c) c.textContent = getTimeString();
    if (g) g.textContent = getGreeting() + '.';
  }, 10000);
}

function createWebview(tabId, url) {
  const wv = document.createElement('webview');
  wv.dataset.tabId = tabId;
  wv.setAttribute('src', url);
  wv.setAttribute('autosize', 'on');
  wv.setAttribute('preload', 'preload-webview.js');

  wv.addEventListener('did-start-loading', () => {
    showLoading(true);
    updateReloadButton(true);
  });
  wv.addEventListener('did-stop-loading', () => {
    showLoading(false);
    updateReloadButton(false);

    // Apply Extension Stubs
    const extMap = {};
    extensions.forEach((ext) => (extMap[ext.id] = ext.enabled));

    // Dark Reader Stub
    if (extMap['dark-reader']) {
      wv.insertCSS(
        'html, body { filter: invert(1) hue-rotate(180deg) !important; background: #111 !important; } img, video, iframe { filter: invert(1) hue-rotate(180deg) !important; }',
      ).catch(() => {});
    }

    // Speedreader Stub
    if (extMap['speedreader']) {
      wv.insertCSS(
        'body { max-width: 800px; margin: 0 auto; font-family: Georgia, serif; line-height: 1.6; } header, footer, aside, nav { display: none !important; }',
      ).catch(() => {});
    }

    // Password Manager Stub
    if (extMap['password-mgr']) {
      wv.executeJavaScript(
        `
        document.querySelectorAll('input[type="password"]').forEach(pw => {
          pw.style.border = '2px solid #34d399';
          pw.title = 'Krypton Password Manager: Ready to autofill';
        });
      `,
      ).catch(() => {});
    }

    // Translate Stub
    if (extMap['translate']) {
      wv.executeJavaScript(
        `
        if (document.documentElement.lang && !document.documentElement.lang.startsWith('en')) {
          console.log('Krypton Translate: Offer to translate page from ' + document.documentElement.lang);
        }
      `,
      ).catch(() => {});
    }
  });

  wv.addEventListener('did-navigate', (e) => {
    const tab = getTab(tabId);
    if (tab) {
      tab.url = e.url;
      // Record history immediately with URL as placeholder; title/favicon updated later
      tab._historyTs = Date.now();
      recordHistory(e.url, e.url, null, tab._historyTs);
      if (tabId === activeTabId) {
        $urlInput.value = e.url;
        updateSecurityIndicator(e.url);
        updateBookmarkButton();
      }
    }
    updateNavButtons();
  });

  wv.addEventListener('did-navigate-in-page', (e) => {
    const tab = getTab(tabId);
    if (tab && tabId === activeTabId) {
      tab.url = e.url;
      $urlInput.value = e.url;
    }
  });

  wv.addEventListener('page-title-updated', (e) => {
    const tab = getTab(tabId);
    if (tab) {
      tab.title = e.title;
      tab.tabEl.querySelector('.tab-title').textContent = e.title;
      if (tabId === activeTabId) document.title = e.title + ' — KryptonBrowser';
      // Update the history entry with the real page title
      updateHistoryEntry(tab._historyTs, { title: e.title });
    }
  });

  wv.addEventListener('page-favicon-updated', (e) => {
    const tab = getTab(tabId);
    if (tab && e.favicons && e.favicons.length > 0) {
      tab.favicon = e.favicons[0];
      tab.tabEl.querySelector('.tab-favicon').innerHTML =
        `<img src="${e.favicons[0]}" data-fallback="tab-favicon">`;
      // Update the history entry with the favicon
      updateHistoryEntry(tab._historyTs, { favicon: e.favicons[0] });
    }
  });

  wv.addEventListener('did-fail-load', (e) => {
    if (e.errorCode !== -3) showLoading(false);
  });

  // new-window: open in KryptonBrowser instead of system browser
  wv.addEventListener('new-window', (e) => {
    e.preventDefault();
    createTab(e.url);
  });

  // did-navigate: also refresh shield counter
  wv.addEventListener('did-navigate', () => {
    refreshShieldCount();
  });

  // Status bar: show link URL on hover
  wv.addEventListener('update-target-url', (e) => {
    const statusUrl = document.getElementById('status-hover-url');
    if (statusUrl) {
      if (e.url) {
        statusUrl.textContent = e.url;
        statusUrl.classList.add('visible');
      } else {
        statusUrl.classList.remove('visible');
      }
    }
  });

  // Context menu: right-click on webpage
  wv.addEventListener('context-menu', (e) => {
    e.preventDefault();
    showContextMenu(e.params || {}, e.x || e.clientX, e.y || e.clientY, wv);
  });

  // Hook find-in-page results (defined later in the file; call after DOM ready)
  setTimeout(() => {
    if (typeof hookFindInPage === 'function') hookFindInPage(wv);
  }, 0);

  return wv;
}

function navigateInternalPage(tabId, url) {
  const tab = getTab(tabId);
  if (!tab) return;
  const page = INTERNAL_PAGES[url];
  if (!page || !page.file) return;

  // Clean up any existing in-app pages
  if (tab.newTabPage) {
    tab.newTabPage.remove();
    tab.newTabPage = null;
    tab.isNewTab = false;
  }
  if (tab.inAppPage) {
    tab.inAppPage.remove();
    tab.inAppPage = null;
    tab.isInAppPage = false;
  }

  if (!tab.webview) {
    tab.webview = createWebview(tabId, page.file);
    $webviewContainer.appendChild(tab.webview);
  } else {
    tab.webview.src = page.file;
  }

  tab.url = url;
  tab.title = page.title;
  tab.tabEl.querySelector('.tab-title').textContent = page.title;
  tab.tabEl.querySelector('.tab-favicon').innerHTML =
    '<span class="material-icons-outlined">shield</span>';

  if (tabId === activeTabId) {
    showActiveContent(tab);
    $urlInput.value = url;
    updateSecurityIndicator(url);
  }
}

// ═══ History Page (Brave-style) ═══
function createHistoryPage(tabId) {
  const div = document.createElement('div');
  div.className = 'new-tab-page hist-page';
  div.dataset.tabId = tabId;

  let hist = [];
  try {
    hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
  } catch (e) {}

  function getDomain(url) {
    try {
      return new URL(url).hostname;
    } catch (e) {
      return url;
    }
  }

  function render(filter) {
    const container = div.querySelector('.hist-entries');
    if (!container) return;
    const f = (filter || '').toLowerCase();
    const filtered = f
      ? hist.filter(
          (h) =>
            (h.title || '').toLowerCase().includes(f) || (h.url || '').toLowerCase().includes(f),
        )
      : hist;

    if (filtered.length === 0) {
      container.innerHTML =
        '<div class="hist-empty"><span class="material-icons-outlined">history</span><p>' +
        (f ? 'No matching history' : 'No browsing history yet.') +
        '</p></div>';
      return;
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const yday = new Date(today);
    yday.setDate(yday.getDate() - 1);
    let html = '';
    let lastDay = '';

    for (let i = 0; i < filtered.length; i++) {
      const h = filtered[i];
      const d = new Date(h.timestamp);
      const ds = new Date(d);
      ds.setHours(0, 0, 0, 0);
      const dayStr =
        ds.getTime() === today.getTime()
          ? 'Today – ' +
            d.toLocaleDateString(undefined, {
              weekday: 'long',
              day: 'numeric',
              month: 'long',
              year: 'numeric',
            })
          : ds.getTime() === yday.getTime()
            ? 'Yesterday – ' +
              d.toLocaleDateString(undefined, {
                weekday: 'long',
                day: 'numeric',
                month: 'long',
                year: 'numeric',
              })
            : d.toLocaleDateString(undefined, {
                weekday: 'long',
                day: 'numeric',
                month: 'long',
                year: 'numeric',
              });

      if (dayStr !== lastDay) {
        if (lastDay) html += '</div>';
        html += '<div class="hist-day"><div class="hist-day-label">' + dayStr + '</div>';
        lastDay = dayStr;
      }
      const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const domain = getDomain(h.url);
      const faviconHtml = h.favicon
        ? '<img class="hist-favicon-img" src="' + h.favicon + '" data-fallback="language">'
        : '<span class="material-icons-outlined hist-favicon">language</span>';
      html +=
        '<div class="hist-row" data-url="' +
        h.url.replace(/"/g, '&quot;') +
        '" data-ts="' +
        h.timestamp +
        '">' +
        '<input type="checkbox" class="hist-check">' +
        '<span class="hist-time">' +
        time +
        '</span>' +
        faviconHtml +
        '<span class="hist-title">' +
        (h.title || h.url) +
        '</span>' +
        '<span class="hist-domain">' +
        domain +
        '</span>' +
        '<button class="hist-more" data-ts="' +
        h.timestamp +
        '" title="Delete this entry"><span class="material-icons-outlined">delete</span></button>' +
        '</div>';
    }
    if (lastDay) html += '</div>';
    container.innerHTML = sanitizeHTML(html);
  }

  div.innerHTML =
    '<div class="hist-sidebar">' +
    '<a class="hist-nav-item active"><span class="material-icons-outlined">history</span>Krypton history</a>' +
    '<a class="hist-nav-item"><span class="material-icons-outlined">bookmark_border</span>Bookmarks</a>' +
    '<a class="hist-nav-item"><span class="material-icons-outlined">file_download</span>Downloads</a>' +
    '<div class="hist-sidebar-divider"></div>' +
    '<a class="hist-nav-item hist-delete-link" id="he-' +
    tabId +
    '"><span class="material-icons-outlined">file_download</span>Export history</a>' +
    '<a class="hist-nav-item hist-delete-link" id="hc-' +
    tabId +
    '"><span class="material-icons-outlined">delete_outline</span>Delete browsing data</a>' +
    '</div>' +
    '<div class="hist-main">' +
    '<div class="hist-toolbar">' +
    '<div class="hist-search"><span class="material-icons-outlined">search</span>' +
    '<input type="text" placeholder="Search history" id="hs-' +
    tabId +
    '">' +
    '</div>' +
    '</div>' +
    '<div class="hist-entries"></div>' +
    '</div>';

  div.addEventListener('click', (e) => {
    const more = e.target.closest('.hist-more');
    if (more) {
      e.stopPropagation();
      const ts = Number(more.dataset.ts);
      hist = hist.filter((h) => h.timestamp !== ts);
      localStorage.setItem('krypton_history', JSON.stringify(hist));
      const si = div.querySelector('#hs-' + tabId);
      render(si ? si.value : '');
      return;
    }
    if (e.target.closest('.hist-check')) return;
    const row = e.target.closest('.hist-row');
    if (row) {
      navigateActiveTab(row.dataset.url);
      return;
    }
  });

  const si = div.querySelector('#hs-' + tabId);
  if (si) si.addEventListener('input', () => render(si.value));

  const he = div.querySelector('#he-' + tabId);
  if (he) {
    he.addEventListener('click', async () => {
      if (window.kryptonBrowser && window.kryptonBrowser.exportHistory) {
        try {
          // Export the current hist array
          const success = await window.kryptonBrowser.exportHistory(JSON.stringify(hist, null, 2));
          if (success && typeof showSettingsToast === 'function') {
            // In case settings toast works from here
            showSettingsToast('History exported successfully');
          }
        } catch (e) {
          console.error('History export failed', e);
        }
      }
    });
  }

  const cb = div.querySelector('#hc-' + tabId);
  if (cb)
    cb.addEventListener('click', () => {
      hist = [];
      localStorage.setItem('krypton_history', '[]');
      render('');
    });

  // Expose a refresh function so it re-reads localStorage when the tab is re-activated
  div._refreshHistory = function () {
    try {
      hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
    } catch (e) {
      hist = [];
    }
    const si = div.querySelector('#hs-' + tabId);
    render(si ? si.value : '');
  };

  render('');
  return div;
}

// ═══ Settings Page ═══
const ACCENT_COLORS = [
  { name: 'Orange', value: '#fb923c' },
  { name: 'Blue', value: '#60a5fa' },
  { name: 'Purple', value: '#a78bfa' },
  { name: 'Green', value: '#34d399' },
  { name: 'Red', value: '#f87171' },
  { name: 'Pink', value: '#f472b6' },
  { name: 'Cyan', value: '#22d3ee' },
  { name: 'Yellow', value: '#facc15' },
];

const SEARCH_ENGINES = {
  google: { name: 'Google', url: 'https://www.google.com/search?q=' },
  duckduckgo: { name: 'DuckDuckGo', url: 'https://duckduckgo.com/?q=' },
  bing: { name: 'Bing', url: 'https://www.bing.com/search?q=' },
  brave: { name: 'Brave Search', url: 'https://search.brave.com/search?q=' },
  yahoo: { name: 'Yahoo', url: 'https://search.yahoo.com/search?p=' },
};

function getSearchUrl(query) {
  const engine = localStorage.getItem('krypton_search_engine') || 'google';
  const se = SEARCH_ENGINES[engine] || SEARCH_ENGINES.google;
  return se.url + encodeURIComponent(query);
}

function showSettingsToast(msg) {
  let toast = document.querySelector('.settings-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'settings-toast';
    document.body.appendChild(toast);
  }
  toast.innerHTML = sanitizeHTML('<span class="material-icons-outlined">check_circle</span>' + msg);
  toast.classList.add('visible');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove('visible'), 2500);
}

function applyAccentColor() {
  const color = localStorage.getItem('krypton_accent_color') || '#fb923c';
  document.documentElement.style.setProperty('--accent', color);
}

function applyFontSize() {
  const size = localStorage.getItem('krypton_font_size') || 'medium';
  const factor = size === 'small' ? 0.9 : size === 'large' ? 1.1 : 1;
  document.documentElement.style.setProperty('font-size', factor * 100 + '%');
}

function applyBookmarksBarVisibility() {
  const show = localStorage.getItem('krypton_show_bookmarks') !== 'false';
  const bar = document.getElementById('bookmarks-bar');
  if (bar) bar.style.display = show ? '' : 'none';
}

// Apply saved settings on load
applyAccentColor();
applyFontSize();
applyBookmarksBarVisibility();

// Global Fallback Handler
document.addEventListener(
  'error',
  function (e) {
    if (e.target.tagName.toLowerCase() === 'img' && e.target.dataset.fallback) {
      const fb = e.target.dataset.fallback;
      e.target.outerHTML = `<span class="material-icons-outlined">${fb}</span>`;
    }
  },
  true,
);

function createSettingsPage(tabId) {
  const div = document.createElement('div');
  div.className = 'new-tab-page hist-page';
  div.dataset.tabId = tabId;

  // Read current settings
  const searchEngine = localStorage.getItem('krypton_search_engine') || 'google';
  const showBookmarks = localStorage.getItem('krypton_show_bookmarks') !== 'false';
  const showWallpaper = localStorage.getItem('krypton_show_wallpaper') !== 'false';
  const accentColor = localStorage.getItem('krypton_accent_color') || '#fb923c';
  const fontSize = localStorage.getItem('krypton_font_size') || 'medium';
  const blockCookies = localStorage.getItem('krypton_block_cookies') === 'true';
  const sendDNT = localStorage.getItem('krypton_send_dnt') === 'true';
  const startupMode = localStorage.getItem('krypton_startup') || 'newtab';
  const startupUrl = localStorage.getItem('krypton_startup_url') || '';
  const askDownloadLoc = localStorage.getItem('krypton_ask_download_loc') === 'true';

  // Build accent color swatches HTML
  let colorSwatchesHtml = '';
  ACCENT_COLORS.forEach((c) => {
    const sel = c.value === accentColor ? ' selected' : '';
    colorSwatchesHtml +=
      '<div class="settings-color-swatch' +
      sel +
      '" data-color="' +
      c.value +
      '" title="' +
      c.name +
      '" style="background:' +
      c.value +
      ';color:' +
      c.value +
      '"></div>';
  });

  // Build search engine radio buttons
  let searchHtml = '';
  Object.keys(SEARCH_ENGINES).forEach((key) => {
    const se = SEARCH_ENGINES[key];
    const checked = key === searchEngine ? ' checked' : '';
    searchHtml +=
      '<label class="settings-radio-item"><input type="radio" name="se-' +
      tabId +
      '" value="' +
      key +
      '"' +
      checked +
      '><span class="settings-radio-label">' +
      se.name +
      '</span></label>';
  });

  div.innerHTML =
    '<div class="hist-sidebar">' +
    '<a class="hist-nav-item active" data-settings-section="appearance"><span class="material-icons-outlined">palette</span>Appearance</a>' +
    '<a class="hist-nav-item" data-settings-section="privacy"><span class="material-icons-outlined">security</span>Privacy & Security</a>' +
    '<a class="hist-nav-item" data-settings-section="search"><span class="material-icons-outlined">search</span>Search Engine</a>' +
    '<a class="hist-nav-item" data-settings-section="startup"><span class="material-icons-outlined">rocket_launch</span>On Startup</a>' +
    '<a class="hist-nav-item" data-settings-section="downloads"><span class="material-icons-outlined">download</span>Downloads</a>' +
    '<a class="hist-nav-item" data-settings-section="printing"><span class="material-icons-outlined">print</span>Printing</a>' +
    '<div class="hist-sidebar-divider"></div>' +
    '<a class="hist-nav-item" data-settings-section="about"><span class="material-icons-outlined">info</span>About Krypton</a>' +
    '</div>' +
    '<div class="hist-main">' +
    '<div class="settings-content" id="settings-content-' +
    tabId +
    '">' +
    // ── APPEARANCE ──
    '<div class="settings-section active" data-section="appearance">' +
    '<h2 class="settings-heading">Appearance</h2>' +
    '<div class="settings-card">' +
    '<div class="settings-row"><div><div class="settings-label">Dark Mode</div><div class="settings-sublabel">KryptonBrowser uses a dark theme by default</div></div>' +
    '<div class="settings-toggle active disabled" title="Dark mode is always on"></div></div>' +
    '<div class="settings-row"><div><div class="settings-label">Show Bookmarks Bar</div><div class="settings-sublabel">Display bookmarks below the navigation bar</div></div>' +
    '<div class="settings-toggle' +
    (showBookmarks ? ' active' : '') +
    '" id="stgl-bookmarks-' +
    tabId +
    '"></div></div>' +
    '<div class="settings-row"><div><div class="settings-label">New Tab Wallpaper</div><div class="settings-sublabel">Show a landscape wallpaper on the new tab page</div></div>' +
    '<div class="settings-toggle' +
    (showWallpaper ? ' active' : '') +
    '" id="stgl-wallpaper-' +
    tabId +
    '"></div></div>' +
    '<div class="settings-row"><div><div class="settings-label">Font Size</div><div class="settings-sublabel">Adjust the base font size of the browser UI</div></div>' +
    '<select class="settings-select" id="stgl-fontsize-' +
    tabId +
    '"><option value="small"' +
    (fontSize === 'small' ? ' selected' : '') +
    '>Small</option><option value="medium"' +
    (fontSize === 'medium' ? ' selected' : '') +
    '>Medium</option><option value="large"' +
    (fontSize === 'large' ? ' selected' : '') +
    '>Large</option></select></div>' +
    '</div>' +
    '<div class="settings-card">' +
    '<div class="settings-row"><div><div class="settings-label">Accent Color</div><div class="settings-sublabel">Choose a color for buttons, toggles, and highlights</div></div></div>' +
    '<div class="settings-color-picker" id="stgl-color-' +
    tabId +
    '">' +
    colorSwatchesHtml +
    '</div>' +
    '</div>' +
    '</div>' +
    // ── PRIVACY & SECURITY ──
    '<div class="settings-section" data-section="privacy">' +
    '<h2 class="settings-heading">Privacy & Security</h2>' +
    '<div class="settings-card">' +
    '<div class="settings-row"><div><div class="settings-label">PQC Encryption</div><div class="settings-sublabel">Use post-quantum cryptography for all connections</div></div>' +
    '<div class="settings-toggle active disabled" id="stgl-pqc-' +
    tabId +
    '" title="PQC encryption is always enabled"></div></div>' +
    '<div class="settings-row"><div><div class="settings-label">Block Third-Party Cookies</div><div class="settings-sublabel">Prevent cross-site tracking through cookies</div></div>' +
    '<div class="settings-toggle' +
    (blockCookies ? ' active' : '') +
    '" id="stgl-cookies-' +
    tabId +
    '"></div></div>' +
    '<div class="settings-row"><div><div class="settings-label">Send "Do Not Track"</div><div class="settings-sublabel">Request websites not to track your browsing</div></div>' +
    '<div class="settings-toggle' +
    (sendDNT ? ' active' : '') +
    '" id="stgl-dnt-' +
    tabId +
    '"></div></div>' +
    '</div>' +
    '<div class="settings-card">' +
    '<div class="settings-row"><div><div class="settings-label">Clear Browsing Data</div><div class="settings-sublabel">Clear history, bookmarks, cookies, and cached files</div></div>' +
    '<button class="settings-btn-danger" id="settings-clear-data-' +
    tabId +
    '">Clear data…</button></div>' +
    '</div>' +
    '</div>' +
    // ── SEARCH ENGINE ──
    '<div class="settings-section" data-section="search">' +
    '<h2 class="settings-heading">Search Engine</h2>' +
    '<div class="settings-card">' +
    '<div class="settings-radio-group">' +
    searchHtml +
    '</div>' +
    '</div>' +
    '</div>' +
    // ── ON STARTUP ──
    '<div class="settings-section" data-section="startup">' +
    '<h2 class="settings-heading">On Startup</h2>' +
    '<div class="settings-card">' +
    '<div class="settings-radio-group">' +
    '<label class="settings-radio-item"><input type="radio" name="su-' +
    tabId +
    '" value="newtab"' +
    (startupMode === 'newtab' ? ' checked' : '') +
    '><div><span class="settings-radio-label">Open the New Tab page</span><div class="settings-radio-desc">Start with a fresh new tab page</div></div></label>' +
    '<label class="settings-radio-item"><input type="radio" name="su-' +
    tabId +
    '" value="last-session"' +
    (startupMode === 'last-session' ? ' checked' : '') +
    '><div><span class="settings-radio-label">Continue where you left off</span><div class="settings-radio-desc">Restore your last browsing session</div></div></label>' +
    '<label class="settings-radio-item"><input type="radio" name="su-' +
    tabId +
    '" value="custom"' +
    (startupMode === 'custom' ? ' checked' : '') +
    '><div><span class="settings-radio-label">Open a specific page</span><div class="settings-radio-desc">Enter a URL to open on startup</div></div></label>' +
    '</div>' +
    '<div style="padding:8px 12px 4px"><input type="text" class="settings-input" id="stgl-startup-url-' +
    tabId +
    '" placeholder="https://example.com" value="' +
    startupUrl.replace(/"/g, '&quot;') +
    '"' +
    (startupMode !== 'custom' ? ' disabled' : '') +
    '></div>' +
    '</div>' +
    '</div>' +
    // ── DOWNLOADS ──
    '<div class="settings-section" data-section="downloads">' +
    '<h2 class="settings-heading">Downloads</h2>' +
    '<div class="settings-card">' +
    '<div class="settings-row"><div><div class="settings-label">Download Location</div><div class="settings-sublabel">Where files are saved by default</div></div></div>' +
    '<div class="settings-path-display"><span class="material-icons-outlined">folder</span>~/Downloads</div>' +
    '<div class="settings-row" style="margin-top:8px"><div><div class="settings-label">Ask where to save</div><div class="settings-sublabel">Prompt for download location each time</div></div>' +
    '<div class="settings-toggle' +
    (askDownloadLoc ? ' active' : '') +
    '" id="stgl-download-' +
    tabId +
    '"></div></div>' +
    '</div>' +
    '</div>' +
    // ── PRINTING ──
    '<div class="settings-section" data-section="printing">' +
    '<h2 class="settings-heading">Printing</h2>' +
    '<div class="settings-card">' +
    '<div class="settings-row"><div><div class="settings-label">Print Current Page</div><div class="settings-sublabel">Send the active web page to your printer</div></div>' +
    '<button class="settings-btn-danger" id="settings-print-page-' +
    tabId +
    '" style="border-color:var(--accent);color:var(--accent)">Print…</button></div>' +
    '</div>' +
    '<div class="settings-card">' +
    '<div class="settings-row"><div><div class="settings-label">Headers and Footers</div><div class="settings-sublabel">Include page title, URL, date, and page numbers</div></div>' +
    '<div class="settings-toggle' +
    (localStorage.getItem('krypton_print_headers') !== 'false' ? ' active' : '') +
    '" id="stgl-print-headers-' +
    tabId +
    '"></div></div>' +
    '<div class="settings-row"><div><div class="settings-label">Background Graphics</div><div class="settings-sublabel">Include background colors and images when printing</div></div>' +
    '<div class="settings-toggle' +
    (localStorage.getItem('krypton_print_bg') === 'true' ? ' active' : '') +
    '" id="stgl-print-bg-' +
    tabId +
    '"></div></div>' +
    '</div>' +
    '</div>' +
    // ── ABOUT ──
    '<div class="settings-section" data-section="about">' +
    '<h2 class="settings-heading">About Krypton</h2>' +
    '<div class="settings-card-centered">' +
    '<div class="settings-about-icon">🛡️</div>' +
    '<div class="settings-about-name">KryptonBrowser</div>' +
    '<div class="settings-about-version">Version 1.0.0</div>' +
    '<div class="settings-about-desc">Post-Quantum Cryptography Enabled Secure Browser</div>' +
    '<div class="settings-about-engine">Chromium ' +
    (window.kryptonBrowser ? window.kryptonBrowser.chromeVersion : '') +
    ' · Electron ' +
    (window.kryptonBrowser ? window.kryptonBrowser.electronVersion : '') +
    '</div>' +
    '</div>' +
    '</div>' +
    '</div></div>';

  // ── Sidebar navigation ──
  div.querySelectorAll('[data-settings-section]').forEach((item) => {
    item.addEventListener('click', () => {
      div.querySelectorAll('[data-settings-section]').forEach((n) => n.classList.remove('active'));
      item.classList.add('active');
      const sec = item.dataset.settingsSection;
      div.querySelectorAll('.settings-section').forEach((s) => {
        s.classList.remove('active');
        s.style.display = '';
      });
      const target = div.querySelector('.settings-section[data-section="' + sec + '"]');
      if (target) target.classList.add('active');
    });
  });

  // ── Helper: wire up a simple toggle ──
  // Keys that should also be synced to the main process config
  const MAIN_PROCESS_KEYS = new Set([
    'krypton_block_cookies',
    'krypton_send_dnt',
    'krypton_ad_block',
    'krypton_https_upgrade',
    'krypton_ask_download_loc',
  ]);

  function wireToggle(id, storageKey, onChange) {
    const el = div.querySelector('#' + id);
    if (!el || el.classList.contains('disabled')) return;
    el.addEventListener('click', () => {
      el.classList.toggle('active');
      const isOn = el.classList.contains('active');
      localStorage.setItem(storageKey, String(isOn));
      // Sync to main process if this is a network-affecting setting
      if (MAIN_PROCESS_KEYS.has(storageKey) && window.kryptonBrowser) {
        window.kryptonBrowser.setConfig(storageKey, String(isOn));
      }
      if (onChange) onChange(isOn);
      showSettingsToast('Setting saved');
    });
  }

  // ── APPEARANCE toggles ──
  wireToggle('stgl-bookmarks-' + tabId, 'krypton_show_bookmarks', (on) => {
    applyBookmarksBarVisibility();
  });
  wireToggle('stgl-wallpaper-' + tabId, 'krypton_show_wallpaper');

  // Font size
  const fontSel = div.querySelector('#stgl-fontsize-' + tabId);
  if (fontSel) {
    fontSel.addEventListener('change', () => {
      localStorage.setItem('krypton_font_size', fontSel.value);
      applyFontSize();
      showSettingsToast('Font size updated');
    });
  }

  // Accent color
  const colorPicker = div.querySelector('#stgl-color-' + tabId);
  if (colorPicker) {
    colorPicker.addEventListener('click', (e) => {
      const swatch = e.target.closest('.settings-color-swatch');
      if (!swatch) return;
      colorPicker
        .querySelectorAll('.settings-color-swatch')
        .forEach((s) => s.classList.remove('selected'));
      swatch.classList.add('selected');
      const color = swatch.dataset.color;
      localStorage.setItem('krypton_accent_color', color);
      applyAccentColor();
      showSettingsToast('Accent color updated');
    });
  }

  // ── PRIVACY toggles ──
  wireToggle('stgl-cookies-' + tabId, 'krypton_block_cookies');
  wireToggle('stgl-dnt-' + tabId, 'krypton_send_dnt');

  // PQC toggle — show toast that it can't be disabled
  const pqcToggle = div.querySelector('#stgl-pqc-' + tabId);
  if (pqcToggle) {
    pqcToggle.addEventListener('click', () => {
      showSettingsToast('PQC encryption cannot be disabled — quantum security is always on');
    });
  }

  // Clear data — open modal
  const clearBtn = div.querySelector('#settings-clear-data-' + tabId);
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      const overlay = document.createElement('div');
      overlay.className = 'settings-modal-overlay';
      overlay.innerHTML =
        '<div class="settings-modal">' +
        '<div class="settings-modal-header">Clear browsing data</div>' +
        '<div class="settings-modal-body">' +
        '<label class="settings-modal-check"><input type="checkbox" data-clear="history" checked>Browsing history</label>' +
        '<label class="settings-modal-check"><input type="checkbox" data-clear="bookmarks">Bookmarks</label>' +
        '<label class="settings-modal-check"><input type="checkbox" data-clear="cookies" checked>Cookies and site data</label>' +
        '<label class="settings-modal-check"><input type="checkbox" data-clear="cache" checked>Cached images and files</label>' +
        '</div>' +
        '<div class="settings-modal-footer">' +
        '<button class="settings-modal-btn" id="modal-cancel">Cancel</button>' +
        '<button class="settings-modal-btn danger" id="modal-clear">Clear data</button>' +
        '</div></div>';

      document.body.appendChild(overlay);

      overlay.querySelector('#modal-cancel').addEventListener('click', () => overlay.remove());
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.remove();
      });

      overlay.querySelector('#modal-clear').addEventListener('click', () => {
        const checks = overlay.querySelectorAll('input[type="checkbox"]');
        checks.forEach((ch) => {
          if (!ch.checked) return;
          const key = ch.dataset.clear;
          if (key === 'history') localStorage.removeItem('krypton_history');
          if (key === 'bookmarks') {
            localStorage.removeItem('krypton_bookmarks');
            bookmarks = [];
            renderBookmarksBar();
          }
          // cookies and cache are visual-only in Electron
        });
        overlay.remove();
        showSettingsToast('Browsing data cleared');
      });
    });
  }

  // ── SEARCH ENGINE ──
  div.querySelectorAll('input[name="se-' + tabId + '"]').forEach((radio) => {
    radio.addEventListener('change', () => {
      localStorage.setItem('krypton_search_engine', radio.value);
      showSettingsToast('Search engine set to ' + SEARCH_ENGINES[radio.value].name);
    });
  });

  // ── ON STARTUP ──
  const startupUrlInput = div.querySelector('#stgl-startup-url-' + tabId);
  div.querySelectorAll('input[name="su-' + tabId + '"]').forEach((radio) => {
    radio.addEventListener('change', () => {
      localStorage.setItem('krypton_startup', radio.value);
      if (startupUrlInput) startupUrlInput.disabled = radio.value !== 'custom';
      showSettingsToast('Startup behavior saved');
    });
  });
  if (startupUrlInput) {
    startupUrlInput.addEventListener('change', () => {
      localStorage.setItem('krypton_startup_url', startupUrlInput.value.trim());
    });
  }

  // ── DOWNLOADS toggle ──
  wireToggle('stgl-download-' + tabId, 'krypton_ask_download_loc');

  // ── PRINTING ──
  wireToggle('stgl-print-headers-' + tabId, 'krypton_print_headers');
  wireToggle('stgl-print-bg-' + tabId, 'krypton_print_bg');

  const printBtn = div.querySelector('#settings-print-page-' + tabId);
  if (printBtn) {
    printBtn.addEventListener('click', () => {
      const tab = getActiveTab();
      if (tab && tab.webview) {
        tab.webview.print();
        showSettingsToast('Print dialog opened');
      } else {
        showSettingsToast('No web page loaded to print');
      }
    });
  }

  return div;
}

// ═══ Extensions In-App Page ═══
function createExtensionsInAppPage(tabId) {
  const div = document.createElement('div');
  div.className = 'new-tab-page hist-page';
  div.dataset.tabId = tabId;

  function renderExtList() {
    let html =
      '<div class="hist-sidebar">' +
      '<a class="hist-nav-item active"><span class="material-icons-outlined">extension</span>All Extensions</a>' +
      '<a class="hist-nav-item"><span class="material-icons-outlined">check_circle</span>Enabled</a>' +
      '<a class="hist-nav-item"><span class="material-icons-outlined">block</span>Disabled</a>' +
      '</div>' +
      '<div class="hist-main">' +
      '<h2 style="font-size:20px;font-weight:600;margin-bottom:20px;color:var(--text-primary)">Extensions</h2>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">';

    extensions.forEach((ext, i) => {
      html +=
        '<div style="background:var(--bg-tab);border-radius:12px;padding:16px;display:flex;align-items:flex-start;gap:12px">' +
        '<div style="width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;background:' +
        ext.color +
        ';flex-shrink:0">' +
        ext.icon +
        '</div>' +
        '<div style="flex:1;min-width:0">' +
        '<div style="font-size:14px;font-weight:500;color:var(--text-primary)">' +
        ext.name +
        '</div>' +
        '<div style="font-size:12px;color:var(--text-muted);margin-top:2px">' +
        ext.desc +
        '</div>' +
        '</div>' +
        '<div class="ext-page-toggle" data-ext-index="' +
        i +
        '" style="width:40px;height:22px;border-radius:11px;position:relative;cursor:pointer;flex-shrink:0;background:' +
        (ext.enabled ? 'var(--accent)' : 'var(--border)') +
        '">' +
        '<div style="position:absolute;' +
        (ext.enabled ? 'right:2px' : 'left:2px') +
        ';top:2px;width:18px;height:18px;border-radius:50%;background:#fff;transition:all 0.2s"></div>' +
        '</div>' +
        '</div>';
    });

    html += '</div></div>';
    div.innerHTML = html;

    // Bind toggle clicks
    div.querySelectorAll('.ext-page-toggle').forEach((toggle) => {
      toggle.addEventListener('click', () => {
        const idx = Number(toggle.dataset.extIndex);
        extensions[idx].enabled = !extensions[idx].enabled;
        renderExtList();
      });
    });
  }

  renderExtList();
  return div;
}

function activateTab(id) {
  activeTabId = id;
  document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
  const tab = getTab(id);
  if (!tab) return;
  tab.tabEl.classList.add('active');
  showActiveContent(tab);

  // Auto-refresh history page when switching back to it
  if (tab.isInAppPage && tab.inAppPage && tab.inAppPage._refreshHistory) {
    tab.inAppPage._refreshHistory();
  }

  if (tab.isNewTab) {
    $urlInput.value = '';
    updateSecurityIndicator('');
    document.title = 'New Tab — KryptonBrowser';
  } else {
    $urlInput.value = tab.url;
    updateSecurityIndicator(tab.url);
    document.title = (tab.title || 'KryptonBrowser') + ' — KryptonBrowser';
  }
  updateNavButtons();
  updateBookmarkButton();
  updateReaderModeButton();
  // Deactivate reader mode when switching tabs
  deactivateReaderMode();
}

function showActiveContent(tab) {
  document.querySelectorAll('webview').forEach((wv) => wv.classList.remove('active'));
  document.querySelectorAll('.new-tab-page').forEach((ntp) => ntp.classList.remove('active'));
  if (tab.isNewTab && tab.newTabPage) tab.newTabPage.classList.add('active');
  else if (tab.isInAppPage && tab.inAppPage) tab.inAppPage.classList.add('active');
  else if (tab.webview) tab.webview.classList.add('active');
}

function closeTab(id) {
  const idx = tabs.findIndex((t) => t.id === id);
  if (idx === -1) return;
  const tab = tabs[idx];
  tab.tabEl.remove();
  if (tab.webview) tab.webview.remove();
  if (tab.newTabPage) tab.newTabPage.remove();
  if (tab.inAppPage) tab.inAppPage.remove();
  tabs.splice(idx, 1);

  if (tabs.length === 0) {
    createTab();
    return;
  }
  if (activeTabId === id) {
    const ni = Math.min(idx, tabs.length - 1);
    activateTab(tabs[ni].id);
  }
}

function getTab(id) {
  return tabs.find((t) => t.id === id);
}
function getActiveTab() {
  return getTab(activeTabId);
}

// ═══ Navigation ═══
function navigateActiveTab(input) {
  const tab = getActiveTab();
  if (!tab) return;
  const url = normalizeUrl(input);

  if (url.startsWith('krypton://')) {
    if (url === 'krypton://newtab') return;
    // For in-app pages, open in a new tab
    if (
      url === 'krypton://history' ||
      url === 'krypton://settings' ||
      url === 'krypton://extensions'
    ) {
      createTab(url);
      return;
    }
    navigateInternalPage(tab.id, url);
    return;
  }

  // Clean up any overlay pages before navigating to a real URL
  if (tab.isNewTab) {
    if (tab.newTabPage) {
      tab.newTabPage.remove();
      tab.newTabPage = null;
    }
    tab.isNewTab = false;
  }
  if (tab.isInAppPage) {
    if (tab.inAppPage) {
      tab.inAppPage.remove();
      tab.inAppPage = null;
    }
    tab.isInAppPage = false;
  }

  if (!tab.webview) {
    tab.webview = createWebview(tab.id, url);
    $webviewContainer.appendChild(tab.webview);
    showActiveContent(tab);
  } else {
    tab.webview.src = url;
  }

  tab.url = url;
  tab.title = 'Loading...';
  tab.tabEl.querySelector('.tab-title').textContent = 'Loading...';
  tab.tabEl.querySelector('.tab-favicon').innerHTML =
    '<span class="material-icons-outlined">language</span>';
  $urlInput.value = url;
  updateSecurityIndicator(url);
  updateBookmarkButton();
}

function normalizeUrl(input) {
  input = input.trim();
  if (input.startsWith('krypton://')) return input;
  if (input.startsWith('http://') || input.startsWith('https://')) return input;
  if (input.startsWith('file://')) return input;
  if (/^[\w-]+(\.[\w-]+)+/.test(input)) return 'https://' + input;
  return getSearchUrl(input);
}

// ═══ Security Indicator ═══
function updateSecurityIndicator(url) {
  $securityIndicator.className = 'security-indicator';
  $pqcBadge.classList.remove('visible');

  if (!url || url.startsWith('krypton://')) {
    $lockIcon.textContent = 'shield';
    $securityIndicator.classList.add('secure');
    if (url === 'krypton://pqc-security') $pqcBadge.classList.add('visible');
    return;
  }
  if (url.startsWith('https://')) {
    $lockIcon.textContent = 'lock';
    $securityIndicator.classList.add('secure');
    $pqcBadge.classList.add('visible');
  } else if (url.startsWith('http://')) {
    $lockIcon.textContent = 'lock_open';
    $securityIndicator.classList.add('insecure');
  } else {
    $lockIcon.textContent = 'language';
  }
}

// ═══ Nav Buttons ═══
function updateNavButtons() {
  const tab = getActiveTab();
  const $back = document.getElementById('btn-back');
  const $forward = document.getElementById('btn-forward');
  if (tab && tab.webview) {
    try {
      $back.disabled = !tab.webview.canGoBack();
      $forward.disabled = !tab.webview.canGoForward();
    } catch (e) {
      $back.disabled = true;
      $forward.disabled = true;
    }
  } else {
    $back.disabled = true;
    $forward.disabled = true;
  }
}

function updateReloadButton(loading) {
  $reloadIcon.textContent = loading ? 'close' : 'refresh';
}

function showLoading(isLoading) {
  if (isLoading) $loadingBar.classList.add('active');
  else {
    $loadingBar.classList.remove('active');
    $loadingProgress.style.width = '0';
  }
}

// ═══ Panels: close all open panels ═══
function closeAllPanels() {
  $browserMenu.style.display = 'none';
  $extensionsPanel.style.display = 'none';
  $securityPopup.style.display = 'none';
  const shieldsPanel = document.getElementById('shields-panel');
  if (shieldsPanel) shieldsPanel.style.display = 'none';
}

// ═══ Shields Panel (Brave-style) ═══
const $shieldsPanel = document.getElementById('shields-panel');

function toggleShieldsPanel() {
  if ($shieldsPanel.style.display === 'none' || !$shieldsPanel.style.display) {
    closeAllPanels();
    updateShieldsPanel();
    $shieldsPanel.style.display = 'block';
  } else {
    $shieldsPanel.style.display = 'none';
  }
}

async function updateShieldsPanel() {
  const tab = getActiveTab();
  const $site = document.getElementById('shields-site');
  const $breakdown = document.getElementById('shields-breakdown');

  let pageUrl = '';
  if (tab && tab.url && !tab.url.startsWith('krypton://')) {
    try {
      pageUrl = tab.url;
      $site.textContent = new URL(tab.url).hostname;
    } catch {
      $site.textContent = tab.url;
    }
  } else {
    $site.textContent = 'No site loaded';
  }

  if (!window.kryptonBrowser) return;

  // Fetch global + per-site stats in parallel
  const [stats, siteStats] = await Promise.all([
    window.kryptonBrowser.getBlockingStats().catch(() => ({})),
    pageUrl
      ? window.kryptonBrowser.getSiteBlockCount(pageUrl).catch(() => null)
      : Promise.resolve(null),
  ]);

  // Update the global count + popup label
  const $popupBlocked = document.getElementById('popup-blocked');
  const total = stats.blockedRequests || 0;
  if ($popupBlocked) $popupBlocked.textContent = total + ' trackers';

  // Build per-site category breakdown
  if ($breakdown) {
    if (!siteStats || siteStats.total === 0) {
      $breakdown.innerHTML = `<div class="shields-no-data">No trackers detected on this page yet.</div>`;
    } else {
      const cats = [
        { key: 'ads', icon: 'ads_click', label: 'Ads' },
        { key: 'trackers', icon: 'track_changes', label: 'Trackers' },
        { key: 'fingerprinting', icon: 'fingerprint', label: 'Fingerprinting' },
        { key: 'cryptominers', icon: 'currency_bitcoin', label: 'Cryptominers' },
        { key: 'malware', icon: 'bug_report', label: 'Malware' },
        { key: 'social', icon: 'share', label: 'Social' },
        { key: 'telemetry', icon: 'analytics', label: 'Telemetry' },
        { key: 'patterns', icon: 'pattern', label: 'URL Patterns' },
      ];
      const rows = cats
        .filter((c) => siteStats[c.key] > 0)
        .map(
          (c) => `
                    <div class="shields-breakdown-row">
                        <span class="material-icons-outlined shields-cat-icon">${c.icon}</span>
                        <span class="shields-cat-label">${c.label}</span>
                        <span class="shields-cat-count">${siteStats[c.key]}</span>
                    </div>`,
        )
        .join('');
      $breakdown.innerHTML = `
                <div class="shields-breakdown-header">Blocked on this page (${siteStats.total} total)</div>
                ${rows || '<div class="shields-no-data">Breakdown unavailable</div>'}
            `;
    }
  }

  // Sync toggle initial states from IPC config
  const adBlock = await window.kryptonBrowser
    .getConfig('krypton_ad_block', 'true')
    .catch(() => 'true');
  const httpsUp = await window.kryptonBrowser
    .getConfig('krypton_https_upgrade', 'true')
    .catch(() => 'true');
  const globalTog = document.getElementById('shields-global-toggle');
  const httpsTog = document.getElementById('shields-https-toggle');
  if (globalTog) globalTog.classList.toggle('active', adBlock === 'true');
  if (httpsTog) httpsTog.classList.toggle('active', httpsUp === 'true');
}

// Wire shields panel controls
(function wireShieldsControls() {
  const globalToggle = document.getElementById('shields-global-toggle');
  if (globalToggle) {
    globalToggle.addEventListener('click', () => {
      globalToggle.classList.toggle('active');
      const isOn = globalToggle.classList.contains('active');
      if (window.kryptonBrowser) {
        window.kryptonBrowser.setConfig('krypton_ad_block', isOn ? 'true' : 'false');
      }
      localStorage.setItem('krypton_ad_block', isOn ? 'true' : 'false');
      showSettingsToast(
        isOn ? 'KryptonShield enabled for this site' : 'KryptonShield disabled for this site',
      );
    });
  }

  const httpsToggle = document.getElementById('shields-https-toggle');
  if (httpsToggle) {
    httpsToggle.addEventListener('click', () => {
      httpsToggle.classList.toggle('active');
      const isOn = httpsToggle.classList.contains('active');
      if (window.kryptonBrowser)
        window.kryptonBrowser.setConfig('krypton_https_upgrade', isOn ? 'true' : 'false');
      showSettingsToast(isOn ? 'HTTPS upgrade enabled' : 'HTTPS upgrade disabled');
    });
  }

  const scriptsToggle = document.getElementById('shields-scripts-toggle');
  if (scriptsToggle) {
    scriptsToggle.addEventListener('click', () => {
      scriptsToggle.classList.toggle('active');
      showSettingsToast(
        scriptsToggle.classList.contains('active')
          ? 'Script blocking enabled'
          : 'Script blocking disabled',
      );
    });
  }

  const advBtn = document.getElementById('shields-advanced-btn');
  if (advBtn)
    advBtn.addEventListener('click', () => {
      $shieldsPanel.style.display = 'none';
      createTab('krypton://settings');
    });

  const reportBtn = document.getElementById('shields-report-btn');
  if (reportBtn)
    reportBtn.addEventListener('click', () => {
      showSettingsToast('Broken site report submitted');
      $shieldsPanel.style.display = 'none';
    });
})();

// ═══ Tab Reordering ═══
function reorderTabs(draggedTabId, targetTabId) {
  const draggedIdx = tabs.findIndex((t) => t.id === draggedTabId);
  const targetIdx = tabs.findIndex((t) => t.id === targetTabId);
  if (draggedIdx === -1 || targetIdx === -1) return;

  const [tab] = tabs.splice(draggedIdx, 1);
  tabs.splice(targetIdx, 0, tab);

  // Re-order DOM
  const newTabBtn = document.getElementById('btn-new-tab');
  tabs.forEach((t) => $tabsContainer.insertBefore(t.tabEl, newTabBtn));
}

// ═══ Tab Context Menu ═══
const $tabCtxMenu = document.getElementById('tab-ctx-menu');
let tabCtxTargetId = null;

function showTabContextMenu(tabId, x, y) {
  tabCtxTargetId = tabId;
  const tab = getTab(tabId);
  if (!tab) return;

  // Update labels
  const pinLabel = document.getElementById('tab-ctx-pin-label');
  if (pinLabel) pinLabel.textContent = tab.pinned ? 'Unpin Tab' : 'Pin Tab';
  const muteLabel = document.getElementById('tab-ctx-mute-label');
  if (muteLabel) muteLabel.textContent = tab.muted ? 'Unmute Tab' : 'Mute Tab';

  $tabCtxMenu.style.display = 'block';
  const menuW = $tabCtxMenu.offsetWidth || 200;
  const menuH = $tabCtxMenu.offsetHeight || 260;
  $tabCtxMenu.style.left = Math.min(x, window.innerWidth - menuW - 8) + 'px';
  $tabCtxMenu.style.top = Math.min(y, window.innerHeight - menuH - 8) + 'px';
}

function hideTabContextMenu() {
  $tabCtxMenu.style.display = 'none';
  tabCtxTargetId = null;
}

$tabCtxMenu.addEventListener('click', (e) => {
  const item = e.target.closest('.ctx-item');
  if (!item) return;
  const action = item.dataset.tabAction;
  if (!tabCtxTargetId) return;

  const tab = getTab(tabCtxTargetId);
  if (!tab) {
    hideTabContextMenu();
    return;
  }

  switch (action) {
    case 'pin':
      tab.pinned = !tab.pinned;
      tab.tabEl.classList.toggle('pinned', tab.pinned);
      break;
    case 'duplicate':
      createTab(tab.url || 'krypton://newtab');
      break;
    case 'mute':
      tab.muted = !tab.muted;
      if (tab.webview) {
        try {
          tab.webview.setAudioMuted(tab.muted);
        } catch (e) {}
      }
      break;
    case 'reload':
      if (tab.webview) tab.webview.reload();
      break;
    case 'close-others': {
      const othersToClose = tabs
        .filter((t) => t.id !== tabCtxTargetId && !t.pinned)
        .map((t) => t.id);
      othersToClose.forEach((id) => closeTab(id));
      break;
    }
    case 'close-right': {
      const idx = tabs.findIndex((t) => t.id === tabCtxTargetId);
      const rightToClose = tabs
        .slice(idx + 1)
        .filter((t) => !t.pinned)
        .map((t) => t.id);
      rightToClose.forEach((id) => closeTab(id));
      break;
    }
    case 'close':
      closeTab(tabCtxTargetId);
      break;
  }
  hideTabContextMenu();
});

document.addEventListener('click', () => hideTabContextMenu());
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') hideTabContextMenu();
});

// ═══ Sidebar ═══
const $sidebar = document.getElementById('sidebar');

function toggleSidebar() {
  sidebarOpen = !sidebarOpen;
  $sidebar.style.display = sidebarOpen ? 'flex' : 'none';
  document.body.classList.toggle('sidebar-open', sidebarOpen);
  if (sidebarOpen) {
    refreshSidebarContent();
  }
}

function refreshSidebarContent() {
  renderSidebarBookmarks();
  renderSidebarHistory();
  renderSidebarReadingList();
}

function renderSidebarBookmarks(filter = '') {
  const list = document.getElementById('sidebar-bookmarks-list');
  if (!list) return;
  list.innerHTML = '';
  const f = filter.toLowerCase();
  const filtered = f
    ? bookmarks.filter((b) => b.title.toLowerCase().includes(f) || b.url.toLowerCase().includes(f))
    : bookmarks;

  if (filtered.length === 0) {
    list.innerHTML =
      '<div class="sidebar-empty"><span class="material-icons-outlined">bookmark_border</span><p>' +
      (f ? 'No matching bookmarks' : 'No bookmarks yet') +
      '</p></div>';
    return;
  }

  filtered.forEach((bm) => {
    const item = document.createElement('div');
    item.className = 'sidebar-list-item';
    const iconHtml = bm.favicon
      ? `<img src="${bm.favicon}" data-fallback="bookmark">`
      : '<span class="material-icons-outlined">bookmark</span>';

    item.innerHTML = sanitizeHTML(`
            <div class="sidebar-list-item-icon">${iconHtml}</div>
            <div class="sidebar-list-item-text">
                <div class="sidebar-list-item-title">${bm.title}</div>
                <div class="sidebar-list-item-url">${bm.url}</div>
            </div>
            <button class="sidebar-list-item-delete" title="Remove"><span class="material-icons-outlined">close</span></button>
        `);
    item.addEventListener('click', (e) => {
      if (e.target.closest('.sidebar-list-item-delete')) return;
      navigateActiveTab(bm.url);
    });
    item.querySelector('.sidebar-list-item-delete').addEventListener('click', (e) => {
      e.stopPropagation();
      bookmarks = bookmarks.filter((b) => b.url !== bm.url);
      saveBookmarks();
      renderSidebarBookmarks(filter);
      updateBookmarkButton();
    });
    list.appendChild(item);
  });
}

function renderSidebarHistory(filter = '') {
  const list = document.getElementById('sidebar-history-list');
  if (!list) return;
  list.innerHTML = '';
  let hist = [];
  try {
    hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
  } catch (e) {}

  const f = filter.toLowerCase();
  const filtered = f
    ? hist.filter(
        (h) => (h.title || '').toLowerCase().includes(f) || (h.url || '').toLowerCase().includes(f),
      )
    : hist;
  const limited = filtered.slice(0, 50);

  if (limited.length === 0) {
    list.innerHTML =
      '<div class="sidebar-empty"><span class="material-icons-outlined">history</span><p>' +
      (f ? 'No matching history' : 'No history yet') +
      '</p></div>';
    return;
  }

  limited.forEach((h) => {
    const item = document.createElement('div');
    item.className = 'sidebar-list-item';
    const iconHtml = h.favicon
      ? `<img src="${h.favicon}" data-fallback="language">`
      : '<span class="material-icons-outlined">language</span>';
    const time = new Date(h.timestamp).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    });

    item.innerHTML = sanitizeHTML(`
            <div class="sidebar-list-item-icon">${iconHtml}</div>
            <div class="sidebar-list-item-text">
                <div class="sidebar-list-item-title">${h.title || h.url}</div>
                <div class="sidebar-list-item-url">${h.url}</div>
            </div>
            <span class="sidebar-list-item-time">${time}</span>
        `);
    item.addEventListener('click', () => navigateActiveTab(h.url));
    list.appendChild(item);
  });
}

function renderSidebarReadingList() {
  const list = document.getElementById('sidebar-reading-list');
  const empty = document.getElementById('sidebar-reading-empty');
  if (!list) return;
  list.innerHTML = '';

  if (readingList.length === 0) {
    if (empty) empty.style.display = '';
    return;
  }
  if (empty) empty.style.display = 'none';

  readingList.forEach((item, i) => {
    const el = document.createElement('div');
    el.className = 'sidebar-list-item';
    el.innerHTML = sanitizeHTML(`
            <div class="sidebar-list-item-icon"><span class="material-icons-outlined">auto_stories</span></div>
            <div class="sidebar-list-item-text">
                <div class="sidebar-list-item-title">${item.title}</div>
                <div class="sidebar-list-item-url">${item.url}</div>
            </div>
            <button class="sidebar-list-item-delete" title="Remove"><span class="material-icons-outlined">close</span></button>
        `);
    el.addEventListener('click', (e) => {
      if (e.target.closest('.sidebar-list-item-delete')) return;
      navigateActiveTab(item.url);
    });
    el.querySelector('.sidebar-list-item-delete').addEventListener('click', (e) => {
      e.stopPropagation();
      readingList.splice(i, 1);
      localStorage.setItem('krypton_reading_list', JSON.stringify(readingList));
      renderSidebarReadingList();
    });
    list.appendChild(el);
  });
}

// Sidebar tab switching
document.querySelectorAll('.sidebar-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.sidebar-tab').forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.sidebar-pane').forEach((p) => p.classList.remove('active'));
    const pane = document.querySelector(`[data-sidebar-pane="${tab.dataset.sidebarTab}"]`);
    if (pane) pane.classList.add('active');
    refreshSidebarContent();
  });
});

// Sidebar search inputs
const sidebarBookmarkSearch = document.getElementById('sidebar-bookmark-search');
if (sidebarBookmarkSearch)
  sidebarBookmarkSearch.addEventListener('input', () =>
    renderSidebarBookmarks(sidebarBookmarkSearch.value),
  );

const sidebarHistorySearch = document.getElementById('sidebar-history-search');
if (sidebarHistorySearch)
  sidebarHistorySearch.addEventListener('input', () =>
    renderSidebarHistory(sidebarHistorySearch.value),
  );

// Sidebar add bookmark
const sidebarAddBookmark = document.getElementById('sidebar-add-bookmark');
if (sidebarAddBookmark)
  sidebarAddBookmark.addEventListener('click', () => {
    toggleBookmark();
    renderSidebarBookmarks();
  });

// Sidebar add to reading list
const sidebarAddReading = document.getElementById('sidebar-add-reading');
if (sidebarAddReading)
  sidebarAddReading.addEventListener('click', () => {
    const tab = getActiveTab();
    if (tab && tab.url && !tab.url.startsWith('krypton://')) {
      if (!readingList.find((r) => r.url === tab.url)) {
        readingList.push({ title: tab.title || tab.url, url: tab.url, addedAt: Date.now() });
        localStorage.setItem('krypton_reading_list', JSON.stringify(readingList));
        renderSidebarReadingList();
        showSettingsToast('Added to reading list');
      } else {
        showSettingsToast('Already in reading list');
      }
    }
  });

// Sidebar clear history
const sidebarClearHistory = document.getElementById('sidebar-clear-history');
if (sidebarClearHistory)
  sidebarClearHistory.addEventListener('click', () => {
    localStorage.removeItem('krypton_history');
    renderSidebarHistory();
    showSettingsToast('History cleared');
  });

// ═══ Reader Mode ═══
const $readerOverlay = document.getElementById('reader-overlay');
const $readerContent = document.getElementById('reader-content');
const $readerBtn = document.getElementById('btn-reader-mode');
const $readerTitle = document.getElementById('reader-title');

function toggleReaderMode() {
  if ($readerOverlay.style.display === 'none' || !$readerOverlay.style.display) {
    activateReaderMode();
  } else {
    deactivateReaderMode();
  }
}

function activateReaderMode() {
  const tab = getActiveTab();
  if (!tab || !tab.webview) return;

  $readerBtn.classList.add('active-reader');
  $readerOverlay.style.display = 'flex';
  $readerTitle.textContent = tab.title || 'Reader Mode';

  // Extract page content from webview
  tab.webview
    .executeJavaScript(
      `
        (function() {
            // Simple content extraction
            const article = document.querySelector('article') || document.querySelector('[role="main"]') || document.querySelector('main') || document.body;
            const title = document.querySelector('h1')?.textContent || document.title || '';
            const content = article ? article.innerHTML : document.body.innerHTML;
            return { title, content };
        })()
    `,
    )
    .then((result) => {
      if (result) {
        let html = '';
        if (result.title) html += '<h1>' + result.title + '</h1>';
        html += result.content || '<p>Could not extract readable content from this page.</p>';
        $readerContent.innerHTML = window.DOMPurify ? DOMPurify.sanitize(html) : html;
      }
    })
    .catch(() => {
      $readerContent.innerHTML =
        '<h1>Reader Mode</h1><p>Could not extract content from this page. Try a different page with article content.</p>';
    });

  $readerContent.style.fontSize = readerFontSize + 'px';
}

function deactivateReaderMode() {
  $readerOverlay.style.display = 'none';
  $readerBtn.classList.remove('active-reader');
}

// Reader controls
document.getElementById('reader-close').addEventListener('click', deactivateReaderMode);
document.getElementById('reader-font-minus').addEventListener('click', () => {
  readerFontSize = Math.max(12, readerFontSize - 2);
  $readerContent.style.fontSize = readerFontSize + 'px';
});
document.getElementById('reader-font-plus').addEventListener('click', () => {
  readerFontSize = Math.min(28, readerFontSize + 2);
  $readerContent.style.fontSize = readerFontSize + 'px';
});
document.getElementById('reader-theme-toggle').addEventListener('click', () => {
  readerLightTheme = !readerLightTheme;
  $readerContent.classList.toggle('light', readerLightTheme);
  $readerOverlay.style.background = readerLightTheme ? '#f5f5f5' : '#1a1a2e';
});

// Show reader mode button for web pages
function updateReaderModeButton() {
  const tab = getActiveTab();
  if (tab && tab.webview && tab.url && tab.url.startsWith('https://')) {
    $readerBtn.style.display = 'flex';
    $readerBtn.classList.add('available');
  } else {
    $readerBtn.style.display = 'none';
    $readerBtn.classList.remove('available');
  }
}

// ═══ Private Window Mode ═══
function togglePrivateMode() {
  isPrivateMode = !isPrivateMode;
  document.body.classList.toggle('private-mode', isPrivateMode);
  const banner = document.getElementById('private-mode-banner');
  if (banner) banner.style.display = isPrivateMode ? 'flex' : 'none';
  showSettingsToast(
    isPrivateMode ? 'Private browsing: no history will be saved' : 'Exited private mode',
  );
}

// ═══ Browser Menu ═══
function toggleMenu() {
  if ($browserMenu.style.display === 'none' || !$browserMenu.style.display) {
    closeAllPanels();
    $browserMenu.style.display = 'block';
  } else {
    $browserMenu.style.display = 'none';
  }
}

function handleMenuAction(action) {
  closeAllPanels();
  switch (action) {
    case 'new-tab':
      createTab();
      break;
    case 'new-window':
      createTab();
      break;
    case 'private-window':
      togglePrivateMode();
      createTab();
      break;
    case 'pqc-panel':
      createTab('krypton://pqc-security');
      break;
    case 'history':
      createTab('krypton://history');
      break;
    case 'bookmarks':
      toggleSidebar();
      break;
    case 'downloads':
      toggleDownloadsPanel();
      break;
    case 'extensions':
      toggleExtensionsPanel();
      break;
    case 'find':
      toggleFindBar();
      break;
    case 'print': {
      const tab = getActiveTab();
      if (tab && tab.webview) tab.webview.print();
      break;
    }
    case 'shield-toggle':
      toggleAdBlocking();
      break;
    case 'settings':
      createTab('krypton://settings');
      break;
  }
}

// Extensions panel
function toggleExtensionsPanel() {
  if ($extensionsPanel.style.display === 'none' || !$extensionsPanel.style.display) {
    closeAllPanels();
    renderExtensionsList();
    $extensionsPanel.style.display = 'block';
  } else {
    $extensionsPanel.style.display = 'none';
  }
}

// ═══ Downloads Panel ═══
function toggleDownloadsPanel() {
  if ($downloadsPanel.style.display === 'none' || !$downloadsPanel.style.display) {
    closeAllPanels();
    $downloadsPanel.style.display = 'flex';
  } else {
    $downloadsPanel.style.display = 'none';
  }
}

function renderDownloadItem(info) {
  const pct = info.totalBytes > 0 ? Math.round((info.receivedBytes / info.totalBytes) * 100) : 0;
  const isDone = info.state === 'completed';
  const isErr = info.state === 'interrupted' || info.state === 'cancelled';
  const metaText = isDone
    ? `${formatBytes(info.totalBytes)} — Done`
    : isErr
      ? `${info.state}`
      : `${formatBytes(info.receivedBytes)} / ${formatBytes(info.totalBytes)} — ${formatSpeed(info.speed)}`;

  let el = document.getElementById('dl-item-' + info.id);
  if (!el) {
    el = document.createElement('div');
    el.className = 'dl-item';
    el.id = 'dl-item-' + info.id;
    // Remove empty placeholder
    const empty = $dlList.querySelector('.dl-empty');
    if (empty) empty.remove();
    $dlList.insertBefore(el, $dlList.firstChild);
  }

  el.innerHTML = sanitizeHTML(
    `<div class="dl-file-icon"><span class="material-icons-outlined">${getFileIcon(info.filename)}</span></div>` +
      `<div class="dl-info">` +
      `<div class="dl-filename" title="${info.filename}">${info.filename}</div>` +
      `<div class="dl-meta">${metaText}</div>` +
      `<div class="dl-progress-bar-wrap"><div class="dl-progress-bar${isDone ? ' complete' : isErr ? ' error' : ''}" style="width:${isDone ? 100 : isErr ? 100 : pct}%"></div></div>` +
      (isDone
        ? `<div class="dl-actions"><button class="dl-action-btn primary dl-btn-open">Open</button><button class="dl-action-btn dl-btn-folder">Show in Folder</button></div>`
        : isErr
          ? `<div class="dl-actions"><span style="font-size:11px;color:var(--accent-red)">${info.state}</span></div>`
          : `<div class="dl-actions"><span style="font-size:11px;color:var(--text-muted)">${pct}%</span></div>`) +
      `</div>`,
  );

  if (isDone) {
    const btnOpen = el.querySelector('.dl-btn-open');
    const btnFolder = el.querySelector('.dl-btn-folder');
    if (btnOpen)
      btnOpen.addEventListener('click', () => window.kryptonBrowser.openDownload(info.savePath));
    if (btnFolder)
      btnFolder.addEventListener('click', () =>
        window.kryptonBrowser.showDownloadInFolder(info.savePath),
      );
  }
}

function renderExtensionsList() {
  const $list = document.getElementById('ext-list');
  $list.innerHTML = '';
  extensions.forEach((ext) => {
    const item = document.createElement('div');
    item.className = 'ext-item';
    item.innerHTML = `
      <div class="ext-icon" style="background:${ext.color}">${ext.icon}</div>
      <div class="ext-info">
        <div class="ext-name">${ext.name}</div>
        <div class="ext-desc">${ext.desc}</div>
      </div>
      <div class="ext-toggle ${ext.enabled ? 'active' : ''}" data-ext-id="${ext.id}"></div>
    `;
    item.querySelector('.ext-toggle').addEventListener('click', (e) => {
      ext.enabled = !ext.enabled;
      e.target.classList.toggle('active');
    });
    $list.appendChild(item);
  });
}

// ═══ Security Popup ═══
async function updateSecurityPopup() {
  const tab = getActiveTab();
  if (!tab) return;
  const $title = document.getElementById('popup-title');
  const $subtitle = document.getElementById('popup-subtitle');
  const $popupLock = document.getElementById('popup-lock-icon');
  const $protocol = document.getElementById('popup-protocol');
  const $kem = document.getElementById('popup-kem');
  const $cipher = document.getElementById('popup-cipher');
  const $pqc = document.getElementById('popup-pqc');

  if (tab.url && tab.url.startsWith('https://')) {
    const secInfo = await window.kryptonBrowser.getSecurityInfo(tab.url);
    if (secInfo && secInfo.secure) {
      $title.textContent = 'Connection is secure';
      $subtitle.textContent = secInfo.pqcActive
        ? 'Post-quantum encryption active'
        : 'Standard encryption active';
      $popupLock.textContent = 'lock';
      $popupLock.style.color = 'var(--accent-green)';
      $protocol.textContent = secInfo.protocol || 'TLS 1.3';
      $kem.textContent = secInfo.kem || 'Standard';
      $cipher.textContent = secInfo.cipher || 'Standard';
      if (secInfo.pqcActive) {
        $pqc.textContent = '✓ Active';
        $pqc.className = 'popup-value pqc-active';
      } else {
        $pqc.textContent = '⚠ Inactive';
        $pqc.className = 'popup-value';
        $pqc.style.color = 'var(--text-muted)';
      }
    } else {
      $title.textContent = 'Connection is secure';
      $subtitle.textContent = 'Standard encryption active';
      $popupLock.textContent = 'lock';
      $popupLock.style.color = 'var(--accent-green)';
      $protocol.textContent = 'TLS 1.2/1.3';
      $kem.textContent = 'Standard';
      $cipher.textContent = 'Standard';
      $pqc.textContent = '⚠ Inactive';
      $pqc.className = 'popup-value';
      $pqc.style.color = 'var(--text-muted)';
    }
  } else if (tab.url && tab.url.startsWith('http://')) {
    $title.textContent = 'Connection is NOT secure';
    $subtitle.textContent = 'No encryption — data may be intercepted';
    $popupLock.textContent = 'lock_open';
    $popupLock.style.color = 'var(--accent-red)';
    $protocol.textContent = 'None';
    $kem.textContent = 'None';
    $cipher.textContent = 'None';
    $pqc.textContent = '✗ Inactive';
    $pqc.className = 'popup-value';
    $pqc.style.color = 'var(--accent-red)';
  } else {
    $title.textContent = 'Internal page';
    $subtitle.textContent = 'KryptonBrowser internal resources';
    $popupLock.textContent = 'shield';
    $popupLock.style.color = 'var(--accent-green)';
    $protocol.textContent = 'Local';
    $kem.textContent = 'N/A';
    $cipher.textContent = 'N/A';
    $pqc.textContent = 'N/A';
    $pqc.className = 'popup-value';
    $pqc.style.color = 'var(--text-muted)';
  }
}

// ═══ Zoom ═══
function setZoom(delta) {
  zoomLevel = Math.max(25, Math.min(500, zoomLevel + delta));
  document.getElementById('zoom-level').textContent = zoomLevel + '%';
  const tab = getActiveTab();
  if (tab && tab.webview) {
    tab.webview.setZoomFactor(zoomLevel / 100);
  }
}

// ═══ Event Listeners ═══
const $acDropdown = document.getElementById('autocomplete-dropdown');
let acSelectedIndex = -1;

function showAutocomplete(query) {
  if (!query || query.length < 1) {
    hideAutocomplete();
    return;
  }
  const q = query.toLowerCase();
  const results = [];

  // Search history
  try {
    const hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
    const seen = new Set();
    hist.forEach((h) => {
      if (seen.has(h.url)) return;
      if ((h.title || '').toLowerCase().includes(q) || (h.url || '').toLowerCase().includes(q)) {
        seen.add(h.url);
        results.push({ title: h.title || h.url, url: h.url, icon: 'history', type: 'History' });
      }
    });
  } catch (e) {}

  // Search bookmarks
  bookmarks.forEach((b) => {
    if (results.some((r) => r.url === b.url)) return;
    if ((b.title || '').toLowerCase().includes(q) || (b.url || '').toLowerCase().includes(q)) {
      results.push({ title: b.title || b.url, url: b.url, icon: 'bookmark', type: 'Bookmark' });
    }
  });

  // Search engine suggestion (uses selected engine)
  const _curEngine = localStorage.getItem('krypton_search_engine') || 'google';
  const _curSE = SEARCH_ENGINES[_curEngine] || SEARCH_ENGINES.google;
  results.push({
    title: 'Search ' + _curSE.name + ' for "' + query + '"',
    url: _curSE.url + encodeURIComponent(query),
    icon: 'search',
    type: 'Search',
  });

  function renderResults() {
    if (results.length === 0) {
      hideAutocomplete();
      return;
    }

    // Limit
    const limited = results.slice(0, 8);
    $acDropdown.innerHTML = '';
    acSelectedIndex = -1;

    limited.forEach((item, i) => {
      const row = document.createElement('div');
      row.className = 'ac-item';
      row.dataset.index = i;

      // Highlight matching text
      let displayTitle = item.title;
      const matchIdx = displayTitle.toLowerCase().indexOf(q);
      if (matchIdx >= 0) {
        displayTitle =
          displayTitle.substring(0, matchIdx) +
          '<b>' +
          displayTitle.substring(matchIdx, matchIdx + q.length) +
          '</b>' +
          displayTitle.substring(matchIdx + q.length);
      }

      row.innerHTML = sanitizeHTML(
        '<span class="material-icons-outlined">' +
          item.icon +
          '</span>' +
          '<span class="ac-title">' +
          displayTitle +
          '</span>' +
          '<span class="ac-url">' +
          item.url +
          '</span>' +
          '<span class="ac-type">' +
          item.type +
          '</span>',
      );

      row.addEventListener('mousedown', (e) => {
        e.preventDefault(); // prevent blur
        navigateActiveTab(item.url);
        hideAutocomplete();
        $urlInput.blur();
      });

      $acDropdown.appendChild(row);
    });

    $acDropdown.style.display = 'block';
  }

  // Render initial synchronous results immediately
  renderResults();

  // DuckDuckGo autocomplete integration
  if (query.length > 1) {
    fetch(`https://duckduckgo.com/ac/?q=${encodeURIComponent(query)}&type=list`)
      .then((res) => res.json())
      .then((data) => {
        if (data && data[1]) {
          const suggestions = data[1].slice(0, 4);
          let added = false;
          suggestions.forEach((sug) => {
            if (!results.some((r) => r.title === sug)) {
              results.push({
                title: sug,
                url: _curSE.url + encodeURIComponent(sug),
                icon: 'search',
                type: 'Suggestion',
              });
              added = true;
            }
          });
          if (added) renderResults();
        }
      })
      .catch(() => {});
  }
}

function hideAutocomplete() {
  $acDropdown.style.display = 'none';
  $acDropdown.innerHTML = '';
  acSelectedIndex = -1;
}

function selectAcItem(delta) {
  const items = $acDropdown.querySelectorAll('.ac-item');
  if (items.length === 0) return;
  items.forEach((it) => it.classList.remove('selected'));
  acSelectedIndex = (acSelectedIndex + delta + items.length) % items.length;
  items[acSelectedIndex].classList.add('selected');
  items[acSelectedIndex].scrollIntoView({ block: 'nearest' });
  // Update URL input with the selected item's URL
  $urlInput.value = items[acSelectedIndex].querySelector('.ac-url').textContent;
}

$urlInput.addEventListener('input', () => {
  showAutocomplete($urlInput.value);
});
$urlInput.addEventListener('keydown', (e) => {
  if ($acDropdown.style.display !== 'none') {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectAcItem(1);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectAcItem(-1);
      return;
    }
  }
  if (e.key === 'Enter') {
    e.preventDefault();
    hideAutocomplete();
    navigateActiveTab($urlInput.value);
    $urlInput.blur();
  }
  if (e.key === 'Escape') {
    hideAutocomplete();
    const tab = getActiveTab();
    if (tab) $urlInput.value = tab.url || '';
    $urlInput.blur();
  }
});
$urlInput.addEventListener('focus', () => {
  setTimeout(() => {
    $urlInput.select();
    if ($urlInput.value) showAutocomplete($urlInput.value);
  }, 50);
});
$urlInput.addEventListener('blur', () => {
  // Small delay to allow mousedown on suggestions
  setTimeout(() => hideAutocomplete(), 150);
});

// Nav buttons
document.getElementById('btn-back').addEventListener('click', () => {
  const tab = getActiveTab();
  if (tab && tab.webview) {
    try {
      tab.webview.goBack();
    } catch (e) {}
  }
});
document.getElementById('btn-forward').addEventListener('click', () => {
  const tab = getActiveTab();
  if (tab && tab.webview) {
    try {
      tab.webview.goForward();
    } catch (e) {}
  }
});
document.getElementById('btn-reload').addEventListener('click', () => {
  const tab = getActiveTab();
  if (!tab || !tab.webview) return;
  if ($reloadIcon.textContent === 'close') tab.webview.stop();
  else tab.webview.reload();
});

document.getElementById('btn-new-tab').addEventListener('click', () => createTab());

// Bookmark button
$bookmarkBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  toggleBookmark();
});

// PQC Security Panel button
document.getElementById('btn-security-panel').addEventListener('click', () => {
  closeAllPanels();
  createTab('krypton://pqc-security');
});

// Extensions button
document.getElementById('btn-extensions').addEventListener('click', (e) => {
  e.stopPropagation();
  toggleExtensionsPanel();
});

// Menu button
document.getElementById('btn-menu').addEventListener('click', (e) => {
  e.stopPropagation();
  toggleMenu();
});

// Menu items
$browserMenu.addEventListener('click', (e) => {
  const item = e.target.closest('.menu-item');
  if (item && item.dataset.action) {
    handleMenuAction(item.dataset.action);
  }
});

// Zoom controls
document.getElementById('zoom-out').addEventListener('click', (e) => {
  e.stopPropagation();
  setZoom(-10);
});
document.getElementById('zoom-in').addEventListener('click', (e) => {
  e.stopPropagation();
  setZoom(10);
});
document.getElementById('zoom-fullscreen').addEventListener('click', (e) => {
  e.stopPropagation();
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen();
});

// Security indicator click
$securityIndicator.addEventListener('click', (e) => {
  e.stopPropagation();
  if ($securityPopup.style.display === 'none' || !$securityPopup.style.display) {
    closeAllPanels();
    $securityPopup.style.display = 'block';
    updateSecurityPopup();
  } else {
    $securityPopup.style.display = 'none';
  }
});

// Close panels on outside click
document.addEventListener('click', (e) => {
  if (!$browserMenu.contains(e.target) && !e.target.closest('#btn-menu')) {
    $browserMenu.style.display = 'none';
  }
  if (!$extensionsPanel.contains(e.target) && !e.target.closest('#btn-extensions')) {
    $extensionsPanel.style.display = 'none';
  }
  if (!$securityPopup.contains(e.target) && !$securityIndicator.contains(e.target)) {
    $securityPopup.style.display = 'none';
  }
  // Close shields panel on outside click
  const shieldsPanel = document.getElementById('shields-panel');
  if (
    shieldsPanel &&
    shieldsPanel.style.display === 'flex' &&
    !shieldsPanel.contains(e.target) &&
    !e.target.closest('#btn-shield')
  ) {
    shieldsPanel.style.display = 'none';
  }
  // Close sidebar on outside click (only if click is not in sidebar or its toggle)
  const sidebar = document.getElementById('sidebar');
  if (sidebar && sidebarOpen && !sidebar.contains(e.target) && !e.target.closest('#btn-sidebar')) {
    toggleSidebar();
  }
});

// Popup details btn
document.getElementById('btn-popup-details').addEventListener('click', () => {
  closeAllPanels();
  createTab('krypton://pqc-security');
});

// ═══ Find In Page ═══
function toggleFindBar() {
  findBarVisible = !findBarVisible;
  $findBar.style.display = findBarVisible ? 'flex' : 'none';
  if (findBarVisible) {
    $findInput.focus();
    $findInput.select();
    findCurrentTabId = activeTabId;
  } else {
    closeFindBar();
  }
}

function closeFindBar() {
  findBarVisible = false;
  $findBar.style.display = 'none';
  $findInput.value = '';
  $findCount.textContent = '';
  $findInput.classList.remove('no-match');
  const tab = getActiveTab();
  if (tab && tab.webview) {
    try {
      tab.webview.stopFindInPage('clearSelection');
    } catch (e) {}
  }
}

function doFind(forward = true) {
  const query = $findInput.value;
  const tab = getActiveTab();
  if (!tab || !tab.webview || !query) {
    $findCount.textContent = '';
    return;
  }
  tab.webview.findInPage(query, { forward, findNext: true });
}

$findInput.addEventListener('input', () => {
  const query = $findInput.value;
  const tab = getActiveTab();
  if (!query) {
    $findCount.textContent = '';
    $findInput.classList.remove('no-match');
    return;
  }
  if (tab && tab.webview) tab.webview.findInPage(query, { forward: true, findNext: false });
});

$findInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    doFind(!e.shiftKey);
  }
  if (e.key === 'Escape') {
    closeFindBar();
  }
});

document.getElementById('find-prev').addEventListener('click', () => doFind(false));
document.getElementById('find-next').addEventListener('click', () => doFind(true));
document.getElementById('find-close').addEventListener('click', closeFindBar);

// Listen for find results from webview
document.addEventListener('found-in-page', (e) => {
  if (e.result) {
    const { activeMatchOrdinal, matches } = e.result;
    if (matches === 0) {
      $findCount.textContent = 'No results';
      $findInput.classList.add('no-match');
    } else {
      $findCount.textContent = `${activeMatchOrdinal} / ${matches}`;
      $findInput.classList.remove('no-match');
    }
  }
});

// Wire found-in-page event per webview
function hookFindInPage(wv) {
  wv.addEventListener('found-in-page', (e) => {
    if (e.result) {
      const { activeMatchOrdinal, matches } = e.result;
      if (matches === 0) {
        $findCount.textContent = 'No results';
        $findInput.classList.add('no-match');
      } else {
        $findCount.textContent = `${activeMatchOrdinal} / ${matches}`;
        $findInput.classList.remove('no-match');
      }
    }
  });
}

// ═══ Context Menu ═══
function showContextMenu(params, x, y, wv) {
  hideContextMenu();
  $ctxMenu.innerHTML = '';

  const items = [];

  if (params.linkURL) {
    items.push({
      icon: 'open_in_new',
      label: 'Open Link in New Tab',
      action: () => createTab(params.linkURL),
    });
    items.push({
      icon: 'content_copy',
      label: 'Copy Link Address',
      action: () => navigator.clipboard.writeText(params.linkURL),
    });
    items.push('---');
  }

  if (params.mediaType === 'image') {
    items.push({
      icon: 'image',
      label: 'Copy Image URL',
      action: () => navigator.clipboard.writeText(params.srcURL),
    });
    items.push({
      icon: 'download',
      label: 'Save Image As…',
      action: () => {
        if (wv) wv.downloadURL(params.srcURL);
      },
    });
    items.push('---');
  }

  if (params.selectionText) {
    items.push({
      icon: 'content_copy',
      label: 'Copy',
      action: () => navigator.clipboard.writeText(params.selectionText),
    });
    const q = encodeURIComponent(params.selectionText);
    items.push({
      icon: 'search',
      label: `Search for “${params.selectionText.substring(0, 30)}…”`,
      action: () => createTab(getSearchUrl(params.selectionText)),
    });
    items.push('---');
  }

  if (!params.linkURL && !params.selectionText) {
    items.push({
      icon: 'arrow_back',
      label: 'Back',
      action: () => {
        const t = getActiveTab();
        if (t && t.webview) t.webview.goBack();
      },
    });
    items.push({
      icon: 'refresh',
      label: 'Reload',
      action: () => {
        const t = getActiveTab();
        if (t && t.webview) t.webview.reload();
      },
    });
    items.push({ icon: 'bookmark_border', label: 'Bookmark This Page', action: toggleBookmark });
    items.push('---');
    items.push({
      icon: 'code',
      label: 'View Page Source',
      action: () => {
        const t = getActiveTab();
        if (t && t.url) createTab('view-source:' + t.url);
      },
    });
  }

  items.push({
    icon: 'bug_report',
    label: 'Inspect Element',
    action: () => {
      if (wv) {
        try {
          wv.openDevTools({ mode: 'detach' });
        } catch (e) {}
      }
    },
  });

  items.forEach((item) => {
    if (item === '---') {
      const sep = document.createElement('div');
      sep.className = 'ctx-separator';
      $ctxMenu.appendChild(sep);
      return;
    }
    const el = document.createElement('div');
    el.className = 'ctx-item';
    el.innerHTML = `<span class="material-icons-outlined">${item.icon}</span>${item.label}`;
    el.addEventListener('click', () => {
      item.action();
      hideContextMenu();
    });
    $ctxMenu.appendChild(el);
  });

  // Position within screen bounds
  $ctxMenu.style.display = 'block';
  const menuW = $ctxMenu.offsetWidth || 220;
  const menuH = $ctxMenu.offsetHeight || 200;
  const left = Math.min(x, window.innerWidth - menuW - 8);
  const top = Math.min(y, window.innerHeight - menuH - 8);
  $ctxMenu.style.left = left + 'px';
  $ctxMenu.style.top = top + 'px';
}

function hideContextMenu() {
  $ctxMenu.style.display = 'none';
  $ctxMenu.innerHTML = '';
}

document.addEventListener('click', () => hideContextMenu());
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') hideContextMenu();
});

// ═══ Shield Badge Refresh ═══
function refreshShieldCount() {
  if (!window.kryptonBrowser) return;
  window.kryptonBrowser
    .getBlockingStats()
    .then((stats) => {
      if (!stats) return;
      shieldTotalBlocked = stats.blockedRequests || 0;
      $shieldCount.textContent = shieldTotalBlocked;
      if (shieldTotalBlocked > 0) $shieldBadgeWrap.classList.add('blocked-active');
      // Update security popup blocked count
      const $popupBlocked = document.getElementById('popup-blocked');
      if ($popupBlocked) $popupBlocked.textContent = shieldTotalBlocked + ' trackers';
    })
    .catch(() => {});
}

// ═══ Ad Blocking Toggle ═══
function toggleAdBlocking() {
  if (!window.kryptonBrowser) return;
  window.kryptonBrowser.getConfig('krypton_ad_block', 'true').then((current) => {
    const next = current === 'true' ? 'false' : 'true';
    window.kryptonBrowser.setConfig('krypton_ad_block', next);
    localStorage.setItem('krypton_ad_block', next);
    const badge = document.getElementById('shield-menu-badge');
    if (badge) {
      badge.textContent = next === 'true' ? 'ON' : 'OFF';
      badge.classList.toggle('off', next !== 'true');
    }
    showSettingsToast(next === 'true' ? 'KryptonShield enabled' : 'KryptonShield disabled');
  });
}

// ═══ Permission Dialog ═══
const PERM_INFO = {
  camera: { icon: 'videocam', label: 'Camera Access', desc: 'wants to access your camera.' },
  microphone: { icon: 'mic', label: 'Microphone Access', desc: 'wants to access your microphone.' },
  geolocation: {
    icon: 'location_on',
    label: 'Location Access',
    desc: 'wants to know your location.',
  },
  notifications: {
    icon: 'notifications',
    label: 'Notifications',
    desc: 'wants to send you notifications.',
  },
  midi: { icon: 'piano', label: 'MIDI Device', desc: 'wants to access MIDI devices.' },
};

function showPermissionDialog(details) {
  const info = PERM_INFO[details.permission] || {
    icon: 'security',
    label: 'Permission Request',
    desc: 'is requesting a permission.',
  };
  let origin = details.origin || 'A website';
  try {
    origin = new URL(details.origin).hostname;
  } catch (e) {}

  $permOverlay.querySelector('#perm-icon').innerHTML =
    `<span class="material-icons-outlined">${info.icon}</span>`;
  $permOverlay.querySelector('#perm-title').textContent = info.label;
  $permOverlay.querySelector('#perm-origin').textContent = origin;
  $permOverlay.querySelector('#perm-desc').textContent =
    `${origin} ${info.desc} KryptonBrowser has blocked this request for security.`;
  $permOverlay.style.display = 'flex';

  document.getElementById('perm-deny').onclick = () => {
    $permOverlay.style.display = 'none';
  };
  document.getElementById('perm-allow').onclick = () => {
    $permOverlay.style.display = 'none';
    showSettingsToast('Note: permission enforcement is managed by the system');
  };
}

// ═══ Settings → Main Process Sync ═══
// Wire settings changes to also update main-process config so webRequest rules re-apply on restart
function syncSettingToMain(localKey, mainKey) {
  if (!window.kryptonBrowser) return;
  const val = localStorage.getItem(localKey);
  if (val !== null) window.kryptonBrowser.setConfig(mainKey || localKey, val);
}

// Sync on startup
['krypton_ad_block', 'krypton_https_upgrade', 'krypton_send_dnt', 'krypton_block_cookies'].forEach(
  (k) => syncSettingToMain(k),
);

// Patch settings page wiring via localStorage event (settings page writes to localStorage, we relay to main)
window.addEventListener('storage', (e) => {
  const syncKeys = [
    'krypton_ad_block',
    'krypton_https_upgrade',
    'krypton_send_dnt',
    'krypton_block_cookies',
  ];
  if (syncKeys.includes(e.key) && window.kryptonBrowser) {
    window.kryptonBrowser.setConfig(e.key, e.newValue);
  }
});

// ═══ Menu IPC ═══
if (window.kryptonBrowser) {
  window.kryptonBrowser.onNavigateTo((url) => createTab(url));
  window.kryptonBrowser.onNewTab(() => createTab());
  window.kryptonBrowser.onCloseTab(() => {
    if (activeTabId) closeTab(activeTabId);
  });
  window.kryptonBrowser.onFocusUrlBar(() => {
    $urlInput.focus();
    $urlInput.select();
  });
  window.kryptonBrowser.onReloadPage(() => {
    const tab = getActiveTab();
    if (tab && tab.webview) tab.webview.reload();
  });
  window.kryptonBrowser.onShowSecurityInfo(() => {
    closeAllPanels();
    $securityPopup.style.display = 'block';
    updateSecurityPopup();
  });

  // New: open URL in new tab (from main process target=_blank intercept)
  window.kryptonBrowser.onOpenUrlInNewTab((url) => createTab(url));

  // New: toggle find bar from native menu (Cmd+F)
  window.kryptonBrowser.onToggleFindBar(() => toggleFindBar());

  // New: download lifecycle
  window.kryptonBrowser.onDownloadStarted((info) => {
    downloadItems[info.id] = info;
    if ($downloadsPanel.style.display === 'none' || !$downloadsPanel.style.display) {
      toggleDownloadsPanel();
    }
    renderDownloadItem(info);
  });
  window.kryptonBrowser.onDownloadUpdated((info) => {
    downloadItems[info.id] = info;
    renderDownloadItem(info);
  });
  window.kryptonBrowser.onDownloadDone((info) => {
    downloadItems[info.id] = info;
    renderDownloadItem(info);
    if (info.state === 'completed') showSettingsToast(`Downloaded: ${info.filename}`);
  });

  // New: permission request notification
  window.kryptonBrowser.onPermissionRequest((details) => showPermissionDialog(details));

  // New: clear browsing data from menu shortcut
  window.kryptonBrowser.onClearBrowsingData(() => {
    localStorage.removeItem('krypton_history');
    showSettingsToast('Browsing data cleared');
  });

  // New: native menu action forwarding
  if (window.kryptonBrowser.onMenuAction) {
    window.kryptonBrowser.onMenuAction((action) => {
      switch (action) {
        case 'private-window':
          togglePrivateMode();
          break;
        case 'toggle-sidebar':
          toggleSidebar();
          break;
        case 'reader-mode':
          toggleReaderMode();
          break;
        case 'toggle-shields':
          toggleShieldsPanel();
          break;
      }
    });
  }
}

// ═══ Keyboard Shortcuts ═══
document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'l') {
    e.preventDefault();
    $urlInput.focus();
    $urlInput.select();
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 'd') {
    e.preventDefault();
    toggleBookmark();
  }
  if ((e.metaKey || e.ctrlKey) && e.key === 'f') {
    e.preventDefault();
    toggleFindBar();
  }
  if ((e.metaKey || e.ctrlKey) && e.altKey && e.key === 'l') {
    e.preventDefault();
    toggleDownloadsPanel();
  }
  // Cmd/Ctrl+B → Toggle Sidebar
  if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.key === 'b') {
    e.preventDefault();
    toggleSidebar();
  }
  // Cmd/Ctrl+Shift+R → Toggle Reader Mode
  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'R') {
    e.preventDefault();
    toggleReaderMode();
  }
  // Cmd/Ctrl+Shift+N → Toggle Private Mode
  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'N') {
    e.preventDefault();
    togglePrivateMode();
  }
  // Cmd/Ctrl+Shift+S → Toggle Shields Panel
  if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'S') {
    e.preventDefault();
    toggleShieldsPanel();
  }
});

// ═══ Extra Button Wiring ═══
document.getElementById('btn-downloads').addEventListener('click', (e) => {
  e.stopPropagation();
  toggleDownloadsPanel();
});

document.getElementById('dl-panel-close').addEventListener('click', () => {
  $downloadsPanel.style.display = 'none';
});

document.getElementById('dl-open-downloads-folder').addEventListener('click', () => {
  if (window.kryptonBrowser) window.kryptonBrowser.openDownloadsFolder();
});

document.getElementById('btn-shield').addEventListener('click', (e) => {
  e.stopPropagation();
  toggleShieldsPanel();
});

// Sidebar toggle button
document.getElementById('btn-sidebar').addEventListener('click', (e) => {
  e.stopPropagation();
  toggleSidebar();
});

// Fix: manage extensions button
document.getElementById('btn-manage-extensions').addEventListener('click', () => {
  closeAllPanels();
  createTab('krypton://extensions');
});

// ═══ Initialize ═══
renderBookmarksBar();
refreshShieldCount();

// Status bar: update blocked count periodically
(function initStatusBar() {
  const statusBlocked = document.getElementById('status-blocked');
  async function updateStatusBar() {
    if (window.kryptonBrowser && window.kryptonBrowser.getBlockingStats) {
      try {
        const stats = await window.kryptonBrowser.getBlockingStats();
        if (statusBlocked) {
          statusBlocked.textContent = `${stats.trackersBlocked} trackers blocked`;
        }
      } catch (e) {
        /* ignore */
      }
    }
  }
  updateStatusBar();
  setInterval(updateStatusBar, 5000);
})();

// Startup behavior
(function initStartup() {
  const mode = localStorage.getItem('krypton_startup') || 'newtab';
  if (mode === 'last-session') {
    const lastUrl = localStorage.getItem('krypton_last_url');
    if (lastUrl && lastUrl !== 'krypton://newtab') {
      createTab(lastUrl);
    } else {
      createTab('krypton://newtab');
    }
  } else if (mode === 'custom') {
    const customUrl = localStorage.getItem('krypton_startup_url');
    if (customUrl && customUrl.trim()) {
      createTab(
        customUrl.trim().startsWith('http') ? customUrl.trim() : 'https://' + customUrl.trim(),
      );
    } else {
      createTab('krypton://newtab');
    }
  } else {
    createTab('krypton://newtab');
  }
})();

// Save last URL for "continue where you left off"
window.addEventListener('beforeunload', () => {
  const tab = getActiveTab();
  if (tab && tab.url) {
    localStorage.setItem('krypton_last_url', tab.url);
  }
});

// ═══ Global Error Handler for Images ═══
document.addEventListener(
  'error',
  function (event) {
    if (event.target && event.target.tagName === 'IMG') {
      const img = event.target;
      const fallback = img.getAttribute('data-fallback');
      if (fallback) {
        let className = 'material-icons-outlined';
        if (img.classList.contains('hist-favicon-img')) {
          className += ' hist-favicon';
        }
        if (fallback === 'tab-favicon') {
          if (img.parentElement) {
            img.parentElement.innerHTML = '<span class="' + className + '">language</span>';
          }
        } else {
          img.outerHTML = '<span class="' + className + '">' + fallback + '</span>';
        }
      }
    }
  },
  true,
);
