// state/store.js
export const tabs = [];
export let activeTabId = null;
export let tabCounter = 0;
export let clockInterval = null;
export let zoomLevel = 100;

// Find-in-page state
export let findBarVisible = false;

// Per-tab blocked request counts (populated from IPC)
export let shieldTotalBlocked = 0;

// Downloads
export const downloadItems = {}; // id → info

// Bookmarks stored in memory (persisted to localStorage)
export let bookmarks = JSON.parse(localStorage.getItem('krypton_bookmarks') || '[]');

// Built-in extensions
export const extensions = [
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

export const INTERNAL_PAGES = {
  'krypton://pqc-security': { title: 'PQC Security', file: 'pages/pqc_security.html' },
  'krypton://newtab': { title: 'New Tab', internal: true },
  'krypton://history': { title: 'History', internal: true },
  'krypton://settings': { title: 'Settings', internal: true },
  'krypton://extensions': { title: 'Extensions', internal: true },
};

// NTP wallpapers — CSS gradients (offline-safe; no external image requests)
export const WALLPAPERS = [
  { type: 'gradient', value: 'linear-gradient(135deg, #0f2027 0%, #203a43 50%, #2c5364 100%)' },
  { type: 'gradient', value: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)' },
  { type: 'gradient', value: 'linear-gradient(160deg, #0d1b2a 0%, #1b2838 40%, #1d3557 100%)' },
  { type: 'gradient', value: 'linear-gradient(145deg, #16181f 0%, #1a2035 50%, #0e1628 100%)' },
  { type: 'gradient', value: 'linear-gradient(135deg, #0a0a1a 0%, #1a0a2e 50%, #2d1b69 100%)' },
  { type: 'gradient', value: 'linear-gradient(135deg, #0d1117 0%, #161b22 50%, #21262d 100%)' },
];

export const QUOTES = [
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
export let readingList = JSON.parse(localStorage.getItem('krypton_reading_list') || '[]');

// Sidebar state
export let sidebarOpen = false;

// Private mode state
export let isPrivateMode = false;

// Reader mode state
export let readerFontSize = 17;
export let readerLightTheme = false;

// ═══ DOM Refs ═══
export const $tabsContainer = document.getElementById('tabs-container');
export const $webviewContainer = document.getElementById('webview-container');
export const $urlInput = document.getElementById('url-input');
export const $securityIndicator = document.getElementById('security-indicator');
export const $lockIcon = document.getElementById('lock-icon');
export const $pqcBadge = document.getElementById('pqc-badge');
export const $loadingBar = document.getElementById('loading-bar');
export const $loadingProgress = document.getElementById('loading-progress');
export const $securityPopup = document.getElementById('security-popup');
export const $reloadIcon = document.getElementById('reload-icon');
export const $bookmarkBtn = document.getElementById('btn-bookmark');
export const $bookmarkIcon = document.getElementById('bookmark-icon');
export const $bookmarksList = document.getElementById('bookmarks-list');
export const $browserMenu = document.getElementById('browser-menu');
export const $extensionsPanel = document.getElementById('extensions-panel');

// New element refs
export const $findBar = document.getElementById('find-bar');
export const $findInput = document.getElementById('find-input');
export const $findCount = document.getElementById('find-count');
export const $shieldCount = document.getElementById('shield-count');
export const $shieldBadgeWrap = document.getElementById('shield-badge-wrap');
export const $downloadsPanel = document.getElementById('downloads-panel');
export const $dlList = document.getElementById('dl-list');
export const $ctxMenu = document.getElementById('ctx-menu');
export const $permOverlay = document.getElementById('permission-overlay');

// ═══ Setters ═══
export function setActiveTabId(id) {
  activeTabId = id;
}
export function incrementTabCounter() {
  return ++tabCounter;
}
export function setClockInterval(interval) {
  clockInterval = interval;
}
export function setZoomLevel(level) {
  zoomLevel = level;
}
export function setFindBarVisible(visible) {
  findBarVisible = visible;
}
export function setShieldTotalBlocked(val) {
  shieldTotalBlocked = val;
}
export function setBookmarks(val) {
  bookmarks = val;
}
export function setReadingList(val) {
  readingList = val;
}
export function setSidebarOpen(val) {
  sidebarOpen = val;
}
export function setIsPrivateMode(val) {
  isPrivateMode = val;
}
export function setReaderFontSize(val) {
  readerFontSize = val;
}
export function setReaderLightTheme(val) {
  readerLightTheme = val;
}
