import { sanitizeHTML } from '../js/utils.js';
import { getActiveTab, createTab } from '../tabs/tab-manager.js';

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

export function getSearchUrl(query) {
  const engine = localStorage.getItem('krypton_search_engine') || 'google';
  const se = SEARCH_ENGINES[engine] || SEARCH_ENGINES.google;
  return se.url + encodeURIComponent(query);
}

export function showSettingsToast(msg) {
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

export function applyAccentColor() {
  const color = localStorage.getItem('krypton_accent_color') || '#fb923c';
  document.documentElement.style.setProperty('--accent', color);
}

export function applyFontSize() {
  const size = localStorage.getItem('krypton_font_size') || 'medium';
  const factor = size === 'small' ? 0.9 : size === 'large' ? 1.1 : 1;
  document.documentElement.style.setProperty('font-size', factor * 100 + '%');
}

export function applyBookmarksBarVisibility() {
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

export function createSettingsPage(tabId) {
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
  wireToggle('stgl-bookmarks-' + tabId, 'krypton_show_bookmarks', () => {
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

      overlay.querySelector('#modal-clear').addEventListener('click', async () => {
        const checks = overlay.querySelectorAll('input[type="checkbox"]');
        let clearCookiesCache = false;
        checks.forEach((ch) => {
          if (!ch.checked) return;
          const key = ch.dataset.clear;
          if (key === 'history') localStorage.removeItem('krypton_history');
          if (key === 'bookmarks') {
            localStorage.removeItem('krypton_bookmarks');
            // eslint-disable-next-line no-undef
            if (typeof bookmarks !== 'undefined') bookmarks.length = 0;
            // eslint-disable-next-line no-undef
            if (typeof renderBookmarksBar === 'function') renderBookmarksBar();
          }
          if (key === 'cookies' || key === 'cache') clearCookiesCache = true;
        });
        // Actually wipe the Electron session partition (cookies, cache, HTTP auth, storage)
        if (clearCookiesCache && window.kryptonBrowser) {
          await window.kryptonBrowser.clearSessionData();
          localStorage.removeItem('krypton_reading_list');
        }
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
