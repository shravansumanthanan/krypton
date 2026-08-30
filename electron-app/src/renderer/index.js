import { renderBookmarksBar } from './bookmarks/bookmarks-manager.js';
import { refreshShieldCount, initStatusBar } from './ui/status-bar.js';
import { initIpcBridge } from './ipc/ipc-bridge.js';
import { initUrlBar } from './navigation/url-bar.js';
import { initShortcuts } from './utils/shortcuts.js';
import { wireShieldsControls, toggleShieldsPanel } from './shields/shields-controller.js';
import { createTab, getActiveTab } from './tabs/tab-manager.js';
import { toggleDownloadsPanel } from './downloads/downloads-panel.js';
import { toggleSidebar } from './sidebar/sidebar-controller.js';
import { toggleMenu } from './ui/browser-menu.js';
import { toggleExtensionsPanel } from './ui/extensions-popup.js';
import { toggleBookmark } from './bookmarks/bookmarks-manager.js';

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

// Startup
initIpcBridge();
initUrlBar();
initShortcuts();
initStatusBar();
wireShieldsControls();

// ═══ Initialize ═══
renderBookmarksBar();
refreshShieldCount();

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

// ═══ Extra Button Wiring ═══

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
  const $reloadIcon = document.getElementById('reload-icon');
  if ($reloadIcon.textContent === 'close') tab.webview.stop();
  else tab.webview.reload();
});

document.getElementById('btn-new-tab').addEventListener('click', () => createTab());

// Bookmark button
document.getElementById('btn-bookmark').addEventListener('click', (e) => {
  e.stopPropagation();
  toggleBookmark();
});

// PQC Security Panel button
document.getElementById('btn-security-panel').addEventListener('click', () => {
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

// Zoom controls
import { zoomLevel, setZoomLevel } from './state/store.js';
function setZoom(delta) {
  const newLevel = Math.max(25, Math.min(500, zoomLevel + delta));
  setZoomLevel(newLevel);
  document.getElementById('zoom-level').textContent = newLevel + '%';
  const tab = getActiveTab();
  if (tab && tab.webview) {
    tab.webview.setZoomFactor(newLevel / 100);
  }
}
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

document.getElementById('btn-downloads').addEventListener('click', (e) => {
  e.stopPropagation();
  toggleDownloadsPanel();
});

document.getElementById('dl-panel-close').addEventListener('click', () => {
  document.getElementById('downloads-panel').style.display = 'none';
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

// Manage extensions button
const extBtn = document.getElementById('btn-manage-extensions');
if (extBtn) {
  extBtn.addEventListener('click', () => {
    createTab('krypton://extensions');
  });
}
