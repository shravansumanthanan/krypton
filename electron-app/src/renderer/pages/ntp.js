import {
  bookmarks,
  shieldTotalBlocked,
  isPrivateMode,
  WALLPAPERS,
  QUOTES,
  $urlInput,
  clockInterval,
  setClockInterval,
} from '../state/store.js';
import { pick, getTimeString, getGreeting } from '../js/utils.js';
import { navigateActiveTab } from '../navigation/nav-controller.js';
import { createTab } from '../tabs/tab-manager.js';

export function createNewTabPage(tabId) {
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

export function startClock(tabId) {
  if (clockInterval) clearInterval(clockInterval);
  setClockInterval(
    setInterval(() => {
      const c = document.getElementById(`ntp-clock-${tabId}`);
      const g = document.getElementById(`ntp-greeting-${tabId}`);
      if (c) c.textContent = getTimeString();
      if (g) g.textContent = getGreeting() + '.';
    }, 10000),
  );
}
