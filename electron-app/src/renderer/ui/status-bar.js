import {
  $shieldCount,
  $shieldBadgeWrap,
  shieldTotalBlocked,
  setShieldTotalBlocked,
} from '../state/store.js';
import { getActiveTab } from '../tabs/tab-manager.js';
import { showSettingsToast } from '../pages/settings-page.js';

// ═══ Shield Badge Refresh ═══
export function refreshShieldCount() {
  if (!window.kryptonBrowser) return;
  const tab = typeof getActiveTab === 'function' ? getActiveTab() : null;
  const pageUrl = tab && tab.url && !tab.url.startsWith('krypton://') ? tab.url : null;

  Promise.all([
    window.kryptonBrowser.getBlockingStats
      ? window.kryptonBrowser.getBlockingStats().catch(() => ({}))
      : Promise.resolve({}),
    pageUrl && window.kryptonBrowser.getSiteBlockCount
      ? window.kryptonBrowser.getSiteBlockCount(pageUrl).catch(() => null)
      : Promise.resolve(null),
  ])
    .then(([stats, siteStats]) => {
      const siteCount = siteStats ? siteStats.total || 0 : null;
      const globalCount =
        stats?.blockedRequestCount ?? stats?.blockedRequests ?? stats?.trackersBlockedCount ?? 0;
      const count = siteCount !== null && siteCount !== undefined ? siteCount : globalCount;

      setShieldTotalBlocked(count);
      const sc = document.getElementById('shield-count') || $shieldCount;
      const wrap = document.getElementById('shield-badge-wrap') || $shieldBadgeWrap;
      if (sc) sc.textContent = count;
      if (wrap) wrap.classList.toggle('blocked-active', count > 0);

      // Update security popup blocked count
      const $popupBlocked = document.getElementById('popup-blocked');
      if ($popupBlocked) $popupBlocked.textContent = count + ' trackers';
    })
    .catch(() => {});
}

// ═══ Ad Blocking Toggle ═══
export function toggleAdBlocking() {
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

// Status bar: update blocked count periodically
export function initStatusBar() {
  const statusBlocked = document.getElementById('status-blocked');
  async function updateStatusBar() {
    if (window.kryptonBrowser && window.kryptonBrowser.getBlockingStats) {
      try {
        const stats = await window.kryptonBrowser.getBlockingStats();
        if (statusBlocked) {
          const count =
            stats.trackersBlockedCount ?? stats.trackersBlocked ?? stats.blockedRequestCount ?? 0;
          statusBlocked.textContent = `${count} trackers blocked`;
        }
      } catch (e) {
        /* ignore */
      }
    }
  }
  updateStatusBar();
  setInterval(updateStatusBar, 5000);

  if (window.kryptonBrowser?.onShieldBlockedUpdate) {
    window.kryptonBrowser.onShieldBlockedUpdate(() => {
      refreshShieldCount();
      updateStatusBar();
    });
  }
}
