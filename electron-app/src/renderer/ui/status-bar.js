import {
  $shieldCount,
  $shieldBadgeWrap,
  shieldTotalBlocked,
  setShieldTotalBlocked,
} from '../state/store.js';
import { showSettingsToast } from '../pages/settings-page.js';

// ═══ Shield Badge Refresh ═══
export function refreshShieldCount() {
  if (!window.kryptonBrowser) return;
  window.kryptonBrowser
    .getBlockingStats()
    .then((stats) => {
      if (!stats) return;
      setShieldTotalBlocked(stats.blockedRequests || 0);
      $shieldCount.textContent = shieldTotalBlocked;
      if (shieldTotalBlocked > 0) $shieldBadgeWrap.classList.add('blocked-active');
      // Update security popup blocked count
      const $popupBlocked = document.getElementById('popup-blocked');
      if ($popupBlocked) $popupBlocked.textContent = shieldTotalBlocked + ' trackers';
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
          statusBlocked.textContent = `${stats.trackersBlocked} trackers blocked`;
        }
      } catch (e) {
        /* ignore */
      }
    }
  }
  updateStatusBar();
  setInterval(updateStatusBar, 5000);
}
