import { getActiveTab, createTab } from '../tabs/tab-manager.js';
import { showSettingsToast } from '../pages/settings-page.js';
import { $browserMenu, $extensionsPanel, $securityPopup } from '../state/store.js';

// ═══ Panels: close all open panels ═══
export function closeAllPanels() {
  $browserMenu.style.display = 'none';
  $extensionsPanel.style.display = 'none';
  $securityPopup.style.display = 'none';
  const shieldsPanel = document.getElementById('shields-panel');
  if (shieldsPanel) shieldsPanel.style.display = 'none';
}

// ═══ Shields Panel (Brave-style) ═══
function getShieldsPanel() {
  return document.getElementById('shields-panel');
}

export function toggleShieldsPanel() {
  const panel = getShieldsPanel();
  if (!panel) return;
  if (panel.style.display === 'none' || !panel.style.display) {
    closeAllPanels();
    updateShieldsPanel();
    panel.style.display = 'block';
  } else {
    panel.style.display = 'none';
  }
}

export async function updateShieldsPanel() {
  const tab = getActiveTab();
  const $site = document.getElementById('shields-site');
  const $breakdown = document.getElementById('shields-breakdown');

  let pageUrl = '';
  if (tab && tab.url && !tab.url.startsWith('krypton://')) {
    try {
      pageUrl = tab.url;
      if ($site) $site.textContent = new URL(tab.url).hostname;
    } catch {
      if ($site) $site.textContent = tab.url;
    }
  } else {
    if ($site) $site.textContent = 'No site loaded';
  }

  if (!window.kryptonBrowser) return;

  // Fetch global + per-site stats in parallel
  const [stats, siteStats] = await Promise.all([
    window.kryptonBrowser.getBlockingStats
      ? window.kryptonBrowser.getBlockingStats().catch(() => ({}))
      : Promise.resolve({}),
    pageUrl && window.kryptonBrowser.getSiteBlockCount
      ? window.kryptonBrowser.getSiteBlockCount(pageUrl).catch(() => null)
      : Promise.resolve(null),
  ]);

  // Update shields panel summary numbers
  const trackersEl = document.getElementById('shields-stat-trackers');
  const httpsEl = document.getElementById('shields-stat-https');
  const scriptsEl = document.getElementById('shields-stat-scripts');
  const fpEl = document.getElementById('shields-stat-fp');

  const totalTrackers = siteStats
    ? siteStats.total || 0
    : stats?.blockedRequestCount || stats?.blockedRequests || 0;

  if (trackersEl) trackersEl.textContent = totalTrackers;
  if (httpsEl) httpsEl.textContent = stats?.httpsUpgradedCount || 0;
  if (scriptsEl) scriptsEl.textContent = siteStats ? siteStats.scripts || 0 : 0;
  if (fpEl) fpEl.textContent = siteStats ? siteStats.fingerprinting || 0 : 0;

  // Update the global count + popup label
  const $popupBlocked = document.getElementById('popup-blocked');
  if ($popupBlocked) $popupBlocked.textContent = totalTrackers + ' trackers';

  // Build per-site category breakdown
  if ($breakdown) {
    if (!siteStats || siteStats.total === 0) {
      $breakdown.innerHTML = `<div class="shields-no-data" style="padding:12px 0;font-size:12px;color:var(--text-muted);text-align:center;">No trackers detected on this page yet.</div>`;
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
        { key: 'scripts', icon: 'code_off', label: 'Scripts' },
      ];
      const rows = cats
        .filter((c) => siteStats[c.key] > 0)
        .map(
          (c) => `
            <div class="shields-breakdown-row" style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;font-size:12px;border-bottom:1px solid rgba(255,255,255,0.05);">
              <span style="display:flex;align-items:center;gap:6px;color:var(--text-secondary);">
                <span class="material-icons-outlined" style="font-size:16px;">${c.icon}</span>
                <span>${c.label}</span>
              </span>
              <span style="font-weight:600;color:var(--accent);">${siteStats[c.key]}</span>
            </div>`,
        )
        .join('');
      $breakdown.innerHTML = `
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);margin-bottom:8px;font-weight:600;">Blocked on this page (${siteStats.total} total)</div>
        ${rows || '<div class="shields-no-data" style="padding:8px 0;color:var(--text-muted);font-size:12px;">Breakdown unavailable</div>'}
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

export function wireShieldsControls() {
  const globalToggle = document.getElementById('shields-global-toggle');
  if (globalToggle) {
    globalToggle.addEventListener('click', () => {
      globalToggle.classList.toggle('active');
      const isOn = globalToggle.classList.contains('active');
      if (window.kryptonBrowser) {
        window.kryptonBrowser.setConfig('krypton_ad_block', isOn ? 'true' : 'false');
      }
      localStorage.setItem('krypton_ad_block', isOn ? 'true' : 'false');
      showSettingsToast(isOn ? 'KryptonShield enabled' : 'KryptonShield disabled');
      // Reload active webview to apply change immediately
      const tab = getActiveTab();
      if (tab && tab.webview) tab.webview.reload();
    });
  }

  // Auto-refresh shields panel if open when a block occurs
  if (window.kryptonBrowser?.onShieldBlockedUpdate) {
    window.kryptonBrowser.onShieldBlockedUpdate(() => {
      const panel = getShieldsPanel();
      if (panel && panel.style.display !== 'none') {
        updateShieldsPanel();
      }
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
      const isOn = scriptsToggle.classList.contains('active');
      if (window.kryptonBrowser) {
        window.kryptonBrowser.setConfig('krypton_block_scripts', isOn ? 'true' : 'false');
      }
      localStorage.setItem('krypton_block_scripts', isOn ? 'true' : 'false');
      showSettingsToast(isOn ? 'Script blocking enabled' : 'Script blocking disabled');
    });
  }

  // Wire fingerprint-level radio/select (id: shields-fp-level)
  const fpSelect = document.getElementById('shields-fp-level');
  if (fpSelect) {
    // Initialise from saved config
    if (window.kryptonBrowser) {
      window.kryptonBrowser
        .getConfig('krypton_fp_level', 'standard')
        .then((v) => {
          fpSelect.value = v;
        })
        .catch(() => {});
    }
    fpSelect.addEventListener('change', () => {
      const level = fpSelect.value;
      if (window.kryptonBrowser) {
        window.kryptonBrowser.setConfig('krypton_fp_level', level);
        if (window.kryptonBrowser.setFingerprintPolicy) {
          window.kryptonBrowser.setFingerprintPolicy(level);
        }
      }
      showSettingsToast(`Fingerprint protection: ${level}`);
    });
  }

  // Wire cookie-level select (id: shields-cookies-level)
  const cookieSelect = document.getElementById('shields-cookies-level');
  if (cookieSelect) {
    if (window.kryptonBrowser) {
      window.kryptonBrowser
        .getConfig('krypton_cookie_level', 'standard')
        .then((v) => {
          cookieSelect.value = v;
        })
        .catch(() => {});
    }
    cookieSelect.addEventListener('change', () => {
      const level = cookieSelect.value;
      if (window.kryptonBrowser) {
        window.kryptonBrowser.setConfig('krypton_cookie_level', level);
      }
      showSettingsToast(`Cookie isolation: ${level}`);
    });
  }

  const advBtn = document.getElementById('shields-advanced-btn');
  if (advBtn)
    advBtn.addEventListener('click', () => {
      const panel = getShieldsPanel();
      if (panel) panel.style.display = 'none';
      createTab('krypton://settings');
    });

  const reportBtn = document.getElementById('shields-report-btn');
  if (reportBtn)
    reportBtn.addEventListener('click', () => {
      showSettingsToast('Broken site report submitted');
      const panel = getShieldsPanel();
      if (panel) panel.style.display = 'none';
    });
}
