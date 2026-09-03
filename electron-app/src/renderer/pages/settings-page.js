export const SEARCH_ENGINES = {
  google: { name: 'Google', url: 'https://www.google.com/search?q=' },
  duckduckgo: { name: 'DuckDuckGo', url: 'https://duckduckgo.com/?q=' },
  bing: { name: 'Bing', url: 'https://www.bing.com/search?q=' },
  brave: { name: 'Brave Search', url: 'https://search.brave.com/search?q=' },
  yahoo: { name: 'Yahoo', url: 'https://search.yahoo.com/search?p=' },
};

export function getSearchUrl(query) {
  const engine = localStorage.getItem('krypton_search_engine') || 'google';
  const urlBase = (SEARCH_ENGINES[engine] || SEARCH_ENGINES.google).url;
  return urlBase + encodeURIComponent(query);
}

export function showSettingsToast(msg) {
  let toast = document.getElementById('settings-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'settings-toast';
    toast.className = 'settings-toast';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.classList.add('visible');
  if (toast._timeout) clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => {
    toast.classList.remove('visible');
  }, 3000);
}

export function applyFontSize() {
  const size = localStorage.getItem('krypton_font_size') || 'medium';
  if (size === 'small') document.documentElement.style.fontSize = '14px';
  else if (size === 'large') document.documentElement.style.fontSize = '18px';
  else document.documentElement.style.fontSize = '16px';
}

export function createSettingsPage(tabId) {
  const div = document.createElement('div');
  div.className = 'internal-page';

  // Read state
  const showWallpaper = localStorage.getItem('krypton_show_wallpaper') !== 'false';
  const fontSize = localStorage.getItem('krypton_font_size') || 'medium';
  const blockCookies = localStorage.getItem('krypton_block_cookies') !== 'false';
  const sendDNT = localStorage.getItem('krypton_send_dnt') !== 'false';
  const askDownloadLoc = localStorage.getItem('krypton_ask_download_loc') !== 'false';
  const startupMode = localStorage.getItem('krypton_startup') || 'newtab';
  const startupUrl = localStorage.getItem('krypton_startup_url') || '';
  const searchEngine = localStorage.getItem('krypton_search_engine') || 'google';

  // Build search engine HTML
  let searchHtml = '';
  Object.keys(SEARCH_ENGINES).forEach((key) => {
    const isChecked = searchEngine === key ? ' checked' : '';
    searchHtml +=
      '<label class="settings-radio-item"><input type="radio" name="se-' +
      tabId +
      '" value="' +
      key +
      '"' +
      isChecked +
      '><div><span class="settings-radio-label">' +
      SEARCH_ENGINES[key].name +
      '</span></div></label>';
  });

  div.innerHTML = `
    <div class="settings-layout">
      <div class="settings-sidebar">
        <div class="settings-nav-item active" data-settings-section="appearance"><span class="material-icons-outlined">palette</span>Appearance</div>
        <div class="settings-nav-item" data-settings-section="privacy"><span class="material-icons-outlined">security</span>Privacy & Security</div>
        <div class="settings-nav-item" data-settings-section="search"><span class="material-icons-outlined">search</span>Search Engine</div>
        <div class="settings-nav-item" data-settings-section="startup"><span class="material-icons-outlined">power_settings_new</span>On Startup</div>
        <div class="settings-nav-item" data-settings-section="downloads"><span class="material-icons-outlined">file_download</span>Downloads</div>
        <div class="settings-nav-item" data-settings-section="printing"><span class="material-icons-outlined">print</span>Printing</div>
        <div class="settings-nav-item" data-settings-section="about"><span class="material-icons-outlined">info</span>About Krypton</div>
      </div>
      <div class="settings-content">
        
        <!-- APPEARANCE -->
        <div class="settings-section active" data-section="appearance">
          <h2 class="settings-heading">Appearance</h2>
          <div class="settings-card">
            <div class="settings-row"><div><div class="settings-label">Dark Mode</div><div class="settings-sublabel">KryptonBrowser uses a dark theme by default</div></div><div class="settings-toggle active disabled"></div></div>
            <div class="settings-row"><div><div class="settings-label">New Tab Wallpaper</div><div class="settings-sublabel">Show a landscape wallpaper on the new tab page</div></div><div class="settings-toggle\${showWallpaper ? ' active' : ''}" id="stgl-wallpaper-\${tabId}"></div></div>
            <div class="settings-row"><div><div class="settings-label">Font Size</div><div class="settings-sublabel">Adjust the base font size of the browser UI</div></div>
              <select class="settings-select" id="stgl-fontsize-\${tabId}">
                <option value="small"\${fontSize === 'small' ? ' selected' : ''}>Small</option>
                <option value="medium"\${fontSize === 'medium' ? ' selected' : ''}>Medium</option>
                <option value="large"\${fontSize === 'large' ? ' selected' : ''}>Large</option>
              </select>
            </div>
          </div>
        </div>
        
        <!-- PRIVACY -->
        <div class="settings-section" data-section="privacy">
          <h2 class="settings-heading">Privacy & Security</h2>
          <div class="settings-card">
            <div class="settings-row"><div><div class="settings-label">PQC Encryption</div><div class="settings-sublabel">Use post-quantum cryptography for all connections</div></div><div class="settings-toggle active disabled" id="stgl-pqc-\${tabId}"></div></div>
            <div class="settings-row"><div><div class="settings-label">Block Third-Party Cookies</div><div class="settings-sublabel">Prevent cross-site tracking through cookies</div></div><div class="settings-toggle\${blockCookies ? ' active' : ''}" id="stgl-cookies-\${tabId}"></div></div>
            <div class="settings-row"><div><div class="settings-label">Send "Do Not Track"</div><div class="settings-sublabel">Request websites not to track your browsing</div></div><div class="settings-toggle\${sendDNT ? ' active' : ''}" id="stgl-dnt-\${tabId}"></div></div>
          </div>
        </div>

        <!-- SEARCH ENGINE -->
        <div class="settings-section" data-section="search">
          <h2 class="settings-heading">Search Engine</h2>
          <div class="settings-card">
            <div class="settings-radio-group">\${searchHtml}</div>
          </div>
        </div>

        <!-- DOWNLOADS -->
        <div class="settings-section" data-section="downloads">
          <h2 class="settings-heading">Downloads</h2>
          <div class="settings-card">
            <div class="settings-row"><div><div class="settings-label">Download Location</div><div class="settings-sublabel">~/Downloads</div></div></div>
            <div class="settings-row" style="margin-top:8px"><div><div class="settings-label">Ask where to save</div></div><div class="settings-toggle\${askDownloadLoc ? ' active' : ''}" id="stgl-download-\${tabId}"></div></div>
          </div>
        </div>

        <!-- PRINTING -->
        <div class="settings-section" data-section="printing">
          <h2 class="settings-heading">Printing</h2>
          <div class="settings-card">
            <div class="settings-row"><div><div class="settings-label">Headers and Footers</div></div><div class="settings-toggle\${localStorage.getItem('krypton_print_headers') !== 'false' ? ' active' : ''}" id="stgl-print-headers-\${tabId}"></div></div>
            <div class="settings-row"><div><div class="settings-label">Background Graphics</div></div><div class="settings-toggle\${localStorage.getItem('krypton_print_bg') === 'true' ? ' active' : ''}" id="stgl-print-bg-\${tabId}"></div></div>
          </div>
        </div>

        <!-- ABOUT -->
        <div class="settings-section" data-section="about">
          <h2 class="settings-heading">About Krypton</h2>
          <div class="settings-card-centered">
            <div class="settings-about-icon">🛡️</div>
            <div class="settings-about-name">KryptonBrowser</div>
            <div class="settings-about-version">Version 1.0.0</div>
            <div class="settings-about-desc">Post-Quantum Cryptography Enabled Secure Browser</div>
          </div>
        </div>

      </div>
    </div>
  `;

  // Wiring...
  div.querySelectorAll('[data-settings-section]').forEach((item) => {
    item.addEventListener('click', () => {
      div.querySelectorAll('[data-settings-section]').forEach((n) => n.classList.remove('active'));
      item.classList.add('active');
      const sec = item.dataset.settingsSection;
      div.querySelectorAll('.settings-section').forEach((s) => s.classList.remove('active'));
      const target = div.querySelector('.settings-section[data-section="' + sec + '"]');
      if (target) target.classList.add('active');
    });
  });

  const MAIN_PROCESS_KEYS = new Set([
    'krypton_block_cookies',
    'krypton_send_dnt',
    'krypton_ask_download_loc',
  ]);
  function wireToggle(id, storageKey, onChange) {
    const el = div.querySelector('#' + id);
    if (!el) return;
    el.addEventListener('click', () => {
      el.classList.toggle('active');
      const isOn = el.classList.contains('active');
      localStorage.setItem(storageKey, String(isOn));
      if (MAIN_PROCESS_KEYS.has(storageKey) && window.kryptonBrowser) {
        window.kryptonBrowser.setConfig(storageKey, String(isOn));
      }
      if (onChange) onChange(isOn);
      showSettingsToast('Setting saved');
    });
  }

  wireToggle('stgl-wallpaper-' + tabId, 'krypton_show_wallpaper');
  wireToggle('stgl-cookies-' + tabId, 'krypton_block_cookies');
  wireToggle('stgl-dnt-' + tabId, 'krypton_send_dnt');
  wireToggle('stgl-download-' + tabId, 'krypton_ask_download_loc');
  wireToggle('stgl-print-headers-' + tabId, 'krypton_print_headers');
  wireToggle('stgl-print-bg-' + tabId, 'krypton_print_bg');

  const fontSel = div.querySelector('#stgl-fontsize-' + tabId);
  if (fontSel) {
    fontSel.addEventListener('change', () => {
      localStorage.setItem('krypton_font_size', fontSel.value);
      applyFontSize();
      showSettingsToast('Font size updated');
    });
  }

  div.querySelectorAll('input[name="se-' + tabId + '"]').forEach((radio) => {
    radio.addEventListener('change', () => {
      localStorage.setItem('krypton_search_engine', radio.value);
      showSettingsToast('Search engine saved');
    });
  });

  return div;
}
