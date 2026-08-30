import { sanitizeHTML } from '../js/utils.js';
import { navigateActiveTab } from '../navigation/nav-controller.js';

export function createHistoryPage(tabId) {
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
            // showSettingsToast is a global provided by the shell when loaded in-page
            // eslint-disable-next-line no-undef
            showSettingsToast('History exported successfully');
          }
        } catch (e) {
          // eslint-disable-next-line no-console
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
