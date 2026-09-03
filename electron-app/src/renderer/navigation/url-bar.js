import { $urlInput, bookmarks } from '../state/store.js';
import { getSearchUrl } from '../pages/settings-page.js';
import { navigateActiveTab } from './nav-controller.js';
import { getActiveTab } from '../tabs/tab-manager.js';
import { sanitizeHTML } from '../js/utils.js';

const $acDropdown = document.getElementById('autocomplete-dropdown');
let acSelectedIndex = -1;

export function showAutocomplete(query) {
  if (!query || query.length < 1) {
    hideAutocomplete();
    return;
  }
  const q = query.toLowerCase();
  const results = [];

  // Search bookmarks
  bookmarks.forEach((b) => {
    if (results.some((r) => r.url === b.url)) return;
    if ((b.title || '').toLowerCase().includes(q) || (b.url || '').toLowerCase().includes(q)) {
      results.push({ title: b.title || b.url, url: b.url, icon: 'bookmark', type: 'Bookmark' });
    }
  });

  // Search engine suggestion (uses selected engine)
  const _curEngine = localStorage.getItem('krypton_search_engine') || 'google';
  const SEARCH_ENGINES = {
    google: { name: 'Google', url: 'https://www.google.com/search?q=' },
    duckduckgo: { name: 'DuckDuckGo', url: 'https://duckduckgo.com/?q=' },
    bing: { name: 'Bing', url: 'https://www.bing.com/search?q=' },
    brave: { name: 'Brave Search', url: 'https://search.brave.com/search?q=' },
    yahoo: { name: 'Yahoo', url: 'https://search.yahoo.com/search?p=' },
  };
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

export function hideAutocomplete() {
  $acDropdown.style.display = 'none';
  $acDropdown.innerHTML = '';
  acSelectedIndex = -1;
}

export function selectAcItem(delta) {
  const items = $acDropdown.querySelectorAll('.ac-item');
  if (items.length === 0) return;
  items.forEach((it) => it.classList.remove('selected'));
  acSelectedIndex = (acSelectedIndex + delta + items.length) % items.length;
  items[acSelectedIndex].classList.add('selected');
  items[acSelectedIndex].scrollIntoView({ block: 'nearest' });
  // Update URL input with the selected item's URL
  $urlInput.value = items[acSelectedIndex].querySelector('.ac-url').textContent;
}

export function initUrlBar() {
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
}
