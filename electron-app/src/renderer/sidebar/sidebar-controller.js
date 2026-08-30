import {
  bookmarks,
  setBookmarks,
  readingList,
  sidebarOpen,
  setSidebarOpen,
} from '../state/store.js';
import { navigateActiveTab } from '../navigation/nav-controller.js';
import { getActiveTab } from '../tabs/tab-manager.js';
import {
  saveBookmarks,
  toggleBookmark,
  updateBookmarkButton,
} from '../bookmarks/bookmarks-manager.js';
import { showSettingsToast } from '../pages/settings-page.js';
import { sanitizeHTML } from '../js/utils.js';

// ═══ Sidebar ═══
const $sidebar = document.getElementById('sidebar');

export function toggleSidebar() {
  setSidebarOpen(!sidebarOpen);
  $sidebar.style.display = sidebarOpen ? 'flex' : 'none';
  document.body.classList.toggle('sidebar-open', sidebarOpen);
  if (sidebarOpen) {
    refreshSidebarContent();
  }
}

export function refreshSidebarContent() {
  renderSidebarBookmarks();
  renderSidebarHistory();
  renderSidebarReadingList();
}

export function renderSidebarBookmarks(filter = '') {
  const list = document.getElementById('sidebar-bookmarks-list');
  if (!list) return;
  list.innerHTML = '';
  const f = filter.toLowerCase();
  const filtered = f
    ? bookmarks.filter((b) => b.title.toLowerCase().includes(f) || b.url.toLowerCase().includes(f))
    : bookmarks;

  if (filtered.length === 0) {
    list.innerHTML =
      '<div class="sidebar-empty"><span class="material-icons-outlined">bookmark_border</span><p>' +
      (f ? 'No matching bookmarks' : 'No bookmarks yet') +
      '</p></div>';
    return;
  }

  filtered.forEach((bm) => {
    const item = document.createElement('div');
    item.className = 'sidebar-list-item';
    const iconHtml = bm.favicon
      ? `<img src="${bm.favicon}" data-fallback="bookmark">`
      : '<span class="material-icons-outlined">bookmark</span>';

    item.innerHTML = sanitizeHTML(`
            <div class="sidebar-list-item-icon">${iconHtml}</div>
            <div class="sidebar-list-item-text">
                <div class="sidebar-list-item-title">${bm.title}</div>
                <div class="sidebar-list-item-url">${bm.url}</div>
            </div>
            <button class="sidebar-list-item-delete" title="Remove"><span class="material-icons-outlined">close</span></button>
        `);
    item.addEventListener('click', (e) => {
      if (e.target.closest('.sidebar-list-item-delete')) return;
      navigateActiveTab(bm.url);
    });
    item.querySelector('.sidebar-list-item-delete').addEventListener('click', (e) => {
      e.stopPropagation();
      setBookmarks(bookmarks.filter((b) => b.url !== bm.url));
      saveBookmarks();
      renderSidebarBookmarks(filter);
      updateBookmarkButton();
    });
    list.appendChild(item);
  });
}

export function renderSidebarHistory(filter = '') {
  const list = document.getElementById('sidebar-history-list');
  if (!list) return;
  list.innerHTML = '';
  let hist = [];
  try {
    hist = JSON.parse(localStorage.getItem('krypton_history') || '[]');
  } catch (e) {}

  const f = filter.toLowerCase();
  const filtered = f
    ? hist.filter(
        (h) => (h.title || '').toLowerCase().includes(f) || (h.url || '').toLowerCase().includes(f),
      )
    : hist;
  const limited = filtered.slice(0, 50);

  if (limited.length === 0) {
    list.innerHTML =
      '<div class="sidebar-empty"><span class="material-icons-outlined">history</span><p>' +
      (f ? 'No matching history' : 'No history yet') +
      '</p></div>';
    return;
  }

  limited.forEach((h) => {
    const item = document.createElement('div');
    item.className = 'sidebar-list-item';
    const iconHtml = h.favicon
      ? `<img src="${h.favicon}" data-fallback="language">`
      : '<span class="material-icons-outlined">language</span>';
    const time = new Date(h.timestamp).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    });

    item.innerHTML = sanitizeHTML(`
            <div class="sidebar-list-item-icon">${iconHtml}</div>
            <div class="sidebar-list-item-text">
                <div class="sidebar-list-item-title">${h.title || h.url}</div>
                <div class="sidebar-list-item-url">${h.url}</div>
            </div>
            <span class="sidebar-list-item-time">${time}</span>
        `);
    item.addEventListener('click', () => navigateActiveTab(h.url));
    list.appendChild(item);
  });
}

export function renderSidebarReadingList() {
  const list = document.getElementById('sidebar-reading-list');
  const empty = document.getElementById('sidebar-reading-empty');
  if (!list) return;
  list.innerHTML = '';

  if (readingList.length === 0) {
    if (empty) empty.style.display = '';
    return;
  }
  if (empty) empty.style.display = 'none';

  readingList.forEach((item, i) => {
    const el = document.createElement('div');
    el.className = 'sidebar-list-item';
    el.innerHTML = sanitizeHTML(`
            <div class="sidebar-list-item-icon"><span class="material-icons-outlined">auto_stories</span></div>
            <div class="sidebar-list-item-text">
                <div class="sidebar-list-item-title">${item.title}</div>
                <div class="sidebar-list-item-url">${item.url}</div>
            </div>
            <button class="sidebar-list-item-delete" title="Remove"><span class="material-icons-outlined">close</span></button>
        `);
    el.addEventListener('click', (e) => {
      if (e.target.closest('.sidebar-list-item-delete')) return;
      navigateActiveTab(item.url);
    });
    el.querySelector('.sidebar-list-item-delete').addEventListener('click', (e) => {
      e.stopPropagation();
      readingList.splice(i, 1);
      localStorage.setItem('krypton_reading_list', JSON.stringify(readingList));
      renderSidebarReadingList();
    });
    list.appendChild(el);
  });
}

// Sidebar tab switching
document.querySelectorAll('.sidebar-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.sidebar-tab').forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.sidebar-pane').forEach((p) => p.classList.remove('active'));
    const pane = document.querySelector(`[data-sidebar-pane="${tab.dataset.sidebarTab}"]`);
    if (pane) pane.classList.add('active');
    refreshSidebarContent();
  });
});

// Sidebar search inputs
const sidebarBookmarkSearch = document.getElementById('sidebar-bookmark-search');
if (sidebarBookmarkSearch)
  sidebarBookmarkSearch.addEventListener('input', () =>
    renderSidebarBookmarks(sidebarBookmarkSearch.value),
  );

const sidebarHistorySearch = document.getElementById('sidebar-history-search');
if (sidebarHistorySearch)
  sidebarHistorySearch.addEventListener('input', () =>
    renderSidebarHistory(sidebarHistorySearch.value),
  );

// Sidebar add bookmark
const sidebarAddBookmark = document.getElementById('sidebar-add-bookmark');
if (sidebarAddBookmark)
  sidebarAddBookmark.addEventListener('click', () => {
    toggleBookmark();
    renderSidebarBookmarks();
  });

// Sidebar add to reading list
const sidebarAddReading = document.getElementById('sidebar-add-reading');
if (sidebarAddReading)
  sidebarAddReading.addEventListener('click', () => {
    const tab = getActiveTab();
    if (tab && tab.url && !tab.url.startsWith('krypton://')) {
      if (!readingList.find((r) => r.url === tab.url)) {
        readingList.push({ title: tab.title || tab.url, url: tab.url, addedAt: Date.now() });
        localStorage.setItem('krypton_reading_list', JSON.stringify(readingList));
        renderSidebarReadingList();
        showSettingsToast('Added to reading list');
      } else {
        showSettingsToast('Already in reading list');
      }
    }
  });

// Sidebar clear history
const sidebarClearHistory = document.getElementById('sidebar-clear-history');
if (sidebarClearHistory)
  sidebarClearHistory.addEventListener('click', () => {
    localStorage.removeItem('krypton_history');
    renderSidebarHistory();
    showSettingsToast('History cleared');
  });
