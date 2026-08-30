import {
  bookmarks,
  setBookmarks,
  $bookmarksList,
  $bookmarkBtn,
  $bookmarkIcon,
} from '../state/store.js';
import { getActiveTab } from '../tabs/tab-manager.js';
import { navigateActiveTab } from '../navigation/nav-controller.js';

// ═══ Bookmarks ═══
export function saveBookmarks() {
  localStorage.setItem('krypton_bookmarks', JSON.stringify(bookmarks));
  renderBookmarksBar();
}

export function isBookmarked(url) {
  return bookmarks.some((b) => b.url === url);
}

export function toggleBookmark() {
  const tab = getActiveTab();
  if (!tab || tab.isNewTab) return;

  const url = tab.url;
  if (!url) return;

  if (isBookmarked(url)) {
    setBookmarks(bookmarks.filter((b) => b.url !== url));
  } else {
    bookmarks.push({
      url: url,
      title: tab.title || url,
      favicon: tab.favicon || null,
      addedAt: Date.now(),
    });
    setBookmarks(bookmarks);
  }
  saveBookmarks();
  updateBookmarkButton();
}

export function updateBookmarkButton() {
  const tab = getActiveTab();
  if (!tab || tab.isNewTab || !tab.url) {
    $bookmarkBtn.classList.remove('bookmarked');
    $bookmarkIcon.textContent = 'bookmark_border';
    return;
  }
  if (isBookmarked(tab.url)) {
    $bookmarkBtn.classList.add('bookmarked');
    $bookmarkIcon.textContent = 'bookmark';
  } else {
    $bookmarkBtn.classList.remove('bookmarked');
    $bookmarkIcon.textContent = 'bookmark_border';
  }
}

export function renderBookmarksBar() {
  $bookmarksList.innerHTML = '';
  bookmarks.forEach((bm) => {
    const el = document.createElement('button');
    el.className = 'bookmark-item';
    const safeTitle = (bm.title || '').replace(/[<>"&]/g, '');
    const faviconHtml = bm.favicon
      ? `<img src="${encodeURI(bm.favicon)}" data-fallback="bookmark">`
      : '<span class="material-icons-outlined">bookmark</span>';
    const displayTitle = safeTitle.length > 20 ? safeTitle.substring(0, 20) + '…' : safeTitle;
    el.innerHTML = `${faviconHtml}${displayTitle}`;
    el.title = bm.url;
    el.addEventListener('click', () => navigateActiveTab(bm.url));
    // Right-click to remove
    el.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      setBookmarks(bookmarks.filter((b) => b.url !== bm.url));
      saveBookmarks();
      updateBookmarkButton();
    });
    $bookmarksList.appendChild(el);
  });
}
