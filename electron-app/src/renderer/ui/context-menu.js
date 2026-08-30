import { $ctxMenu } from '../state/store.js';
import { getActiveTab, createTab } from '../tabs/tab-manager.js';
import { toggleBookmark } from '../bookmarks/bookmarks-manager.js';
import { getSearchUrl } from '../pages/settings-page.js';

// ═══ Context Menu ═══
export function showContextMenu(params, x, y, wv) {
  hideContextMenu();
  $ctxMenu.innerHTML = '';

  const items = [];

  if (params.linkURL) {
    items.push({
      icon: 'open_in_new',
      label: 'Open Link in New Tab',
      action: () => createTab(params.linkURL),
    });
    items.push({
      icon: 'content_copy',
      label: 'Copy Link Address',
      action: () => navigator.clipboard.writeText(params.linkURL),
    });
    items.push('---');
  }

  if (params.mediaType === 'image') {
    items.push({
      icon: 'image',
      label: 'Copy Image URL',
      action: () => navigator.clipboard.writeText(params.srcURL),
    });
    items.push({
      icon: 'download',
      label: 'Save Image As…',
      action: () => {
        if (wv) wv.downloadURL(params.srcURL);
      },
    });
    items.push('---');
  }

  if (params.selectionText) {
    items.push({
      icon: 'content_copy',
      label: 'Copy',
      action: () => navigator.clipboard.writeText(params.selectionText),
    });
    items.push({
      icon: 'search',
      label: `Search for “${params.selectionText.substring(0, 30)}…”`,
      action: () => createTab(getSearchUrl(params.selectionText)),
    });
    items.push('---');
  }

  if (!params.linkURL && !params.selectionText) {
    items.push({
      icon: 'arrow_back',
      label: 'Back',
      action: () => {
        const t = getActiveTab();
        if (t && t.webview) t.webview.goBack();
      },
    });
    items.push({
      icon: 'refresh',
      label: 'Reload',
      action: () => {
        const t = getActiveTab();
        if (t && t.webview) t.webview.reload();
      },
    });
    items.push({ icon: 'bookmark_border', label: 'Bookmark This Page', action: toggleBookmark });
    items.push('---');
    items.push({
      icon: 'code',
      label: 'View Page Source',
      action: () => {
        const t = getActiveTab();
        if (t && t.url) createTab('view-source:' + t.url);
      },
    });
  }

  items.push({
    icon: 'bug_report',
    label: 'Inspect Element',
    action: () => {
      if (wv) {
        try {
          wv.openDevTools({ mode: 'detach' });
        } catch (e) {}
      }
    },
  });

  items.forEach((item) => {
    if (item === '---') {
      const sep = document.createElement('div');
      sep.className = 'ctx-separator';
      $ctxMenu.appendChild(sep);
      return;
    }
    const el = document.createElement('div');
    el.className = 'ctx-item';
    el.innerHTML = `<span class="material-icons-outlined">${item.icon}</span>${item.label}`;
    el.addEventListener('click', () => {
      item.action();
      hideContextMenu();
    });
    $ctxMenu.appendChild(el);
  });

  // Position within screen bounds
  $ctxMenu.style.display = 'block';
  const menuW = $ctxMenu.offsetWidth || 220;
  const menuH = $ctxMenu.offsetHeight || 200;
  const left = Math.min(x, window.innerWidth - menuW - 8);
  const top = Math.min(y, window.innerHeight - menuH - 8);
  $ctxMenu.style.left = left + 'px';
  $ctxMenu.style.top = top + 'px';
}

export function hideContextMenu() {
  $ctxMenu.style.display = 'none';
  $ctxMenu.innerHTML = '';
}

document.addEventListener('click', () => hideContextMenu());
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') hideContextMenu();
});
