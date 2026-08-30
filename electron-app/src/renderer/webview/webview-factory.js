import { extensions, $webviewContainer, $urlInput, activeTabId } from '../state/store.js';
import { recordHistory, updateHistoryEntry } from '../history/history-manager.js';
import { updateSecurityIndicator } from '../security/security-indicator.js';
import { updateNavButtons, updateReloadButton, showLoading } from '../navigation/nav-controller.js';
import { updateBookmarkButton } from '../bookmarks/bookmarks-manager.js';
import { getTab, getActiveTab, createTab, showActiveContent } from '../tabs/tab-manager.js';
import { refreshShieldCount } from '../ui/status-bar.js';
import { showContextMenu } from '../ui/context-menu.js';
import { hookFindInPage } from '../ui/find-bar.js';
import { INTERNAL_PAGES } from '../state/store.js';

export function createWebview(tabId, url) {
  const wv = document.createElement('webview');
  wv.dataset.tabId = tabId;
  wv.setAttribute('src', url);
  wv.setAttribute('autosize', 'on');
  wv.setAttribute('preload', 'preload-webview.js');

  wv.addEventListener('did-start-loading', () => {
    showLoading(true);
    updateReloadButton(true);
  });
  wv.addEventListener('did-stop-loading', () => {
    showLoading(false);
    updateReloadButton(false);

    // Apply Extension Stubs
    const extMap = {};
    extensions.forEach((ext) => (extMap[ext.id] = ext.enabled));

    // Dark Reader Stub
    if (extMap['dark-reader']) {
      wv.insertCSS(
        'html, body { filter: invert(1) hue-rotate(180deg) !important; background: #111 !important; } img, video, iframe { filter: invert(1) hue-rotate(180deg) !important; }',
      ).catch(() => {});
    }

    // Speedreader Stub
    if (extMap['speedreader']) {
      wv.insertCSS(
        'body { max-width: 800px; margin: 0 auto; font-family: Georgia, serif; line-height: 1.6; } header, footer, aside, nav { display: none !important; }',
      ).catch(() => {});
    }

    // Password Manager Stub
    if (extMap['password-mgr']) {
      wv.executeJavaScript(
        `
        document.querySelectorAll('input[type="password"]').forEach(pw => {
          pw.style.border = '2px solid #34d399';
          pw.title = 'Krypton Password Manager: Ready to autofill';
        });
      `,
      ).catch(() => {});
    }

    // Translate Stub
    if (extMap['translate']) {
      wv.executeJavaScript(
        `
        if (document.documentElement.lang && !document.documentElement.lang.startsWith('en')) {
          console.log('Krypton Translate: Offer to translate page from ' + document.documentElement.lang);
        }
      `,
      ).catch(() => {});
    }
  });

  wv.addEventListener('did-navigate', (e) => {
    const tab = getTab(tabId);
    if (tab) {
      tab.url = e.url;
      // Record history immediately with URL as placeholder; title/favicon updated later
      tab._historyTs = Date.now();
      recordHistory(e.url, e.url, null, tab._historyTs);
      if (tabId === activeTabId) {
        $urlInput.value = e.url;
        updateSecurityIndicator(e.url);
        updateBookmarkButton();
      }
    }
    updateNavButtons();
  });

  wv.addEventListener('did-navigate-in-page', (e) => {
    const tab = getTab(tabId);
    if (tab && tabId === activeTabId) {
      tab.url = e.url;
      $urlInput.value = e.url;
    }
  });

  wv.addEventListener('page-title-updated', (e) => {
    const tab = getTab(tabId);
    if (tab) {
      tab.title = e.title;
      tab.tabEl.querySelector('.tab-title').textContent = e.title;
      if (tabId === activeTabId) document.title = e.title + ' — KryptonBrowser';
      // Update the history entry with the real page title
      updateHistoryEntry(tab._historyTs, { title: e.title });
    }
  });

  wv.addEventListener('page-favicon-updated', (e) => {
    const tab = getTab(tabId);
    if (tab && e.favicons && e.favicons.length > 0) {
      tab.favicon = e.favicons[0];
      tab.tabEl.querySelector('.tab-favicon').innerHTML =
        `<img src="${e.favicons[0]}" data-fallback="tab-favicon">`;
      // Update the history entry with the favicon
      updateHistoryEntry(tab._historyTs, { favicon: e.favicons[0] });
    }
  });

  wv.addEventListener('did-fail-load', (e) => {
    if (e.errorCode !== -3) showLoading(false);
  });

  // new-window: open in KryptonBrowser instead of system browser
  wv.addEventListener('new-window', (e) => {
    e.preventDefault();
    createTab(e.url);
  });

  // did-navigate: also refresh shield counter
  wv.addEventListener('did-navigate', () => {
    refreshShieldCount();
  });

  // Status bar: show link URL on hover
  wv.addEventListener('update-target-url', (e) => {
    const statusUrl = document.getElementById('status-hover-url');
    if (statusUrl) {
      if (e.url) {
        statusUrl.textContent = e.url;
        statusUrl.classList.add('visible');
      } else {
        statusUrl.classList.remove('visible');
      }
    }
  });

  // Context menu: right-click on webpage
  wv.addEventListener('context-menu', (e) => {
    e.preventDefault();
    showContextMenu(e.params || {}, e.x || e.clientX, e.y || e.clientY, wv);
  });

  // Hook find-in-page results (defined later in the file; call after DOM ready)
  setTimeout(() => {
    if (typeof hookFindInPage === 'function') hookFindInPage(wv);
  }, 0);

  return wv;
}

export function navigateInternalPage(tabId, url) {
  const tab = getTab(tabId);
  if (!tab) return;
  const page = INTERNAL_PAGES[url];
  if (!page || !page.file) return;

  // Clean up any existing in-app pages
  if (tab.newTabPage) {
    tab.newTabPage.remove();
    tab.newTabPage = null;
    tab.isNewTab = false;
  }
  if (tab.inAppPage) {
    tab.inAppPage.remove();
    tab.inAppPage = null;
    tab.isInAppPage = false;
  }

  if (!tab.webview) {
    tab.webview = createWebview(tabId, page.file);
    $webviewContainer.appendChild(tab.webview);
  } else {
    tab.webview.src = page.file;
  }

  tab.url = url;
  tab.title = page.title;
  tab.tabEl.querySelector('.tab-title').textContent = page.title;
  tab.tabEl.querySelector('.tab-favicon').innerHTML =
    '<span class="material-icons-outlined">shield</span>';

  if (tabId === activeTabId) {
    showActiveContent(tab);
    $urlInput.value = url;
    updateSecurityIndicator(url);
  }
}
