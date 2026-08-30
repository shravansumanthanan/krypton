import {
  tabs,
  activeTabId,
  setActiveTabId,
  incrementTabCounter,
  $tabsContainer,
  $webviewContainer,
  $urlInput,
} from '../state/store.js';
import { createNewTabPage } from '../pages/ntp.js';
import { createHistoryPage } from '../pages/history-page.js';
import { createSettingsPage } from '../pages/settings-page.js';
import { createExtensionsInAppPage } from '../pages/extensions-page.js';
import { createWebview, navigateInternalPage } from '../webview/webview-factory.js';
import { showTabContextMenu, reorderTabs } from './tab-context-menu.js';
import { updateNavButtons } from '../navigation/nav-controller.js';
import { updateBookmarkButton } from '../bookmarks/bookmarks-manager.js';
import { updateReaderModeButton, deactivateReaderMode } from '../pages/reader-mode.js';
import { updateSecurityIndicator } from '../security/security-indicator.js';

export function createTab(url = 'krypton://newtab') {
  const id = 'tab-' + incrementTabCounter();
  const isInternal = url.startsWith('krypton://');
  const isNewTab = url === 'krypton://newtab';
  const isHistory = url === 'krypton://history';
  const isSettings = url === 'krypton://settings';
  const isExtensions = url === 'krypton://extensions';
  const isInAppPage = isHistory || isSettings || isExtensions;

  // Determine favicon and title
  let faviconIcon = 'language';
  let initialTitle = 'Loading...';
  if (isNewTab) {
    faviconIcon = 'security';
    initialTitle = 'New Tab';
  } else if (isHistory) {
    faviconIcon = 'history';
    initialTitle = 'History';
  } else if (isSettings) {
    faviconIcon = 'settings';
    initialTitle = 'Settings';
  } else if (isExtensions) {
    faviconIcon = 'extension';
    initialTitle = 'Extensions';
  } else if (url === 'krypton://pqc-security') {
    faviconIcon = 'shield';
  }

  const tabEl = document.createElement('div');
  tabEl.className = 'tab';
  tabEl.id = id;

  tabEl.innerHTML = `
    <div class="tab-favicon">
      <span class="material-icons-outlined">${faviconIcon}</span>
    </div>
    <span class="tab-title">${initialTitle}</span>
    <button class="tab-close" title="Close tab">×</button>
  `;

  tabEl.querySelector('.tab-close').addEventListener('click', (e) => {
    e.stopPropagation();
    closeTab(id);
  });
  tabEl.addEventListener('click', () => activateTab(id));

  // Tab context menu (right-click)
  tabEl.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    e.stopPropagation();
    showTabContextMenu(id, e.clientX, e.clientY);
  });

  // Tab drag-and-drop for reordering
  tabEl.setAttribute('draggable', 'true');
  tabEl.addEventListener('dragstart', (e) => {
    e.dataTransfer.setData('text/plain', id);
    tabEl.classList.add('dragging');
  });
  tabEl.addEventListener('dragend', () => {
    tabEl.classList.remove('dragging');
    document.querySelectorAll('.tab.drag-over').forEach((t) => t.classList.remove('drag-over'));
  });
  tabEl.addEventListener('dragover', (e) => {
    e.preventDefault();
    const dragging = document.querySelector('.tab.dragging');
    if (dragging && dragging !== tabEl) {
      tabEl.classList.add('drag-over');
    }
  });
  tabEl.addEventListener('dragleave', () => {
    tabEl.classList.remove('drag-over');
  });
  tabEl.addEventListener('drop', (e) => {
    e.preventDefault();
    tabEl.classList.remove('drag-over');
    const draggedId = e.dataTransfer.getData('text/plain');
    reorderTabs(draggedId, id);
  });

  const newTabBtn = document.getElementById('btn-new-tab');
  $tabsContainer.insertBefore(tabEl, newTabBtn);

  let webview = null;
  let newTabPage = null;
  let inAppPage = null;

  if (isNewTab) {
    newTabPage = createNewTabPage(id);
    $webviewContainer.appendChild(newTabPage);
  } else if (isHistory) {
    inAppPage = createHistoryPage(id);
    $webviewContainer.appendChild(inAppPage);
  } else if (isSettings) {
    inAppPage = createSettingsPage(id);
    $webviewContainer.appendChild(inAppPage);
  } else if (isExtensions) {
    inAppPage = createExtensionsInAppPage(id);
    $webviewContainer.appendChild(inAppPage);
  } else if (!isInAppPage) {
    webview = createWebview(id, url);
    $webviewContainer.appendChild(webview);
  }

  const tab = {
    id,
    tabEl,
    webview,
    newTabPage,
    inAppPage,
    url,
    title: initialTitle,
    isNewTab,
    isInAppPage,
    favicon: null,
    pinned: false,
    muted: false,
  };
  tabs.push(tab);

  activateTab(id);

  // For internal pages that use a webview (e.g. pqc-security with a file), navigate
  if (isInternal && !isNewTab && !isInAppPage) navigateInternalPage(id, url);
  return tab;
}

export function activateTab(id) {
  setActiveTabId(id);
  document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
  const tab = getTab(id);
  if (!tab) return;
  tab.tabEl.classList.add('active');
  showActiveContent(tab);

  // Auto-refresh history page when switching back to it
  if (tab.isInAppPage && tab.inAppPage && tab.inAppPage._refreshHistory) {
    tab.inAppPage._refreshHistory();
  }

  if (tab.isNewTab) {
    $urlInput.value = '';
    updateSecurityIndicator('');
    document.title = 'New Tab — KryptonBrowser';
  } else {
    $urlInput.value = tab.url;
    updateSecurityIndicator(tab.url);
    document.title = (tab.title || 'KryptonBrowser') + ' — KryptonBrowser';
  }
  updateNavButtons();
  updateBookmarkButton();
  updateReaderModeButton();
  // Deactivate reader mode when switching tabs
  deactivateReaderMode();
}

export function showActiveContent(tab) {
  document.querySelectorAll('webview').forEach((wv) => wv.classList.remove('active'));
  document.querySelectorAll('.new-tab-page').forEach((ntp) => ntp.classList.remove('active'));
  if (tab.isNewTab && tab.newTabPage) tab.newTabPage.classList.add('active');
  else if (tab.isInAppPage && tab.inAppPage) tab.inAppPage.classList.add('active');
  else if (tab.webview) tab.webview.classList.add('active');
}

export function closeTab(id) {
  const idx = tabs.findIndex((t) => t.id === id);
  if (idx === -1) return;
  const tab = tabs[idx];
  tab.tabEl.remove();
  if (tab.webview) tab.webview.remove();
  if (tab.newTabPage) tab.newTabPage.remove();
  if (tab.inAppPage) tab.inAppPage.remove();
  tabs.splice(idx, 1);

  if (tabs.length === 0) {
    createTab();
    return;
  }
  if (activeTabId === id) {
    const ni = Math.min(idx, tabs.length - 1);
    activateTab(tabs[ni].id);
  }
}

export function getTab(id) {
  return tabs.find((t) => t.id === id);
}
export function getActiveTab() {
  return getTab(activeTabId);
}
