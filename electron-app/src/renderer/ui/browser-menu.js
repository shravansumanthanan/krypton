import { $browserMenu } from '../state/store.js';
import { closeAllPanels } from '../shields/shields-controller.js';
import { createTab, getActiveTab } from '../tabs/tab-manager.js';
import { togglePrivateMode } from '../pages/private-mode.js';
import { toggleSidebar } from '../sidebar/sidebar-controller.js';
import { toggleDownloadsPanel } from '../downloads/downloads-panel.js';
import { toggleExtensionsPanel } from './extensions-popup.js';
import { toggleFindBar } from './find-bar.js';
import { toggleAdBlocking } from './status-bar.js';

// ═══ Browser Menu ═══
export function toggleMenu() {
  if ($browserMenu.style.display === 'none' || !$browserMenu.style.display) {
    closeAllPanels();
    $browserMenu.style.display = 'block';
  } else {
    $browserMenu.style.display = 'none';
  }
}

export function handleMenuAction(action) {
  closeAllPanels();
  switch (action) {
    case 'new-tab':
      createTab();
      break;
    case 'new-window':
      createTab();
      break;
    case 'private-window':
      togglePrivateMode();
      createTab();
      break;
    case 'pqc-panel':
      createTab('krypton://pqc-security');
      break;
    case 'history':
      createTab('krypton://history');
      break;
    case 'bookmarks':
      toggleSidebar();
      break;
    case 'downloads':
      toggleDownloadsPanel();
      break;
    case 'extensions':
      toggleExtensionsPanel();
      break;
    case 'find':
      toggleFindBar();
      break;
    case 'print': {
      const tab = getActiveTab();
      if (tab && tab.webview) tab.webview.print();
      break;
    }
    case 'shield-toggle':
      toggleAdBlocking();
      break;
    case 'settings':
      createTab('krypton://settings');
      break;
  }
}
