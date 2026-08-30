import { createTab, closeTab, getActiveTab } from '../tabs/tab-manager.js';
import { activeTabId, $urlInput, $securityPopup, downloadItems } from '../state/store.js';
import { updateSecurityPopup } from '../security/security-indicator.js';
import { closeAllPanels, toggleShieldsPanel } from '../shields/shields-controller.js';
import { toggleDownloadsPanel, renderDownloadItem } from '../downloads/downloads-panel.js';
import { showPermissionDialog } from '../security/permission-dialog.js';
import { toggleFindBar } from '../ui/find-bar.js';
import { showSettingsToast } from '../pages/settings-page.js';
import { togglePrivateMode } from '../pages/private-mode.js';
import { toggleSidebar } from '../sidebar/sidebar-controller.js';
import { toggleReaderMode } from '../pages/reader-mode.js';

// ═══ Menu IPC ═══
export function initIpcBridge() {
  if (window.kryptonBrowser) {
    window.kryptonBrowser.onNavigateTo((url) => createTab(url));
    window.kryptonBrowser.onNewTab(() => createTab());
    window.kryptonBrowser.onCloseTab(() => {
      if (activeTabId) closeTab(activeTabId);
    });
    window.kryptonBrowser.onFocusUrlBar(() => {
      $urlInput.focus();
      $urlInput.select();
    });
    window.kryptonBrowser.onReloadPage(() => {
      const tab = getActiveTab();
      if (tab && tab.webview) tab.webview.reload();
    });
    window.kryptonBrowser.onShowSecurityInfo(() => {
      closeAllPanels();
      $securityPopup.style.display = 'block';
      updateSecurityPopup();
    });

    // New: open URL in new tab (from main process target=_blank intercept)
    window.kryptonBrowser.onOpenUrlInNewTab((url) => createTab(url));

    // New: toggle find bar from native menu (Cmd+F)
    window.kryptonBrowser.onToggleFindBar(() => toggleFindBar());

    // New: download lifecycle
    window.kryptonBrowser.onDownloadStarted((info) => {
      downloadItems[info.id] = info;
      const $downloadsPanel = document.getElementById('downloads-panel');
      if ($downloadsPanel.style.display === 'none' || !$downloadsPanel.style.display) {
        toggleDownloadsPanel();
      }
      renderDownloadItem(info);
    });
    window.kryptonBrowser.onDownloadUpdated((info) => {
      downloadItems[info.id] = info;
      renderDownloadItem(info);
    });
    window.kryptonBrowser.onDownloadDone((info) => {
      downloadItems[info.id] = info;
      renderDownloadItem(info);
      if (info.state === 'completed') showSettingsToast(`Downloaded: ${info.filename}`);
    });

    // New: permission request notification
    window.kryptonBrowser.onPermissionRequest((details) => showPermissionDialog(details));

    // New: clear browsing data from menu shortcut
    window.kryptonBrowser.onClearBrowsingData(() => {
      localStorage.removeItem('krypton_history');
      showSettingsToast('Browsing data cleared');
    });

    // New: native menu action forwarding
    if (window.kryptonBrowser.onMenuAction) {
      window.kryptonBrowser.onMenuAction((action) => {
        switch (action) {
          case 'private-window':
            if (typeof togglePrivateMode === 'function') togglePrivateMode();
            break;
          case 'toggle-sidebar':
            toggleSidebar();
            break;
          case 'reader-mode':
            toggleReaderMode();
            break;
          case 'toggle-shields':
            toggleShieldsPanel();
            break;
        }
      });
    }
  }
}
