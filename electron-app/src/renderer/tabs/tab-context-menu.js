import { tabs, $tabsContainer } from '../state/store.js';
import { getTab, createTab, closeTab } from '../tabs/tab-manager.js';

// ═══ Tab Reordering ═══
export function reorderTabs(draggedTabId, targetTabId) {
  const draggedIdx = tabs.findIndex((t) => t.id === draggedTabId);
  const targetIdx = tabs.findIndex((t) => t.id === targetTabId);
  if (draggedIdx === -1 || targetIdx === -1) return;

  const [tab] = tabs.splice(draggedIdx, 1);
  tabs.splice(targetIdx, 0, tab);

  // Re-order DOM
  const newTabBtn = document.getElementById('btn-new-tab');
  tabs.forEach((t) => $tabsContainer.insertBefore(t.tabEl, newTabBtn));
}

// ═══ Tab Context Menu ═══
const $tabCtxMenu = document.getElementById('tab-ctx-menu');
let tabCtxTargetId = null;

export function showTabContextMenu(tabId, x, y) {
  tabCtxTargetId = tabId;
  const tab = getTab(tabId);
  if (!tab) return;

  // Update labels
  const pinLabel = document.getElementById('tab-ctx-pin-label');
  if (pinLabel) pinLabel.textContent = tab.pinned ? 'Unpin Tab' : 'Pin Tab';
  const muteLabel = document.getElementById('tab-ctx-mute-label');
  if (muteLabel) muteLabel.textContent = tab.muted ? 'Unmute Tab' : 'Mute Tab';

  $tabCtxMenu.style.display = 'block';
  const menuW = $tabCtxMenu.offsetWidth || 200;
  const menuH = $tabCtxMenu.offsetHeight || 260;
  $tabCtxMenu.style.left = Math.min(x, window.innerWidth - menuW - 8) + 'px';
  $tabCtxMenu.style.top = Math.min(y, window.innerHeight - menuH - 8) + 'px';
}

export function hideTabContextMenu() {
  $tabCtxMenu.style.display = 'none';
  tabCtxTargetId = null;
}

$tabCtxMenu.addEventListener('click', (e) => {
  const item = e.target.closest('.ctx-item');
  if (!item) return;
  const action = item.dataset.tabAction;
  if (!tabCtxTargetId) return;

  const tab = getTab(tabCtxTargetId);
  if (!tab) {
    hideTabContextMenu();
    return;
  }

  switch (action) {
    case 'pin':
      tab.pinned = !tab.pinned;
      tab.tabEl.classList.toggle('pinned', tab.pinned);
      break;
    case 'duplicate':
      createTab(tab.url || 'krypton://newtab');
      break;
    case 'mute':
      tab.muted = !tab.muted;
      if (tab.webview) {
        try {
          tab.webview.setAudioMuted(tab.muted);
        } catch (e) {}
      }
      break;
    case 'reload':
      if (tab.webview) tab.webview.reload();
      break;
    case 'close-others': {
      const othersToClose = tabs
        .filter((t) => t.id !== tabCtxTargetId && !t.pinned)
        .map((t) => t.id);
      othersToClose.forEach((id) => closeTab(id));
      break;
    }
    case 'close-right': {
      const idx = tabs.findIndex((t) => t.id === tabCtxTargetId);
      const rightToClose = tabs
        .slice(idx + 1)
        .filter((t) => !t.pinned)
        .map((t) => t.id);
      rightToClose.forEach((id) => closeTab(id));
      break;
    }
    case 'close':
      closeTab(tabCtxTargetId);
      break;
  }
  hideTabContextMenu();
});

document.addEventListener('click', () => hideTabContextMenu());
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') hideTabContextMenu();
});
