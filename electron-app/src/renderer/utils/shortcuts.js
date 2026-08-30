import { $urlInput } from '../state/store.js';
import { toggleBookmark } from '../bookmarks/bookmarks-manager.js';
import { toggleFindBar } from '../ui/find-bar.js';
import { toggleDownloadsPanel } from '../downloads/downloads-panel.js';
import { toggleSidebar } from '../sidebar/sidebar-controller.js';
import { toggleReaderMode } from '../pages/reader-mode.js';
import { togglePrivateMode } from '../pages/private-mode.js';
import { toggleShieldsPanel } from '../shields/shields-controller.js';

// ═══ Keyboard Shortcuts ═══
export function initShortcuts() {
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'l') {
      e.preventDefault();
      $urlInput.focus();
      $urlInput.select();
    }
    if ((e.metaKey || e.ctrlKey) && e.key === 'd') {
      e.preventDefault();
      toggleBookmark();
    }
    if ((e.metaKey || e.ctrlKey) && e.key === 'f') {
      e.preventDefault();
      toggleFindBar();
    }
    if ((e.metaKey || e.ctrlKey) && e.altKey && e.key === 'l') {
      e.preventDefault();
      toggleDownloadsPanel();
    }
    // Cmd/Ctrl+B → Toggle Sidebar
    if ((e.metaKey || e.ctrlKey) && !e.shiftKey && e.key === 'b') {
      e.preventDefault();
      toggleSidebar();
    }
    // Cmd/Ctrl+Shift+R → Toggle Reader Mode
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'R') {
      e.preventDefault();
      toggleReaderMode();
    }
    // Cmd/Ctrl+Shift+N → Toggle Private Mode
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'N') {
      e.preventDefault();
      togglePrivateMode();
    }
    // Cmd/Ctrl+Shift+S → Toggle Shields Panel
    if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'S') {
      e.preventDefault();
      toggleShieldsPanel();
    }
  });
}
