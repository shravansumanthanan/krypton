import { getActiveTab } from '../tabs/tab-manager.js';
import { createTab } from '../tabs/tab-manager.js';
import { createWebview, navigateInternalPage } from '../webview/webview-factory.js';
import { showActiveContent } from '../tabs/tab-manager.js';
import { updateSecurityIndicator } from '../security/security-indicator.js';
import { updateBookmarkButton } from '../bookmarks/bookmarks-manager.js';
import {
  $urlInput,
  $webviewContainer,
  $reloadIcon,
  $loadingBar,
  $loadingProgress,
} from '../state/store.js';
import { getSearchUrl } from '../pages/settings-page.js';

// ═══ Navigation ═══
export function navigateActiveTab(input) {
  const tab = getActiveTab();
  if (!tab) return;
  const url = normalizeUrl(input);

  if (url.startsWith('krypton://')) {
    if (url === 'krypton://newtab') return;
    // For in-app pages, open in a new tab
    if (
      url === 'krypton://history' ||
      url === 'krypton://settings' ||
      url === 'krypton://extensions' ||
      url === 'krypton://pqc-security'
    ) {
      createTab(url);
      return;
    }
    navigateInternalPage(tab.id, url);
    return;
  }

  // Clean up any overlay pages before navigating to a real URL
  if (tab.isNewTab) {
    if (tab.newTabPage) {
      tab.newTabPage.remove();
      tab.newTabPage = null;
    }
    tab.isNewTab = false;
  }
  if (tab.isInAppPage) {
    if (tab.inAppPage) {
      tab.inAppPage.remove();
      tab.inAppPage = null;
    }
    tab.isInAppPage = false;
  }

  if (!tab.webview) {
    tab.webview = createWebview(tab.id, url);
    $webviewContainer.appendChild(tab.webview);
    showActiveContent(tab);
  } else {
    tab.webview.src = url;
  }

  tab.url = url;
  tab.title = 'Loading...';
  tab.tabEl.querySelector('.tab-title').textContent = 'Loading...';
  tab.tabEl.querySelector('.tab-favicon').innerHTML =
    '<span class="material-icons-outlined">language</span>';
  $urlInput.value = url;
  updateSecurityIndicator(url);
  updateBookmarkButton();
}

export function normalizeUrl(input) {
  input = input.trim();
  if (input.startsWith('krypton://')) return input;
  if (input.startsWith('http://') || input.startsWith('https://')) return input;
  if (input.startsWith('file://')) return input;
  if (/^[\w-]+(\.[\w-]+)+/.test(input)) return 'https://' + input;
  return getSearchUrl(input);
}

// ═══ Nav Buttons ═══
export function updateNavButtons() {
  const tab = getActiveTab();
  const $back = document.getElementById('btn-back');
  const $forward = document.getElementById('btn-forward');
  if (tab && tab.webview) {
    try {
      $back.disabled = !tab.webview.canGoBack();
      $forward.disabled = !tab.webview.canGoForward();
    } catch (e) {
      $back.disabled = true;
      $forward.disabled = true;
    }
  } else {
    $back.disabled = true;
    $forward.disabled = true;
  }
}

export function updateReloadButton(loading) {
  $reloadIcon.textContent = loading ? 'close' : 'refresh';
}

export function showLoading(isLoading) {
  if (isLoading) $loadingBar.classList.add('active');
  else {
    $loadingBar.classList.remove('active');
    $loadingProgress.style.width = '0';
  }
}
