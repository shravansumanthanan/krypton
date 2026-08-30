import {
  $findBar,
  $findInput,
  $findCount,
  findBarVisible,
  setFindBarVisible,
} from '../state/store.js';
import { getActiveTab } from '../tabs/tab-manager.js';

// ═══ Find In Page ═══
export function toggleFindBar() {
  setFindBarVisible(!findBarVisible);
  $findBar.style.display = findBarVisible ? 'flex' : 'none';
  if (findBarVisible) {
    $findInput.focus();
    $findInput.select();
  } else {
    closeFindBar();
  }
}

export function closeFindBar() {
  setFindBarVisible(false);
  $findBar.style.display = 'none';
  $findInput.value = '';
  $findCount.textContent = '';
  $findInput.classList.remove('no-match');
  const tab = getActiveTab();
  if (tab && tab.webview) {
    try {
      tab.webview.stopFindInPage('clearSelection');
    } catch (e) {}
  }
}

export function doFind(forward = true) {
  const query = $findInput.value;
  const tab = getActiveTab();
  if (!tab || !tab.webview || !query) {
    $findCount.textContent = '';
    return;
  }
  tab.webview.findInPage(query, { forward, findNext: true });
}

$findInput.addEventListener('input', () => {
  const query = $findInput.value;
  const tab = getActiveTab();
  if (!query) {
    $findCount.textContent = '';
    $findInput.classList.remove('no-match');
    return;
  }
  if (tab && tab.webview) tab.webview.findInPage(query, { forward: true, findNext: false });
});

$findInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    doFind(!e.shiftKey);
  }
  if (e.key === 'Escape') {
    closeFindBar();
  }
});

document.getElementById('find-prev').addEventListener('click', () => doFind(false));
document.getElementById('find-next').addEventListener('click', () => doFind(true));
document.getElementById('find-close').addEventListener('click', closeFindBar);

// Listen for find results from webview
document.addEventListener('found-in-page', (e) => {
  if (e.result) {
    const { activeMatchOrdinal, matches } = e.result;
    if (matches === 0) {
      $findCount.textContent = 'No results';
      $findInput.classList.add('no-match');
    } else {
      $findCount.textContent = `${activeMatchOrdinal} / ${matches}`;
      $findInput.classList.remove('no-match');
    }
  }
});

// Wire found-in-page event per webview
export function hookFindInPage(wv) {
  wv.addEventListener('found-in-page', (e) => {
    if (e.result) {
      const { activeMatchOrdinal, matches } = e.result;
      if (matches === 0) {
        $findCount.textContent = 'No results';
        $findInput.classList.add('no-match');
      } else {
        $findCount.textContent = `${activeMatchOrdinal} / ${matches}`;
        $findInput.classList.remove('no-match');
      }
    }
  });
}
