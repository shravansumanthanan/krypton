import { getActiveTab } from '../tabs/tab-manager.js';
import {
  readerFontSize,
  readerLightTheme,
  setReaderFontSize,
  setReaderLightTheme,
} from '../state/store.js';

// ═══ Reader Mode ═══
const $readerOverlay = document.getElementById('reader-overlay');
const $readerContent = document.getElementById('reader-content');
const $readerBtn = document.getElementById('btn-reader-mode');
const $readerTitle = document.getElementById('reader-title');

export function toggleReaderMode() {
  if ($readerOverlay.style.display === 'none' || !$readerOverlay.style.display) {
    activateReaderMode();
  } else {
    deactivateReaderMode();
  }
}

export function activateReaderMode() {
  const tab = getActiveTab();
  if (!tab || !tab.webview) return;

  $readerBtn.classList.add('active-reader');
  $readerOverlay.style.display = 'flex';
  $readerTitle.textContent = tab.title || 'Reader Mode';

  // Extract page content from webview
  tab.webview
    .executeJavaScript(
      `
        (function() {
            // Simple content extraction
            const article = document.querySelector('article') || document.querySelector('[role="main"]') || document.querySelector('main') || document.body;
            const title = document.querySelector('h1')?.textContent || document.title || '';
            const content = article ? article.innerHTML : document.body.innerHTML;
            return { title, content };
        })()
    `,
    )
    .then((result) => {
      if (result) {
        let html = '';
        if (result.title) html += '<h1>' + result.title + '</h1>';
        html += result.content || '<p>Could not extract readable content from this page.</p>';
        $readerContent.innerHTML = window.DOMPurify ? DOMPurify.sanitize(html) : html;
      }
    })
    .catch(() => {
      $readerContent.innerHTML =
        '<h1>Reader Mode</h1><p>Could not extract content from this page. Try a different page with article content.</p>';
    });

  $readerContent.style.fontSize = readerFontSize + 'px';
}

export function deactivateReaderMode() {
  $readerOverlay.style.display = 'none';
  $readerBtn.classList.remove('active-reader');
}

// Reader controls
document.getElementById('reader-close').addEventListener('click', deactivateReaderMode);
document.getElementById('reader-font-minus').addEventListener('click', () => {
  setReaderFontSize(Math.max(12, readerFontSize - 2));
  $readerContent.style.fontSize = readerFontSize + 'px';
});
document.getElementById('reader-font-plus').addEventListener('click', () => {
  setReaderFontSize(Math.min(28, readerFontSize + 2));
  $readerContent.style.fontSize = readerFontSize + 'px';
});
document.getElementById('reader-theme-toggle').addEventListener('click', () => {
  setReaderLightTheme(!readerLightTheme);
  $readerContent.classList.toggle('light', readerLightTheme);
  $readerOverlay.style.background = readerLightTheme ? '#f5f5f5' : '#1a1a2e';
});

// Show reader mode button for web pages
export function updateReaderModeButton() {
  const tab = getActiveTab();
  if (tab && tab.webview && tab.url && tab.url.startsWith('https://')) {
    $readerBtn.style.display = 'flex';
    $readerBtn.classList.add('available');
  } else {
    $readerBtn.style.display = 'none';
    $readerBtn.classList.remove('available');
  }
}
