'use strict';

/**
 * PQC Security In-App Page Component
 * Embeds pages/pqc_security.html via an iframe inside the main window
 * and seamlessly provides window.kryptonBrowser bridge.
 */
export function createPqcSecurityPage(tabId) {
  const iframe = document.createElement('iframe');
  iframe.className = 'new-tab-page pqc-page';
  iframe.dataset.tabId = tabId;
  iframe.src = 'pages/pqc_security.html';
  iframe.style.width = '100%';
  iframe.style.height = '100%';
  iframe.style.border = 'none';
  iframe.style.background = '#0d0f14';

  iframe.addEventListener('load', () => {
    try {
      if (iframe.contentWindow) {
        iframe.contentWindow.kryptonBrowser = window.kryptonBrowser;
      }
    } catch (e) {
      console.warn('[PQC Page] Could not inject kryptonBrowser into iframe:', e);
    }
  });

  return iframe;
}
