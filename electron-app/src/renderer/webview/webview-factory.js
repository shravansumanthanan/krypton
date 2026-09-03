import { extensions, $webviewContainer, $urlInput, activeTabId } from '../state/store.js';
import { recordHistory, updateHistoryEntry } from '../history/history-manager.js';
import { updateSecurityIndicator } from '../security/security-indicator.js';
import { updateNavButtons, updateReloadButton, showLoading } from '../navigation/nav-controller.js';
import { updateBookmarkButton } from '../bookmarks/bookmarks-manager.js';
import { getTab, createTab, showActiveContent } from '../tabs/tab-manager.js';
import { refreshShieldCount } from '../ui/status-bar.js';
import { showContextMenu } from '../ui/context-menu.js';
import { hookFindInPage } from '../ui/find-bar.js';
import { INTERNAL_PAGES } from '../state/store.js';

function applyAdBlockerAndSkipper(wv, tabId) {
  window.kryptonBrowser
    ?.getConfig('krypton_ad_block', 'true')
    .then((val) => {
      if (val !== 'false') {
        wv.insertCSS(
          `
          .adsbygoogle, [class*="ad-banner"], [class*="ad_banner"], [id*="google_ads"],
          [id*="ad-slot"], [class*="ad-container"], [class*="ad-placement"],
          .ad-placeholder, .advertisement, div[data-ad-unit], div[data-ad-slot],
          iframe[src*="doubleclick"], iframe[src*="googlesyndication"],
          .video-ads, .ytp-ad-module, ytd-ad-slot-renderer, ytd-banner-promo-renderer,
          #player-ads, ytd-in-feed-ad-layout-renderer, ytd-action-companion-ad-renderer,
          .ytp-ad-overlay-container, ytd-promoted-sparkles-web-renderer, ytd-promoted-video-renderer,
          ytd-display-ad-renderer, ytd-statement-banner-renderer, ytd-mealbar-promo-renderer,
          #masthead-ad, .ytd-merch-shelf-renderer, .sparkles-light-cta, .ytp-ad-text,
          .ytp-ad-preview-container, .ytp-ad-progress, .ytp-ad-progress-list,
          ytd-rich-item-renderer:has(ytd-ad-slot-renderer),
          tp-yt-paper-dialog:has(#feedback),
          ytd-enforcement-message-view-model,
          .yt-playability-error-supported-renderers {
            display: none !important;
            visibility: hidden !important;
            height: 0 !important;
            width: 0 !important;
            opacity: 0 !important;
            pointer-events: none !important;
          }
        `,
        ).catch(() => {});

        // YouTube Ad Skipper
        const tab = getTab(tabId);
        const currentUrl = (tab && tab.url) || wv.getAttribute('src') || '';
        if (/(?:^|\.)youtube\.com|youtube-nocookie\.com/i.test(currentUrl)) {
          wv.executeJavaScript(
            `
            (function() {
              if (window.__kryptonYtSkipperInstalled) return;
              window.__kryptonYtSkipperInstalled = true;
              function skipAds() {
                const dismiss = document.querySelector('tp-yt-paper-dialog #dismiss-button, ytd-enforcement-message-view-model #dismiss-button, yt-mealbar-promo-renderer #dismiss-button');
                if (dismiss) { try { dismiss.click(); } catch(e){} }
                const skipBtns = [
                  '.ytp-skip-ad-button',
                  '.ytp-ad-skip-button-modern',
                  '.ytp-ad-skip-button',
                  '.ytp-ad-skip-button-slot button',
                  'button.ytp-ad-skip-button',
                  'button.ytp-ad-skip-button-modern',
                  '[class*="ytp-ad-skip-button"]',
                  '.ytp-ad-overlay-close-button'
                ];
                for (const s of skipBtns) {
                  const b = document.querySelector(s);
                  if (b) { try { b.click(); } catch(e){} }
                }
                const player = document.querySelector('#movie_player, .html5-video-player');
                if (player && typeof player.skipAd === 'function') {
                  try { player.skipAd(); } catch(e){}
                }
                const isAd = player && (
                  player.classList.contains('ad-showing') ||
                  player.classList.contains('ad-interrupting') ||
                  document.querySelector('.ad-showing, .ad-interrupting, .video-ads .ytp-ad-text') !== null
                );
                if (isAd) {
                  const v = document.querySelector('video.html5-main-video') || document.querySelector('video');
                  if (v) {
                    try {
                      v.muted = true;
                      v.playbackRate = 16;
                      if (!isNaN(v.duration) && isFinite(v.duration) && v.duration > 0) {
                        v.currentTime = v.duration;
                      }
                      if (v.paused) v.play().catch(() => {});
                    } catch(e){}
                  }
                }
              }
              setInterval(skipAds, 100);
              const obs = new MutationObserver(skipAds);
              if (document.body) obs.observe(document.body, { childList: true, subtree: true });
              window.addEventListener('yt-navigate-finish', skipAds);
            })();
          `,
          ).catch(() => {});
        }
      }
    })
    .catch(() => {});
}

export function createWebview(tabId, url) {
  const wv = document.createElement('webview');
  wv.dataset.tabId = tabId;
  wv.setAttribute('src', url);
  wv.setAttribute('autosize', 'on');
  wv.setAttribute('partition', 'burner-session');
  wv.setAttribute('allowpopups', 'true');
  wv.setAttribute(
    'webpreferences',
    'contextIsolation=yes, sandbox=yes, nodeIntegration=no, webSecurity=yes',
  );
  const preloadPath = window.kryptonBrowser?.webviewPreloadPath || 'preload-webview.js';
  wv.setAttribute('preload', preloadPath);

  wv.addEventListener('did-start-loading', () => {
    showLoading(true);
    updateReloadButton(true);
  });
  wv.addEventListener('dom-ready', () => {
    applyAdBlockerAndSkipper(wv, tabId);
  });
  wv.addEventListener('did-stop-loading', () => {
    showLoading(false);
    updateReloadButton(false);
    refreshShieldCount();
    applyAdBlockerAndSkipper(wv, tabId);

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
    if (tab) {
      tab.url = e.url;
      if (tabId === activeTabId) {
        $urlInput.value = e.url;
        updateSecurityIndicator(e.url);
      }
    }
    applyAdBlockerAndSkipper(wv, tabId);
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
