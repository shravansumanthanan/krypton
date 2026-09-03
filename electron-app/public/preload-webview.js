// KryptonBrowser — Webview Preload Script
// Runs inside each <webview> guest page context.
// Provides a minimal bridge for webview-specific functionality.

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kryptonWebview', {
  // Report page metrics back to the host
  reportMetrics: (metrics) => ipcRenderer.sendToHost('page-metrics', metrics),

  // Request PQC certificate info for the current page
  getCertificateInfo: (url) => ipcRenderer.invoke('get-certificate-info', url),
});

// ═══ YouTube Ad Blocker & Video Ad Skipper ═══
(function initYouTubeAdBlocker() {
  if (!/(?:^|\.)youtube\.com$|youtube-nocookie\.com$/i.test(location.hostname)) return;

  // 1. Cosmetic CSS to hide ad modules, banners, overlays, and companion ads
  const injectStyles = () => {
    if (document.getElementById('krypton-yt-cosmetic-styles')) return;
    const style = document.createElement('style');
    style.id = 'krypton-yt-cosmetic-styles';
    style.textContent = `
      .video-ads,
      .ytp-ad-module,
      ytd-ad-slot-renderer,
      ytd-banner-promo-renderer,
      #player-ads,
      ytd-in-feed-ad-layout-renderer,
      ytd-action-companion-ad-renderer,
      .ytp-ad-overlay-container,
      ytd-promoted-sparkles-web-renderer,
      ytd-promoted-video-renderer,
      ytd-display-ad-renderer,
      ytd-statement-banner-renderer,
      ytd-mealbar-promo-renderer,
      #masthead-ad,
      .ytd-merch-shelf-renderer,
      .sparkles-light-cta,
      .ytp-ad-text,
      .ytp-ad-preview-container,
      .ytp-ad-progress,
      .ytp-ad-progress-list,
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
    `;
    (document.head || document.documentElement).appendChild(style);
  };

  if (document.head || document.documentElement) {
    injectStyles();
  } else {
    document.addEventListener('DOMContentLoaded', injectStyles);
  }

  // 2. Continuous player ad detector & skipper
  function skipPlayerAds() {
    // Dismiss anti-adblock dialogs if present
    const dismissBtn = document.querySelector(
      'tp-yt-paper-dialog #dismiss-button, ytd-enforcement-message-view-model #dismiss-button, yt-mealbar-promo-renderer #dismiss-button',
    );
    if (dismissBtn) {
      try {
        dismissBtn.click();
      } catch {}
    }

    // Click any visible skip button
    const skipSelectors = [
      '.ytp-skip-ad-button',
      '.ytp-ad-skip-button-modern',
      '.ytp-ad-skip-button',
      '.ytp-ad-skip-button-slot button',
      'button.ytp-ad-skip-button',
      'button.ytp-ad-skip-button-modern',
      '[class*="ytp-ad-skip-button"]',
      '.ytp-ad-overlay-close-button',
    ];
    for (const sel of skipSelectors) {
      const btn = document.querySelector(sel);
      if (btn) {
        try {
          btn.click();
        } catch {}
      }
    }

    // Detect active ad in video player
    const player = document.querySelector('#movie_player, .html5-video-player');
    if (player && typeof player.skipAd === 'function') {
      try {
        player.skipAd();
      } catch {}
    }

    const isAdShowing =
      player &&
      (player.classList.contains('ad-showing') ||
        player.classList.contains('ad-interrupting') ||
        document.querySelector('.ad-showing, .ad-interrupting, .video-ads .ytp-ad-text') !== null);

    if (isAdShowing) {
      const video =
        document.querySelector('video.html5-main-video') || document.querySelector('video');
      if (video) {
        try {
          video.muted = true;
          video.playbackRate = 16;
          if (!isNaN(video.duration) && isFinite(video.duration) && video.duration > 0) {
            video.currentTime = video.duration;
          }
          if (video.paused) {
            video.play().catch(() => {});
          }
        } catch {}
      }
    }
  }

  // Fast polling + MutationObserver for immediate ad elimination
  setInterval(skipPlayerAds, 100);

  const observer = new MutationObserver(() => {
    skipPlayerAds();
  });

  const observeTarget = () => {
    const target = document.body || document.documentElement;
    if (target) {
      observer.observe(target, { childList: true, subtree: true });
    }
  };

  if (document.body || document.documentElement) {
    observeTarget();
  } else {
    document.addEventListener('DOMContentLoaded', observeTarget);
  }

  // Hook into YouTube SPA navigation events
  window.addEventListener('yt-navigate-finish', () => {
    injectStyles();
    skipPlayerAds();
  });
})();
