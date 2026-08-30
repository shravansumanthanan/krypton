'use strict';

module.exports = function registerShieldsHandlers(ipcMain, services) {
  const { statsGetter, siteBlockCountsGetter } = services;

  // Blocking stats
  ipcMain.handle('get-blocking-stats', async () => statsGetter());

  // Per-site shield stats
  ipcMain.handle('get-site-block-count', async (e, pageUrl) => {
    if (!pageUrl) return null;
    try {
      const hostname = new URL(pageUrl).hostname.toLowerCase();
      const siteBlockCounts = siteBlockCountsGetter();
      return (
        siteBlockCounts.get(hostname) || {
          total: 0,
          ads: 0,
          trackers: 0,
          fingerprinting: 0,
          cryptominers: 0,
          malware: 0,
          social: 0,
          telemetry: 0,
          patterns: 0,
        }
      );
    } catch {
      return null;
    }
  });

  // Full site block map (for shields summary)
  ipcMain.handle('get-all-site-stats', async () => {
    const result = [];
    const siteBlockCounts = siteBlockCountsGetter();
    for (const [host, counts] of siteBlockCounts.entries()) {
      result.push({ host, ...counts });
    }
    return result.sort((a, b) => b.total - a.total).slice(0, 50);
  });
};
