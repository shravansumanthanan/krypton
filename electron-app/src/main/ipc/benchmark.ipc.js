'use strict';

// KryptonBrowser — Benchmark IPC Handlers
// Wraps pqc-benchmark-service.js for renderer access.
// Long-running benchmarks run in a detached Promise to avoid blocking IPC.

module.exports = function registerBenchmarkHandlers(ipcMain, services) {
  const { pqcBenchmarkService } = services;

  // Run full benchmark suite (all 6 algorithms, N runs each)
  // Returns the structured result; blocks the IPC call for the duration.
  ipcMain.handle('pqc-benchmark-run-all', async (e, options = {}) => {
    const runs = Math.max(1, Math.min(parseInt(options.runs) || 20, 100));
    // run synchronously — this is a deliberate user action, not background work
    return pqcBenchmarkService.runAll({ runs });
  });

  // Run a single algorithm quick benchmark
  ipcMain.handle('pqc-benchmark-run-one', async (e, algorithm, runs) => {
    const n = Math.max(1, Math.min(parseInt(runs) || 10, 50));
    return pqcBenchmarkService.runOne(algorithm, n);
  });

  // Get the most recent result from history
  ipcMain.handle('pqc-benchmark-get-latest', async () => {
    return pqcBenchmarkService.getLatest();
  });

  // Get rolling benchmark history
  ipcMain.handle('pqc-benchmark-get-history', async (e, limit) => {
    return pqcBenchmarkService.getHistory(parseInt(limit) || 10);
  });
};
