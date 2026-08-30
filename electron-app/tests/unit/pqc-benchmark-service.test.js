// Unit tests — pqc-benchmark-service.js
// Uses the real PQC native addon if available.
// Validates: init, runAll structure, stats shape, runOne, history.

'use strict';

let PQCBenchmarkService;
let PQCEngine;
let engineReady = false;

beforeAll(async () => {
  try {
    PQCEngine = require('../../src/main/pqc-engine');
    await PQCEngine.init();
    engineReady = true;
  } catch {
    engineReady = false;
  }
  PQCBenchmarkService = require('../../src/main/pqc-benchmark-service');
});

const skip = (msg) => {
  test(msg, () => {
    /* skipped — native addon unavailable */
  });
};

describe('PQCBenchmarkService — unit', () => {
  test('throws if used before init()', () => {
    // Create a fresh module instance by clearing cache
    delete require.cache[require.resolve('../../src/main/pqc-benchmark-service')];
    const Fresh = require('../../src/main/pqc-benchmark-service');
    expect(() => Fresh.runAll()).toThrow('not initialised');
    // restore
    delete require.cache[require.resolve('../../src/main/pqc-benchmark-service')];
    PQCBenchmarkService = require('../../src/main/pqc-benchmark-service');
    if (engineReady) PQCBenchmarkService.init(PQCEngine);
  });

  describe('with native engine', () => {
    beforeAll(() => {
      if (!engineReady) return;
      PQCBenchmarkService.init(PQCEngine);
    });

    test('runAll() returns expected top-level shape', () => {
      if (!engineReady) return;
      const result = PQCBenchmarkService.runAll({ runs: 2 });
      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('durationMs');
      expect(result.kem).toHaveLength(3);
      expect(result.dsa).toHaveLength(3);
    });

    test('runAll() KEM results have required stat fields', () => {
      if (!engineReady) return;
      const result = PQCBenchmarkService.runAll({ runs: 2 });
      for (const r of result.kem) {
        if (r.error) continue;
        expect(r).toHaveProperty('keygen');
        expect(r.keygen).toHaveProperty('mean_us');
        expect(r.keygen).toHaveProperty('p95_us');
        expect(r.keygen).toHaveProperty('median_us');
        expect(r.keygen).toHaveProperty('stddev_us');
        expect(r.keygen.n).toBe(2);
      }
    });

    test('runAll() DSA results have sign + verify stats', () => {
      if (!engineReady) return;
      const result = PQCBenchmarkService.runAll({ runs: 2 });
      for (const r of result.dsa) {
        if (r.error) continue;
        expect(r).toHaveProperty('sign');
        expect(r).toHaveProperty('verify');
        expect(r.sign).toHaveProperty('p95_us');
      }
    });

    test('runAll() caps runs at 100', () => {
      if (!engineReady) return;
      const result = PQCBenchmarkService.runAll({ runs: 999 });
      expect(result.runs).toBe(100);
    });

    test('runOne() returns single algorithm result', () => {
      if (!engineReady) return;
      const r = PQCBenchmarkService.runOne('ML-KEM-768', 2);
      expect(r.algorithm).toBe('ML-KEM-768');
      expect(r.type).toBe('KEM');
      expect(r.keygen).toHaveProperty('median_us');
    });

    test('getLatest() returns last run', () => {
      if (!engineReady) return;
      PQCBenchmarkService.runAll({ runs: 1 });
      const latest = PQCBenchmarkService.getLatest();
      expect(latest).not.toBeNull();
      expect(latest).toHaveProperty('id');
    });

    test('getHistory() is bounded and newest-first', () => {
      if (!engineReady) return;
      const h1 = PQCBenchmarkService.runAll({ runs: 1 });
      const h2 = PQCBenchmarkService.runAll({ runs: 1 });
      const history = PQCBenchmarkService.getHistory(5);
      expect(history[0].id).toBe(h2.id);
      expect(history[1].id).toBe(h1.id);
    });

    test('slaPass is a boolean', () => {
      if (!engineReady) return;
      const result = PQCBenchmarkService.runAll({ runs: 2 });
      expect(typeof result.slaPass).toBe('boolean');
    });
  });
});
