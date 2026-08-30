// KryptonBrowser — PQC Benchmark Service
// Server-side benchmark runner using process.hrtime.bigint() for nanosecond
// precision (avoids renderer-side timer throttling and IPC round-trip noise).
//
// Design:
//  - All crypto work runs inside the main process on the native addon
//  - Results are stored in-memory (capped at 20 runs) and exposed via IPC
//  - Statistical summary: min, max, mean, median, p95, stddev (N=runs per op)
//  - Default: RUNS=20 per operation across all 6 algorithms
//  - Shared secrets are NEVER stored or returned across IPC

'use strict';

const DEFAULT_RUNS = 20;
const MAX_STORED_RESULTS = 20; // rolling window

let _pqcEngine = null;
const _history = []; // rolling array of benchmark runs

/** Nanoseconds → microseconds (2 dp) */
const ns2us = (ns) => (Number(ns) / 1000).toFixed(2);

/** Compute statistics over an array of BigInt ns durations */
function stats(samples) {
  if (!samples || samples.length === 0) return null;
  const nums = samples.map(Number);
  nums.sort((a, b) => a - b);
  const n = nums.length;
  const mean = nums.reduce((s, v) => s + v, 0) / n;
  const variance = nums.reduce((s, v) => s + (v - mean) ** 2, 0) / n;
  const stddev = Math.sqrt(variance);
  const pct = (p) => nums[Math.min(Math.floor(p * n), n - 1)];
  return {
    n,
    min_us: ns2us(nums[0]),
    max_us: ns2us(nums[n - 1]),
    mean_us: ns2us(mean),
    median_us: ns2us(pct(0.5)),
    p95_us: ns2us(pct(0.95)),
    stddev_us: ns2us(stddev),
  };
}

/** Time a synchronous thunk, return BigInt nanoseconds */
function timeNs(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  return process.hrtime.bigint() - t0;
}

/** Run a full KEM benchmark for one algorithm */
function benchKem(algorithm, runs = DEFAULT_RUNS) {
  const keygenSamples = [];
  const encapsSamples = [];
  const decapsSamples = [];

  let lastPk, lastSk, lastCt;

  for (let i = 0; i < runs; i++) {
    // Keygen
    let kp;
    keygenSamples.push(
      timeNs(() => {
        kp = _pqcEngine.kemKeygenAgile(algorithm);
      }),
    );
    lastPk = kp.publicKey;
    lastSk = kp.secretKey;

    // Encapsulate
    let enc;
    encapsSamples.push(
      timeNs(() => {
        enc = _pqcEngine.kemEncapsulateAgile(algorithm, lastPk);
      }),
    );
    lastCt = enc.cipherText;

    // Decapsulate — shared secret discarded immediately
    decapsSamples.push(
      timeNs(() => {
        _pqcEngine.kemDecapsulateAgile(algorithm, lastCt, lastSk);
      }),
    );
  }

  return {
    algorithm,
    type: 'KEM',
    runs,
    keygen: stats(keygenSamples),
    encaps: stats(encapsSamples),
    decaps: stats(decapsSamples),
  };
}

/** Run a full DSA benchmark for one algorithm */
function benchDsa(algorithm, runs = DEFAULT_RUNS) {
  const keygenSamples = [];
  const signSamples = [];
  const verifySamples = [];

  const message = Buffer.from('KryptonBrowser PQC self-test message v1');
  let lastPk, lastSk, lastSig;

  for (let i = 0; i < runs; i++) {
    // Keygen
    let kp;
    keygenSamples.push(
      timeNs(() => {
        kp = _pqcEngine.dsaKeygenAgile(algorithm);
      }),
    );
    lastPk = kp.publicKey;
    lastSk = kp.secretKey;

    // Sign
    let sigObj;
    signSamples.push(
      timeNs(() => {
        sigObj = _pqcEngine.dsaSign(message, lastSk);
      }),
    );
    lastSig = sigObj.signature;

    // Verify
    verifySamples.push(
      timeNs(() => {
        _pqcEngine.dsaVerify(message, lastPk, lastSig);
      }),
    );
  }

  return {
    algorithm,
    type: 'DSA',
    runs,
    keygen: stats(keygenSamples),
    sign: stats(signSamples),
    verify: stats(verifySamples),
  };
}

const PQCBenchmarkService = {
  /**
   * Inject the shared PQCEngine singleton.
   * Called by main.js after pqcEngine.init().
   */
  init(pqcEngine) {
    _pqcEngine = pqcEngine;
  },

  /**
   * Run the full benchmark suite across all 6 algorithms.
   * Returns a structured result object immediately (sync, blocks main thread
   * for the duration — acceptable for an explicit user action).
   *
   * @param {object} [options]
   * @param {number} [options.runs=20]  Number of iterations per operation
   * @returns {BenchmarkResult}
   */
  runAll(options = {}) {
    if (!_pqcEngine)
      throw new Error('BenchmarkService not initialised — call init(pqcEngine) first');

    const runs = Math.max(1, Math.min(options.runs ?? DEFAULT_RUNS, 100));
    const startedAt = Date.now();

    const kemAlgs = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'];
    const dsaAlgs = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];

    const kemResults = kemAlgs.map((alg) => {
      try {
        return benchKem(alg, runs);
      } catch (e) {
        return { algorithm: alg, type: 'KEM', error: e.message };
      }
    });

    const dsaResults = dsaAlgs.map((alg) => {
      try {
        return benchDsa(alg, runs);
      } catch (e) {
        return { algorithm: alg, type: 'DSA', error: e.message };
      }
    });

    const result = {
      id: `bench-${Date.now()}`,
      startedAt,
      durationMs: Date.now() - startedAt,
      runs,
      kem: kemResults,
      dsa: dsaResults,
      // Performance SLA assessment (target: keygen p95 < 5 ms = 5000 µs)
      slaPass:
        kemResults.every((r) => !r.error && parseFloat(r.keygen?.p95_us) < 5000) &&
        dsaResults.every((r) => !r.error && parseFloat(r.keygen?.p95_us) < 5000),
    };

    // Rolling history
    _history.unshift(result);
    if (_history.length > MAX_STORED_RESULTS) _history.pop();

    return result;
  },

  /**
   * Run a quick benchmark of a single algorithm (KEM or DSA).
   */
  runOne(algorithm, runs = 10) {
    if (!_pqcEngine) throw new Error('BenchmarkService not initialised');
    const isKem = algorithm.includes('KEM');
    return isKem ? benchKem(algorithm, runs) : benchDsa(algorithm, runs);
  },

  /** Return the most-recent benchmark result, or null. */
  getLatest() {
    return _history[0] ?? null;
  },

  /** Return rolling history (newest first). */
  getHistory(limit = 10) {
    return _history.slice(0, limit);
  },
};

module.exports = PQCBenchmarkService;
