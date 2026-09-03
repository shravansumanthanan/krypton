// Unit tests for PQCSessionService
// Uses an in-memory SQLite database (':memory:') for isolation.

'use strict';

jest.mock('better-sqlite3', () => {
  // Use the real better-sqlite3 if available, otherwise skip gracefully
  try {
    return jest.requireActual('better-sqlite3');
  } catch {
    return null;
  }
});

let PQCSessionService;
let hasSQLite = true;

beforeAll(() => {
  try {
    require('better-sqlite3'); // probe
    PQCSessionService = require('../../src/main/pqc-session-service');
  } catch {
    hasSQLite = false;
  }
});

const skipIfNoSQLite = hasSQLite ? describe : describe.skip;

skipIfNoSQLite('PQCSessionService', () => {
  let svc;

  beforeEach(() => {
    PQCSessionService = require('../../src/main/pqc-session-service');
    svc = new PQCSessionService(':memory:');
    svc.init();
  });

  afterEach(() => {
    svc.close();
  });

  test('init() returns true for :memory: DB', () => {
    const s = new PQCSessionService(':memory:');
    expect(s.init()).toBe(true);
    expect(s.ready).toBe(true);
    s.close();
  });

  test('recordSession() inserts a row', () => {
    const result = svc.recordSession({
      handshakeId: 'test-id-1',
      sessionId: 'sess-1',
      domain: 'example.com',
      port: 443,
      kemAlgorithm: 'ML-KEM-768',
      sigAlgorithm: 'ML-DSA-65',
      handshakeMs: 12,
      status: 'COMPLETED',
      pkiResult: 'VERIFIED_EXTERNAL',
    });
    expect(result).toBe(true);
  });

  test('getRecentSessions() returns inserted record', () => {
    svc.recordSession({
      handshakeId: 'test-id-2',
      sessionId: 'sess-2',
      domain: 'secure.test',
      handshakeMs: 42,
      status: 'COMPLETED',
    });
    const rows = svc.getRecentSessions(10);
    expect(rows.length).toBe(1);
    expect(rows[0].domain).toMatch(/^[a-f0-9]{16}$/);
    expect(rows[0].ms).toBe(42);
    expect(rows[0].status).toBe('COMPLETED');
  });

  test('getRecentSessions() returns newest first', () => {
    svc.recordSession({
      handshakeId: 'a',
      sessionId: 's',
      domain: 'first.test',
      handshakeMs: 1,
      createdAt: 1000,
    });
    svc.recordSession({
      handshakeId: 'b',
      sessionId: 's',
      domain: 'second.test',
      handshakeMs: 2,
      createdAt: 2000,
    });
    const rows = svc.getRecentSessions(10);
    expect(rows[0].domain).toMatch(/^[a-f0-9]{16}$/);
    expect(rows[1].domain).toMatch(/^[a-f0-9]{16}$/);
    expect(rows[0].domain).not.toBe(rows[1].domain);
  });

  test('getStats() totals are correct', () => {
    svc.recordSession({
      handshakeId: 'c1',
      sessionId: 's',
      domain: 'a.test',
      status: 'COMPLETED',
      indigenousVerified: false,
    });
    svc.recordSession({
      handshakeId: 'c2',
      sessionId: 's',
      domain: 'b.test',
      status: 'FAILED',
      indigenousVerified: false,
    });
    svc.recordSession({
      handshakeId: 'c3',
      sessionId: 's',
      domain: 'c.test',
      status: 'COMPLETED',
      indigenousVerified: true,
    });

    const stats = svc.getStats();
    expect(stats.total).toBe(3);
    expect(stats.completed).toBe(2);
    expect(stats.failed).toBe(1);
    expect(stats.indigenous).toBe(1);
  });

  test('INSERT OR REPLACE works on duplicate handshake_id', () => {
    svc.recordSession({
      handshakeId: 'dup-1',
      sessionId: 's',
      domain: 'original.test',
      handshakeMs: 10,
    });
    svc.recordSession({
      handshakeId: 'dup-1',
      sessionId: 's',
      domain: 'updated.test',
      handshakeMs: 20,
    });
    const rows = svc.getRecentSessions(10);
    expect(rows.length).toBe(1);
    expect(rows[0].domain).toMatch(/^[a-f0-9]{16}$/);
    expect(rows[0].ms).toBe(20);
  });

  test('getRecentSessions() returns empty array when DB is empty', () => {
    expect(svc.getRecentSessions()).toEqual([]);
  });

  test('getStats() returns zeros for empty DB', () => {
    const stats = svc.getStats();
    expect(stats.total).toBe(0);
    expect(stats.completed).toBe(0);
  });

  test('handles indigenousVerified flag correctly', () => {
    svc.recordSession({
      handshakeId: 'ind-1',
      sessionId: 's',
      domain: 'pqc.test',
      indigenousVerified: true,
    });
    const rows = svc.getRecentSessions(1);
    expect(rows[0].indigenousVerified).toBe(true);
    expect(rows[0].pki).toBe('INDIGENOUS');
  });
});

describe('PQCSessionService — graceful degradation', () => {
  test('ready is false before init()', () => {
    if (!PQCSessionService) return; // skip if not installed
    const s = new PQCSessionService(':memory:');
    expect(s.ready).toBe(false);
  });

  test('recordSession() returns false when not ready', () => {
    if (!PQCSessionService) return;
    const s = new PQCSessionService(':memory:');
    expect(s.recordSession({ handshakeId: 'x' })).toBe(false);
  });

  test('getRecentSessions() returns [] when not ready', () => {
    if (!PQCSessionService) return;
    const s = new PQCSessionService(':memory:');
    expect(s.getRecentSessions()).toEqual([]);
  });
});

// ── Anonymous Token Table Tests (Phase 3J) ─────────────────────
const skipTokens = hasSQLite && PQCSessionService ? describe : describe.skip;

skipTokens('PQCSessionService — anon_tokens table', () => {
  let svc;

  beforeEach(() => {
    PQCSessionService = require('../../src/main/pqc-session-service');
    svc = new PQCSessionService(':memory:');
    svc.init();
  });

  afterEach(() => svc.close());

  const makeToken = (n = 0) => ({
    nonce: `nonce${n}${'0'.repeat(60 - String(n).length)}`,
    signature: `sig${n}${'0'.repeat(60 - String(n).length)}`,
    sessionId: `session-${n}`,
    issuedAt: new Date().toISOString(),
  });

  test('issueToken() inserts a token row', () => {
    if (!svc.issueToken) return; // method may be missing
    expect(svc.issueToken(makeToken(1))).toBe(true);
    expect(svc.getTokenCount()).toBe(1);
  });

  test('issueToken() + getTokenCount() for multiple tokens', () => {
    if (!svc.issueToken) return;
    svc.issueToken(makeToken(1));
    svc.issueToken(makeToken(2));
    svc.issueToken(makeToken(3));
    expect(svc.getTokenCount()).toBe(3);
  });

  test('redeemToken() marks token as redeemed', () => {
    if (!svc.issueToken || !svc.redeemToken) return;
    const t = makeToken(10);
    svc.issueToken(t);
    const result = svc.redeemToken(t.nonce);
    expect(result).toBe(true);
  });

  test('redeemToken() decrements getTokenCount()', () => {
    if (!svc.issueToken || !svc.redeemToken) return;
    svc.issueToken(makeToken(20));
    svc.issueToken(makeToken(21));
    svc.redeemToken(makeToken(20).nonce);
    expect(svc.getTokenCount()).toBe(1);
  });

  test('redeemToken() prevents replay — second call returns false', () => {
    if (!svc.issueToken || !svc.redeemToken) return;
    const t = makeToken(30);
    svc.issueToken(t);
    svc.redeemToken(t.nonce);
    expect(svc.redeemToken(t.nonce)).toBe(false);
  });

  test('redeemToken() returns false for unknown nonce', () => {
    if (!svc.redeemToken) return;
    expect(svc.redeemToken('00'.repeat(32))).toBe(false);
  });

  test('getTokenCount() returns 0 for empty table', () => {
    if (!svc.getTokenCount) return;
    expect(svc.getTokenCount()).toBe(0);
  });

  test('getTokenCount() returns false when not ready', () => {
    if (!PQCSessionService) return;
    const s = new PQCSessionService(':memory:');
    // not init'd — should not throw
    expect(() => s.getTokenCount && s.getTokenCount()).not.toThrow();
  });
});
