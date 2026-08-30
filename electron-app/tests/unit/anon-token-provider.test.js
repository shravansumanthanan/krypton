// Unit tests — anon-token-provider.js
// Tests the ML-DSA-65 token issuance and redemption logic.
// Uses real PQCEngine when available; gracefully skips if native addon is absent.

'use strict';

let AnonTokenProvider;
let PQCEngine;
let engineReady = false;

// Minimal in-memory mock for PQCSessionService token methods
function mockSessionService() {
  const tokens = new Map(); // nonce → { signature, redeemed }
  return {
    ready: true,
    issueToken({ nonce, signature }) {
      tokens.set(nonce, { signature, redeemed: false });
    },
    redeemToken(nonce) {
      const t = tokens.get(nonce);
      if (!t || t.redeemed) return false;
      t.redeemed = true;
      return true;
    },
    getTokenCount() {
      return [...tokens.values()].filter((t) => !t.redeemed).length;
    },
  };
}

beforeAll(async () => {
  try {
    PQCEngine = require('../../src/main/pqc-engine');
    await PQCEngine.init();
    engineReady = true;
  } catch {
    engineReady = false;
  }
  // Force a fresh singleton for isolated tests
  delete require.cache[require.resolve('../../src/main/anon-token-provider')];
  AnonTokenProvider = require('../../src/main/anon-token-provider');
});

describe('AnonTokenProvider', () => {
  test('ready is false before init()', () => {
    expect(AnonTokenProvider.ready).toBe(false);
  });

  test('issueToken() returns error when not ready', () => {
    const result = AnonTokenProvider.issueToken('sess-xyz');
    expect(result).toHaveProperty('error');
  });

  describe('after init with native engine', () => {
    let svc;

    beforeAll(() => {
      if (!engineReady) return;
      svc = mockSessionService();
      AnonTokenProvider.init(PQCEngine, svc);
    });

    test('ready is true after init()', () => {
      if (!engineReady) return;
      expect(AnonTokenProvider.ready).toBe(true);
    });

    test('issueToken() returns nonce, signature, issuedAt', () => {
      if (!engineReady) return;
      const result = AnonTokenProvider.issueToken('test-session-id-001');
      expect(result).not.toHaveProperty('error');
      expect(result).toHaveProperty('nonce');
      expect(result).toHaveProperty('signature');
      expect(result).toHaveProperty('issuedAt');
      expect(result.nonce).toMatch(/^[0-9a-f]{64}$/); // 32 bytes hex
    });

    test('issueToken() does NOT expose sessionId', () => {
      if (!engineReady) return;
      const sessionId = 'super-secret-session';
      const result = AnonTokenProvider.issueToken(sessionId);
      expect(JSON.stringify(result)).not.toContain(sessionId);
    });

    test('two tokens for same session have different nonces (randomness)', () => {
      if (!engineReady) return;
      const a = AnonTokenProvider.issueToken('same-session');
      const b = AnonTokenProvider.issueToken('same-session');
      expect(a.nonce).not.toBe(b.nonce);
    });

    test('redeemToken() succeeds for valid token', () => {
      if (!engineReady) return;
      const sessId = 'redeem-test-session';
      const { nonce, signature } = AnonTokenProvider.issueToken(sessId);
      const result = AnonTokenProvider.redeemToken(nonce, signature, sessId);
      expect(result.valid).toBe(true);
    });

    test('redeemToken() fails for wrong sessionId (commitment mismatch)', () => {
      if (!engineReady) return;
      const { nonce, signature } = AnonTokenProvider.issueToken('real-session');
      const result = AnonTokenProvider.redeemToken(nonce, signature, 'wrong-session');
      expect(result.valid).toBe(false);
    });

    test('redeemToken() prevents replay (second redeem returns false)', () => {
      if (!engineReady) return;
      const sessId = 'anti-replay-session';
      const { nonce, signature } = AnonTokenProvider.issueToken(sessId);
      AnonTokenProvider.redeemToken(nonce, signature, sessId);
      const second = AnonTokenProvider.redeemToken(nonce, signature, sessId);
      expect(second.valid).toBe(false);
    });

    test('getTokenCount() decrements after redeem', () => {
      if (!engineReady) return;
      const freshSvc = mockSessionService();
      AnonTokenProvider.init(PQCEngine, freshSvc);
      AnonTokenProvider.issueToken('cnt-session-1');
      AnonTokenProvider.issueToken('cnt-session-2');
      expect(AnonTokenProvider.getTokenCount()).toBe(2);
      const { nonce, signature } = AnonTokenProvider.issueToken('cnt-session-3');
      AnonTokenProvider.redeemToken(nonce, signature, 'cnt-session-3');
      expect(AnonTokenProvider.getTokenCount()).toBe(2);
    });

    test('issueToken() rejects empty sessionId', () => {
      if (!engineReady) return;
      const result = AnonTokenProvider.issueToken('');
      expect(result).toHaveProperty('error');
    });
  });
});
