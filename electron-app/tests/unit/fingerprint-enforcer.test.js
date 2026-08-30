// Unit tests — fingerprint-enforcer.js
// Tests policy enforcement, header injection, and script generation logic.

'use strict';

// Reset the singleton between test suites
let FingerprintEnforcer;

beforeEach(() => {
  // Fresh module for each test group
  delete require.cache[require.resolve('../../src/main/fingerprint-enforcer')];
  FingerprintEnforcer = require('../../src/main/fingerprint-enforcer');
});

describe('FingerprintEnforcer', () => {
  describe('Policy management', () => {
    test('default policy is standard', () => {
      expect(FingerprintEnforcer.getPolicy()).toBe('standard');
    });

    test('setPolicy("strict") returns true and updates policy', () => {
      expect(FingerprintEnforcer.setPolicy('strict')).toBe(true);
      expect(FingerprintEnforcer.getPolicy()).toBe('strict');
    });

    test('setPolicy("off") returns true', () => {
      expect(FingerprintEnforcer.setPolicy('off')).toBe(true);
      expect(FingerprintEnforcer.getPolicy()).toBe('off');
    });

    test('setPolicy("invalid") returns false and does not change policy', () => {
      FingerprintEnforcer.setPolicy('standard');
      const result = FingerprintEnforcer.setPolicy('nuclear');
      expect(result).toBe(false);
      expect(FingerprintEnforcer.getPolicy()).toBe('standard');
    });

    test('setPolicy rejects empty string', () => {
      expect(FingerprintEnforcer.setPolicy('')).toBe(false);
    });
  });

  describe('Header injection', () => {
    test('strict mode adds Permissions-Policy header', () => {
      FingerprintEnforcer.setPolicy('strict');
      const headers = {};
      FingerprintEnforcer.applyHeaders(headers);
      expect(headers['Permissions-Policy']).toBeDefined();
      expect(headers['Permissions-Policy'][0]).toContain('camera=()');
    });

    test('strict mode adds COEP and CORP headers', () => {
      FingerprintEnforcer.setPolicy('strict');
      const headers = {};
      FingerprintEnforcer.applyHeaders(headers);
      expect(headers['Cross-Origin-Embedder-Policy']).toEqual(['require-corp']);
      expect(headers['Cross-Origin-Resource-Policy']).toEqual(['same-origin']);
    });

    test('off mode does NOT add Permissions-Policy', () => {
      FingerprintEnforcer.setPolicy('off');
      const headers = {};
      FingerprintEnforcer.applyHeaders(headers);
      expect(headers['Permissions-Policy']).toBeUndefined();
    });

    test('standard mode strips ETag to prevent tracking', () => {
      FingerprintEnforcer.setPolicy('standard');
      const headers = { etag: ['"abc123"'], ETag: ['"abc123"'] };
      FingerprintEnforcer.applyHeaders(headers);
      expect(headers['etag']).toBeUndefined();
      expect(headers['ETag']).toBeUndefined();
    });

    test('off mode does NOT strip ETag', () => {
      FingerprintEnforcer.setPolicy('off');
      const headers = { etag: ['"abc123"'] };
      FingerprintEnforcer.applyHeaders(headers);
      expect(headers['etag']).toBeDefined();
    });

    test('applyHeaders returns the mutated headers object', () => {
      FingerprintEnforcer.setPolicy('standard');
      const h = {};
      const result = FingerprintEnforcer.applyHeaders(h);
      expect(result).toBe(h);
    });
  });

  describe('Script injection (injectIntoWebContents)', () => {
    function fakeWebContents(policy) {
      const listeners = {};
      return {
        _policy: policy,
        isDestroyed: () => false,
        executeJavaScript: jest.fn().mockResolvedValue(undefined),
        on(event, cb) {
          listeners[event] = cb;
        },
        _trigger(event) {
          if (listeners[event]) listeners[event]();
        },
      };
    }

    test('off mode does not inject any script', () => {
      FingerprintEnforcer.setPolicy('off');
      const wc = fakeWebContents('off');
      FingerprintEnforcer.injectIntoWebContents(wc);
      wc._trigger('did-navigate');
      expect(wc.executeJavaScript).not.toHaveBeenCalled();
    });

    test('standard mode injects noise script on navigate', () => {
      FingerprintEnforcer.setPolicy('standard');
      const wc = fakeWebContents('standard');
      FingerprintEnforcer.injectIntoWebContents(wc);
      wc._trigger('did-navigate');
      expect(wc.executeJavaScript).toHaveBeenCalledTimes(1);
      expect(wc.executeJavaScript.mock.calls[0][0]).toContain('SEED');
    });

    test('strict mode injects blocking script', () => {
      FingerprintEnforcer.setPolicy('strict');
      const wc = fakeWebContents('strict');
      FingerprintEnforcer.injectIntoWebContents(wc);
      wc._trigger('did-navigate');
      expect(wc.executeJavaScript).toHaveBeenCalledTimes(1);
      expect(wc.executeJavaScript.mock.calls[0][0]).toContain('fingerprinting API blocked');
    });

    test('does not inject into destroyed webcontents', () => {
      FingerprintEnforcer.setPolicy('standard');
      const wc = {
        isDestroyed: () => true,
        executeJavaScript: jest.fn(),
        on: jest.fn(),
      };
      FingerprintEnforcer.injectIntoWebContents(wc);
      expect(wc.on).not.toHaveBeenCalled();
    });
  });
});
