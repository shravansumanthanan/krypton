// Unit tests for PQCCertificateValidator

'use strict';

const PQCCertificateValidator = require('../../src/main/pqc-certificate-validator');

describe('PQCCertificateValidator', () => {
  let validator;

  beforeEach(() => {
    validator = new PQCCertificateValidator();
  });

  test('checkOCSP() resolves good with partial warning when responder is reachable', async () => {
    // Mock the ping to return true
    jest.spyOn(validator, '_pingOCSPResponder').mockResolvedValue(true);

    const result = await validator.checkOCSP('example.com', {
      ocspUrls: ['http://ocsp.example.com'],
    });
    expect(result.result).toBe('good');
    expect(result.warning).toBe(false);
    expect(result.message).toContain('partial check');
  });

  test('checkOCSP() resolves unknown with warning when responder is unreachable (fail-open)', async () => {
    // Mock the ping to return false
    jest.spyOn(validator, '_pingOCSPResponder').mockResolvedValue(false);

    const result = await validator.checkOCSP('example.com', {
      ocspUrls: ['http://ocsp.example.com'],
    });
    expect(result.result).toBe('unknown');
    expect(result.warning).toBe(true);
    expect(result.message).toContain('unreachable (fail-open)');
  });

  test('checkOCSP() resolves unknown with warning when no OCSP URL is found', async () => {
    const result = await validator.checkOCSP('unknown.com', { ocspUrls: [] });
    expect(result.result).toBe('unknown');
    expect(result.warning).toBe(true);
    expect(result.message).toContain('No OCSP responder URL');
  });

  test('checkOCSP() resolves unknown with warning on network error', async () => {
    // Mock the ping to throw
    jest.spyOn(validator, '_pingOCSPResponder').mockRejectedValue(new Error('Network error'));

    const result = await validator.checkOCSP('example.com', {
      ocspUrls: ['http://ocsp.example.com'],
    });
    expect(result.result).toBe('unknown');
    expect(result.warning).toBe(true);
    expect(result.message).toContain('Network error');
  });

  test('resolves OCSP URL from known issuers when ocspUrls is missing', () => {
    expect(validator._resolveOCSPUrl('ex.com', { issuerName: "Let's Encrypt Authority X3" })).toBe(
      'http://r3.o.lencr.org',
    );
    expect(validator._resolveOCSPUrl('ex.com', { issuerName: 'DigiCert SHA2 Secure Server CA' })).toBe(
      'http://ocsp.digicert.com',
    );
    expect(validator._resolveOCSPUrl('ex.com', { issuerName: 'Sectigo RSA Domain Validation' })).toBe(
      'http://ocsp.sectigo.com',
    );
    expect(validator._resolveOCSPUrl('ex.com', { issuerName: 'GlobalSign Extended Validation' })).toBe(
      'http://ocsp2.globalsign.com',
    );
    expect(validator._resolveOCSPUrl('ex.com', { issuerName: 'Unknown Custom Issuer' })).toBeNull();
  });

  test('clears cache and parses URLs safely', async () => {
    validator._cache.set('test.com', { result: 'good', checkedAt: Date.now() });
    const cached = await validator.checkOCSP('test.com');
    expect(cached.result).toBe('good');

    validator.clearCache();
    expect(validator._cache.has('test.com')).toBe(false);

    expect(validator._parseUrl('https://valid.com:8443/ocsp')).not.toBeNull();
    expect(validator._parseUrl('not-a-url')).toBeNull();
  });
});
