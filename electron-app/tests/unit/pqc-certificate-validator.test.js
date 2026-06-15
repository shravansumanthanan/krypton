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

    const result = await validator.checkOCSP('example.com', { ocspUrls: ['http://ocsp.example.com'] });
    expect(result.result).toBe('good');
    expect(result.warning).toBe(false);
    expect(result.message).toContain('partial check');
  });

  test('checkOCSP() resolves unknown with warning when responder is unreachable (fail-open)', async () => {
    // Mock the ping to return false
    jest.spyOn(validator, '_pingOCSPResponder').mockResolvedValue(false);

    const result = await validator.checkOCSP('example.com', { ocspUrls: ['http://ocsp.example.com'] });
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

    const result = await validator.checkOCSP('example.com', { ocspUrls: ['http://ocsp.example.com'] });
    expect(result.result).toBe('unknown');
    expect(result.warning).toBe(true);
    expect(result.message).toContain('Network error');
  });
});
