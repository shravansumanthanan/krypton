// Unit tests for PQCHandshakeService

'use strict';

const { PQCHandshakeService, HandshakeState, PKIResult } = require('../../src/main/pqc-handshake-service');

describe('PQCHandshakeService', () => {
  let svc;
  let mockSessionService;

  beforeEach(() => {
    mockSessionService = {
      ready: true,
      recordSession: jest.fn()
    };
    // Pass a mock DB service
    svc = new PQCHandshakeService(mockSessionService, null);
  });

  test('onNavigationStart() initializes state to RESOLVING_DNS', () => {
    svc.onNavigationStart('example.com');
    const record = svc._activeHandshakes.get('example.com');
    expect(record).toBeDefined();
    expect(record.domain).toBe('example.com');
    expect(record.stateHistory[0]).toContain(HandshakeState.RESOLVING_DNS);
  });

  test('onCertVerified(success=true) completes handshake and records session', () => {
    svc.onNavigationStart('example.com');
    
    const record = svc.onCertVerified('example.com', {
      success: true,
      ocspResult: 'good',
      pqcKem: 'ML-KEM-768'
    });

    expect(record.status).toBe('COMPLETED');
    expect(record.pkiResult).toBe(PKIResult.VERIFIED_EXTERNAL);
    expect(mockSessionService.recordSession).toHaveBeenCalledWith(record);
    // Handshake should be removed from active handshakes
    expect(svc._activeHandshakes.has('example.com')).toBe(false);
  });

  test('onCertVerified(success=false) fails handshake and records session', () => {
    svc.onNavigationStart('fail.com');
    
    const record = svc.onCertVerified('fail.com', {
      success: false,
      pkiResult: PKIResult.FAILED_INVALID_SIG,
      reason: 'Bad signature'
    });

    expect(record.status).toBe('FAILED');
    expect(record.pkiResult).toBe(PKIResult.FAILED_INVALID_SIG);
    expect(mockSessionService.recordSession).toHaveBeenCalledWith(record);
    expect(svc._activeHandshakes.has('fail.com')).toBe(false);
  });

  test('onConnectionTerminated() fails handshake and records session', () => {
    svc.onNavigationStart('timeout.com');
    
    svc.onConnectionTerminated('timeout.com', 'ERR_TIMED_OUT');
    
    expect(mockSessionService.recordSession).toHaveBeenCalled();
    const calledWith = mockSessionService.recordSession.mock.calls[0][0];
    expect(calledWith.status).toBe('FAILED');
    expect(calledWith.pkiResult).toBe(PKIResult.UNKNOWN);
    expect(calledWith.stateHistory[calledWith.stateHistory.length - 1]).toContain('ERR_TIMED_OUT');
    expect(svc._activeHandshakes.has('timeout.com')).toBe(false);
  });
});
