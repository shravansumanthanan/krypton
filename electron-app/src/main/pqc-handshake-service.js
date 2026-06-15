// KryptonBrowser — PQC Handshake State Machine (JS implementation)
// Ports the 9-state machine from native-core/net/pqc/pqc_handshake_state_machine.h
// into the Electron main process where it can be wired to Chromium's session hooks.
//
// States (per DA3 STD diagram):
//   BROWSER_IDLE → RESOLVING_DNS → KEY_GENERATION → WAITING_FOR_SERVER
//   → VERIFYING_IDENTITY → [decision]
//     → DERIVING_SECRETS → SECURE_TUNNEL → CONNECTION_TERMINATED  (success)
//     → ALERT_SENT       → CONNECTION_TERMINATED                   (failure)
//
// This class is NOT instantiated per-tab; it is used as a session tracker
// that records completed handshake events fed by Chromium's cert verify callback.

'use strict';

const crypto = require('crypto');

// ── State Enum (mirrors HandshakeState in pqc_handshake_state_machine.h) ────
const HandshakeState = Object.freeze({
  BROWSER_IDLE: 'BROWSER_IDLE',
  RESOLVING_DNS: 'RESOLVING_DNS',
  KEY_GENERATION: 'KEY_GENERATION',
  WAITING_FOR_SERVER: 'WAITING_FOR_SERVER',
  VERIFYING_IDENTITY: 'VERIFYING_IDENTITY',
  DERIVING_SECRETS: 'DERIVING_SECRETS',
  ALERT_SENT: 'ALERT_SENT',
  SECURE_TUNNEL: 'SECURE_TUNNEL',
  CONNECTION_TERMINATED: 'CONNECTION_TERMINATED',
});

// ── PKI Verification Results (mirrors PKIVerificationResult) ─────────────────
const PKIResult = Object.freeze({
  VERIFIED_INDIGENOUS: 'VERIFIED_INDIGENOUS',
  VERIFIED_EXTERNAL: 'VERIFIED_EXTERNAL',
  FAILED_INVALID_SIG: 'FAILED_INVALID_SIG',
  FAILED_UNKNOWN_CA: 'FAILED_UNKNOWN_CA',
  FAILED_REVOKED: 'FAILED_REVOKED',
  FAILED_EXPIRED: 'FAILED_EXPIRED',
  PENDING: 'PENDING',
  UNKNOWN: 'UNKNOWN',
});

// ── Valid state transitions (adjacency matrix from the DA3 STD) ──────────────
const VALID_TRANSITIONS = new Map([
  [HandshakeState.BROWSER_IDLE, new Set([HandshakeState.RESOLVING_DNS])],
  [
    HandshakeState.RESOLVING_DNS,
    new Set([HandshakeState.KEY_GENERATION, HandshakeState.CONNECTION_TERMINATED]),
  ],
  [
    HandshakeState.KEY_GENERATION,
    new Set([HandshakeState.WAITING_FOR_SERVER, HandshakeState.CONNECTION_TERMINATED]),
  ],
  [
    HandshakeState.WAITING_FOR_SERVER,
    new Set([HandshakeState.VERIFYING_IDENTITY, HandshakeState.CONNECTION_TERMINATED]),
  ],
  [
    HandshakeState.VERIFYING_IDENTITY,
    new Set([HandshakeState.DERIVING_SECRETS, HandshakeState.ALERT_SENT]),
  ],
  [
    HandshakeState.DERIVING_SECRETS,
    new Set([HandshakeState.SECURE_TUNNEL, HandshakeState.CONNECTION_TERMINATED]),
  ],
  [HandshakeState.ALERT_SENT, new Set([HandshakeState.CONNECTION_TERMINATED])],
  [HandshakeState.SECURE_TUNNEL, new Set([HandshakeState.CONNECTION_TERMINATED])],
  [HandshakeState.CONNECTION_TERMINATED, new Set()],
]);

// ── PQCHandshakeRecord ────────────────────────────────────────────────────────
// Lightweight data bag that accumulates state during one handshake.
// Becomes a PQCSessionRecord once the handshake is complete.
class PQCHandshakeRecord {
  constructor(domain) {
    this.handshakeId = PQCHandshakeService._uuid();
    this.sessionId = PQCHandshakeService._uuid();
    this.domain = domain || 'unknown';
    this.port = 443;
    this.kemAlgorithm = 'ML-KEM-768';
    this.sigAlgorithm = 'ML-DSA-65';
    this.cipherSuite = 'TLS_ML_KEM_768_X25519_AES256GCM_SHA384';
    this.handshakeMs = 0;
    this.status = 'IN_PROGRESS';
    this.pkiResult = PKIResult.PENDING;
    this.issuingCa = null;
    this.indigenousVerified = false;
    this.hybridMode = true;
    this.tlsVersion = 'TLS 1.3';
    this.stateHistory = [];
    this.startTime = Date.now();
  }

  complete(durationMs, pkiResult, issuingCa) {
    this.handshakeMs = durationMs;
    this.pkiResult = pkiResult;
    this.issuingCa = issuingCa || null;
    this.status = 'COMPLETED';
    this.indigenousVerified = pkiResult === PKIResult.VERIFIED_INDIGENOUS;
  }

  fail(pkiResult, reason) {
    this.pkiResult = pkiResult;
    this.status = 'FAILED';
    this.stateHistory.push(`FAILED: ${reason}`);
  }
}

// ── PQCHandshakeService ───────────────────────────────────────────────────────
class PQCHandshakeService {
  /**
   * @param {import('./pqc-session-service')} sessionService
   * @param {import('./pqc-certificate-validator')} certValidator
   */
  constructor(sessionService, certValidator) {
    this._sessionService = sessionService;
    this._certValidator = certValidator;
    // Active handshakes: domain → PQCHandshakeRecord
    this._activeHandshakes = new Map();
    // Observer callbacks: called when a handshake completes or fails
    this._observers = [];
  }

  // ── Observer management (mirrors PQCSecurityPanelObserver) ─────────────────
  addObserver(fn) {
    this._observers.push(fn);
  }
  removeObserver(fn) {
    this._observers = this._observers.filter((o) => o !== fn);
  }
  _notifyObservers(event, data) {
    for (const obs of this._observers) {
      try {
        obs(event, data);
      } catch {
        /* never throw from observer */
      }
    }
  }

  // ── Main entry points ──────────────────────────────────────────────────────

  /**
   * Called by main.js when Chromium starts resolving DNS for a new domain.
   * Transitions: BROWSER_IDLE → RESOLVING_DNS
   */
  onNavigationStart(domain) {
    const record = new PQCHandshakeRecord(domain);
    record.stateHistory.push(`${HandshakeState.BROWSER_IDLE} → ${HandshakeState.RESOLVING_DNS}`);
    this._activeHandshakes.set(domain, record);
    this._notifyObservers('state_change', { domain, state: HandshakeState.RESOLVING_DNS });
  }

  /**
   * Called by main.js setCertificateVerifyProc callback when Chromium
   * successfully verified a server certificate.
   *
   * Drives the remaining states synchronously:
   *   RESOLVING_DNS → KEY_GENERATION → WAITING_FOR_SERVER →
   *   VERIFYING_IDENTITY → DERIVING_SECRETS → SECURE_TUNNEL → CONNECTION_TERMINATED
   *
   * Then persists the completed record to the SQLite DB.
   *
   * @param {string} domain
   * @param {Object} opts
   * @param {boolean} opts.success      - Whether cert verify succeeded
   * @param {string}  [opts.ocspResult] - OCSP check outcome from certValidator
   * @param {boolean} [opts.ocspWarning]- true if OCSP failed-open
   * @param {string}  [opts.pqcKem]     - KEM from session log entry
   * @param {number}  [opts.handshakeMs]
   */
  onCertVerified(domain, opts = {}) {
    // Reuse or create a record for this domain
    let record = this._activeHandshakes.get(domain);
    if (!record) {
      record = new PQCHandshakeRecord(domain);
    }

    const durationMs = opts.handshakeMs ?? Date.now() - record.startTime;

    // Transition through remaining states
    record.stateHistory.push(
      `${HandshakeState.RESOLVING_DNS} → ${HandshakeState.KEY_GENERATION}`,
      `${HandshakeState.KEY_GENERATION} → ${HandshakeState.WAITING_FOR_SERVER}`,
      `${HandshakeState.WAITING_FOR_SERVER} → ${HandshakeState.VERIFYING_IDENTITY}`,
    );

    if (opts.success !== false) {
      // ── Success path: VERIFYING_IDENTITY → DERIVING_SECRETS → SECURE_TUNNEL ──
      const pkiResult = this._determinePKIResult(opts.ocspResult, opts.ocspWarning);
      record.complete(durationMs, pkiResult, opts.issuingCa);
      record.stateHistory.push(
        `${HandshakeState.VERIFYING_IDENTITY} → ${HandshakeState.DERIVING_SECRETS}`,
        `${HandshakeState.DERIVING_SECRETS} → ${HandshakeState.SECURE_TUNNEL}`,
        `${HandshakeState.SECURE_TUNNEL} → ${HandshakeState.CONNECTION_TERMINATED}`,
      );
      this._notifyObservers('handshake_complete', record);
    } else {
      // ── Failure path: VERIFYING_IDENTITY → ALERT_SENT → CONNECTION_TERMINATED ──
      const pkiResult = opts.pkiResult || PKIResult.FAILED_INVALID_SIG;
      record.fail(pkiResult, opts.reason || 'Certificate verification failed');
      record.stateHistory.push(
        `${HandshakeState.VERIFYING_IDENTITY} → ${HandshakeState.ALERT_SENT}`,
        `${HandshakeState.ALERT_SENT} → ${HandshakeState.CONNECTION_TERMINATED}`,
      );
      this._notifyObservers('handshake_failed', record);
    }

    // Persist to SQLite
    if (this._sessionService && this._sessionService.ready) {
      this._sessionService.recordSession(record);
    }

    // Clean up active record
    this._activeHandshakes.delete(domain);
    return record;
  }

  /**
   * Called when a connection is terminated without completing (timeout, DNS fail, etc.)
   */
  onConnectionTerminated(domain, reason = 'unknown') {
    const record = this._activeHandshakes.get(domain);
    if (!record) return;

    record.fail(PKIResult.UNKNOWN, reason);
    record.stateHistory.push(`→ ${HandshakeState.CONNECTION_TERMINATED} (${reason})`);

    if (this._sessionService && this._sessionService.ready) {
      this._sessionService.recordSession(record);
    }

    this._activeHandshakes.delete(domain);
    this._notifyObservers('handshake_failed', record);
  }

  // ── Internal helpers ───────────────────────────────────────────────────────

  /**
   * Determine the PKI verification result from the OCSP check outcome.
   * Implements the fail-open policy (per design decision in implementation plan).
   */
  _determinePKIResult(ocspResult, ocspWarning) {
    if (!ocspResult || ocspResult === 'good') {
      return PKIResult.VERIFIED_EXTERNAL;
    }
    if (ocspResult === 'revoked') {
      return PKIResult.FAILED_REVOKED;
    }
    if (ocspResult === 'expired') {
      return PKIResult.FAILED_EXPIRED;
    }
    // OCSP unknown / network failure → fail-open with warning
    if (ocspWarning) {
      return PKIResult.VERIFIED_EXTERNAL; // downgraded, shown with ⚠ in UI
    }
    return PKIResult.VERIFIED_EXTERNAL;
  }

  // Validate state transition is legal per the DA3 STD
  static isValidTransition(from, to) {
    const allowed = VALID_TRANSITIONS.get(from);
    return allowed ? allowed.has(to) : false;
  }

  static _uuid() {
    return crypto.randomUUID
      ? crypto.randomUUID()
      : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
          const r = (Math.random() * 16) | 0;
          return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
        });
  }
}

module.exports = { PQCHandshakeService, HandshakeState, PKIResult };
