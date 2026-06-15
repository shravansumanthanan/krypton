// KryptonBrowser — PQC Session Persistence Service
// Wraps better-sqlite3 for durable PQC handshake session storage.
//
// CRITICAL: The DB lives in persistentDataPath (app.getPath('appData')/KryptonBrowser/),
// NOT in burnerTempDir. This is intentional — session history survives the
// ephemeral burner session and is NOT wiped by the panic button.
//
// Schema mirrors native-core/net/pqc/pqc_session_record.h

'use strict';

const path = require('path');

// Schema constants — keep in sync with PQCSessionRecord fields
const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS pqc_sessions (
    handshake_id        TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    domain              TEXT,
    port                INTEGER DEFAULT 443,
    kem_algorithm       TEXT DEFAULT 'ML-KEM-768',
    sig_algorithm       TEXT DEFAULT 'ML-DSA-65',
    cipher_suite        TEXT DEFAULT 'TLS_ML_KEM_768_X25519_AES256GCM_SHA384',
    handshake_ms        INTEGER DEFAULT 0,
    status              TEXT DEFAULT 'COMPLETED',
    pki_result          TEXT DEFAULT 'PENDING',
    issuing_ca          TEXT,
    indigenous_verified INTEGER DEFAULT 0,
    hybrid_mode         INTEGER DEFAULT 1,
    tls_version         TEXT DEFAULT 'TLS 1.3',
    created_at          INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_pqc_domain   ON pqc_sessions(domain);
  CREATE INDEX IF NOT EXISTS idx_pqc_created  ON pqc_sessions(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_pqc_status   ON pqc_sessions(status);
`;

const INSERT_SESSION_SQL = `
  INSERT OR REPLACE INTO pqc_sessions (
    handshake_id, session_id, domain, port,
    kem_algorithm, sig_algorithm, cipher_suite,
    handshake_ms, status, pki_result, issuing_ca,
    indigenous_verified, hybrid_mode, tls_version, created_at
  ) VALUES (
    @handshake_id, @session_id, @domain, @port,
    @kem_algorithm, @sig_algorithm, @cipher_suite,
    @handshake_ms, @status, @pki_result, @issuing_ca,
    @indigenous_verified, @hybrid_mode, @tls_version, @created_at
  )
`;

const GET_RECENT_SQL = `
  SELECT * FROM pqc_sessions
  ORDER BY created_at DESC
  LIMIT @limit
`;

const GET_STATS_SQL = `
  SELECT
    COUNT(*) as total,
    SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as completed,
    SUM(CASE WHEN status = 'FAILED'    THEN 1 ELSE 0 END) as failed,
    SUM(CASE WHEN indigenous_verified = 1 THEN 1 ELSE 0 END) as indigenous,
    AVG(handshake_ms) as avg_handshake_ms
  FROM pqc_sessions
`;

const PRUNE_OLD_SQL = `
  DELETE FROM pqc_sessions
  WHERE handshake_id NOT IN (
    SELECT handshake_id FROM pqc_sessions ORDER BY created_at DESC LIMIT 2000
  )
`;

class PQCSessionService {
  /**
   * @param {string} dbPath - Absolute path to the SQLite database file.
   *                          Must be in persistentDataPath, NOT in burnerTempDir.
   */
  constructor(dbPath) {
    this._dbPath = dbPath;
    this._db = null;
    this._stmtInsert = null;
    this._stmtGetRecent = null;
    this._stmtGetStats = null;
    this._ready = false;
  }

  /**
   * Open or create the database. Must be called once before any other method.
   * @returns {boolean} true if successfully initialized
   */
  init() {
    try {
      // better-sqlite3 is a production dependency that must be installed
      const Database = require('better-sqlite3');
      this._db = new Database(this._dbPath, {
        verbose: null, // disable query logging in production
        fileMustExist: false,
      });

      // Performance tuning — WAL mode for concurrent reads
      this._db.pragma('journal_mode = WAL');
      this._db.pragma('synchronous = NORMAL');
      this._db.pragma('foreign_keys = ON');

      // Create schema
      this._db.exec(CREATE_TABLE_SQL);

      // Pre-compile statements
      this._stmtInsert = this._db.prepare(INSERT_SESSION_SQL);
      this._stmtGetRecent = this._db.prepare(GET_RECENT_SQL);
      this._stmtGetStats = this._db.prepare(GET_STATS_SQL);
      this._stmtPrune = this._db.prepare(PRUNE_OLD_SQL);

      this._ready = true;
      return true;
    } catch (err) {
      console.error('[PQCSessionService] Failed to initialize SQLite DB:', err.message);
      this._ready = false;
      return false;
    }
  }

  get ready() {
    return this._ready;
  }

  /**
   * Record a completed handshake session to the database.
   * Fields mirror PQCSessionRecord from native-core.
   *
   * @param {Object} record
   * @param {string}  record.handshakeId     - UUID v4 (from pqcEngine or addon)
   * @param {string}  record.sessionId       - Browser session identifier
   * @param {string}  record.domain          - Target domain (e.g. "example.com")
   * @param {number}  [record.port=443]
   * @param {string}  [record.kemAlgorithm='ML-KEM-768']
   * @param {string}  [record.sigAlgorithm='ML-DSA-65']
   * @param {string}  [record.cipherSuite]
   * @param {number}  [record.handshakeMs=0] - Duration in milliseconds
   * @param {string}  [record.status='COMPLETED'] - COMPLETED | FAILED | IN_PROGRESS
   * @param {string}  [record.pkiResult='PENDING']
   * @param {string}  [record.issuingCa]
   * @param {boolean} [record.indigenousVerified=false]
   * @param {boolean} [record.hybridMode=true]
   * @param {string}  [record.tlsVersion='TLS 1.3']
   * @param {number}  [record.createdAt=Date.now()]
   */
  recordSession(record) {
    if (!this._ready) return false;
    try {
      this._stmtInsert.run({
        handshake_id: record.handshakeId || this._uuid(),
        session_id: record.sessionId || 'unknown',
        domain: record.domain || null,
        port: record.port ?? 443,
        kem_algorithm: record.kemAlgorithm || 'ML-KEM-768',
        sig_algorithm: record.sigAlgorithm || 'ML-DSA-65',
        cipher_suite: record.cipherSuite || 'TLS_ML_KEM_768_X25519_AES256GCM_SHA384',
        handshake_ms: record.handshakeMs ?? 0,
        status: record.status || 'COMPLETED',
        pki_result: record.pkiResult || 'PENDING',
        issuing_ca: record.issuingCa || null,
        indigenous_verified: record.indigenousVerified ? 1 : 0,
        hybrid_mode: record.hybridMode !== false ? 1 : 0,
        tls_version: record.tlsVersion || 'TLS 1.3',
        created_at: record.createdAt || Date.now(),
      });

      // Prune old records periodically (every 100 inserts)
      this._insertCount = (this._insertCount || 0) + 1;
      if (this._insertCount % 100 === 0) {
        this._stmtPrune.run();
      }

      return true;
    } catch (err) {
      console.error('[PQCSessionService] recordSession error:', err.message);
      return false;
    }
  }

  /**
   * Retrieve the N most recent session records, newest first.
   * Returns an array of plain objects matching the renderer's expected shape.
   *
   * @param {number} [limit=50]
   * @returns {Object[]}
   */
  getRecentSessions(limit = 50) {
    if (!this._ready) return [];
    try {
      const rows = this._stmtGetRecent.all({ limit });
      // Transform DB column names → camelCase for JS consumers
      return rows.map((r) => ({
        handshakeId: r.handshake_id,
        sessionId: r.session_id,
        domain: r.domain || '—',
        port: r.port,
        kem: r.kem_algorithm,
        sig: r.sig_algorithm,
        cipherSuite: r.cipher_suite,
        ms: r.handshake_ms,
        status: r.status,
        pkiResult: r.pki_result,
        issuingCa: r.issuing_ca || '—',
        indigenousVerified: r.indigenous_verified === 1,
        hybridMode: r.hybrid_mode === 1,
        tlsVersion: r.tls_version,
        // Format time field for UI compatibility with the old in-memory log
        time: new Date(r.created_at).toISOString().replace('T', ' ').slice(0, 19),
        // Backward-compat aliases used by browser-chrome.js PQC panel
        ca: r.issuing_ca || '—',
        pki: r.indigenous_verified ? 'INDIGENOUS' : 'STANDARD',
      }));
    } catch (err) {
      console.error('[PQCSessionService] getRecentSessions error:', err.message);
      return [];
    }
  }

  /**
   * Retrieve the most recent session record for a specific domain.
   *
   * @param {string} domain - Target domain (e.g. "example.com")
   * @returns {Object|null}
   */
  getSessionByDomain(domain) {
    if (!this._ready || !domain) return null;
    try {
      if (!this._stmtGetByDomain) {
        this._stmtGetByDomain = this._db.prepare(`
          SELECT * FROM pqc_sessions
          WHERE domain = @domain OR domain = @domain2
          ORDER BY created_at DESC
          LIMIT 1
        `);
      }

      // Allow exact match or match with www. prefix removed/added just in case
      let domain2 = domain;
      if (domain.startsWith('www.')) domain2 = domain.slice(4);
      else domain2 = 'www.' + domain;

      const r = this._stmtGetByDomain.get({ domain, domain2 });
      if (!r) return null;

      return {
        handshakeId: r.handshake_id,
        sessionId: r.session_id,
        domain: r.domain || '—',
        port: r.port,
        kem: r.kem_algorithm,
        sig: r.sig_algorithm,
        cipherSuite: r.cipher_suite,
        ms: r.handshake_ms,
        status: r.status,
        pkiResult: r.pki_result,
        issuingCa: r.issuing_ca || '—',
        indigenousVerified: r.indigenous_verified === 1,
        hybridMode: r.hybrid_mode === 1,
        tlsVersion: r.tls_version,
        time: new Date(r.created_at).toISOString().replace('T', ' ').slice(0, 19),
        ca: r.issuing_ca || '—',
        pki: r.indigenous_verified ? 'INDIGENOUS' : 'STANDARD',
      };
    } catch (err) {
      console.error('[PQCSessionService] getSessionByDomain error:', err.message);
      return null;
    }
  }

  /**
   * Returns aggregate statistics for the security panel.
   * @returns {{ total, completed, failed, indigenous, avgHandshakeMs }}
   */
  getStats() {
    if (!this._ready)
      return { total: 0, completed: 0, failed: 0, indigenous: 0, avgHandshakeMs: 0 };
    try {
      const row = this._stmtGetStats.get();
      return {
        total: row.total || 0,
        completed: row.completed || 0,
        failed: row.failed || 0,
        indigenous: row.indigenous || 0,
        avgHandshakeMs: Math.round(row.avg_handshake_ms || 0),
      };
    } catch (err) {
      console.error('[PQCSessionService] getStats error:', err.message);
      return { total: 0, completed: 0, failed: 0, indigenous: 0, avgHandshakeMs: 0 };
    }
  }

  /**
   * Gracefully close the database connection.
   * Must be called in app before-quit handler.
   */
  close() {
    if (this._db && this._ready) {
      try {
        this._db.close();
      } catch {
        /* ignore */
      }
      this._ready = false;
      this._db = null;
    }
  }

  // ── Internal ───────────────────────────────────────────────
  _uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }
}

module.exports = PQCSessionService;
