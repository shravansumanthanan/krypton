-- Copyright 2025 The ArjunBrowser Authors. All rights reserved.
-- Use of this source code is governed by a BSD-style license that can be
-- found in the LICENSE file.

-- ArjunBrowser PQC Session Database Schema
-- Implements the five-entity ER schema from DA3:
--   USER, BROWSER_SESSION, TLS_HANDSHAKE, DIGITAL_CERTIFICATE, TRUST_STORE
--
-- Database: SQLite via Chromium's sql::Database wrapper
-- Engine: components/pqc_sessions/pqc_session_db.cc

-- ══════════════════════════════════════════════════════════════
-- Entity 1: USERS
-- DA3 ER: USER(User_ID PK, Username, PQC_Preference)
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS users (
    user_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    pqc_preference TEXT NOT NULL DEFAULT 'ML-KEM-768',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ══════════════════════════════════════════════════════════════
-- Entity 2: BROWSER_SESSIONS
-- DA3 ER: BROWSER_SESSION(Session_ID PK, Start_Time, Session_Key)
-- Relationship: USER 1:M BROWSER_SESSION
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS browser_sessions (
    session_id  TEXT PRIMARY KEY,          -- UUID v4
    user_id     INTEGER NOT NULL,
    start_time  DATETIME NOT NULL,
    session_key BLOB,                      -- encrypted AES-256-GCM key blob
    end_time    DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- ══════════════════════════════════════════════════════════════
-- Entity 3: TLS_HANDSHAKES
-- DA3 ER: TLS_HANDSHAKE(Handshake_ID PK, KEM_Algorithm,
--          SIG_Algorithm, Cipher_Suite, Status)
-- Relationship: BROWSER_SESSION 1:1 TLS_HANDSHAKE
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS tls_handshakes (
    handshake_id    TEXT PRIMARY KEY,      -- UUID v4
    session_id      TEXT NOT NULL UNIQUE,
    kem_algorithm   TEXT NOT NULL,         -- "ML-KEM-768"
    sig_algorithm   TEXT NOT NULL,         -- "ML-DSA-65"
    cipher_suite    TEXT NOT NULL,
    handshake_ms    INTEGER,               -- duration in milliseconds
    status          TEXT NOT NULL,         -- COMPLETED | FAILED | IN_PROGRESS
    domain          TEXT,
    ip_address      TEXT,
    port            INTEGER DEFAULT 443,
    pki_result      TEXT,                  -- PKI verification result
    issuing_ca      TEXT,                  -- Name of the verifying CA
    indigenous      INTEGER DEFAULT 0,     -- 1 if Indigenous PKI verified
    hybrid_mode     INTEGER DEFAULT 1,     -- 1 if X25519+ML-KEM-768
    tls_version     TEXT DEFAULT 'TLS 1.3',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES browser_sessions(session_id)
);

-- ══════════════════════════════════════════════════════════════
-- Entity 4: DIGITAL_CERTIFICATES
-- DA3 ER: DIGITAL_CERTIFICATE(Cert_Serial PK, Issuer,
--          Valid_From, Valid_To, Signature)
-- Relationship: TLS_HANDSHAKE M:N DIGITAL_CERTIFICATE
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS digital_certificates (
    cert_serial TEXT PRIMARY KEY,
    issuer      TEXT NOT NULL,
    valid_from  DATETIME NOT NULL,
    valid_to    DATETIME NOT NULL,
    signature   BLOB NOT NULL,             -- Raw signature bytes
    subject_cn  TEXT,
    public_key  BLOB,
    is_pqc      INTEGER DEFAULT 0,         -- 1 if ML-DSA-65
    ocsp_status TEXT DEFAULT 'UNKNOWN',    -- GOOD | REVOKED | UNKNOWN
    algorithm   TEXT                        -- Signature algorithm name
);

-- ══════════════════════════════════════════════════════════════
-- Entity 5: TRUST_STORE
-- DA3 ER: TRUST_STORE(Root_ID PK, CA_Name, Public_Key, Algorithm)
-- Relationship: DIGITAL_CERTIFICATE M:1 TRUST_STORE
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS trust_store (
    root_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_name     TEXT NOT NULL UNIQUE,
    public_key  BLOB NOT NULL,
    algorithm   TEXT NOT NULL,
    organization TEXT,
    country     TEXT DEFAULT 'IN',
    is_indigenous INTEGER DEFAULT 1,       -- 1 = Indian CA, 0 = Foreign
    trusted     INTEGER DEFAULT 1,         -- 1 = trusted, 0 = untrusted
    pqc_capable INTEGER DEFAULT 0,         -- 1 = issues PQC certs
    ocsp_url    TEXT,
    added_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME
);

-- ══════════════════════════════════════════════════════════════
-- Junction table: HANDSHAKE ↔ CERTIFICATE (M:N relationship)
-- Tracks which handshake verified which certificate(s)
-- ══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS handshake_certificates (
    handshake_id TEXT NOT NULL,
    cert_serial  TEXT NOT NULL,
    verified_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (handshake_id, cert_serial),
    FOREIGN KEY (handshake_id) REFERENCES tls_handshakes(handshake_id),
    FOREIGN KEY (cert_serial)  REFERENCES digital_certificates(cert_serial)
);

-- ══════════════════════════════════════════════════════════════
-- Indexes for query performance
-- ══════════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON browser_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_handshakes_domain
    ON tls_handshakes(domain);
CREATE INDEX IF NOT EXISTS idx_handshakes_created
    ON tls_handshakes(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_handshakes_indigenous
    ON tls_handshakes(indigenous);
CREATE INDEX IF NOT EXISTS idx_certs_issuer
    ON digital_certificates(issuer);
CREATE INDEX IF NOT EXISTS idx_trust_store_indigenous
    ON trust_store(is_indigenous);

-- ══════════════════════════════════════════════════════════════
-- Pre-seed Indigenous Root CAs
-- ══════════════════════════════════════════════════════════════
INSERT OR IGNORE INTO trust_store (ca_name, public_key, algorithm,
    organization, country, is_indigenous, trusted, pqc_capable, ocsp_url)
VALUES
    ('NIC Root CA 2025', X'00', 'ML-DSA-65',
     'National Informatics Centre', 'IN', 1, 1, 1,
     'http://ocsp.nic.in'),
    ('CCA India Root CA', X'00', 'RSA-4096',
     'Controller of Certifying Authorities, India', 'IN', 1, 1, 0,
     'http://ocsp.cca.gov.in'),
    ('Indian Army PKI Root', X'00', 'ML-DSA-65',
     'Indian Army Signal Corps', 'IN', 1, 1, 1,
     'http://ocsp.army.mil.in'),
    ('DRDO Internal CA', X'00', 'ML-DSA-65',
     'Defence Research and Development Organisation', 'IN', 1, 1, 1,
     'http://ocsp.drdo.gov.in'),
    ('eMudhra Class 3 CA', X'00', 'RSA-4096',
     'eMudhra Limited', 'IN', 1, 1, 0,
     'http://ocsp.emudhra.com');
