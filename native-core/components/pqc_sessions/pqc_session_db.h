// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PQC Session Database — SQLite wrapper for the DA3 ER schema.
//
// This wraps Chromium's sql::Database to manage the five-entity
// schema: USER, BROWSER_SESSION, TLS_HANDSHAKE, DIGITAL_CERTIFICATE,
// TRUST_STORE.

#ifndef COMPONENTS_PQC_SESSIONS_PQC_SESSION_DB_H_
#define COMPONENTS_PQC_SESSIONS_PQC_SESSION_DB_H_

#include <memory>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/sequence_checker.h"
#include "sql/database.h"
#include "sql/statement.h"

namespace pqc_sessions {

// Represents a user entry in the users table.
struct UserRecord {
  int64_t user_id = 0;
  std::string username;
  std::string pqc_preference;
};

// Represents a browser session entry.
struct SessionRecord {
  std::string session_id;
  int64_t user_id = 0;
  std::string start_time;
  std::string end_time;
};

// Represents a TLS handshake entry.
struct HandshakeRecord {
  std::string handshake_id;
  std::string session_id;
  std::string kem_algorithm;
  std::string sig_algorithm;
  std::string cipher_suite;
  int handshake_ms = 0;
  std::string status;
  std::string domain;
  std::string ip_address;
  int port = 443;
  std::string pki_result;
  std::string issuing_ca;
  bool indigenous = false;
  bool hybrid_mode = true;
  std::string tls_version;
  std::string created_at;
};

// Represents a certificate entry.
struct CertRecord {
  std::string cert_serial;
  std::string issuer;
  std::string valid_from;
  std::string valid_to;
  std::string subject_cn;
  bool is_pqc = false;
  std::string ocsp_status;
  std::string algorithm;
};

// Represents a trust store entry.
struct TrustStoreRecord {
  int64_t root_id = 0;
  std::string ca_name;
  std::string algorithm;
  std::string organization;
  std::string country;
  bool is_indigenous = true;
  bool trusted = true;
  bool pqc_capable = false;
  std::string ocsp_url;
};

// ─── PQCSessionDB ──────────────────────────────────────────

class PQCSessionDB {
public:
  PQCSessionDB();
  ~PQCSessionDB();

  // Open or create the database at the given path.
  bool Open(const base::FilePath &db_path);

  // Close the database.
  void Close();

  // Check if the database is open and valid.
  bool IsOpen() const;

  // ── USER operations ──
  bool InsertUser(const UserRecord &user);
  bool GetUser(int64_t user_id, UserRecord *out);
  bool GetUserByName(const std::string &username, UserRecord *out);
  int64_t GetOrCreateUser(const std::string &username);

  // ── BROWSER_SESSION operations ──
  bool InsertSession(const SessionRecord &session);
  bool EndSession(const std::string &session_id, const std::string &end_time);
  bool GetSession(const std::string &session_id, SessionRecord *out);

  // ── TLS_HANDSHAKE operations ──
  bool InsertHandshake(const HandshakeRecord &record);
  bool UpdateHandshakeStatus(const std::string &handshake_id,
                             const std::string &status, int handshake_ms);
  std::vector<HandshakeRecord> GetRecentHandshakes(int limit = 50);
  std::vector<HandshakeRecord> GetHandshakesByDomain(const std::string &domain,
                                                     int limit = 50);
  std::vector<HandshakeRecord> GetIndigenousHandshakes(int limit = 50);

  // ── DIGITAL_CERTIFICATE operations ──
  bool InsertCertificate(const CertRecord &cert);
  bool GetCertificate(const std::string &serial, CertRecord *out);
  bool UpdateOCSPStatus(const std::string &serial, const std::string &status);
  bool LinkHandshakeCertificate(const std::string &handshake_id,
                                const std::string &cert_serial);

  // ── TRUST_STORE operations ──
  bool InsertTrustEntry(const TrustStoreRecord &entry);
  std::vector<TrustStoreRecord> GetAllTrustEntries();
  std::vector<TrustStoreRecord> GetIndigenousCAs();
  bool SetTrustStatus(const std::string &ca_name, bool trusted);
  bool DeleteTrustEntry(const std::string &ca_name);

  // ── Export ──
  std::string ExportHandshakesCSV(int limit = 1000);

private:
  // Initialize the database schema (create tables if needed).
  bool InitSchema();

  // Check and migrate schema version.
  bool MigrateSchema();

  sql::Database db_;

  SEQUENCE_CHECKER(sequence_checker_);
};

} // namespace pqc_sessions

#endif // COMPONENTS_PQC_SESSIONS_PQC_SESSION_DB_H_
