// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pqc_sessions/pqc_session_db.h"

#include <sstream>

#include "base/files/file_util.h"
#include "base/logging.h"
#include "components/pqc_sessions/db/schema_version.h"
#include "sql/statement.h"
#include "sql/transaction.h"

namespace pqc_sessions {

PQCSessionDB::PQCSessionDB() { DETACH_FROM_SEQUENCE(sequence_checker_); }

PQCSessionDB::~PQCSessionDB() { Close(); }

bool PQCSessionDB::Open(const base::FilePath &db_path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (db_.is_open()) {
    return true;
  }

  // Ensure the directory exists
  base::FilePath dir = db_path.DirName();
  if (!base::CreateDirectory(dir)) {
    LOG(ERROR) << "PQCSessionDB: Failed to create directory: " << dir;
    return false;
  }

  if (!db_.Open(db_path)) {
    LOG(ERROR) << "PQCSessionDB: Failed to open database: " << db_path;
    return false;
  }

  // Enable WAL mode for better concurrent access
  db_.Execute("PRAGMA journal_mode=WAL");
  db_.Execute("PRAGMA foreign_keys=ON");

  if (!InitSchema()) {
    LOG(ERROR) << "PQCSessionDB: Schema initialization failed.";
    db_.Close();
    return false;
  }

  LOG(INFO) << "PQCSessionDB: Opened at " << db_path;
  return true;
}

void PQCSessionDB::Close() {
  if (db_.is_open()) {
    db_.Close();
  }
}

bool PQCSessionDB::IsOpen() const { return db_.is_open(); }

bool PQCSessionDB::InitSchema() {
  sql::Transaction transaction(&db_);
  if (!transaction.Begin())
    return false;

  // Create all tables
  const char *create_tables[] = {
      "CREATE TABLE IF NOT EXISTS users ("
      "  user_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  username TEXT NOT NULL UNIQUE,"
      "  pqc_preference TEXT NOT NULL DEFAULT 'ML-KEM-768',"
      "  created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
      ")",

      "CREATE TABLE IF NOT EXISTS browser_sessions ("
      "  session_id TEXT PRIMARY KEY,"
      "  user_id INTEGER NOT NULL,"
      "  start_time DATETIME NOT NULL,"
      "  session_key BLOB,"
      "  end_time DATETIME,"
      "  FOREIGN KEY (user_id) REFERENCES users(user_id)"
      ")",

      "CREATE TABLE IF NOT EXISTS tls_handshakes ("
      "  handshake_id TEXT PRIMARY KEY,"
      "  session_id TEXT NOT NULL UNIQUE,"
      "  kem_algorithm TEXT NOT NULL,"
      "  sig_algorithm TEXT NOT NULL,"
      "  cipher_suite TEXT NOT NULL,"
      "  handshake_ms INTEGER,"
      "  status TEXT NOT NULL,"
      "  domain TEXT,"
      "  ip_address TEXT,"
      "  port INTEGER DEFAULT 443,"
      "  pki_result TEXT,"
      "  issuing_ca TEXT,"
      "  indigenous INTEGER DEFAULT 0,"
      "  hybrid_mode INTEGER DEFAULT 1,"
      "  tls_version TEXT DEFAULT 'TLS 1.3',"
      "  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
      "  FOREIGN KEY (session_id) REFERENCES browser_sessions(session_id)"
      ")",

      "CREATE TABLE IF NOT EXISTS digital_certificates ("
      "  cert_serial TEXT PRIMARY KEY,"
      "  issuer TEXT NOT NULL,"
      "  valid_from DATETIME NOT NULL,"
      "  valid_to DATETIME NOT NULL,"
      "  signature BLOB NOT NULL,"
      "  subject_cn TEXT,"
      "  public_key BLOB,"
      "  is_pqc INTEGER DEFAULT 0,"
      "  ocsp_status TEXT DEFAULT 'UNKNOWN',"
      "  algorithm TEXT"
      ")",

      "CREATE TABLE IF NOT EXISTS trust_store ("
      "  root_id INTEGER PRIMARY KEY AUTOINCREMENT,"
      "  ca_name TEXT NOT NULL UNIQUE,"
      "  public_key BLOB NOT NULL,"
      "  algorithm TEXT NOT NULL,"
      "  organization TEXT,"
      "  country TEXT DEFAULT 'IN',"
      "  is_indigenous INTEGER DEFAULT 1,"
      "  trusted INTEGER DEFAULT 1,"
      "  pqc_capable INTEGER DEFAULT 0,"
      "  ocsp_url TEXT,"
      "  added_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
      "  expires_at DATETIME"
      ")",

      "CREATE TABLE IF NOT EXISTS handshake_certificates ("
      "  handshake_id TEXT NOT NULL,"
      "  cert_serial TEXT NOT NULL,"
      "  verified_at DATETIME DEFAULT CURRENT_TIMESTAMP,"
      "  PRIMARY KEY (handshake_id, cert_serial),"
      "  FOREIGN KEY (handshake_id) REFERENCES tls_handshakes(handshake_id),"
      "  FOREIGN KEY (cert_serial) REFERENCES digital_certificates(cert_serial)"
      ")",
  };

  for (const char *sql : create_tables) {
    if (!db_.Execute(sql)) {
      return false;
    }
  }

  // Create indexes
  db_.Execute("CREATE INDEX IF NOT EXISTS idx_sessions_user "
              "ON browser_sessions(user_id)");
  db_.Execute("CREATE INDEX IF NOT EXISTS idx_handshakes_domain "
              "ON tls_handshakes(domain)");
  db_.Execute("CREATE INDEX IF NOT EXISTS idx_handshakes_created "
              "ON tls_handshakes(created_at DESC)");
  db_.Execute("CREATE INDEX IF NOT EXISTS idx_handshakes_indigenous "
              "ON tls_handshakes(indigenous)");

  return transaction.Commit();
}

// ── USER Operations ─────────────────────────────────────────

bool PQCSessionDB::InsertUser(const UserRecord &user) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "INSERT INTO users (username, pqc_preference) VALUES (?, ?)"));
  stmt.BindString(0, user.username);
  stmt.BindString(1, user.pqc_preference);
  return stmt.Run();
}

bool PQCSessionDB::GetUser(int64_t user_id, UserRecord *out) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "SELECT user_id, username, pqc_preference FROM users "
      "WHERE user_id = ?"));
  stmt.BindInt64(0, user_id);
  if (!stmt.Step())
    return false;
  out->user_id = stmt.ColumnInt64(0);
  out->username = stmt.ColumnString(1);
  out->pqc_preference = stmt.ColumnString(2);
  return true;
}

bool PQCSessionDB::GetUserByName(const std::string &username, UserRecord *out) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "SELECT user_id, username, pqc_preference FROM users "
      "WHERE username = ?"));
  stmt.BindString(0, username);
  if (!stmt.Step())
    return false;
  out->user_id = stmt.ColumnInt64(0);
  out->username = stmt.ColumnString(1);
  out->pqc_preference = stmt.ColumnString(2);
  return true;
}

int64_t PQCSessionDB::GetOrCreateUser(const std::string &username) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  UserRecord user;
  if (GetUserByName(username, &user)) {
    return user.user_id;
  }
  UserRecord new_user;
  new_user.username = username;
  new_user.pqc_preference = "ML-KEM-768";
  if (!InsertUser(new_user))
    return -1;
  return db_.GetLastInsertRowId();
}

// ── BROWSER_SESSION Operations ──────────────────────────────

bool PQCSessionDB::InsertSession(const SessionRecord &session) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "INSERT INTO browser_sessions (session_id, user_id, start_time) "
      "VALUES (?, ?, ?)"));
  stmt.BindString(0, session.session_id);
  stmt.BindInt64(1, session.user_id);
  stmt.BindString(2, session.start_time);
  return stmt.Run();
}

bool PQCSessionDB::EndSession(const std::string &session_id,
                              const std::string &end_time) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "UPDATE browser_sessions SET end_time = ? WHERE session_id = ?"));
  stmt.BindString(0, end_time);
  stmt.BindString(1, session_id);
  return stmt.Run();
}

// ── TLS_HANDSHAKE Operations ────────────────────────────────

bool PQCSessionDB::InsertHandshake(const HandshakeRecord &record) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "INSERT INTO tls_handshakes "
      "(handshake_id, session_id, kem_algorithm, sig_algorithm, "
      " cipher_suite, handshake_ms, status, domain, ip_address, "
      " port, pki_result, issuing_ca, indigenous, hybrid_mode, "
      " tls_version) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"));
  stmt.BindString(0, record.handshake_id);
  stmt.BindString(1, record.session_id);
  stmt.BindString(2, record.kem_algorithm);
  stmt.BindString(3, record.sig_algorithm);
  stmt.BindString(4, record.cipher_suite);
  stmt.BindInt(5, record.handshake_ms);
  stmt.BindString(6, record.status);
  stmt.BindString(7, record.domain);
  stmt.BindString(8, record.ip_address);
  stmt.BindInt(9, record.port);
  stmt.BindString(10, record.pki_result);
  stmt.BindString(11, record.issuing_ca);
  stmt.BindBool(12, record.indigenous);
  stmt.BindBool(13, record.hybrid_mode);
  stmt.BindString(14, record.tls_version);
  return stmt.Run();
}

bool PQCSessionDB::UpdateHandshakeStatus(const std::string &handshake_id,
                                         const std::string &status,
                                         int handshake_ms) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "UPDATE tls_handshakes SET status = ?, handshake_ms = ? "
      "WHERE handshake_id = ?"));
  stmt.BindString(0, status);
  stmt.BindInt(1, handshake_ms);
  stmt.BindString(2, handshake_id);
  return stmt.Run();
}

std::vector<HandshakeRecord> PQCSessionDB::GetRecentHandshakes(int limit) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  std::vector<HandshakeRecord> results;
  sql::Statement stmt(db_.GetUniqueStatement(
      "SELECT handshake_id, session_id, kem_algorithm, sig_algorithm, "
      "cipher_suite, handshake_ms, status, domain, ip_address, port, "
      "pki_result, issuing_ca, indigenous, hybrid_mode, tls_version, "
      "created_at FROM tls_handshakes ORDER BY created_at DESC LIMIT ?"));
  stmt.BindInt(0, limit);
  while (stmt.Step()) {
    HandshakeRecord r;
    r.handshake_id = stmt.ColumnString(0);
    r.session_id = stmt.ColumnString(1);
    r.kem_algorithm = stmt.ColumnString(2);
    r.sig_algorithm = stmt.ColumnString(3);
    r.cipher_suite = stmt.ColumnString(4);
    r.handshake_ms = stmt.ColumnInt(5);
    r.status = stmt.ColumnString(6);
    r.domain = stmt.ColumnString(7);
    r.ip_address = stmt.ColumnString(8);
    r.port = stmt.ColumnInt(9);
    r.pki_result = stmt.ColumnString(10);
    r.issuing_ca = stmt.ColumnString(11);
    r.indigenous = stmt.ColumnBool(12);
    r.hybrid_mode = stmt.ColumnBool(13);
    r.tls_version = stmt.ColumnString(14);
    r.created_at = stmt.ColumnString(15);
    results.push_back(std::move(r));
  }
  return results;
}

std::vector<HandshakeRecord>
PQCSessionDB::GetHandshakesByDomain(const std::string &domain, int limit) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  std::vector<HandshakeRecord> results;
  sql::Statement stmt(db_.GetUniqueStatement(
      "SELECT handshake_id, session_id, kem_algorithm, sig_algorithm, "
      "cipher_suite, handshake_ms, status, domain, ip_address, port, "
      "pki_result, issuing_ca, indigenous, hybrid_mode, tls_version, "
      "created_at FROM tls_handshakes WHERE domain = ? "
      "ORDER BY created_at DESC LIMIT ?"));
  stmt.BindString(0, domain);
  stmt.BindInt(1, limit);
  while (stmt.Step()) {
    HandshakeRecord r;
    r.handshake_id = stmt.ColumnString(0);
    r.session_id = stmt.ColumnString(1);
    r.kem_algorithm = stmt.ColumnString(2);
    r.sig_algorithm = stmt.ColumnString(3);
    r.cipher_suite = stmt.ColumnString(4);
    r.handshake_ms = stmt.ColumnInt(5);
    r.status = stmt.ColumnString(6);
    r.domain = stmt.ColumnString(7);
    r.ip_address = stmt.ColumnString(8);
    r.port = stmt.ColumnInt(9);
    r.pki_result = stmt.ColumnString(10);
    r.issuing_ca = stmt.ColumnString(11);
    r.indigenous = stmt.ColumnBool(12);
    r.hybrid_mode = stmt.ColumnBool(13);
    r.tls_version = stmt.ColumnString(14);
    r.created_at = stmt.ColumnString(15);
    results.push_back(std::move(r));
  }
  return results;
}

std::vector<HandshakeRecord> PQCSessionDB::GetIndigenousHandshakes(int limit) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  std::vector<HandshakeRecord> results;
  sql::Statement stmt(db_.GetUniqueStatement(
      "SELECT handshake_id, session_id, kem_algorithm, sig_algorithm, "
      "cipher_suite, handshake_ms, status, domain, ip_address, port, "
      "pki_result, issuing_ca, indigenous, hybrid_mode, tls_version, "
      "created_at FROM tls_handshakes WHERE indigenous = 1 "
      "ORDER BY created_at DESC LIMIT ?"));
  stmt.BindInt(0, limit);
  while (stmt.Step()) {
    HandshakeRecord r;
    r.handshake_id = stmt.ColumnString(0);
    r.session_id = stmt.ColumnString(1);
    r.kem_algorithm = stmt.ColumnString(2);
    r.sig_algorithm = stmt.ColumnString(3);
    r.cipher_suite = stmt.ColumnString(4);
    r.handshake_ms = stmt.ColumnInt(5);
    r.status = stmt.ColumnString(6);
    r.domain = stmt.ColumnString(7);
    r.ip_address = stmt.ColumnString(8);
    r.port = stmt.ColumnInt(9);
    r.pki_result = stmt.ColumnString(10);
    r.issuing_ca = stmt.ColumnString(11);
    r.indigenous = stmt.ColumnBool(12);
    r.hybrid_mode = stmt.ColumnBool(13);
    r.tls_version = stmt.ColumnString(14);
    r.created_at = stmt.ColumnString(15);
    results.push_back(std::move(r));
  }
  return results;
}

// ── DIGITAL_CERTIFICATE Operations ──────────────────────────

bool PQCSessionDB::InsertCertificate(const CertRecord &cert) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "INSERT OR REPLACE INTO digital_certificates "
      "(cert_serial, issuer, valid_from, valid_to, signature, "
      " subject_cn, is_pqc, ocsp_status, algorithm) "
      "VALUES (?,?,?,?,X'00',?,?,?,?)"));
  stmt.BindString(0, cert.cert_serial);
  stmt.BindString(1, cert.issuer);
  stmt.BindString(2, cert.valid_from);
  stmt.BindString(3, cert.valid_to);
  stmt.BindString(4, cert.subject_cn);
  stmt.BindBool(5, cert.is_pqc);
  stmt.BindString(6, cert.ocsp_status);
  stmt.BindString(7, cert.algorithm);
  return stmt.Run();
}

bool PQCSessionDB::GetCertificate(const std::string &serial, CertRecord *out) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "SELECT cert_serial, issuer, valid_from, valid_to, subject_cn, "
      "is_pqc, ocsp_status, algorithm FROM digital_certificates "
      "WHERE cert_serial = ?"));
  stmt.BindString(0, serial);
  if (!stmt.Step())
    return false;
  out->cert_serial = stmt.ColumnString(0);
  out->issuer = stmt.ColumnString(1);
  out->valid_from = stmt.ColumnString(2);
  out->valid_to = stmt.ColumnString(3);
  out->subject_cn = stmt.ColumnString(4);
  out->is_pqc = stmt.ColumnBool(5);
  out->ocsp_status = stmt.ColumnString(6);
  out->algorithm = stmt.ColumnString(7);
  return true;
}

bool PQCSessionDB::UpdateOCSPStatus(const std::string &serial,
                                    const std::string &status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(
      db_.GetUniqueStatement("UPDATE digital_certificates SET ocsp_status = ? "
                             "WHERE cert_serial = ?"));
  stmt.BindString(0, status);
  stmt.BindString(1, serial);
  return stmt.Run();
}

bool PQCSessionDB::LinkHandshakeCertificate(const std::string &handshake_id,
                                            const std::string &cert_serial) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(
      db_.GetUniqueStatement("INSERT OR IGNORE INTO handshake_certificates "
                             "(handshake_id, cert_serial) VALUES (?, ?)"));
  stmt.BindString(0, handshake_id);
  stmt.BindString(1, cert_serial);
  return stmt.Run();
}

// ── TRUST_STORE Operations ──────────────────────────────────

bool PQCSessionDB::InsertTrustEntry(const TrustStoreRecord &entry) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "INSERT OR REPLACE INTO trust_store "
      "(ca_name, public_key, algorithm, organization, country, "
      " is_indigenous, trusted, pqc_capable, ocsp_url) "
      "VALUES (?, X'00', ?, ?, ?, ?, ?, ?, ?)"));
  stmt.BindString(0, entry.ca_name);
  stmt.BindString(1, entry.algorithm);
  stmt.BindString(2, entry.organization);
  stmt.BindString(3, entry.country);
  stmt.BindBool(4, entry.is_indigenous);
  stmt.BindBool(5, entry.trusted);
  stmt.BindBool(6, entry.pqc_capable);
  stmt.BindString(7, entry.ocsp_url);
  return stmt.Run();
}

std::vector<TrustStoreRecord> PQCSessionDB::GetAllTrustEntries() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  std::vector<TrustStoreRecord> results;
  sql::Statement stmt(db_.GetUniqueStatement(
      "SELECT root_id, ca_name, algorithm, organization, country, "
      "is_indigenous, trusted, pqc_capable, ocsp_url "
      "FROM trust_store ORDER BY ca_name"));
  while (stmt.Step()) {
    TrustStoreRecord r;
    r.root_id = stmt.ColumnInt64(0);
    r.ca_name = stmt.ColumnString(1);
    r.algorithm = stmt.ColumnString(2);
    r.organization = stmt.ColumnString(3);
    r.country = stmt.ColumnString(4);
    r.is_indigenous = stmt.ColumnBool(5);
    r.trusted = stmt.ColumnBool(6);
    r.pqc_capable = stmt.ColumnBool(7);
    r.ocsp_url = stmt.ColumnString(8);
    results.push_back(std::move(r));
  }
  return results;
}

std::vector<TrustStoreRecord> PQCSessionDB::GetIndigenousCAs() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  std::vector<TrustStoreRecord> results;
  sql::Statement stmt(db_.GetUniqueStatement(
      "SELECT root_id, ca_name, algorithm, organization, country, "
      "is_indigenous, trusted, pqc_capable, ocsp_url "
      "FROM trust_store WHERE is_indigenous = 1 ORDER BY ca_name"));
  while (stmt.Step()) {
    TrustStoreRecord r;
    r.root_id = stmt.ColumnInt64(0);
    r.ca_name = stmt.ColumnString(1);
    r.algorithm = stmt.ColumnString(2);
    r.organization = stmt.ColumnString(3);
    r.country = stmt.ColumnString(4);
    r.is_indigenous = stmt.ColumnBool(5);
    r.trusted = stmt.ColumnBool(6);
    r.pqc_capable = stmt.ColumnBool(7);
    r.ocsp_url = stmt.ColumnString(8);
    results.push_back(std::move(r));
  }
  return results;
}

bool PQCSessionDB::SetTrustStatus(const std::string &ca_name, bool trusted) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "UPDATE trust_store SET trusted = ? WHERE ca_name = ?"));
  stmt.BindBool(0, trusted);
  stmt.BindString(1, ca_name);
  return stmt.Run();
}

bool PQCSessionDB::DeleteTrustEntry(const std::string &ca_name) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  sql::Statement stmt(db_.GetUniqueStatement(
      "DELETE FROM trust_store WHERE ca_name = ? AND is_indigenous = 0"));
  stmt.BindString(0, ca_name);
  return stmt.Run();
}

// ── Export ───────────────────────────────────────────────────

std::string PQCSessionDB::ExportHandshakesCSV(int limit) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  std::ostringstream csv;
  csv << "handshake_id,session_id,domain,kem_algorithm,sig_algorithm,"
      << "cipher_suite,handshake_ms,status,pki_result,issuing_ca,"
      << "indigenous,hybrid_mode,tls_version,created_at\n";

  auto records = GetRecentHandshakes(limit);
  for (const auto &r : records) {
    csv << r.handshake_id << "," << r.session_id << "," << r.domain << ","
        << r.kem_algorithm << "," << r.sig_algorithm << "," << r.cipher_suite
        << "," << r.handshake_ms << "," << r.status << "," << r.pki_result
        << "," << r.issuing_ca << "," << (r.indigenous ? "1" : "0") << ","
        << (r.hybrid_mode ? "1" : "0") << "," << r.tls_version << ","
        << r.created_at << "\n";
  }
  return csv.str();
}

bool PQCSessionDB::MigrateSchema() {
  // Future: handle schema upgrades when kCurrentSchemaVersion > 1
  return true;
}

} // namespace pqc_sessions
