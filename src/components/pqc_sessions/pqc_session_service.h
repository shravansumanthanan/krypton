// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PQC Session Service — BrowserContextKeyedService for session management.
//
// This service initializes at browser startup and manages all PQC session
// database operations on a dedicated DB sequence (non-blocking UI thread).

#ifndef COMPONENTS_PQC_SESSIONS_PQC_SESSION_SERVICE_H_
#define COMPONENTS_PQC_SESSIONS_PQC_SESSION_SERVICE_H_

#include <memory>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/memory/scoped_refptr.h"
#include "base/sequence_checker.h"
#include "base/task/sequenced_task_runner.h"
#include "components/pqc_sessions/pqc_session_db.h"

namespace pqc_sessions {

// PQCSessionService — Keyed service for PQC session database.
//
// Lifecycle:
//   1. Created by PQCSessionServiceFactory at browser startup
//   2. Opens the SQLite database on the DB sequence
//   3. All database operations are posted to the DB sequence
//   4. Destroyed at browser shutdown
//
// Thread safety:
//   All public methods can be called from any thread. DB operations
//   are internally serialized on the DB sequence.
class PQCSessionService {
public:
  explicit PQCSessionService(const base::FilePath &profile_path);
  ~PQCSessionService();

  // Non-copyable
  PQCSessionService(const PQCSessionService &) = delete;
  PQCSessionService &operator=(const PQCSessionService &) = delete;

  // Initialize the database. Must be called after construction.
  void Initialize();

  // Shutdown the database. Called at browser shutdown.
  void Shutdown();

  // ── Async Operations (posted to DB sequence) ──

  // Record a new TLS handshake result.
  void RecordHandshake(const HandshakeRecord &record);

  // Update a handshake's status.
  void UpdateHandshake(const std::string &handshake_id,
                       const std::string &status, int handshake_ms);

  // Record a certificate seen during a handshake.
  void RecordCertificate(const CertRecord &cert,
                         const std::string &handshake_id);

  // Update OCSP status for a certificate.
  void UpdateCertificateOCSP(const std::string &cert_serial,
                             const std::string &ocsp_status);

  // Create a new browser session.
  void CreateSession(const std::string &session_id,
                     const std::string &username);

  // End a browser session.
  void EndSession(const std::string &session_id);

  // ── Sync Queries ──

  // Get recent handshake records (callback on UI thread).
  using HandshakeCallback =
      base::OnceCallback<void(std::vector<HandshakeRecord>)>;
  void GetRecentHandshakes(int limit, HandshakeCallback callback);

  // Get handshakes by domain.
  void GetHandshakesByDomain(const std::string &domain, int limit,
                             HandshakeCallback callback);

  // Get trust store entries.
  using TrustStoreCallback =
      base::OnceCallback<void(std::vector<TrustStoreRecord>)>;
  void GetTrustStoreEntries(TrustStoreCallback callback);

  // Export handshakes as CSV.
  using CSVCallback = base::OnceCallback<void(std::string)>;
  void ExportCSV(int limit, CSVCallback callback);

  // ── Trust Store Management ──

  void AddTrustEntry(const TrustStoreRecord &entry);
  void SetTrustStatus(const std::string &ca_name, bool trusted);
  void RemoveTrustEntry(const std::string &ca_name);

private:
  // Internal DB operations (run on db_task_runner_)
  void InitializeOnDB();
  void RecordHandshakeOnDB(const HandshakeRecord &record);
  void UpdateHandshakeOnDB(const std::string &handshake_id,
                           const std::string &status, int ms);
  void RecordCertificateOnDB(const CertRecord &cert,
                             const std::string &handshake_id);
  void GetRecentHandshakesOnDB(int limit, HandshakeCallback callback);
  void GetHandshakesByDomainOnDB(const std::string &domain, int limit,
                                 HandshakeCallback callback);

  // Database instance (accessed only on db_task_runner_)
  std::unique_ptr<PQCSessionDB> db_;

  // File path for the database
  base::FilePath db_path_;

  // Task runner for DB operations
  scoped_refptr<base::SequencedTaskRunner> db_task_runner_;

  // Whether the service has been initialized
  bool initialized_ = false;
};

} // namespace pqc_sessions

#endif // COMPONENTS_PQC_SESSIONS_PQC_SESSION_SERVICE_H_
