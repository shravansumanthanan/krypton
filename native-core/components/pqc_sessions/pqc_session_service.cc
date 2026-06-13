// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/pqc_sessions/pqc_session_service.h"

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "components/pqc_sessions/db/schema_version.h"

namespace pqc_sessions {

PQCSessionService::PQCSessionService(const base::FilePath &profile_path)
    : db_(std::make_unique<PQCSessionDB>()),
      db_path_(profile_path.AppendASCII(kDatabaseFileName)),
      db_task_runner_(base::ThreadPool::CreateSequencedTaskRunner(
          {base::MayBlock(), base::TaskPriority::USER_VISIBLE,
           base::TaskShutdownBehavior::BLOCK_SHUTDOWN})) {}

PQCSessionService::~PQCSessionService() { Shutdown(); }

void PQCSessionService::Initialize() {
  if (initialized_)
    return;
  db_task_runner_->PostTask(FROM_HERE,
                            base::BindOnce(&PQCSessionService::InitializeOnDB,
                                           base::Unretained(this)));
  initialized_ = true;
}

void PQCSessionService::Shutdown() {
  if (!initialized_)
    return;
  db_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce([](PQCSessionDB *db) { db->Close(); }, db_.get()));
  initialized_ = false;
}

void PQCSessionService::InitializeOnDB() {
  if (!db_->Open(db_path_)) {
    LOG(ERROR) << "PQCSessionService: Failed to open DB at " << db_path_;
    return;
  }
  LOG(INFO) << "PQCSessionService: Database initialized at " << db_path_;
}

// ── Async Write Operations ──────────────────────────────────

void PQCSessionService::RecordHandshake(const HandshakeRecord &record) {
  db_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&PQCSessionService::RecordHandshakeOnDB,
                                base::Unretained(this), record));
}

void PQCSessionService::RecordHandshakeOnDB(const HandshakeRecord &record) {
  if (!db_->IsOpen())
    return;
  if (!db_->InsertHandshake(record)) {
    LOG(ERROR) << "PQCSessionService: Failed to insert handshake "
               << record.handshake_id;
  }
}

void PQCSessionService::UpdateHandshake(const std::string &handshake_id,
                                        const std::string &status,
                                        int handshake_ms) {
  db_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&PQCSessionService::UpdateHandshakeOnDB,
                                base::Unretained(this), handshake_id, status,
                                handshake_ms));
}

void PQCSessionService::UpdateHandshakeOnDB(const std::string &handshake_id,
                                            const std::string &status, int ms) {
  if (!db_->IsOpen())
    return;
  db_->UpdateHandshakeStatus(handshake_id, status, ms);
}

void PQCSessionService::RecordCertificate(const CertRecord &cert,
                                          const std::string &handshake_id) {
  db_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&PQCSessionService::RecordCertificateOnDB,
                                base::Unretained(this), cert, handshake_id));
}

void PQCSessionService::RecordCertificateOnDB(const CertRecord &cert,
                                              const std::string &handshake_id) {
  if (!db_->IsOpen())
    return;
  db_->InsertCertificate(cert);
  db_->LinkHandshakeCertificate(handshake_id, cert.cert_serial);
}

void PQCSessionService::UpdateCertificateOCSP(const std::string &cert_serial,
                                              const std::string &ocsp_status) {
  db_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](PQCSessionDB *db, std::string serial, std::string status) {
            if (db->IsOpen())
              db->UpdateOCSPStatus(serial, status);
          },
          db_.get(), cert_serial, ocsp_status));
}

void PQCSessionService::CreateSession(const std::string &session_id,
                                      const std::string &username) {
  db_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(
                     [](PQCSessionDB *db, std::string sid, std::string uname) {
                       if (!db->IsOpen())
                         return;
                       int64_t user_id = db->GetOrCreateUser(uname);
                       if (user_id < 0)
                         return;
                       SessionRecord session;
                       session.session_id = sid;
                       session.user_id = user_id;
                       session.start_time = "CURRENT_TIMESTAMP";
                       db->InsertSession(session);
                     },
                     db_.get(), session_id, username));
}

void PQCSessionService::EndSession(const std::string &session_id) {
  db_task_runner_->PostTask(FROM_HERE,
                            base::BindOnce(
                                [](PQCSessionDB *db, std::string sid) {
                                  if (db->IsOpen())
                                    db->EndSession(sid, "CURRENT_TIMESTAMP");
                                },
                                db_.get(), session_id));
}

// ── Async Read Operations ───────────────────────────────────

void PQCSessionService::GetRecentHandshakes(int limit,
                                            HandshakeCallback callback) {
  db_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&PQCSessionService::GetRecentHandshakesOnDB,
                     base::Unretained(this), limit, std::move(callback)));
}

void PQCSessionService::GetRecentHandshakesOnDB(int limit,
                                                HandshakeCallback callback) {
  auto records = db_->GetRecentHandshakes(limit);
  std::move(callback).Run(std::move(records));
}

void PQCSessionService::GetHandshakesByDomain(const std::string &domain,
                                              int limit,
                                              HandshakeCallback callback) {
  db_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&PQCSessionService::GetHandshakesByDomainOnDB,
                                base::Unretained(this), domain, limit,
                                std::move(callback)));
}

void PQCSessionService::GetHandshakesByDomainOnDB(const std::string &domain,
                                                  int limit,
                                                  HandshakeCallback callback) {
  auto records = db_->GetHandshakesByDomain(domain, limit);
  std::move(callback).Run(std::move(records));
}

void PQCSessionService::GetTrustStoreEntries(TrustStoreCallback callback) {
  db_task_runner_->PostTask(FROM_HERE,
                            base::BindOnce(
                                [](PQCSessionDB *db, TrustStoreCallback cb) {
                                  auto entries = db->GetAllTrustEntries();
                                  std::move(cb).Run(std::move(entries));
                                },
                                db_.get(), std::move(callback)));
}

void PQCSessionService::ExportCSV(int limit, CSVCallback callback) {
  db_task_runner_->PostTask(FROM_HERE,
                            base::BindOnce(
                                [](PQCSessionDB *db, int lim, CSVCallback cb) {
                                  auto csv = db->ExportHandshakesCSV(lim);
                                  std::move(cb).Run(std::move(csv));
                                },
                                db_.get(), limit, std::move(callback)));
}

// ── Trust Store Management ──────────────────────────────────

void PQCSessionService::AddTrustEntry(const TrustStoreRecord &entry) {
  db_task_runner_->PostTask(FROM_HERE,
                            base::BindOnce(
                                [](PQCSessionDB *db, TrustStoreRecord e) {
                                  if (db->IsOpen())
                                    db->InsertTrustEntry(e);
                                },
                                db_.get(), entry));
}

void PQCSessionService::SetTrustStatus(const std::string &ca_name,
                                       bool trusted) {
  db_task_runner_->PostTask(FROM_HERE,
                            base::BindOnce(
                                [](PQCSessionDB *db, std::string name, bool t) {
                                  if (db->IsOpen())
                                    db->SetTrustStatus(name, t);
                                },
                                db_.get(), ca_name, trusted));
}

void PQCSessionService::RemoveTrustEntry(const std::string &ca_name) {
  db_task_runner_->PostTask(FROM_HERE,
                            base::BindOnce(
                                [](PQCSessionDB *db, std::string name) {
                                  if (db->IsOpen())
                                    db->DeleteTrustEntry(name);
                                },
                                db_.get(), ca_name));
}

} // namespace pqc_sessions
