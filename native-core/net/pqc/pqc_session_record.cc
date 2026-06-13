// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/pqc/pqc_session_record.h"

#include <sstream>

#include "base/time/time.h"

namespace net {
namespace pqc {

PQCSessionRecord::PQCSessionRecord()
    : created_at(base::Time::Now()), tls_version("TLS 1.3") {}

PQCSessionRecord::~PQCSessionRecord() = default;

void PQCSessionRecord::Complete(int duration_ms, PKIVerificationResult result,
                                const std::string &ca_name) {
  handshake_ms = duration_ms;
  pki_result = result;
  issuing_ca = ca_name;
  status = HandshakeStatus::COMPLETED;
  indigenous_verified = (result == PKIVerificationResult::VERIFIED_INDIGENOUS);
}

void PQCSessionRecord::Fail(PKIVerificationResult result,
                            const std::string &reason) {
  pki_result = result;
  status = HandshakeStatus::FAILED;
  indigenous_verified = false;
  state_history.push_back("FAILED: " + reason);
}

std::string PQCSessionRecord::ToSummaryString() const {
  std::ostringstream ss;
  ss << "PQC Session: " << domain << ":" << port << "\n"
     << "  Session ID: " << session_id << "\n"
     << "  Handshake ID: " << handshake_id << "\n"
     << "  Status: " << StatusToString(status) << "\n"
     << "  KEM: " << kem_algorithm << "\n"
     << "  SIG: " << sig_algorithm << "\n"
     << "  Cipher Suite: " << cipher_suite << "\n"
     << "  Duration: " << handshake_ms << " ms\n"
     << "  TLS Version: " << tls_version << "\n"
     << "  PKI Result: " << PKIResultToString(pki_result) << "\n"
     << "  Issuing CA: " << issuing_ca << "\n"
     << "  Indigenous: " << (indigenous_verified ? "YES" : "NO") << "\n"
     << "  Hybrid Mode: " << (hybrid_mode ? "YES" : "NO") << "\n"
     << "  Server Cert: " << server_cert.subject_cn << "\n"
     << "  Cert PQC: " << (server_cert.is_pqc ? "ML-DSA-65" : "Classical")
     << "\n";

  if (!state_history.empty()) {
    ss << "  State History:\n";
    for (size_t i = 0; i < state_history.size(); i++) {
      ss << "    [" << i << "] " << state_history[i] << "\n";
    }
  }

  return ss.str();
}

// static
std::string PQCSessionRecord::PKIResultToString(PKIVerificationResult result) {
  switch (result) {
  case PKIVerificationResult::VERIFIED_INDIGENOUS:
    return "VERIFIED (Indigenous PKI)";
  case PKIVerificationResult::VERIFIED_EXTERNAL:
    return "VERIFIED (External CA - Warning)";
  case PKIVerificationResult::FAILED_INVALID_SIG:
    return "FAILED (Invalid Signature)";
  case PKIVerificationResult::FAILED_UNKNOWN_CA:
    return "FAILED (Unknown CA)";
  case PKIVerificationResult::FAILED_REVOKED:
    return "FAILED (Certificate Revoked)";
  case PKIVerificationResult::FAILED_EXPIRED:
    return "FAILED (Certificate Expired)";
  case PKIVerificationResult::PENDING:
    return "PENDING";
  }
  return "UNKNOWN";
}

// static
std::string PQCSessionRecord::StatusToString(HandshakeStatus status) {
  switch (status) {
  case HandshakeStatus::IN_PROGRESS:
    return "IN_PROGRESS";
  case HandshakeStatus::COMPLETED:
    return "COMPLETED";
  case HandshakeStatus::FAILED:
    return "FAILED";
  }
  return "UNKNOWN";
}

} // namespace pqc
} // namespace net
