// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PQC Session Record — Data structure for tracking handshake sessions.
//
// This maps to the tls_handshakes entity in the DA3 ER Diagram.

#ifndef NET_PQC_PQC_SESSION_RECORD_H_
#define NET_PQC_PQC_SESSION_RECORD_H_

#include <cstdint>
#include <string>
#include <vector>

#include "base/time/time.h"

namespace net {
namespace pqc {

// Handshake completion status
enum class HandshakeStatus {
  IN_PROGRESS,
  COMPLETED,
  FAILED,
};

// PKI verification outcome
enum class PKIVerificationResult {
  VERIFIED_INDIGENOUS, // ✓ Path A: valid sig + Indian Root CA
  VERIFIED_EXTERNAL,   // ⚠ Valid sig, but foreign CA
  FAILED_INVALID_SIG,  // ✗ Cryptographic verification failed
  FAILED_UNKNOWN_CA,   // ✗ Issuer not in any trusted store
  FAILED_REVOKED,      // ✗ OCSP says revoked
  FAILED_EXPIRED,      // ✗ Certificate expired
  PENDING,             // ⏳ Not yet verified
};

// Certificate record — maps to DIGITAL_CERTIFICATE entity
struct CertificateRecord {
  std::string cert_serial;
  std::string issuer;
  base::Time valid_from;
  base::Time valid_to;
  std::vector<uint8_t> signature;
  std::string subject_cn;
  std::vector<uint8_t> public_key;
  bool is_pqc = false;
  std::string ocsp_status; // "GOOD", "REVOKED", "UNKNOWN"
};

// PQC Session Record — combines TLS_HANDSHAKE + related data.
class PQCSessionRecord {
public:
  PQCSessionRecord();
  ~PQCSessionRecord();

  // ── TLS_HANDSHAKE fields (from DA3 ER) ──
  std::string handshake_id;  // UUID v4
  std::string session_id;    // Links to BROWSER_SESSION
  std::string kem_algorithm; // "ML-KEM-768"
  std::string sig_algorithm; // "ML-DSA-65"
  std::string cipher_suite;  // "TLS_KYBER768_X25519_AES256GCM_SHA384"
  int handshake_ms = 0;      // Duration in milliseconds
  HandshakeStatus status = HandshakeStatus::IN_PROGRESS;
  base::Time created_at;

  // ── Extended fields ──
  std::string domain;     // Target domain
  std::string ip_address; // Resolved IP
  uint16_t port = 443;    // Port number
  PKIVerificationResult pki_result = PKIVerificationResult::PENDING;
  std::string issuing_ca;           // Name of the CA that signed the cert
  bool indigenous_verified = false; // True if Indigenous PKI verified
  bool hybrid_mode = true;          // True if X25519+ML-KEM-768
  std::string tls_version;          // "TLS 1.3"

  // ── Associated certificate ──
  CertificateRecord server_cert;

  // ── State machine ──
  std::vector<std::string> state_history; // State transition log

  // Convenience: mark as completed
  void Complete(int duration_ms, PKIVerificationResult result,
                const std::string &ca_name);

  // Convenience: mark as failed
  void Fail(PKIVerificationResult result, const std::string &reason);

  // Serialize to a human-readable summary (for UI display)
  std::string ToSummaryString() const;

  // Get PKI result as a display string
  static std::string PKIResultToString(PKIVerificationResult result);

  // Get status as a display string
  static std::string StatusToString(HandshakeStatus status);
};

} // namespace pqc
} // namespace net

#endif // NET_PQC_PQC_SESSION_RECORD_H_
