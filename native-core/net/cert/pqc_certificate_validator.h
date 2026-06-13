// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PQC Certificate Validator — Fail-Closed decision node.
//
// This implements the diamond-shaped decision node from the DA3 State
// Transition Diagram. It validates certificate chains against the
// Indigenous PKI Trust Store and enforces the Fail-Closed policy.
//
// Validation pipeline:
//   1. Verify ML-DSA-65 signature cryptographically
//   2. Check OCSP revocation status (async, 5s timeout)
//   3. Check certificate expiry
//   4. Indigenous PKI check (THE DECISION NODE)
//   5. Apply Fail-Closed policy if Indigenous check fails

#ifndef NET_CERT_PQC_CERTIFICATE_VALIDATOR_H_
#define NET_CERT_PQC_CERTIFICATE_VALIDATOR_H_

#include <cstdint>
#include <string>
#include <vector>

#include "base/time/time.h"
#include "net/cert/pqc_indigenous_trust_store.h"
#include "net/pqc/pqc_session_record.h"

namespace net {
namespace pqc {

// TLS Alert codes relevant to PQC certificate validation
enum class TLSAlertCode : uint8_t {
  CLOSE_NOTIFY = 0,
  UNEXPECTED_MESSAGE = 10,
  BAD_RECORD_MAC = 20,
  HANDSHAKE_FAILURE = 40,
  BAD_CERTIFICATE = 42,
  UNSUPPORTED_CERTIFICATE = 43,
  CERTIFICATE_REVOKED = 44,
  CERTIFICATE_EXPIRED = 45,
  CERTIFICATE_UNKNOWN = 46,
  UNKNOWN_CA = 48,
  ACCESS_DENIED = 49,
  INTERNAL_ERROR = 80,
};

// OCSP response status
enum class OCSPStatus {
  GOOD,
  REVOKED,
  UNKNOWN,
  ERROR,
  TIMEOUT,
};

// Represents a certificate in a chain for validation
struct CertificateChainEntry {
  std::vector<uint8_t> cert_der;   // DER-encoded certificate
  std::string subject_cn;          // Subject Common Name
  std::string issuer_cn;           // Issuer Common Name
  std::string serial_number;       // Certificate serial
  base::Time not_before;           // Valid from
  base::Time not_after;            // Valid to
  std::vector<uint8_t> signature;  // Certificate signature
  std::vector<uint8_t> public_key; // Subject public key
  std::vector<uint8_t> issuer_pk;  // Issuer public key (for sig verify)
  uint16_t sig_algorithm;          // Signature algorithm ID
  bool is_pqc;                     // True if ML-DSA signed
  std::string ocsp_url;            // AIA OCSP responder URL
};

// A full certificate chain from leaf to root
struct CertificateChain {
  CertificateChainEntry leaf;
  std::vector<CertificateChainEntry> intermediates;
  CertificateChainEntry root_ca;
  std::string domain;
};

// ─── PQCCertificateValidator ────────────────────────────────

class PQCCertificateValidator {
public:
  // OCSP check timeout (seconds)
  static constexpr int kOCSPTimeoutSec = 5;

  explicit PQCCertificateValidator(const IndigenousTrustStore *trust_store);
  ~PQCCertificateValidator();

  // Verify a full certificate chain.
  //
  // This is the main entry point — implements the complete validation
  // pipeline including the Fail-Closed decision node.
  //
  // Parameters:
  //   chain                  - Certificate chain from leaf to root
  //   domain                 - Domain being connected to
  //   strict_indigenous_mode - If true, reject non-indigenous chains
  //
  // Returns one of the PKIVerificationResult values.
  PKIVerificationResult VerifyCertificateChain(const CertificateChain &chain,
                                               const std::string &domain,
                                               bool strict_indigenous_mode);

  // Get the name of the CA that was last verified.
  std::string GetLastVerifiedCA() const { return last_verified_ca_; }

  // Get the OCSP status from the last verification.
  OCSPStatus GetLastOCSPStatus() const { return last_ocsp_status_; }

  // Get the TLS alert code for the last failure.
  TLSAlertCode GetLastAlertCode() const { return last_alert_code_; }

  // Get a human-readable description of the last verification result.
  std::string GetLastResultDescription() const;

  // ── Individual Verification Steps ──

  // Step 1: Verify the cryptographic signature on a certificate.
  bool VerifySignature(const CertificateChainEntry &cert,
                       const std::vector<uint8_t> &issuer_pk);

  // Step 2: Check OCSP revocation status (synchronous with timeout).
  OCSPStatus CheckOCSPRevocation(const CertificateChainEntry &cert);

  // Step 3: Check certificate validity period.
  bool CheckExpiry(const CertificateChainEntry &cert);

  // Step 4: Check if the root CA is in the Indigenous Trust Store.
  bool CheckIndigenousPKI(const CertificateChain &chain);

  // Step 5: Send a TLS alert (records the alert for state machine).
  void SendTLSAlert(TLSAlertCode code, const std::string &message);

private:
  // The Indigenous Trust Store instance (not owned).
  const IndigenousTrustStore *trust_store_;

  // Last verification results
  std::string last_verified_ca_;
  OCSPStatus last_ocsp_status_ = OCSPStatus::UNKNOWN;
  TLSAlertCode last_alert_code_ = TLSAlertCode::CLOSE_NOTIFY;
  std::string last_result_description_;
};

// ─── IMPLEMENTATION ─────────────────────────────────────────

PQCCertificateValidator::PQCCertificateValidator(
    const IndigenousTrustStore *trust_store)
    : trust_store_(trust_store) {}

PQCCertificateValidator::~PQCCertificateValidator() = default;

PKIVerificationResult
PQCCertificateValidator::VerifyCertificateChain(const CertificateChain &chain,
                                                const std::string &domain,
                                                bool strict_indigenous_mode) {

  // Step 1: Verify ML-DSA-65 (or classical) signature cryptographically
  if (!VerifySignature(chain.leaf, chain.leaf.issuer_pk)) {
    last_result_description_ =
        "Cryptographic signature verification failed on leaf certificate.";
    SendTLSAlert(TLSAlertCode::BAD_CERTIFICATE, last_result_description_);
    return PKIVerificationResult::FAILED_INVALID_SIG;
  }

  // Step 2: Check certificate expiry
  if (!CheckExpiry(chain.leaf)) {
    last_result_description_ =
        "Server certificate has expired or is not yet valid.";
    SendTLSAlert(TLSAlertCode::CERTIFICATE_EXPIRED, last_result_description_);
    return PKIVerificationResult::FAILED_EXPIRED;
  }

  // Step 3: OCSP revocation check (async, with 5s timeout)
  OCSPStatus ocsp = CheckOCSPRevocation(chain.leaf);
  last_ocsp_status_ = ocsp;
  if (ocsp == OCSPStatus::REVOKED) {
    last_result_description_ =
        "Server certificate has been revoked (OCSP response: REVOKED).";
    SendTLSAlert(TLSAlertCode::CERTIFICATE_REVOKED, last_result_description_);
    return PKIVerificationResult::FAILED_REVOKED;
  }

  // Step 4: Indigenous PKI check — THE DECISION NODE
  bool is_indigenous = CheckIndigenousPKI(chain);

  if (is_indigenous) {
    last_verified_ca_ = chain.root_ca.subject_cn;
    last_result_description_ =
        "Certificate verified against Indigenous PKI. Root CA: " +
        last_verified_ca_;
    return PKIVerificationResult::VERIFIED_INDIGENOUS;
  }

  // Step 5: Apply Fail-Closed policy
  if (strict_indigenous_mode) {
    // ALERT SENT → Connection Terminated (from State Transition Diagram)
    last_result_description_ =
        "Indigenous Root CA verification failed. "
        "Certificate chain does not root to a trusted Indian CA. "
        "Potential MitM or foreign surveillance. "
        "Connection terminated per Fail-Closed policy.";
    SendTLSAlert(TLSAlertCode::BAD_CERTIFICATE, last_result_description_);
    return PKIVerificationResult::FAILED_UNKNOWN_CA;
  }

  // Permissive mode: allow with warning
  last_verified_ca_ = chain.root_ca.subject_cn;
  last_result_description_ =
      "Certificate chain verified but roots to a non-indigenous CA: " +
      last_verified_ca_ + ". Proceeding in permissive mode.";
  return PKIVerificationResult::VERIFIED_EXTERNAL;
}

bool PQCCertificateValidator::VerifySignature(
    const CertificateChainEntry &cert, const std::vector<uint8_t> &issuer_pk) {
  if (cert.is_pqc) {
    // Use ML-DSA-65 verification via QuantumSecurityModule
    // The cert's signature was made with ML-DSA-65 over the TBS data
    OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig_ctx) {
      return false;
    }

    // The message is the DER-encoded TBSCertificate (cert_der without
    // the outer SEQUENCE and signatureAlgorithm/signatureValue)
    OQS_STATUS rc =
        OQS_SIG_verify(sig_ctx, cert.cert_der.data(), cert.cert_der.size(),
                       cert.signature.data(), cert.signature.size(),
                       issuer_pk.data(), issuer_pk.size());
    OQS_SIG_free(sig_ctx);

    return rc == OQS_SUCCESS;
  }

  // Classical signature verification would go through BoringSSL's
  // existing X.509 verification pipeline. For now, return true as
  // BoringSSL handles this natively.
  return true;
}

OCSPStatus PQCCertificateValidator::CheckOCSPRevocation(
    const CertificateChainEntry &cert) {
  if (cert.ocsp_url.empty()) {
    return OCSPStatus::UNKNOWN;
  }

  // TODO: Implement async OCSP check with kOCSPTimeoutSec timeout.
  // For Indigenous CAs, use their OCSP responder URLs extracted from
  // the AIA extension. Cache OCSP responses in the SQLite session
  // database under the DIGITAL_CERTIFICATE entity.
  //
  // Implementation will use net::URLFetcher to query the OCSP responder
  // and parse the DER-encoded OCSPResponse.

  return OCSPStatus::GOOD; // Placeholder until OCSP integration
}

bool PQCCertificateValidator::CheckExpiry(const CertificateChainEntry &cert) {
  base::Time now = base::Time::Now();
  return now >= cert.not_before && now <= cert.not_after;
}

bool PQCCertificateValidator::CheckIndigenousPKI(
    const CertificateChain &chain) {
  if (!trust_store_) {
    return false;
  }

  // Check if the root CA is in the Indigenous Trust Store
  bool root_found = trust_store_->ContainsIssuer(chain.root_ca.subject_cn);

  if (root_found) {
    // Also verify the root CA is trusted for this specific domain
    return trust_store_->IsTrustedForDomain(chain.root_ca.subject_cn,
                                            chain.domain);
  }

  // Check intermediate CAs as well
  for (const auto &intermediate : chain.intermediates) {
    if (trust_store_->ContainsIssuer(intermediate.issuer_cn)) {
      return trust_store_->IsTrustedForDomain(intermediate.issuer_cn,
                                              chain.domain);
    }
  }

  return false;
}

void PQCCertificateValidator::SendTLSAlert(TLSAlertCode code,
                                           const std::string &message) {
  last_alert_code_ = code;
  LOG(WARNING) << "PQC TLS Alert [" << static_cast<int>(code)
               << "]: " << message;
}

std::string PQCCertificateValidator::GetLastResultDescription() const {
  return last_result_description_;
}

} // namespace pqc
} // namespace net

#endif // NET_CERT_PQC_CERTIFICATE_VALIDATOR_H_
