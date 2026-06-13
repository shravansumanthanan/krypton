// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Indigenous PKI Trust Store — Indian Root CA management.
//
// This implements the "D1: Indigenous Trust Store" data store from the
// DA3 Level-1 DFD. It maintains a hardcoded list of Indian Root CAs
// (NIC, CCA, Indian Army PKI, DRDO, eMudhra) that are trusted by default.
//
// In strict Indigenous PKI mode ("fail_closed_policy"), connections whose
// certificate chain does not root to one of these CAs are terminated.

#ifndef NET_CERT_PQC_INDIGENOUS_TRUST_STORE_H_
#define NET_CERT_PQC_INDIGENOUS_TRUST_STORE_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace net {
namespace pqc {

// Certificate algorithm type
enum class CertAlgorithm {
  RSA_2048,
  RSA_4096,
  ECDSA_P256,
  ECDSA_P384,
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  ML_KEM_768, // For Key Exchange certificates
};

// Represents a single Indigenous Certificate Authority entry.
struct IndigenousCA {
  // Human-readable name of the CA
  const char *name;
  // Organization that operates the CA
  const char *organization;
  // Country code (always "IN" for Indigenous CAs)
  const char *country;
  // List of domains this CA is trusted for (empty = trust all .in domains)
  std::vector<std::string> trusted_domains;
  // Whether this CA issues PQC (ML-DSA) certificates
  bool pqc_capable;
  // Certificate algorithm used by this CA
  CertAlgorithm algorithm;
  // OCSP responder URL
  const char *ocsp_url;
  // CA root certificate serial number
  const char *serial;
  // Whether this CA is currently active/trusted
  bool active;
};

// ─── Hardcoded Indian Root CA Registry ──────────────────────

static const IndigenousCA kIndigenousCAs[] = {
    {
        /* name */ "NIC Root CA 2025",
        /* organization */ "National Informatics Centre",
        /* country */ "IN",
        /* trusted_domains */
        {"gov.in", "nic.in", "army.mil.in", "defence.gov.in", "mea.gov.in",
         "mod.gov.in", "india.gov.in"},
        /* pqc_capable */ true,
        /* algorithm */ CertAlgorithm::ML_DSA_65,
        /* ocsp_url */ "http://ocsp.nic.in",
        /* serial */ "NIC-ROOT-2025-001",
        /* active */ true,
    },
    {
        /* name */ "CCA India Root CA",
        /* organization */ "Controller of Certifying Authorities, India",
        /* country */ "IN",
        /* trusted_domains */ {}, // Trust all .in TLDs
        /* pqc_capable */ false,
        /* algorithm */ CertAlgorithm::RSA_4096,
        /* ocsp_url */ "http://ocsp.cca.gov.in",
        /* serial */ "CCA-ROOT-2024-001",
        /* active */ true,
    },
    {
        /* name */ "Indian Army PKI Root",
        /* organization */ "Indian Army Signal Corps",
        /* country */ "IN",
        /* trusted_domains */
        {"army.mil.in", "indianarmy.nic.in", "signals.army.mil.in",
         "armedforces.mil.in"},
        /* pqc_capable */ true,
        /* algorithm */ CertAlgorithm::ML_DSA_65,
        /* ocsp_url */ "http://ocsp.army.mil.in",
        /* serial */ "ARMY-PKI-ROOT-2025-001",
        /* active */ true,
    },
    {
        /* name */ "DRDO Internal CA",
        /* organization */ "Defence Research and Development Organisation",
        /* country */ "IN",
        /* trusted_domains */
        {"drdo.gov.in", "drdo.in", "rac.gov.in", "lastec.drdo.in"},
        /* pqc_capable */ true,
        /* algorithm */ CertAlgorithm::ML_DSA_65,
        /* ocsp_url */ "http://ocsp.drdo.gov.in",
        /* serial */ "DRDO-CA-ROOT-2025-001",
        /* active */ true,
    },
    {
        /* name */ "eMudhra Class 3 CA",
        /* organization */ "eMudhra Limited",
        /* country */ "IN",
        /* trusted_domains */ {}, // Trust all domains
        /* pqc_capable */ false,
        /* algorithm */ CertAlgorithm::RSA_4096,
        /* ocsp_url */ "http://ocsp.emudhra.com",
        /* serial */ "EMUDHRA-C3-ROOT-2024-001",
        /* active */ true,
    },
};

// Number of hardcoded Indigenous CAs
constexpr size_t kNumIndigenousCAs =
    sizeof(kIndigenousCAs) / sizeof(kIndigenousCAs[0]);

// ─── IndigenousTrustStore Class ─────────────────────────────

class IndigenousTrustStore {
public:
  IndigenousTrustStore();
  ~IndigenousTrustStore();

  // Check if a given CA name is in the Indigenous trust store.
  bool ContainsIssuer(const std::string &issuer_name) const;

  // Check if a given CA serial is in the Indigenous trust store.
  bool ContainsSerial(const std::string &serial) const;

  // Check if a CA is trusted for a specific domain.
  // Returns true if the CA's trusted_domains list is empty (wildcard)
  // or if the domain matches one of the trusted patterns.
  bool IsTrustedForDomain(const std::string &ca_name,
                          const std::string &domain) const;

  // Check if a CA supports PQC certificates.
  bool IsPQCCapable(const std::string &ca_name) const;

  // Get the OCSP responder URL for a given CA.
  std::string GetOCSPUrl(const std::string &ca_name) const;

  // Get the full IndigenousCA record for a given CA name.
  // Returns nullptr if not found.
  const IndigenousCA *FindCA(const std::string &ca_name) const;

  // Get all active Indigenous CAs.
  std::vector<const IndigenousCA *> GetAllCAs() const;

  // Get only PQC-capable CAs.
  std::vector<const IndigenousCA *> GetPQCCapableCAs() const;

  // ── User-managed trust store extensions ──

  // Add a custom CA (from user import).
  void AddCustomCA(const IndigenousCA &ca);

  // Remove a custom CA by name.
  bool RemoveCustomCA(const std::string &ca_name);

  // Toggle trust for a CA.
  bool SetTrustStatus(const std::string &ca_name, bool trusted);

  // Clear all non-indigenous (custom/imported) CAs.
  void ClearExternalCAs();

  // Get the number of trusted CAs (built-in + custom).
  size_t TrustedCACount() const;

private:
  // Domain matching helper: checks if |domain| matches |pattern|.
  // Supports suffix matching (e.g., "gov.in" matches "portal.gov.in").
  static bool DomainMatchesPattern(const std::string &domain,
                                   const std::string &pattern);

  // User-added custom CAs
  std::vector<IndigenousCA> custom_cas_;
};

} // namespace pqc
} // namespace net

#endif // NET_CERT_PQC_INDIGENOUS_TRUST_STORE_H_
