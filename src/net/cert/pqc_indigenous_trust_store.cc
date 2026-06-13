// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/pqc_indigenous_trust_store.h"

#include <algorithm>
#include <cstring>

#include "base/logging.h"
#include "base/strings/string_util.h"

namespace net {
namespace pqc {

IndigenousTrustStore::IndigenousTrustStore() {
  LOG(INFO) << "IndigenousTrustStore: Initialized with " << kNumIndigenousCAs
            << " hardcoded Indian Root CAs.";
  for (size_t i = 0; i < kNumIndigenousCAs; i++) {
    VLOG(1) << "  [" << i << "] " << kIndigenousCAs[i].name << " ("
            << kIndigenousCAs[i].organization << ")"
            << (kIndigenousCAs[i].pqc_capable ? " [PQC]" : " [Classical]");
  }
}

IndigenousTrustStore::~IndigenousTrustStore() = default;

bool IndigenousTrustStore::ContainsIssuer(
    const std::string &issuer_name) const {
  // Check hardcoded CAs
  for (size_t i = 0; i < kNumIndigenousCAs; i++) {
    if (kIndigenousCAs[i].active &&
        issuer_name.find(kIndigenousCAs[i].name) != std::string::npos) {
      return true;
    }
    // Also match by organization name
    if (kIndigenousCAs[i].active &&
        issuer_name.find(kIndigenousCAs[i].organization) != std::string::npos) {
      return true;
    }
  }

  // Check custom CAs
  for (const auto &ca : custom_cas_) {
    if (ca.active && issuer_name.find(ca.name) != std::string::npos) {
      return true;
    }
  }

  return false;
}

bool IndigenousTrustStore::ContainsSerial(const std::string &serial) const {
  for (size_t i = 0; i < kNumIndigenousCAs; i++) {
    if (kIndigenousCAs[i].active && serial == kIndigenousCAs[i].serial) {
      return true;
    }
  }
  for (const auto &ca : custom_cas_) {
    if (ca.active && serial == ca.serial) {
      return true;
    }
  }
  return false;
}

bool IndigenousTrustStore::IsTrustedForDomain(const std::string &ca_name,
                                              const std::string &domain) const {
  const IndigenousCA *ca = FindCA(ca_name);
  if (!ca || !ca->active) {
    return false;
  }

  // If trusted_domains is empty, the CA is trusted for all domains
  if (ca->trusted_domains.empty()) {
    return true;
  }

  // Check if the domain matches any of the trusted patterns
  for (const auto &pattern : ca->trusted_domains) {
    if (DomainMatchesPattern(domain, pattern)) {
      return true;
    }
  }

  return false;
}

bool IndigenousTrustStore::IsPQCCapable(const std::string &ca_name) const {
  const IndigenousCA *ca = FindCA(ca_name);
  return ca && ca->pqc_capable;
}

std::string IndigenousTrustStore::GetOCSPUrl(const std::string &ca_name) const {
  const IndigenousCA *ca = FindCA(ca_name);
  if (ca && ca->ocsp_url) {
    return ca->ocsp_url;
  }
  return "";
}

const IndigenousCA *
IndigenousTrustStore::FindCA(const std::string &ca_name) const {
  // Search hardcoded CAs
  for (size_t i = 0; i < kNumIndigenousCAs; i++) {
    if (ca_name == kIndigenousCAs[i].name) {
      return &kIndigenousCAs[i];
    }
  }
  // Search custom CAs
  for (const auto &ca : custom_cas_) {
    if (ca_name == ca.name) {
      return &ca;
    }
  }
  return nullptr;
}

std::vector<const IndigenousCA *> IndigenousTrustStore::GetAllCAs() const {
  std::vector<const IndigenousCA *> result;
  for (size_t i = 0; i < kNumIndigenousCAs; i++) {
    if (kIndigenousCAs[i].active) {
      result.push_back(&kIndigenousCAs[i]);
    }
  }
  for (const auto &ca : custom_cas_) {
    if (ca.active) {
      result.push_back(&ca);
    }
  }
  return result;
}

std::vector<const IndigenousCA *>
IndigenousTrustStore::GetPQCCapableCAs() const {
  std::vector<const IndigenousCA *> result;
  for (size_t i = 0; i < kNumIndigenousCAs; i++) {
    if (kIndigenousCAs[i].active && kIndigenousCAs[i].pqc_capable) {
      result.push_back(&kIndigenousCAs[i]);
    }
  }
  for (const auto &ca : custom_cas_) {
    if (ca.active && ca.pqc_capable) {
      result.push_back(&ca);
    }
  }
  return result;
}

void IndigenousTrustStore::AddCustomCA(const IndigenousCA &ca) {
  // Check for duplicates
  for (const auto &existing : custom_cas_) {
    if (std::strcmp(existing.name, ca.name) == 0) {
      LOG(WARNING) << "IndigenousTrustStore: CA '" << ca.name
                   << "' already exists.";
      return;
    }
  }
  custom_cas_.push_back(ca);
  LOG(INFO) << "IndigenousTrustStore: Added custom CA '" << ca.name << "'";
}

bool IndigenousTrustStore::RemoveCustomCA(const std::string &ca_name) {
  auto it = std::remove_if(
      custom_cas_.begin(), custom_cas_.end(),
      [&ca_name](const IndigenousCA &ca) { return ca_name == ca.name; });
  if (it != custom_cas_.end()) {
    custom_cas_.erase(it, custom_cas_.end());
    LOG(INFO) << "IndigenousTrustStore: Removed CA '" << ca_name << "'";
    return true;
  }
  return false;
}

bool IndigenousTrustStore::SetTrustStatus(const std::string &ca_name,
                                          bool trusted) {
  // Can only modify custom CAs
  for (auto &ca : custom_cas_) {
    if (ca_name == ca.name) {
      ca.active = trusted;
      LOG(INFO) << "IndigenousTrustStore: CA '" << ca_name << "' trust set to "
                << (trusted ? "TRUSTED" : "UNTRUSTED");
      return true;
    }
  }
  LOG(WARNING) << "IndigenousTrustStore: Cannot modify built-in CA '" << ca_name
               << "'";
  return false;
}

void IndigenousTrustStore::ClearExternalCAs() {
  size_t count = custom_cas_.size();
  custom_cas_.clear();
  LOG(INFO) << "IndigenousTrustStore: Cleared " << count << " external CAs.";
}

size_t IndigenousTrustStore::TrustedCACount() const {
  size_t count = 0;
  for (size_t i = 0; i < kNumIndigenousCAs; i++) {
    if (kIndigenousCAs[i].active)
      count++;
  }
  for (const auto &ca : custom_cas_) {
    if (ca.active)
      count++;
  }
  return count;
}

// static
bool IndigenousTrustStore::DomainMatchesPattern(const std::string &domain,
                                                const std::string &pattern) {
  // Exact match
  if (domain == pattern) {
    return true;
  }

  // Suffix match: "portal.gov.in" matches pattern "gov.in"
  if (domain.length() > pattern.length()) {
    size_t offset = domain.length() - pattern.length();
    if (domain[offset - 1] == '.' && domain.substr(offset) == pattern) {
      return true;
    }
  }

  return false;
}

} // namespace pqc
} // namespace net
