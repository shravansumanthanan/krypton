// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_COMMON_PQC_CHROME_CONSTANTS_H_
#define CHROME_COMMON_PQC_CHROME_CONSTANTS_H_

namespace pqc {

// ArjunBrowser branding constants
constexpr char kBrowserProcessExecutableName[] = "arjun";
constexpr char kBrowserProductName[] = "ArjunBrowser";
constexpr char kBrowserVersion[] = "1.0.0";

// User-Agent string component
constexpr char kUserAgentSuffix[] =
    "ArjunBrowser/1.0 (PQC-Enabled; ML-KEM-768; ML-DSA-65; Indigenous-PKI)";

// PQC algorithm identifiers
constexpr char kKEMAlgorithm[] = "ML-KEM-768";
constexpr char kSigAlgorithm[] = "ML-DSA-65";
constexpr char kClassicalKEX[] = "X25519";
constexpr char kCipherSuite[] = "TLS_KYBER768_X25519_AES256GCM_SHA384";
constexpr char kHKDFAlgorithm[] = "HKDF-SHA3-256";

// FIPS standards
constexpr char kFIPS203[] = "NIST FIPS 203";  // ML-KEM
constexpr char kFIPS204[] = "NIST FIPS 204";  // ML-DSA

// Feature page URLs
constexpr char kPQCSecurityURL[] = "chrome://pqc-security/";
constexpr char kPQCSettingsURL[] = "chrome://settings/security#pqc";

// Indigenous PKI configuration
constexpr char kDefaultDOHServer[] = "https://dns.gov.in/dns-query";

// ML-KEM-768 key sizes (NIST FIPS 203)
constexpr size_t kMLKEM768PublicKeySize = 1184;
constexpr size_t kMLKEM768SecretKeySize = 2400;
constexpr size_t kMLKEM768CiphertextSize = 1088;
constexpr size_t kMLKEM768SharedSecretSize = 32;

// ML-DSA-65 key sizes (NIST FIPS 204)
constexpr size_t kMLDSA65PublicKeySize = 1952;
constexpr size_t kMLDSA65SecretKeySize = 4032;
constexpr size_t kMLDSA65SignatureSize = 3309;

// X25519 key sizes
constexpr size_t kX25519PublicKeySize = 32;
constexpr size_t kX25519PrivateKeySize = 32;
constexpr size_t kX25519SharedSecretSize = 32;

// Session key sizes
constexpr size_t kSessionKeySize = 32;   // AES-256
constexpr size_t kSessionIVSize = 12;    // GCM nonce

}  // namespace pqc

#endif  // CHROME_COMMON_PQC_CHROME_CONSTANTS_H_
