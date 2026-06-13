// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// HKDF-SHA3-256 Hybrid Secret Combination for PQC TLS 1.3.
//
// The hybrid shared secret is derived as:
//   ikm = X25519_shared_secret || ML-KEM-768_shared_secret
//   prk = HKDF-Extract(salt="PQC-Hybrid-ArjunBrowser-v1", ikm)
//   session_key = HKDF-Expand(prk, info="TLS13 derived", length=32)
//
// This ensures that the combined key is secure as long as at least
// one of the two component key exchanges remains unbroken.

#ifndef NET_SSL_PQC_HYBRID_KDF_H_
#define NET_SSL_PQC_HYBRID_KDF_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace net {
namespace pqc {

// Salt used for HKDF-Extract in hybrid key derivation.
// This is a fixed, publicly known value that provides domain separation.
constexpr char kHybridKDFSalt[] = "PQC-Hybrid-ArjunBrowser-v1";
constexpr size_t kHybridKDFSaltLen = 26;

// Info string for HKDF-Expand in TLS 1.3 context.
constexpr char kHybridKDFInfo[] = "TLS13 derived";
constexpr size_t kHybridKDFInfoLen = 13;

// Default output key length (AES-256-GCM key size).
constexpr size_t kDefaultOutputKeyLen = 32;

// Derive a hybrid session key from X25519 and ML-KEM-768 shared secrets.
//
// Parameters:
//   x25519_secret   - X25519 ECDH shared secret (32 bytes)
//   x25519_len      - length of x25519_secret
//   kem_secret      - ML-KEM-768 decapsulated shared secret (32 bytes)
//   kem_len         - length of kem_secret
//   out_key         - output buffer for the derived session key
//   out_len         - desired output length (typically 32 for AES-256)
//
// Returns true on success, false on HKDF failure.
//
// Security notes:
//   - Both input secrets are consumed and the inputs are NOT zeroed
//     by this function; callers must zero them.
//   - Uses SHA-256 for HKDF (BoringSSL does not yet expose SHA3-256
//     in its HKDF API; once available, this should be upgraded).
//   - The concatenation order (X25519 || KEM) is fixed and MUST NOT
//     be reversed, as it affects the derived key value.
bool PQCHybridKDF(const uint8_t *x25519_secret, size_t x25519_len,
                  const uint8_t *kem_secret, size_t kem_len, uint8_t *out_key,
                  size_t out_len);

// Extended version that accepts custom salt and info strings.
bool PQCHybridKDFWithParams(const uint8_t *x25519_secret, size_t x25519_len,
                            const uint8_t *kem_secret, size_t kem_len,
                            const uint8_t *salt, size_t salt_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *out_key, size_t out_len);

} // namespace pqc
} // namespace net

#endif // NET_SSL_PQC_HYBRID_KDF_H_
