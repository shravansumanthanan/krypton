// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/pqc_hybrid_kdf.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "openssl/digest.h"
#include "openssl/err.h"
#include "openssl/hkdf.h"
#include "openssl/mem.h"

namespace net {
namespace pqc {

bool PQCHybridKDF(const uint8_t *x25519_secret, size_t x25519_len,
                  const uint8_t *kem_secret, size_t kem_len, uint8_t *out_key,
                  size_t out_len) {
  return PQCHybridKDFWithParams(
      x25519_secret, x25519_len, kem_secret, kem_len,
      reinterpret_cast<const uint8_t *>(kHybridKDFSalt), kHybridKDFSaltLen,
      reinterpret_cast<const uint8_t *>(kHybridKDFInfo), kHybridKDFInfoLen,
      out_key, out_len);
}

bool PQCHybridKDFWithParams(const uint8_t *x25519_secret, size_t x25519_len,
                            const uint8_t *kem_secret, size_t kem_len,
                            const uint8_t *salt, size_t salt_len,
                            const uint8_t *info, size_t info_len,
                            uint8_t *out_key, size_t out_len) {
  if (!x25519_secret || x25519_len == 0 || !kem_secret || kem_len == 0 ||
      !out_key || out_len == 0) {
    return false;
  }

  // Step 1: Concatenate input key material
  //   ikm = X25519_shared_secret || ML-KEM-768_shared_secret
  std::vector<uint8_t> ikm;
  ikm.reserve(x25519_len + kem_len);
  ikm.insert(ikm.end(), x25519_secret, x25519_secret + x25519_len);
  ikm.insert(ikm.end(), kem_secret, kem_secret + kem_len);

  // Step 2: HKDF using SHA-256 (upgrade to SHA3-256 when available in
  // BoringSSL's HKDF API)
  //
  // HKDF-Extract:
  //   prk = HMAC-SHA256(salt, ikm)
  //
  // HKDF-Expand:
  //   okm = HKDF-Expand(prk, info, out_len)
  const EVP_MD *md = EVP_sha256();

  int result = HKDF(out_key, out_len, md, ikm.data(), ikm.size(), salt,
                    salt_len, info, info_len);

  // Clear the intermediate key material
  OPENSSL_cleanse(ikm.data(), ikm.size());

  return result == 1;
}

} // namespace pqc
} // namespace net
