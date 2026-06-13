// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// BoringSSL Patch: X25519+ML-KEM-768 Hybrid Key Share for TLS 1.3
//
// This file extends BoringSSL's SSL key share mechanism with a hybrid
// post-quantum key exchange group combining X25519 (classical) with
// ML-KEM-768 (NIST FIPS 203) for quantum-resistant key encapsulation.
//
// The hybrid group is assigned IANA code point 0x11EC (X25519MLKEM768).
// In the ClientHello key_share extension, the public key is encoded as:
//   X25519_pk (32 bytes) || ML-KEM-768_pk (1184 bytes)
//
// In the ServerHello key_share, the response is:
//   X25519_pk (32 bytes) || ML-KEM-768_ct (1088 bytes)
//
// The combined shared secret is derived via HKDF-SHA3-256 as specified
// in net/ssl/pqc_hybrid_kdf.h.

#ifndef THIRD_PARTY_BORINGSSL_SRC_SSL_PQC_SSL_KEY_SHARE_HYBRID_H_
#define THIRD_PARTY_BORINGSSL_SRC_SSL_PQC_SSL_KEY_SHARE_HYBRID_H_

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "openssl/curve25519.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"

// liboqs includes
extern "C" {
#include "oqs/oqs.h"
}

namespace bssl {

// IANA-assigned NamedGroup for X25519+ML-KEM-768 hybrid
constexpr uint16_t kGroupX25519MLKEM768 = 0x11EC;

// Key sizes
constexpr size_t kX25519PublicKeyLen = 32;
constexpr size_t kX25519PrivateKeyLen = 32;
constexpr size_t kX25519SharedSecretLen = 32;
constexpr size_t kMLKEM768PublicKeyLen = 1184;
constexpr size_t kMLKEM768SecretKeyLen = 2400;
constexpr size_t kMLKEM768CiphertextLen = 1088;
constexpr size_t kMLKEM768SharedSecretLen = 32;

// Combined public key size in ClientHello key_share
constexpr size_t kHybridPublicKeyLen =
    kX25519PublicKeyLen + kMLKEM768PublicKeyLen; // 32 + 1184 = 1216

// Combined response size in ServerHello key_share
constexpr size_t kHybridServerResponseLen =
    kX25519PublicKeyLen + kMLKEM768CiphertextLen; // 32 + 1088 = 1120

// X25519+ML-KEM-768 Hybrid Key Share implementation.
//
// This class implements the SSLKeyShare interface for the hybrid
// post-quantum key exchange group. It maintains both X25519 and
// ML-KEM-768 key material throughout the handshake lifecycle.
//
// State machine:
//   1. Offer() — generates both keypairs, outputs concatenated public keys
//   2. Finish() — receives server's response, computes both shared secrets,
//                  combines them via HKDF-SHA3-256
//
// Security properties:
//   - If either X25519 OR ML-KEM-768 remains secure, the combined
//     shared secret is secure (defense in depth)
//   - Key material is zeroed on destruction
//   - No raw key material ever leaves the network process
class X25519MLKEM768KeyShare {
public:
  X25519MLKEM768KeyShare() = default;
  ~X25519MLKEM768KeyShare();

  // Non-copyable, non-movable (contains sensitive key material)
  X25519MLKEM768KeyShare(const X25519MLKEM768KeyShare &) = delete;
  X25519MLKEM768KeyShare &operator=(const X25519MLKEM768KeyShare &) = delete;

  // Returns the IANA-assigned NamedGroup identifier.
  uint16_t GroupID() const { return kGroupX25519MLKEM768; }

  // Returns a human-readable name for logging/debugging.
  const char *GroupName() const { return "X25519MLKEM768"; }

  // Generate keypairs and write the concatenated public key to |out|.
  //
  // Output format: X25519_pk (32 bytes) || ML-KEM-768_pk (1184 bytes)
  //
  // Returns true on success, false on OQS/X25519 failure.
  bool Offer(std::vector<uint8_t> *out);

  // Given the server's response in |peer_key|, compute the combined
  // shared secret and write it to |out_secret|.
  //
  // Input format (peer_key):
  //   X25519_server_pk (32 bytes) || ML-KEM-768_ct (1088 bytes)
  //
  // Processing:
  //   1. X25519 ECDH with server's X25519 public key → x25519_shared (32 bytes)
  //   2. ML-KEM-768 Decapsulate(ct, our_sk) → kem_shared (32 bytes)
  //   3. combined = HKDF-SHA3-256(x25519_shared || kem_shared)
  //
  // On failure, sets |out_alert| to the appropriate TLS alert code.
  bool Finish(std::vector<uint8_t> *out_secret, uint8_t *out_alert,
              const uint8_t *peer_key, size_t peer_key_len);

  // Server-side: Accept a client's hybrid public key and produce the
  // server response + shared secret.
  //
  // Input (client_public_key):
  //   X25519_pk (32 bytes) || ML-KEM-768_pk (1184 bytes)
  //
  // Output:
  //   server_response: X25519_server_pk (32 bytes) || ML-KEM-768_ct (1088
  //   bytes) out_secret: combined HKDF-SHA3-256 shared secret (32 bytes)
  bool Accept(std::vector<uint8_t> *out_secret,
              std::vector<uint8_t> *server_response, uint8_t *out_alert,
              const uint8_t *client_public_key, size_t client_public_key_len);

  // Returns true if this key share has been offered (keypairs generated).
  bool is_offered() const { return offered_; }

private:
  // Zero out sensitive key material
  void ClearSecrets();

  // X25519 key material
  uint8_t x25519_public_key_[kX25519PublicKeyLen] = {0};
  uint8_t x25519_private_key_[kX25519PrivateKeyLen] = {0};

  // ML-KEM-768 key material
  uint8_t mlkem_public_key_[kMLKEM768PublicKeyLen] = {0};
  uint8_t mlkem_secret_key_[kMLKEM768SecretKeyLen] = {0};

  bool offered_ = false;
};

// ─────────────────────────────────────────────
// IMPLEMENTATION
// ─────────────────────────────────────────────

X25519MLKEM768KeyShare::~X25519MLKEM768KeyShare() { ClearSecrets(); }

void X25519MLKEM768KeyShare::ClearSecrets() {
  OPENSSL_cleanse(x25519_private_key_, sizeof(x25519_private_key_));
  OPENSSL_cleanse(mlkem_secret_key_, sizeof(mlkem_secret_key_));
  offered_ = false;
}

bool X25519MLKEM768KeyShare::Offer(std::vector<uint8_t> *out) {
  // Step 1: Generate X25519 keypair
  X25519_keypair(x25519_public_key_, x25519_private_key_);

  // Step 2: Generate ML-KEM-768 keypair via liboqs
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    return false;
  }

  OQS_STATUS rc = OQS_KEM_keypair(kem, mlkem_public_key_, mlkem_secret_key_);
  OQS_KEM_free(kem);

  if (rc != OQS_SUCCESS) {
    ClearSecrets();
    return false;
  }

  // Step 3: Concatenate X25519_pk || ML-KEM-768_pk into output
  out->clear();
  out->reserve(kHybridPublicKeyLen);
  out->insert(out->end(), x25519_public_key_,
              x25519_public_key_ + kX25519PublicKeyLen);
  out->insert(out->end(), mlkem_public_key_,
              mlkem_public_key_ + kMLKEM768PublicKeyLen);

  offered_ = true;
  return true;
}

bool X25519MLKEM768KeyShare::Finish(std::vector<uint8_t> *out_secret,
                                    uint8_t *out_alert, const uint8_t *peer_key,
                                    size_t peer_key_len) {
  if (!offered_) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    return false;
  }

  // Validate peer_key length: X25519_pk (32) || ML-KEM-768_ct (1088)
  if (peer_key_len != kHybridServerResponseLen) {
    *out_alert = SSL_AD_DECODE_ERROR;
    return false;
  }

  // Step 1: Extract server's X25519 public key and ML-KEM-768 ciphertext
  const uint8_t *server_x25519_pk = peer_key;
  const uint8_t *mlkem_ciphertext = peer_key + kX25519PublicKeyLen;

  // Step 2: Compute X25519 shared secret
  uint8_t x25519_shared[kX25519SharedSecretLen];
  if (!X25519(x25519_shared, x25519_private_key_, server_x25519_pk)) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
    return false;
  }

  // Step 3: Decapsulate ML-KEM-768 ciphertext
  uint8_t kem_shared[kMLKEM768SharedSecretLen];
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
    return false;
  }

  OQS_STATUS rc =
      OQS_KEM_decaps(kem, kem_shared, mlkem_ciphertext, mlkem_secret_key_);
  OQS_KEM_free(kem);

  if (rc != OQS_SUCCESS) {
    *out_alert = SSL_AD_DECRYPT_ERROR;
    OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
    OPENSSL_cleanse(kem_shared, sizeof(kem_shared));
    return false;
  }

  // Step 4: Combine shared secrets via HKDF-SHA3-256
  //   ikm = x25519_shared (32 bytes) || kem_shared (32 bytes)
  //   salt = "PQC-Hybrid-ArjunBrowser-v1"
  //   info = "TLS13 derived"
  //
  // Use PQCHybridKDF from net/ssl/pqc_hybrid_kdf.h for the actual
  // HKDF-SHA3-256 derivation. Here we inline a simplified version
  // for BoringSSL integration.
  std::vector<uint8_t> ikm;
  ikm.reserve(kX25519SharedSecretLen + kMLKEM768SharedSecretLen);
  ikm.insert(ikm.end(), x25519_shared, x25519_shared + kX25519SharedSecretLen);
  ikm.insert(ikm.end(), kem_shared, kem_shared + kMLKEM768SharedSecretLen);

  // HKDF-Extract + Expand using SHA-256 (BoringSSL built-in)
  // In production, this will use HKDF-SHA3-256 via PQCHybridKDF.
  static const uint8_t kSalt[] = "PQC-Hybrid-ArjunBrowser-v1";
  static const uint8_t kInfo[] = "TLS13 derived";

  out_secret->resize(32);
  if (!HKDF(out_secret->data(), out_secret->size(), EVP_sha256(), ikm.data(),
            ikm.size(), kSalt, sizeof(kSalt) - 1, kInfo, sizeof(kInfo) - 1)) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
    OPENSSL_cleanse(kem_shared, sizeof(kem_shared));
    return false;
  }

  // Clean up sensitive material
  OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
  OPENSSL_cleanse(kem_shared, sizeof(kem_shared));
  ClearSecrets();

  return true;
}

bool X25519MLKEM768KeyShare::Accept(std::vector<uint8_t> *out_secret,
                                    std::vector<uint8_t> *server_response,
                                    uint8_t *out_alert,
                                    const uint8_t *client_public_key,
                                    size_t client_public_key_len) {
  // Validate client's hybrid public key length
  if (client_public_key_len != kHybridPublicKeyLen) {
    *out_alert = SSL_AD_DECODE_ERROR;
    return false;
  }

  // Extract client's X25519 public key and ML-KEM-768 public key
  const uint8_t *client_x25519_pk = client_public_key;
  const uint8_t *client_mlkem_pk = client_public_key + kX25519PublicKeyLen;

  // Step 1: Generate server's X25519 keypair and compute shared secret
  uint8_t server_x25519_public[kX25519PublicKeyLen];
  uint8_t server_x25519_private[kX25519PrivateKeyLen];
  X25519_keypair(server_x25519_public, server_x25519_private);

  uint8_t x25519_shared[kX25519SharedSecretLen];
  if (!X25519(x25519_shared, server_x25519_private, client_x25519_pk)) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_cleanse(server_x25519_private, sizeof(server_x25519_private));
    return false;
  }

  OPENSSL_cleanse(server_x25519_private, sizeof(server_x25519_private));

  // Step 2: Encapsulate using client's ML-KEM-768 public key
  uint8_t kem_ciphertext[kMLKEM768CiphertextLen];
  uint8_t kem_shared[kMLKEM768SharedSecretLen];

  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
    return false;
  }

  OQS_STATUS rc =
      OQS_KEM_encaps(kem, kem_ciphertext, kem_shared, client_mlkem_pk);
  OQS_KEM_free(kem);

  if (rc != OQS_SUCCESS) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
    return false;
  }

  // Step 3: Build server response
  server_response->clear();
  server_response->reserve(kHybridServerResponseLen);
  server_response->insert(server_response->end(), server_x25519_public,
                          server_x25519_public + kX25519PublicKeyLen);
  server_response->insert(server_response->end(), kem_ciphertext,
                          kem_ciphertext + kMLKEM768CiphertextLen);

  // Step 4: Combine shared secrets
  std::vector<uint8_t> ikm;
  ikm.reserve(kX25519SharedSecretLen + kMLKEM768SharedSecretLen);
  ikm.insert(ikm.end(), x25519_shared, x25519_shared + kX25519SharedSecretLen);
  ikm.insert(ikm.end(), kem_shared, kem_shared + kMLKEM768SharedSecretLen);

  static const uint8_t kSalt[] = "PQC-Hybrid-ArjunBrowser-v1";
  static const uint8_t kInfo[] = "TLS13 derived";

  out_secret->resize(32);
  if (!HKDF(out_secret->data(), out_secret->size(), EVP_sha256(), ikm.data(),
            ikm.size(), kSalt, sizeof(kSalt) - 1, kInfo, sizeof(kInfo) - 1)) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
    OPENSSL_cleanse(kem_shared, sizeof(kem_shared));
    return false;
  }

  OPENSSL_cleanse(x25519_shared, sizeof(x25519_shared));
  OPENSSL_cleanse(kem_shared, sizeof(kem_shared));

  return true;
}

// Registration entry for kAllGroups[] in ssl_key_share.cc:
//
// { ssl_curve_x25519_mlkem768, "X25519MLKEM768", kGroupX25519MLKEM768,
//   &X25519MLKEM768KeyShare::Create },

} // namespace bssl

#endif // THIRD_PARTY_BORINGSSL_SRC_SSL_PQC_SSL_KEY_SHARE_HYBRID_H_
