// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// BoringSSL Patch: ML-DSA-65 (NIST FIPS 204) Signature Verification
//
// This file adds ML-DSA-65 as a recognized signature algorithm for
// TLS 1.3 server certificate authentication. It integrates with
// BoringSSL's existing certificate verification pipeline.
//
// The ML-DSA-65 signature algorithm is identified by the IETF-assigned
// SignatureScheme value 0x0905.

#ifndef THIRD_PARTY_BORINGSSL_SRC_SSL_PQC_SSL_SIG_MLDSA_H_
#define THIRD_PARTY_BORINGSSL_SRC_SSL_PQC_SSL_SIG_MLDSA_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "openssl/ssl.h"

// liboqs includes
extern "C" {
#include "oqs/oqs.h"
}

namespace bssl {

// IETF-assigned SignatureScheme for ML-DSA-65
// Reference: draft-ietf-tls-ml-dsa
constexpr uint16_t kSignatureAlgorithmMLDSA65 = 0x0905;
constexpr uint16_t kSignatureAlgorithmMLDSA44 = 0x0904;
constexpr uint16_t kSignatureAlgorithmMLDSA87 = 0x0906;

// ML-DSA-65 key and signature sizes (NIST FIPS 204)
constexpr size_t kMLDSA65PublicKeyLen = 1952;
constexpr size_t kMLDSA65SecretKeyLen = 4032;
constexpr size_t kMLDSA65SignatureLen = 3309;

// Verify an ML-DSA-65 signature on a message.
//
// Parameters:
//   msg      - pointer to the message bytes
//   msg_len  - length of the message
//   sig      - pointer to the ML-DSA-65 signature bytes
//   sig_len  - length of the signature (must be kMLDSA65SignatureLen)
//   pk       - pointer to the signer's ML-DSA-65 public key
//   pk_len   - length of the public key (must be kMLDSA65PublicKeyLen)
//
// Returns true if the signature is valid, false otherwise.
// This function does NOT allocate; all OQS objects are stack-scoped.
static bool VerifyMLDSA65(const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len, const uint8_t *pk,
                          size_t pk_len) {
  // Validate key and signature sizes
  if (pk_len != kMLDSA65PublicKeyLen) {
    return false;
  }
  if (sig_len != kMLDSA65SignatureLen) {
    return false;
  }

  // Initialize liboqs ML-DSA-65 context
  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (!sig_ctx) {
    return false;
  }

  // Verify the signature
  OQS_STATUS rc =
      OQS_SIG_verify(sig_ctx, msg, msg_len, sig, sig_len, pk, pk_len);
  OQS_SIG_free(sig_ctx);

  return rc == OQS_SUCCESS;
}

// Sign a message with ML-DSA-65.
//
// Parameters:
//   msg      - pointer to the message bytes
//   msg_len  - length of the message
//   sig      - output buffer for the signature
//   sig_len  - pointer to receive the actual signature length
//   sk       - pointer to the ML-DSA-65 secret key
//   sk_len   - length of the secret key (must be kMLDSA65SecretKeyLen)
//
// Returns true on success, false on failure.
static bool SignMLDSA65(const uint8_t *msg, size_t msg_len, uint8_t *sig,
                        size_t *sig_len, const uint8_t *sk, size_t sk_len) {
  if (sk_len != kMLDSA65SecretKeyLen) {
    return false;
  }

  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (!sig_ctx) {
    return false;
  }

  OQS_STATUS rc = OQS_SIG_sign(sig_ctx, sig, sig_len, msg, msg_len, sk);
  OQS_SIG_free(sig_ctx);

  return rc == OQS_SUCCESS;
}

// Generate an ML-DSA-65 keypair.
//
// Parameters:
//   pk - output buffer for public key (must be kMLDSA65PublicKeyLen bytes)
//   sk - output buffer for secret key (must be kMLDSA65SecretKeyLen bytes)
//
// Returns true on success, false on failure.
static bool GenerateMLDSA65Keypair(uint8_t *pk, uint8_t *sk) {
  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (!sig_ctx) {
    return false;
  }

  OQS_STATUS rc = OQS_SIG_keypair(sig_ctx, pk, sk);
  OQS_SIG_free(sig_ctx);

  return rc == OQS_SUCCESS;
}

// Check if a SignatureScheme value is a supported PQC algorithm.
static bool IsPQCSignatureScheme(uint16_t scheme) {
  switch (scheme) {
  case kSignatureAlgorithmMLDSA44:
  case kSignatureAlgorithmMLDSA65:
  case kSignatureAlgorithmMLDSA87:
    return true;
  default:
    return false;
  }
}

// Verify a signature given a SignatureScheme identifier.
// Dispatches to the appropriate ML-DSA variant.
static bool VerifyPQCSignature(uint16_t scheme, const uint8_t *msg,
                               size_t msg_len, const uint8_t *sig,
                               size_t sig_len, const uint8_t *pk,
                               size_t pk_len) {
  switch (scheme) {
  case kSignatureAlgorithmMLDSA65:
    return VerifyMLDSA65(msg, msg_len, sig, sig_len, pk, pk_len);
  case kSignatureAlgorithmMLDSA44: {
    OQS_SIG *ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!ctx)
      return false;
    OQS_STATUS rc = OQS_SIG_verify(ctx, msg, msg_len, sig, sig_len, pk, pk_len);
    OQS_SIG_free(ctx);
    return rc == OQS_SUCCESS;
  }
  case kSignatureAlgorithmMLDSA87: {
    OQS_SIG *ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!ctx)
      return false;
    OQS_STATUS rc = OQS_SIG_verify(ctx, msg, msg_len, sig, sig_len, pk, pk_len);
    OQS_SIG_free(ctx);
    return rc == OQS_SUCCESS;
  }
  default:
    return false;
  }
}

// Integration point for ssl_verify_peer_cert():
//
// In ssl_x509.cc, the SignatureScheme handler switch should include:
//
//   case kSignatureAlgorithmMLDSA65:
//     if (!VerifyMLDSA65(tbs_data, tbs_len,
//                        sig_data, sig_len,
//                        peer_pk, peer_pk_len)) {
//       OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_SIGNATURE);
//       *out_alert = SSL_AD_DECRYPT_ERROR;
//       return false;
//     }
//     break;

} // namespace bssl

#endif // THIRD_PARTY_BORINGSSL_SRC_SSL_PQC_SSL_SIG_MLDSA_H_
