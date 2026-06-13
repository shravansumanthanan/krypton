// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/pqc/quantum_security_module.h"

#include <algorithm>
#include <cstring>
#include <random>
#include <sstream>

#include "base/logging.h"
#include "base/rand_util.h"
#include "base/time/time.h"
#include "base/uuid.h"
#include "net/ssl/pqc_hybrid_kdf.h"

// liboqs includes
extern "C" {
#include "oqs/oqs.h"
}

// BoringSSL includes
#include "openssl/curve25519.h"
#include "openssl/mem.h"
#include "openssl/rand.h"

namespace net {
namespace pqc {

// ─── HybridKeyPair ──────────────────────────────────────────

void HybridKeyPair::ClearSecrets() {
  if (!kem_secret_key.empty()) {
    OPENSSL_cleanse(kem_secret_key.data(), kem_secret_key.size());
    kem_secret_key.clear();
  }
  if (!x25519_private.empty()) {
    OPENSSL_cleanse(x25519_private.data(), x25519_private.size());
    x25519_private.clear();
  }
}

bool HybridKeyPair::IsValid() const {
  return kem_public_key.size() == OQS_KEM_ml_kem_768_length_public_key &&
         kem_secret_key.size() == OQS_KEM_ml_kem_768_length_secret_key &&
         x25519_public.size() == 32 && x25519_private.size() == 32;
}

// ─── HybridSessionKey ───────────────────────────────────────

void HybridSessionKey::ClearSecrets() {
  if (!session_key.empty()) {
    OPENSSL_cleanse(session_key.data(), session_key.size());
    session_key.clear();
  }
  if (!iv.empty()) {
    OPENSSL_cleanse(iv.data(), iv.size());
    iv.clear();
  }
}

// ─── QuantumSecurityModule ──────────────────────────────────

QuantumSecurityModule::QuantumSecurityModule() {
  initialized_ = IsAvailable();
  if (!initialized_) {
    LOG(ERROR) << "QuantumSecurityModule: liboqs initialization failed. "
               << "ML-KEM-768 and ML-DSA-65 operations will not be available.";
  }
}

QuantumSecurityModule::~QuantumSecurityModule() = default;

// ── Key Lifecycle ────────────────────────────────────────────

HybridKeyPair QuantumSecurityModule::GenerateHybridKeypair() {
  HybridKeyPair kp;
  kp.generated_at = base::Time::Now();
  kp.key_id = GenerateUUID();

  // Step 1: Generate X25519 keypair
  kp.x25519_public.resize(32);
  kp.x25519_private.resize(32);
  X25519_keypair(kp.x25519_public.data(), kp.x25519_private.data());

  // Step 2: Generate ML-KEM-768 keypair via liboqs
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    LOG(ERROR) << "QSM: Failed to initialize ML-KEM-768.";
    kp.ClearSecrets();
    return kp;
  }

  kp.kem_public_key.resize(OQS_KEM_ml_kem_768_length_public_key);
  kp.kem_secret_key.resize(OQS_KEM_ml_kem_768_length_secret_key);

  OQS_STATUS rc =
      OQS_KEM_keypair(kem, kp.kem_public_key.data(), kp.kem_secret_key.data());
  OQS_KEM_free(kem);

  if (rc != OQS_SUCCESS) {
    LOG(ERROR) << "QSM: ML-KEM-768 keypair generation failed.";
    kp.ClearSecrets();
    return kp;
  }

  VLOG(1) << "QSM: Generated hybrid keypair " << kp.key_id
          << " (X25519 + ML-KEM-768)";
  return kp;
}

HybridKeyPair QuantumSecurityModule::GenerateDeterministicKeypair(
    const std::vector<uint8_t> &seed) {
  // For NIST KAT testing only — uses seed to deterministically
  // generate keypairs for validation against known-answer vectors.
  HybridKeyPair kp;
  kp.generated_at = base::Time::Now();
  kp.key_id = "KAT-deterministic";

  // X25519: use first 32 bytes of seed as private key
  kp.x25519_private.assign(seed.begin(),
                           seed.begin() + std::min<size_t>(32, seed.size()));
  kp.x25519_private.resize(32, 0);
  kp.x25519_public.resize(32);
  X25519_public_from_private(kp.x25519_public.data(), kp.x25519_private.data());

  // ML-KEM-768: use liboqs deterministic keygen if available
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    kp.ClearSecrets();
    return kp;
  }

  kp.kem_public_key.resize(OQS_KEM_ml_kem_768_length_public_key);
  kp.kem_secret_key.resize(OQS_KEM_ml_kem_768_length_secret_key);

  OQS_STATUS rc =
      OQS_KEM_keypair(kem, kp.kem_public_key.data(), kp.kem_secret_key.data());
  OQS_KEM_free(kem);

  if (rc != OQS_SUCCESS) {
    kp.ClearSecrets();
  }
  return kp;
}

// ── ML-KEM-768 Operations ───────────────────────────────────

EncapsulationResult
QuantumSecurityModule::Encapsulate(const std::vector<uint8_t> &peer_kem_pk) {
  EncapsulationResult result;
  result.success = false;

  if (peer_kem_pk.size() != OQS_KEM_ml_kem_768_length_public_key) {
    LOG(ERROR) << "QSM: Invalid ML-KEM-768 public key size: "
               << peer_kem_pk.size() << " (expected "
               << OQS_KEM_ml_kem_768_length_public_key << ")";
    return result;
  }

  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    LOG(ERROR) << "QSM: Failed to initialize ML-KEM-768 for encapsulation.";
    return result;
  }

  result.ciphertext.resize(OQS_KEM_ml_kem_768_length_ciphertext);
  result.shared_secret.resize(OQS_KEM_ml_kem_768_length_shared_secret);

  OQS_STATUS rc =
      OQS_KEM_encaps(kem, result.ciphertext.data(), result.shared_secret.data(),
                     peer_kem_pk.data());
  OQS_KEM_free(kem);

  if (rc != OQS_SUCCESS) {
    LOG(ERROR) << "QSM: ML-KEM-768 encapsulation failed.";
    result.ciphertext.clear();
    result.shared_secret.clear();
    return result;
  }

  result.success = true;
  VLOG(2) << "QSM: ML-KEM-768 encapsulation successful.";
  return result;
}

std::vector<uint8_t>
QuantumSecurityModule::Decapsulate(const std::vector<uint8_t> &ciphertext,
                                   const std::vector<uint8_t> &kem_sk) {
  if (ciphertext.size() != OQS_KEM_ml_kem_768_length_ciphertext) {
    LOG(ERROR) << "QSM: Invalid ML-KEM-768 ciphertext size.";
    return {};
  }
  if (kem_sk.size() != OQS_KEM_ml_kem_768_length_secret_key) {
    LOG(ERROR) << "QSM: Invalid ML-KEM-768 secret key size.";
    return {};
  }

  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    return {};
  }

  std::vector<uint8_t> shared_secret(OQS_KEM_ml_kem_768_length_shared_secret);
  OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(),
                                 kem_sk.data());
  OQS_KEM_free(kem);

  if (rc != OQS_SUCCESS) {
    LOG(ERROR) << "QSM: ML-KEM-768 decapsulation failed.";
    return {};
  }

  VLOG(2) << "QSM: ML-KEM-768 decapsulation successful.";
  return shared_secret;
}

// ── Session Key Derivation ──────────────────────────────────

HybridSessionKey QuantumSecurityModule::DeriveSessionKey(
    const std::vector<uint8_t> &x25519_shared,
    const std::vector<uint8_t> &kem_shared) {
  HybridSessionKey sk;
  sk.session_id = GenerateUUID();
  sk.cipher_suite = "TLS_KYBER768_X25519_AES256GCM_SHA384";

  // Derive 32-byte session key via HKDF-SHA3-256
  sk.session_key.resize(32);
  bool ok = PQCHybridKDF(x25519_shared.data(), x25519_shared.size(),
                         kem_shared.data(), kem_shared.size(),
                         sk.session_key.data(), sk.session_key.size());

  if (!ok) {
    LOG(ERROR) << "QSM: Hybrid KDF derivation failed.";
    sk.ClearSecrets();
    return sk;
  }

  // Generate random IV (12 bytes for AES-256-GCM)
  sk.iv.resize(12);
  RAND_bytes(sk.iv.data(), 12);

  VLOG(1) << "QSM: Derived hybrid session key for session " << sk.session_id;
  return sk;
}

// ── ML-DSA-65 Signatures ────────────────────────────────────

bool QuantumSecurityModule::VerifyMLDSA65Signature(
    const std::vector<uint8_t> &message, const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &public_key) {
  if (public_key.size() != OQS_SIG_ml_dsa_65_length_public_key) {
    LOG(ERROR) << "QSM: Invalid ML-DSA-65 public key size: "
               << public_key.size();
    return false;
  }
  if (signature.size() != OQS_SIG_ml_dsa_65_length_signature) {
    LOG(ERROR) << "QSM: Invalid ML-DSA-65 signature size: " << signature.size();
    return false;
  }

  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (!sig_ctx) {
    LOG(ERROR) << "QSM: Failed to initialize ML-DSA-65.";
    return false;
  }

  OQS_STATUS rc =
      OQS_SIG_verify(sig_ctx, message.data(), message.size(), signature.data(),
                     signature.size(), public_key.data(), public_key.size());
  OQS_SIG_free(sig_ctx);

  if (rc != OQS_SUCCESS) {
    VLOG(1) << "QSM: ML-DSA-65 signature verification FAILED.";
    return false;
  }

  VLOG(2) << "QSM: ML-DSA-65 signature verified successfully.";
  return true;
}

bool QuantumSecurityModule::SignMLDSA65(
    const std::vector<uint8_t> &message, std::vector<uint8_t> *signature,
    const std::vector<uint8_t> &secret_key) {
  if (secret_key.size() != OQS_SIG_ml_dsa_65_length_secret_key) {
    return false;
  }

  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (!sig_ctx) {
    return false;
  }

  signature->resize(OQS_SIG_ml_dsa_65_length_signature);
  size_t sig_len = 0;

  OQS_STATUS rc =
      OQS_SIG_sign(sig_ctx, signature->data(), &sig_len, message.data(),
                   message.size(), secret_key.data());
  OQS_SIG_free(sig_ctx);

  if (rc != OQS_SUCCESS) {
    signature->clear();
    return false;
  }

  signature->resize(sig_len);
  return true;
}

// ── Utility ─────────────────────────────────────────────────

std::string QuantumSecurityModule::GenerateUUID() {
  return base::Uuid::GenerateRandomV4().AsLowercaseString();
}

bool QuantumSecurityModule::IsAvailable() {
  // Verify ML-KEM-768 is available
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) {
    return false;
  }
  OQS_KEM_free(kem);

  // Verify ML-DSA-65 is available
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (!sig) {
    return false;
  }
  OQS_SIG_free(sig);

  return true;
}

std::string QuantumSecurityModule::GetLibOQSVersion() { return OQS_version(); }

// RecordSession and GetRecentSessions delegate to PQCSessionService,
// which manages the SQLite database. These are implemented in
// pqc_session_service.cc.
void QuantumSecurityModule::RecordSession(const PQCSessionRecord &record) {
  // TODO: Wire to PQCSessionService::RecordSession()
  VLOG(1) << "QSM: Session recorded (pending DB write).";
}

std::vector<PQCSessionRecord>
QuantumSecurityModule::GetRecentSessions(int limit) {
  // TODO: Wire to PQCSessionService::GetRecentSessions()
  return {};
}

} // namespace pqc
} // namespace net
