// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Quantum Security Module (QSM) — Central PQC component.
//
// This is "Process 2.0: Quantum Security Module" from the DA3 Level-1 DFD.
// It is the single entry point for all post-quantum cryptographic operations
// in ArjunBrowser.
//
// ISOLATION: The QSM runs ONLY in the network process
// (//services/network). It NEVER runs in the renderer process. Raw key
// material never crosses process boundaries; only session_id tokens are
// passed to the renderer via Mojo IPC.
//
// This module provides:
//   - Hybrid keypair generation (X25519 + ML-KEM-768)
//   - ML-KEM-768 encapsulation/decapsulation
//   - ML-DSA-65 signature verification
//   - HKDF-SHA3-256 session key derivation
//   - Session tracking via SQLite (PQCSessionRecord)

#ifndef NET_PQC_QUANTUM_SECURITY_MODULE_H_
#define NET_PQC_QUANTUM_SECURITY_MODULE_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "base/time/time.h"

namespace net {
namespace pqc {

// Forward declarations
class PQCSessionRecord;

// Result of ML-KEM-768 encapsulation.
struct EncapsulationResult {
  // ML-KEM-768 ciphertext (1088 bytes)
  std::vector<uint8_t> ciphertext;
  // Raw KEM shared secret (32 bytes)
  std::vector<uint8_t> shared_secret;
  // Whether encapsulation succeeded
  bool success = false;
};

// Combined hybrid keypair (X25519 + ML-KEM-768).
struct HybridKeyPair {
  // ML-KEM-768 public key (1184 bytes, NIST FIPS 203)
  std::vector<uint8_t> kem_public_key;
  // ML-KEM-768 secret key (2400 bytes)
  std::vector<uint8_t> kem_secret_key;
  // X25519 public key (32 bytes, RFC 7748)
  std::vector<uint8_t> x25519_public;
  // X25519 private key (32 bytes)
  std::vector<uint8_t> x25519_private;
  // Timestamp of generation
  base::Time generated_at;
  // Unique ID for tracking
  std::string key_id;

  // Zero out all secret key material
  void ClearSecrets();

  // Returns true if the keypair is valid (all components present)
  bool IsValid() const;
};

// Derived session key from hybrid handshake.
struct HybridSessionKey {
  // 32-byte AES-256-GCM session key
  std::vector<uint8_t> session_key;
  // 12-byte GCM initialization vector
  std::vector<uint8_t> iv;
  // Cipher suite string
  std::string cipher_suite;
  // Handshake duration
  base::TimeDelta handshake_duration;
  // Session identifier (UUID v4)
  std::string session_id;
  // Whether Indigenous PKI was verified
  bool indigenous_verified = false;
  // Name of the verifying CA
  std::string ca_name;

  void ClearSecrets();
};

// ──────────────────────────────────────────────────────────────
// QuantumSecurityModule — The central PQC cryptographic engine.
// ──────────────────────────────────────────────────────────────
class QuantumSecurityModule {
public:
  QuantumSecurityModule();
  ~QuantumSecurityModule();

  // Non-copyable
  QuantumSecurityModule(const QuantumSecurityModule &) = delete;
  QuantumSecurityModule &operator=(const QuantumSecurityModule &) = delete;

  // ── Key Lifecycle ──────────────────────────────────────────

  // Generate a new hybrid keypair (X25519 + ML-KEM-768).
  // Thread-safe; can be called from any thread.
  static HybridKeyPair GenerateHybridKeypair();

  // Generate a deterministic hybrid keypair for testing (KAT vectors).
  // NOT for production use.
  static HybridKeyPair
  GenerateDeterministicKeypair(const std::vector<uint8_t> &seed);

  // ── ML-KEM-768 Operations ─────────────────────────────────

  // Encapsulate: given a peer's ML-KEM-768 public key, produce a
  // ciphertext and shared secret.
  static EncapsulationResult
  Encapsulate(const std::vector<uint8_t> &peer_kem_pk);

  // Decapsulate: given a ciphertext and our secret key, recover
  // the shared secret.
  static std::vector<uint8_t>
  Decapsulate(const std::vector<uint8_t> &ciphertext,
              const std::vector<uint8_t> &kem_sk);

  // ── Session Key Derivation ────────────────────────────────

  // Derive a hybrid session key from X25519 and ML-KEM-768 shared secrets.
  // Uses HKDF-SHA3-256 (via PQCHybridKDF).
  static HybridSessionKey
  DeriveSessionKey(const std::vector<uint8_t> &x25519_shared,
                   const std::vector<uint8_t> &kem_shared);

  // ── ML-DSA-65 Signature Verification ──────────────────────

  // Verify an ML-DSA-65 (NIST FIPS 204) signature on a message.
  static bool VerifyMLDSA65Signature(const std::vector<uint8_t> &message,
                                     const std::vector<uint8_t> &signature,
                                     const std::vector<uint8_t> &public_key);

  // Sign a message with ML-DSA-65 (for test CA cert generation).
  static bool SignMLDSA65(const std::vector<uint8_t> &message,
                          std::vector<uint8_t> *signature,
                          const std::vector<uint8_t> &secret_key);

  // ── Session Tracking ──────────────────────────────────────

  // Record a completed handshake session to the SQLite database.
  static void RecordSession(const PQCSessionRecord &record);

  // Retrieve recent handshake sessions from the database.
  static std::vector<PQCSessionRecord> GetRecentSessions(int limit = 50);

  // ── Utility ───────────────────────────────────────────────

  // Generate a UUID v4 string for session/key identification.
  static std::string GenerateUUID();

  // Returns true if liboqs is properly initialized and the required
  // algorithms are available.
  static bool IsAvailable();

  // Get the version string of the underlying liboqs library.
  static std::string GetLibOQSVersion();

private:
  // Internal initialization state
  bool initialized_ = false;
};

} // namespace pqc
} // namespace net

#endif // NET_PQC_QUANTUM_SECURITY_MODULE_H_
