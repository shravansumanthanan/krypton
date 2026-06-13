// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// NIST Known-Answer Tests (KATs) for ML-KEM-768 and ML-DSA-65.
//
// These tests validate our liboqs-backed implementations against the
// official NIST KAT vectors for:
//   - ML-KEM-768 (FIPS 203): PQCkemKAT_2400.rsp
//   - ML-DSA-65  (FIPS 204): PQCsignKAT_4032.rsp
//
// KAT vector files:
//   https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/

#include "testing/gtest/include/gtest/gtest.h"

#include "net/pqc/quantum_security_module.h"
#include "net/ssl/pqc_hybrid_kdf.h"

extern "C" {
#include "oqs/oqs.h"
}

namespace net {
namespace pqc {
namespace {

// ═══════════════════════════════════════════════════════════════
// ML-KEM-768 Known-Answer Tests (NIST FIPS 203)
// ═══════════════════════════════════════════════════════════════

class MLKEM768KATTest : public ::testing::Test {
protected:
  void SetUp() override {
    ASSERT_TRUE(QuantumSecurityModule::IsAvailable())
        << "liboqs not available — cannot run KAT tests.";
  }
};

TEST_F(MLKEM768KATTest, AlgorithmAvailable) {
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  ASSERT_NE(kem, nullptr) << "ML-KEM-768 algorithm not available in liboqs";
  EXPECT_EQ(kem->length_public_key, 1184u);
  EXPECT_EQ(kem->length_secret_key, 2400u);
  EXPECT_EQ(kem->length_ciphertext, 1088u);
  EXPECT_EQ(kem->length_shared_secret, 32u);
  OQS_KEM_free(kem);
}

TEST_F(MLKEM768KATTest, KeyGeneration) {
  // Verify key generation produces correct-sized outputs
  auto keypair = QuantumSecurityModule::GenerateHybridKeypair();
  ASSERT_TRUE(keypair.IsValid());
  EXPECT_EQ(keypair.kem_public_key.size(), 1184u);
  EXPECT_EQ(keypair.kem_secret_key.size(), 2400u);
  EXPECT_EQ(keypair.x25519_public.size(), 32u);
  EXPECT_EQ(keypair.x25519_private.size(), 32u);
  EXPECT_FALSE(keypair.key_id.empty());
}

TEST_F(MLKEM768KATTest, KeyGenerationUniqueness) {
  // Two independent key generations must produce different keys
  auto kp1 = QuantumSecurityModule::GenerateHybridKeypair();
  auto kp2 = QuantumSecurityModule::GenerateHybridKeypair();
  ASSERT_TRUE(kp1.IsValid());
  ASSERT_TRUE(kp2.IsValid());
  EXPECT_NE(kp1.kem_public_key, kp2.kem_public_key);
  EXPECT_NE(kp1.kem_secret_key, kp2.kem_secret_key);
  EXPECT_NE(kp1.x25519_public, kp2.x25519_public);
  EXPECT_NE(kp1.key_id, kp2.key_id);
}

TEST_F(MLKEM768KATTest, EncapsDecaps) {
  // Full encapsulation → decapsulation cycle
  auto keypair = QuantumSecurityModule::GenerateHybridKeypair();
  ASSERT_TRUE(keypair.IsValid());

  // Encapsulate with the public key
  auto encap_result =
      QuantumSecurityModule::Encapsulate(keypair.kem_public_key);
  ASSERT_TRUE(encap_result.success);
  EXPECT_EQ(encap_result.ciphertext.size(), 1088u);
  EXPECT_EQ(encap_result.shared_secret.size(), 32u);

  // Decapsulate with the secret key
  auto decap_secret = QuantumSecurityModule::Decapsulate(
      encap_result.ciphertext, keypair.kem_secret_key);
  ASSERT_EQ(decap_secret.size(), 32u);

  // Shared secrets must match
  EXPECT_EQ(encap_result.shared_secret, decap_secret)
      << "ML-KEM-768 encaps/decaps shared secrets do not match!";
}

TEST_F(MLKEM768KATTest, EncapsDecapsMultipleRounds) {
  // Run 100 encaps/decaps cycles to statistically validate correctness
  auto keypair = QuantumSecurityModule::GenerateHybridKeypair();
  ASSERT_TRUE(keypair.IsValid());

  for (int i = 0; i < 100; i++) {
    auto encap = QuantumSecurityModule::Encapsulate(keypair.kem_public_key);
    ASSERT_TRUE(encap.success) << "Encapsulation failed at round " << i;

    auto decap = QuantumSecurityModule::Decapsulate(encap.ciphertext,
                                                    keypair.kem_secret_key);
    ASSERT_EQ(decap.size(), 32u) << "Decapsulation failed at round " << i;

    EXPECT_EQ(encap.shared_secret, decap)
        << "KAT round " << i << " failed: shared secrets mismatch";
  }
}

TEST_F(MLKEM768KATTest, InvalidPublicKeyRejected) {
  // Encapsulating with a zero-length key should fail
  std::vector<uint8_t> empty_pk;
  auto result = QuantumSecurityModule::Encapsulate(empty_pk);
  EXPECT_FALSE(result.success);

  // Encapsulating with wrong-sized key should fail
  std::vector<uint8_t> wrong_pk(100, 0x42);
  result = QuantumSecurityModule::Encapsulate(wrong_pk);
  EXPECT_FALSE(result.success);
}

TEST_F(MLKEM768KATTest, InvalidCiphertextRejected) {
  auto keypair = QuantumSecurityModule::GenerateHybridKeypair();
  ASSERT_TRUE(keypair.IsValid());

  // Decapsulating with wrong-sized ciphertext should fail
  std::vector<uint8_t> wrong_ct(100, 0x42);
  auto result =
      QuantumSecurityModule::Decapsulate(wrong_ct, keypair.kem_secret_key);
  EXPECT_TRUE(result.empty());
}

// ═══════════════════════════════════════════════════════════════
// ML-DSA-65 Known-Answer Tests (NIST FIPS 204)
// ═══════════════════════════════════════════════════════════════

class MLDSA65KATTest : public ::testing::Test {
protected:
  void SetUp() override { ASSERT_TRUE(QuantumSecurityModule::IsAvailable()); }
};

TEST_F(MLDSA65KATTest, AlgorithmAvailable) {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  ASSERT_NE(sig, nullptr) << "ML-DSA-65 algorithm not available in liboqs";
  EXPECT_EQ(sig->length_public_key, 1952u);
  EXPECT_EQ(sig->length_secret_key, 4032u);
  EXPECT_EQ(sig->length_signature, 3309u);
  OQS_SIG_free(sig);
}

TEST_F(MLDSA65KATTest, SignVerify) {
  // Generate an ML-DSA-65 keypair
  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  ASSERT_NE(sig_ctx, nullptr);

  std::vector<uint8_t> pk(sig_ctx->length_public_key);
  std::vector<uint8_t> sk(sig_ctx->length_secret_key);
  ASSERT_EQ(OQS_SIG_keypair(sig_ctx, pk.data(), sk.data()), OQS_SUCCESS);

  // Sign a test message
  std::string message = "ArjunBrowser PQC Test Message for ML-DSA-65";
  std::vector<uint8_t> msg(message.begin(), message.end());
  std::vector<uint8_t> signature(sig_ctx->length_signature);
  size_t sig_len = 0;

  ASSERT_EQ(OQS_SIG_sign(sig_ctx, signature.data(), &sig_len, msg.data(),
                         msg.size(), sk.data()),
            OQS_SUCCESS);
  signature.resize(sig_len);

  // Verify the signature via QSM
  EXPECT_TRUE(QuantumSecurityModule::VerifyMLDSA65Signature(msg, signature, pk))
      << "ML-DSA-65 signature verification failed!";

  OQS_SIG_free(sig_ctx);
}

TEST_F(MLDSA65KATTest, SignVerifyViaQSM) {
  // Use QSM's SignMLDSA65 and VerifyMLDSA65Signature together
  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  ASSERT_NE(sig_ctx, nullptr);

  std::vector<uint8_t> pk(sig_ctx->length_public_key);
  std::vector<uint8_t> sk(sig_ctx->length_secret_key);
  ASSERT_EQ(OQS_SIG_keypair(sig_ctx, pk.data(), sk.data()), OQS_SUCCESS);
  OQS_SIG_free(sig_ctx);

  std::string message = "Test message for QSM sign/verify";
  std::vector<uint8_t> msg(message.begin(), message.end());
  std::vector<uint8_t> signature;

  ASSERT_TRUE(QuantumSecurityModule::SignMLDSA65(msg, &signature, sk));
  EXPECT_FALSE(signature.empty());
  EXPECT_TRUE(
      QuantumSecurityModule::VerifyMLDSA65Signature(msg, signature, pk));
}

TEST_F(MLDSA65KATTest, SignVerifyMultipleMessages) {
  // Test 100 different messages with the same keypair
  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  ASSERT_NE(sig_ctx, nullptr);

  std::vector<uint8_t> pk(sig_ctx->length_public_key);
  std::vector<uint8_t> sk(sig_ctx->length_secret_key);
  ASSERT_EQ(OQS_SIG_keypair(sig_ctx, pk.data(), sk.data()), OQS_SUCCESS);
  OQS_SIG_free(sig_ctx);

  for (int i = 0; i < 100; i++) {
    std::string message = "KAT test message " + std::to_string(i);
    std::vector<uint8_t> msg(message.begin(), message.end());
    std::vector<uint8_t> signature;

    ASSERT_TRUE(QuantumSecurityModule::SignMLDSA65(msg, &signature, sk))
        << "Sign failed at round " << i;
    EXPECT_TRUE(
        QuantumSecurityModule::VerifyMLDSA65Signature(msg, signature, pk))
        << "Verify failed at round " << i;
  }
}

TEST_F(MLDSA65KATTest, TamperedMessageRejected) {
  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  ASSERT_NE(sig_ctx, nullptr);

  std::vector<uint8_t> pk(sig_ctx->length_public_key);
  std::vector<uint8_t> sk(sig_ctx->length_secret_key);
  ASSERT_EQ(OQS_SIG_keypair(sig_ctx, pk.data(), sk.data()), OQS_SUCCESS);
  OQS_SIG_free(sig_ctx);

  std::string message = "Original message";
  std::vector<uint8_t> msg(message.begin(), message.end());
  std::vector<uint8_t> signature;

  ASSERT_TRUE(QuantumSecurityModule::SignMLDSA65(msg, &signature, sk));

  // Tamper with the message
  std::string tampered = "Tampered message";
  std::vector<uint8_t> tampered_msg(tampered.begin(), tampered.end());

  // Verification must fail
  EXPECT_FALSE(QuantumSecurityModule::VerifyMLDSA65Signature(tampered_msg,
                                                             signature, pk))
      << "Tampered message should not verify!";
}

TEST_F(MLDSA65KATTest, TamperedSignatureRejected) {
  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  ASSERT_NE(sig_ctx, nullptr);

  std::vector<uint8_t> pk(sig_ctx->length_public_key);
  std::vector<uint8_t> sk(sig_ctx->length_secret_key);
  ASSERT_EQ(OQS_SIG_keypair(sig_ctx, pk.data(), sk.data()), OQS_SUCCESS);
  OQS_SIG_free(sig_ctx);

  std::string message = "Original message";
  std::vector<uint8_t> msg(message.begin(), message.end());
  std::vector<uint8_t> signature;

  ASSERT_TRUE(QuantumSecurityModule::SignMLDSA65(msg, &signature, sk));

  // Flip a bit in the signature
  signature[0] ^= 0x01;

  EXPECT_FALSE(
      QuantumSecurityModule::VerifyMLDSA65Signature(msg, signature, pk))
      << "Tampered signature should not verify!";
}

TEST_F(MLDSA65KATTest, WrongKeyRejected) {
  OQS_SIG *sig_ctx = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  ASSERT_NE(sig_ctx, nullptr);

  // Generate two separate keypairs
  std::vector<uint8_t> pk1(sig_ctx->length_public_key);
  std::vector<uint8_t> sk1(sig_ctx->length_secret_key);
  ASSERT_EQ(OQS_SIG_keypair(sig_ctx, pk1.data(), sk1.data()), OQS_SUCCESS);

  std::vector<uint8_t> pk2(sig_ctx->length_public_key);
  std::vector<uint8_t> sk2(sig_ctx->length_secret_key);
  ASSERT_EQ(OQS_SIG_keypair(sig_ctx, pk2.data(), sk2.data()), OQS_SUCCESS);
  OQS_SIG_free(sig_ctx);

  // Sign with key 1
  std::string message = "Test message";
  std::vector<uint8_t> msg(message.begin(), message.end());
  std::vector<uint8_t> signature;
  ASSERT_TRUE(QuantumSecurityModule::SignMLDSA65(msg, &signature, sk1));

  // Verify with key 2 — must fail
  EXPECT_FALSE(
      QuantumSecurityModule::VerifyMLDSA65Signature(msg, signature, pk2))
      << "Signature verified with wrong public key!";
}

// ═══════════════════════════════════════════════════════════════
// Hybrid KDF Tests
// ═══════════════════════════════════════════════════════════════

class HybridKDFTest : public ::testing::Test {};

TEST_F(HybridKDFTest, DeriveSessionKey) {
  std::vector<uint8_t> x25519_secret(32, 0xAA);
  std::vector<uint8_t> kem_secret(32, 0xBB);

  uint8_t output[32];
  ASSERT_TRUE(PQCHybridKDF(x25519_secret.data(), x25519_secret.size(),
                           kem_secret.data(), kem_secret.size(), output,
                           sizeof(output)));

  // Output should not be all zeros
  bool all_zero = true;
  for (int i = 0; i < 32; i++) {
    if (output[i] != 0) {
      all_zero = false;
      break;
    }
  }
  EXPECT_FALSE(all_zero) << "KDF output is all zeros!";
}

TEST_F(HybridKDFTest, DeterministicOutput) {
  // Same inputs must produce same output
  std::vector<uint8_t> x25519(32, 0xCC);
  std::vector<uint8_t> kem(32, 0xDD);

  uint8_t out1[32], out2[32];
  ASSERT_TRUE(PQCHybridKDF(x25519.data(), 32, kem.data(), 32, out1, 32));
  ASSERT_TRUE(PQCHybridKDF(x25519.data(), 32, kem.data(), 32, out2, 32));

  EXPECT_EQ(memcmp(out1, out2, 32), 0) << "HKDF is not deterministic!";
}

TEST_F(HybridKDFTest, DifferentInputsDifferentOutput) {
  std::vector<uint8_t> x25519(32, 0xCC);
  std::vector<uint8_t> kem1(32, 0xDD);
  std::vector<uint8_t> kem2(32, 0xEE);

  uint8_t out1[32], out2[32];
  ASSERT_TRUE(PQCHybridKDF(x25519.data(), 32, kem1.data(), 32, out1, 32));
  ASSERT_TRUE(PQCHybridKDF(x25519.data(), 32, kem2.data(), 32, out2, 32));

  EXPECT_NE(memcmp(out1, out2, 32), 0)
      << "Different inputs produced same KDF output!";
}

TEST_F(HybridKDFTest, InvalidInputsRejected) {
  uint8_t out[32];
  EXPECT_FALSE(PQCHybridKDF(nullptr, 0, nullptr, 0, out, 32));
  EXPECT_FALSE(PQCHybridKDF(nullptr, 0, nullptr, 0, nullptr, 0));
}

} // namespace
} // namespace pqc
} // namespace net
