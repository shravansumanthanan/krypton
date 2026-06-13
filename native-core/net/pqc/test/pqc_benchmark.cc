// Copyright 2025 The ArjunBrowser Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PQC Performance Benchmarks — Google Benchmark suite.

#include "benchmark/benchmark.h"

#include "net/pqc/quantum_security_module.h"
#include "net/ssl/pqc_hybrid_kdf.h"

extern "C" {
#include "oqs/oqs.h"
}

#include "openssl/curve25519.h"

namespace net {
namespace pqc {

// ═══════════════════════════════════════════════════════════════
// ML-KEM-768 Benchmarks
// ═══════════════════════════════════════════════════════════════

static void BM_ML_KEM_768_Keygen(benchmark::State &state) {
  for (auto _ : state) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    uint8_t pk[1184], sk[2400];
    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_free(kem);
    benchmark::DoNotOptimize(pk);
    benchmark::DoNotOptimize(sk);
  }
}
BENCHMARK(BM_ML_KEM_768_Keygen)->Iterations(10000);

static void BM_ML_KEM_768_Encaps(benchmark::State &state) {
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  uint8_t pk[1184], sk[2400];
  OQS_KEM_keypair(kem, pk, sk);

  for (auto _ : state) {
    uint8_t ct[1088], ss[32];
    OQS_KEM_encaps(kem, ct, ss, pk);
    benchmark::DoNotOptimize(ct);
    benchmark::DoNotOptimize(ss);
  }
  OQS_KEM_free(kem);
}
BENCHMARK(BM_ML_KEM_768_Encaps)->Iterations(10000);

static void BM_ML_KEM_768_Decaps(benchmark::State &state) {
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  uint8_t pk[1184], sk[2400], ct[1088], ss_enc[32];
  OQS_KEM_keypair(kem, pk, sk);
  OQS_KEM_encaps(kem, ct, ss_enc, pk);

  for (auto _ : state) {
    uint8_t ss_dec[32];
    OQS_KEM_decaps(kem, ss_dec, ct, sk);
    benchmark::DoNotOptimize(ss_dec);
  }
  OQS_KEM_free(kem);
}
BENCHMARK(BM_ML_KEM_768_Decaps)->Iterations(10000);

// ═══════════════════════════════════════════════════════════════
// ML-DSA-65 Benchmarks
// ═══════════════════════════════════════════════════════════════

static void BM_ML_DSA_65_Sign(benchmark::State &state) {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  uint8_t pk[1952], sk[4032];
  OQS_SIG_keypair(sig, pk, sk);

  uint8_t msg[64];
  memset(msg, 0x42, sizeof(msg));

  for (auto _ : state) {
    uint8_t signature[3309];
    size_t sig_len = 0;
    OQS_SIG_sign(sig, signature, &sig_len, msg, sizeof(msg), sk);
    benchmark::DoNotOptimize(signature);
  }
  OQS_SIG_free(sig);
}
BENCHMARK(BM_ML_DSA_65_Sign)->Iterations(10000);

static void BM_ML_DSA_65_Verify(benchmark::State &state) {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  uint8_t pk[1952], sk[4032];
  OQS_SIG_keypair(sig, pk, sk);

  uint8_t msg[64];
  memset(msg, 0x42, sizeof(msg));
  uint8_t signature[3309];
  size_t sig_len = 0;
  OQS_SIG_sign(sig, signature, &sig_len, msg, sizeof(msg), sk);

  for (auto _ : state) {
    OQS_STATUS rc = OQS_SIG_verify(sig, msg, sizeof(msg), signature, sig_len,
                                   pk, sizeof(pk));
    benchmark::DoNotOptimize(rc);
  }
  OQS_SIG_free(sig);
}
BENCHMARK(BM_ML_DSA_65_Verify)->Iterations(10000);

// ═══════════════════════════════════════════════════════════════
// Hybrid KDF Benchmark
// ═══════════════════════════════════════════════════════════════

static void BM_HybridKDF(benchmark::State &state) {
  uint8_t x25519[32], kem[32], out[32];
  memset(x25519, 0xAA, 32);
  memset(kem, 0xBB, 32);

  for (auto _ : state) {
    PQCHybridKDF(x25519, 32, kem, 32, out, 32);
    benchmark::DoNotOptimize(out);
  }
}
BENCHMARK(BM_HybridKDF)->Iterations(100000);

// ═══════════════════════════════════════════════════════════════
// Full Handshake Benchmark (Crypto Only)
// ═══════════════════════════════════════════════════════════════

static void BM_FullHandshake_CryptoOnly(benchmark::State &state) {
  for (auto _ : state) {
    // 1. Generate X25519 + ML-KEM-768 keypairs (client)
    auto client_kp = QuantumSecurityModule::GenerateHybridKeypair();

    // 2. Encapsulate (server side)
    auto encap = QuantumSecurityModule::Encapsulate(client_kp.kem_public_key);

    // 3. Decapsulate (client side)
    auto kem_ss = QuantumSecurityModule::Decapsulate(encap.ciphertext,
                                                     client_kp.kem_secret_key);

    // 4. X25519 DH (simulated)
    uint8_t x25519_ss[32];
    memset(x25519_ss, 0xAA, 32);

    // 5. Derive session key
    auto session_key = QuantumSecurityModule::DeriveSessionKey(
        std::vector<uint8_t>(x25519_ss, x25519_ss + 32), kem_ss);

    benchmark::DoNotOptimize(session_key);
    client_kp.ClearSecrets();
    session_key.ClearSecrets();
  }
}
BENCHMARK(BM_FullHandshake_CryptoOnly)->Iterations(1000);

} // namespace pqc
} // namespace net

BENCHMARK_MAIN();
