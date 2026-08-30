# ADR-005 — Crypto-Agility Architecture

**Status**: Accepted
**Date**: 2026-08-22
**Authors**: KryptonBrowser Team

---

## Context

Post-quantum cryptography is in active standardisation. NIST finalised ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in August 2024, but:

1. Parameter sets may be revised or deprecated as cryptanalysis matures.
2. Hybrid classical/PQC deployments are required during the migration period.
3. Different threat models require different security levels (128-bit vs 192-bit vs 256-bit equivalent).

Hard-coding a single algorithm locks the browser into an algorithm that may be deprecated, weakened, or simply suboptimal for a future use case.

## Decision

Implement **crypto-agility** at every layer of the PQC stack:

### 1. Native addon — parameterised algorithm dispatch

The liboqs N-API addon exposes:

```c++
// Agile KEM — algorithm name passed as string
Napi::Value KemKeygenAgile(const Napi::CallbackInfo& info) {
  std::string algorithm = info[0].As<Napi::String>();
  OQS_KEM *kem = OQS_KEM_new(algorithm.c_str());
  // ... keygen ...
  OQS_KEM_free(kem);
}
```

Supported algorithms at compile time (CMakeLists.txt `OQS_MINIMAL_BUILD`):

| Family | Variants |
|--------|---------|
| ML-KEM | 512 (NIST Level 1), 768 (Level 3), 1024 (Level 5) |
| ML-DSA | 44 (Level 2), 65 (Level 3), 87 (Level 5) |

### 2. Engine wrapper — algorithm-agile methods

```js
// pqc-engine.js
kemKeygenAgile(algorithm = 'ML-KEM-768')  { ... }
kemEncapsulateAgile(algorithm, publicKey) { ... }
kemDecapsulateAgile(algorithm, ct, sk)    { ... }
dsaKeygenAgile(algorithm = 'ML-DSA-65')  { ... }
getEnabledAlgorithms()                   { ... }
```

### 3. Config keys — user-selectable defaults

| Key | Default | Values |
|-----|---------|--------|
| `krypton_kem_algorithm` | `ML-KEM-768` | ML-KEM-512/768/1024 |
| `krypton_sig_algorithm` | `ML-DSA-65` | ML-DSA-44/65/87 |
| `krypton_hybrid_mode` | `true` | true/false |

### 4. IPC channels

- `pqc-keygen-agile(algorithm)`
- `pqc-encapsulate-agile(algorithm, pk)`
- `pqc-decapsulate-agile(algorithm, ct, sk)`  — returns only timing, not shared secret
- `pqc-dsa-keygen-agile(algorithm)`
- `pqc-get-algorithms()` — returns the list of compiled-in algorithms

### 5. Algorithm switching at runtime

The PQC Security dashboard's Algorithms section lets the user select a KEM and DSA variant. Selection persists via `krypton_kem_algorithm` / `krypton_sig_algorithm` config keys. The engine reads this at handshake initiation time.

### 6. Benchmark infrastructure

`pqc-benchmark-service.js` uses `process.hrtime.bigint()` to measure keygen/encaps/decaps/sign/verify latency across all 6 variants, reporting min/max/mean/median/p95/stddev in microseconds. This gives the user objective data to guide algorithm selection.

### Default: ML-KEM-768 + ML-DSA-65

These are the NIST recommended defaults offering NIST Security Level 3 (equivalent to AES-192). Rationale:
- Level 3 provides a comfortable security margin above NSA CNSA 2.0 requirements.
- Key and ciphertext sizes are practical for TLS handshake integration.
- liboqs test vectors confirm correct implementation.

## Consequences

**Positive:**
- Future NIST revisions (e.g., ML-KEM-1024 becoming the mandatory minimum) require only a config change, not a code change.
- Benchmark data lets users and operators make evidence-based algorithm choices.
- The IPC boundary is algorithm-independent — no renderer changes are required when adding a new algorithm to the native addon.

**Negative:**
- Each new algorithm requires a CMakeLists.txt rebuild (+~4 MB binary for 2 new variants). This is a one-time cost per deploy.
- Algorithm dispatch via string lookup adds one `OQS_KEM_new()` / `OQS_KEM_free()` pair per operation vs. compile-time constant. Overhead is negligible (<1 µs on M1/M2).

## Algorithm Size Reference

| Algorithm | Public Key | Secret Key | Ciphertext / Signature |
|-----------|-----------|-----------|------------------------|
| ML-KEM-512 | 800 B | 1632 B | 768 B |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B |
| ML-DSA-44 | 1312 B | 2528 B | 2420 B |
| ML-DSA-65 | 1952 B | 4000 B | 3309 B |
| ML-DSA-87 | 2592 B | 4864 B | 4627 B |
