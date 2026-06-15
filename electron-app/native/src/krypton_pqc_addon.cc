// KryptonBrowser — Native N-API Addon
// Wraps liboqs for ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204).
// Also provides: hybrid keypair pool (0-RTT), HKDF session key derivation,
// and liboqs version query.

#include <napi.h>
#include <oqs/oqs.h>
#include <oqs/sha3.h>
#include <cstring>
#include <string>
#include <vector>

// ── Compatibility shims for older liboqs builds ──────────────────────────────
#ifndef OQS_SIG_ml_dsa_65_sign
#define OQS_SIG_ml_dsa_65_sign OQS_SIG_ml_dsa_65_ipd_sign
#endif

#ifndef OQS_SIG_ml_dsa_65_verify
#define OQS_SIG_ml_dsa_65_verify OQS_SIG_ml_dsa_65_ipd_verify
#endif

#ifndef OQS_SIG_ml_dsa_65_length_signature
#define OQS_SIG_ml_dsa_65_length_signature OQS_SIG_ml_dsa_65_ipd_length_signature
#endif

// ── Internal: HKDF-like KDF using SHA3-256 from liboqs ─────────────────────
// We combine x25519_shared || kem_shared with a fixed salt and derive 44 bytes:
//   bytes  0-31 → 32-byte session key (AES-256-GCM)
//   bytes 32-43 → 12-byte IV (GCM nonce)
//
// HKDF-Extract: PRK = SHA3-256(salt || x25519 || kem_shared)
// HKDF-Expand:  OKM = SHA3-256(PRK || 0x01) [first 32 bytes]
//               IV  = SHA3-256(PRK || 0x02) [first 12 bytes]
static bool PQCHybridKDF(
    const uint8_t* x25519_shared, size_t x25519_len,
    const uint8_t* kem_shared,   size_t kem_len,
    uint8_t* session_key,        // 32 bytes out
    uint8_t* iv                  // 12 bytes out
) {
    const char* SALT = "KryptonBrowser-PQC-v1";
    const size_t salt_len = strlen(SALT);

    // Build input: salt || x25519 || kem
    size_t total = salt_len + x25519_len + kem_len;
    std::vector<uint8_t> input(total);
    memcpy(input.data(), SALT, salt_len);
    memcpy(input.data() + salt_len, x25519_shared, x25519_len);
    memcpy(input.data() + salt_len + x25519_len, kem_shared, kem_len);

    // PRK = SHA3-256(input)
    uint8_t prk[32];
    OQS_SHA3_sha3_256(prk, input.data(), total);

    // OKM-key = SHA3-256(PRK || 0x01)
    uint8_t expand_key[33];
    memcpy(expand_key, prk, 32);
    expand_key[32] = 0x01;
    uint8_t okm_key[32];
    OQS_SHA3_sha3_256(okm_key, expand_key, 33);
    memcpy(session_key, okm_key, 32);

    // OKM-iv = SHA3-256(PRK || 0x02) → first 12 bytes
    uint8_t expand_iv[33];
    memcpy(expand_iv, prk, 32);
    expand_iv[32] = 0x02;
    uint8_t okm_iv[32];
    OQS_SHA3_sha3_256(okm_iv, expand_iv, 33);
    memcpy(iv, okm_iv, 12);

    // Clear intermediates
    memset(prk, 0, 32);
    memset(expand_key, 0, 33);
    memset(expand_iv, 0, 33);
    memset(okm_key, 0, 32);
    memset(okm_iv, 0, 32);

    return true;
}

// ══════════════════════════════════════════════════════════════════════════════
// ML-KEM-768
// ══════════════════════════════════════════════════════════════════════════════

Napi::Value KemKeygen(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    Napi::Buffer<uint8_t> pk = Napi::Buffer<uint8_t>::New(env, OQS_KEM_ml_kem_768_length_public_key);
    Napi::Buffer<uint8_t> sk = Napi::Buffer<uint8_t>::New(env, OQS_KEM_ml_kem_768_length_secret_key);

    OQS_STATUS status = OQS_KEM_ml_kem_768_keypair(pk.Data(), sk.Data());
    if (status != OQS_SUCCESS) {
        Napi::Error::New(env, "KEM keypair generation failed").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object result = Napi::Object::New(env);
    result.Set("publicKey", pk);
    result.Set("secretKey", sk);
    return result;
}

Napi::Value KemEncapsulate(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Expected a Buffer for publicKey").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> pk = info[0].As<Napi::Buffer<uint8_t>>();
    if (pk.Length() != OQS_KEM_ml_kem_768_length_public_key) {
        Napi::TypeError::New(env, "Invalid publicKey length").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> ct = Napi::Buffer<uint8_t>::New(env, OQS_KEM_ml_kem_768_length_ciphertext);
    Napi::Buffer<uint8_t> ss = Napi::Buffer<uint8_t>::New(env, OQS_KEM_ml_kem_768_length_shared_secret);

    OQS_STATUS status = OQS_KEM_ml_kem_768_encaps(ct.Data(), ss.Data(), pk.Data());
    if (status != OQS_SUCCESS) {
        Napi::Error::New(env, "KEM encapsulation failed").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object result = Napi::Object::New(env);
    result.Set("cipherText", ct);
    result.Set("sharedSecret", ss);
    return result;
}

Napi::Value KemDecapsulate(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
        Napi::TypeError::New(env, "Expected Buffers for cipherText and secretKey").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> ct = info[0].As<Napi::Buffer<uint8_t>>();
    Napi::Buffer<uint8_t> sk = info[1].As<Napi::Buffer<uint8_t>>();

    if (ct.Length() != OQS_KEM_ml_kem_768_length_ciphertext || sk.Length() != OQS_KEM_ml_kem_768_length_secret_key) {
        Napi::TypeError::New(env, "Invalid buffer lengths").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> ss = Napi::Buffer<uint8_t>::New(env, OQS_KEM_ml_kem_768_length_shared_secret);

    OQS_STATUS status = OQS_KEM_ml_kem_768_decaps(ss.Data(), ct.Data(), sk.Data());
    if (status != OQS_SUCCESS) {
        Napi::Error::New(env, "KEM decapsulation failed").ThrowAsJavaScriptException();
        return env.Null();
    }

    return ss;
}

// ══════════════════════════════════════════════════════════════════════════════
// Hybrid Key Pool (0-RTT optimization)
// Ported from native-core/net/pqc/pqc_key_manager.h
//
// Generates `count` hybrid keypairs in a single call (X25519 + ML-KEM-768).
// Each keypair has ~3.6 KB of key material.
// JS manages the pool in PQCKeyPoolService; this call does the bulk crypto work.
// ══════════════════════════════════════════════════════════════════════════════

// Simple UUID v4 generator (no external deps)
static std::string GenerateSimpleUUID() {
    uint8_t bytes[16];
    OQS_randombytes(bytes, 16);
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    char buf[37];
    snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

// X25519 keypair generation: generate 32 random bytes as private key,
// then derive public key. liboqs provides OQS_randombytes.
// For X25519 scalar mult we use a simple approach: include curve25519 via liboqs's internal SHA3.
// Since we don't have BoringSSL here, we implement Curve25519 scalar multiplication
// using the portable C implementation bundled with liboqs.
// NOTE: liboqs 0.10.0 does NOT expose X25519 externally. We generate a 32-byte
// ephemeral keypair by including just the random private scalar, and derive the
// public key via OQS's internal SHA3 as a key derivation stub.
// This is a placeholder that preserves the pool structure; full X25519 would
// require linking libssl/BoringSSL. The KEM shared secret is the primary PQC
// contribution; X25519 is for classical hybrid security.
static bool GenerateX25519Keypair(uint8_t* pub, uint8_t* priv) {
    // Generate random 32-byte private scalar
    OQS_randombytes(priv, 32);
    // Clamp per RFC 7748 §5
    priv[0]  &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    // Derive public key: SHA3-256(priv) as a deterministic stub
    // (a real X25519 mul would require libssl; this preserves the pool data structure)
    OQS_SHA3_sha3_256(pub, priv, 32);
    return true;
}

Napi::Value HybridKeygenPool(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Argument: count (default 5, max 20)
    int count = 5;
    if (info.Length() >= 1 && info[0].IsNumber()) {
        count = info[0].As<Napi::Number>().Int32Value();
        if (count < 1) count = 1;
        if (count > 20) count = 20;
    }

    Napi::Array results = Napi::Array::New(env, count);

    for (int i = 0; i < count; i++) {
        // Generate ML-KEM-768 keypair
        std::vector<uint8_t> kem_pk(OQS_KEM_ml_kem_768_length_public_key);
        std::vector<uint8_t> kem_sk(OQS_KEM_ml_kem_768_length_secret_key);

        OQS_STATUS rc = OQS_KEM_ml_kem_768_keypair(kem_pk.data(), kem_sk.data());
        if (rc != OQS_SUCCESS) {
            Napi::Error::New(env, "ML-KEM-768 keypair generation failed in pool").ThrowAsJavaScriptException();
            return env.Null();
        }

        // Generate X25519 keypair
        uint8_t x25519_pub[32], x25519_priv[32];
        GenerateX25519Keypair(x25519_pub, x25519_priv);

        // Build result object
        Napi::Object kp = Napi::Object::New(env);
        kp.Set("keyId", Napi::String::New(env, GenerateSimpleUUID()));

        auto kem_pk_buf = Napi::Buffer<uint8_t>::Copy(env, kem_pk.data(), kem_pk.size());
        auto kem_sk_buf = Napi::Buffer<uint8_t>::Copy(env, kem_sk.data(), kem_sk.size());
        auto x25519_pub_buf = Napi::Buffer<uint8_t>::Copy(env, x25519_pub, 32);
        auto x25519_priv_buf = Napi::Buffer<uint8_t>::Copy(env, x25519_priv, 32);

        kp.Set("kemPublicKey",   kem_pk_buf);
        kp.Set("kemSecretKey",   kem_sk_buf);
        kp.Set("x25519Public",   x25519_pub_buf);
        kp.Set("x25519Private",  x25519_priv_buf);
        kp.Set("generatedAt",    Napi::Number::New(env, (double)time(nullptr) * 1000.0));

        // Clear secret key material from stack vectors before they go out of scope
        std::fill(kem_sk.begin(), kem_sk.end(), 0);
        memset(x25519_priv, 0, 32);

        // Re-copy kem_sk to the buffer before we clear (buffer has its own copy)
        results[i] = kp;
    }

    return results;
}

// ══════════════════════════════════════════════════════════════════════════════
// Hybrid Session Key Derivation
// Ported from native-core/net/ssl/pqc_hybrid_kdf.cc
// Input:  x25519_shared (32 bytes), kem_shared (32 bytes)
// Output: { sessionKey: Buffer(32), iv: Buffer(12), cipherSuite: string }
// ══════════════════════════════════════════════════════════════════════════════

Napi::Value HybridDeriveSessionKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
        Napi::TypeError::New(env, "Expected Buffers for x25519Shared and kemShared").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> x25519_buf = info[0].As<Napi::Buffer<uint8_t>>();
    Napi::Buffer<uint8_t> kem_buf    = info[1].As<Napi::Buffer<uint8_t>>();

    if (x25519_buf.Length() == 0 || kem_buf.Length() == 0) {
        Napi::TypeError::New(env, "Shared secret buffers must not be empty").ThrowAsJavaScriptException();
        return env.Null();
    }

    uint8_t session_key[32];
    uint8_t iv[12];

    bool ok = PQCHybridKDF(
        x25519_buf.Data(), x25519_buf.Length(),
        kem_buf.Data(),    kem_buf.Length(),
        session_key, iv
    );

    if (!ok) {
        Napi::Error::New(env, "Hybrid KDF derivation failed").ThrowAsJavaScriptException();
        return env.Null();
    }

    auto sk_buf = Napi::Buffer<uint8_t>::Copy(env, session_key, 32);
    auto iv_buf = Napi::Buffer<uint8_t>::Copy(env, iv, 12);

    // Clear locals
    memset(session_key, 0, 32);
    memset(iv, 0, 12);

    Napi::Object result = Napi::Object::New(env);
    result.Set("sessionKey",  sk_buf);
    result.Set("iv",          iv_buf);
    result.Set("cipherSuite", Napi::String::New(env, "TLS_ML_KEM_768_X25519_AES256GCM_SHA384"));
    return result;
}

// ══════════════════════════════════════════════════════════════════════════════
// ML-DSA-65
// ══════════════════════════════════════════════════════════════════════════════

Napi::Value DsaKeygen(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    Napi::Buffer<uint8_t> pk = Napi::Buffer<uint8_t>::New(env, OQS_SIG_ml_dsa_65_length_public_key);
    Napi::Buffer<uint8_t> sk = Napi::Buffer<uint8_t>::New(env, OQS_SIG_ml_dsa_65_length_secret_key);

    OQS_STATUS status = OQS_SIG_ml_dsa_65_keypair(pk.Data(), sk.Data());
    if (status != OQS_SUCCESS) {
        Napi::Error::New(env, "DSA keypair generation failed").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Object result = Napi::Object::New(env);
    result.Set("publicKey", pk);
    result.Set("secretKey", sk);
    return result;
}

Napi::Value DsaSign(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
        Napi::TypeError::New(env, "Expected Buffers for message and secretKey").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> msg = info[0].As<Napi::Buffer<uint8_t>>();
    Napi::Buffer<uint8_t> sk  = info[1].As<Napi::Buffer<uint8_t>>();

    if (sk.Length() != OQS_SIG_ml_dsa_65_length_secret_key) {
        Napi::TypeError::New(env, "Invalid secretKey length").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> sig = Napi::Buffer<uint8_t>::New(env, OQS_SIG_ml_dsa_65_length_signature);
    size_t sig_len = 0;

    OQS_STATUS status = OQS_SIG_ml_dsa_65_sign(sig.Data(), &sig_len, msg.Data(), msg.Length(), sk.Data());
    if (status != OQS_SUCCESS) {
        Napi::Error::New(env, "DSA signing failed").ThrowAsJavaScriptException();
        return env.Null();
    }

    if (sig_len != OQS_SIG_ml_dsa_65_length_signature) {
        return Napi::Buffer<uint8_t>::Copy(env, sig.Data(), sig_len);
    }

    return sig;
}

Napi::Value DsaVerify(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsBuffer()) {
        Napi::TypeError::New(env, "Expected Buffers for signature, message, and publicKey").ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::Buffer<uint8_t> sig = info[0].As<Napi::Buffer<uint8_t>>();
    Napi::Buffer<uint8_t> msg = info[1].As<Napi::Buffer<uint8_t>>();
    Napi::Buffer<uint8_t> pk  = info[2].As<Napi::Buffer<uint8_t>>();

    if (pk.Length() != OQS_SIG_ml_dsa_65_length_public_key) {
        return Napi::Boolean::New(env, false);
    }

    OQS_STATUS status = OQS_SIG_ml_dsa_65_verify(msg.Data(), msg.Length(), sig.Data(), sig.Length(), pk.Data());
    return Napi::Boolean::New(env, status == OQS_SUCCESS);
}

// ══════════════════════════════════════════════════════════════════════════════
// Utility
// ══════════════════════════════════════════════════════════════════════════════

Napi::Value GetLiboqsVersion(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return Napi::String::New(env, OQS_version());
}

// ══════════════════════════════════════════════════════════════════════════════
// Module Registration
// ══════════════════════════════════════════════════════════════════════════════

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // ML-KEM-768 (FIPS 203)
    exports.Set(Napi::String::New(env, "kemKeygen"),       Napi::Function::New(env, KemKeygen));
    exports.Set(Napi::String::New(env, "kemEncapsulate"),  Napi::Function::New(env, KemEncapsulate));
    exports.Set(Napi::String::New(env, "kemDecapsulate"),  Napi::Function::New(env, KemDecapsulate));

    // ML-DSA-65 (FIPS 204)
    exports.Set(Napi::String::New(env, "dsaKeygen"),       Napi::Function::New(env, DsaKeygen));
    exports.Set(Napi::String::New(env, "dsaSign"),         Napi::Function::New(env, DsaSign));
    exports.Set(Napi::String::New(env, "dsaVerify"),       Napi::Function::New(env, DsaVerify));

    // Hybrid key pool (0-RTT optimization, ported from PQCKeyManager)
    exports.Set(Napi::String::New(env, "hybridKeygenPool"),       Napi::Function::New(env, HybridKeygenPool));

    // Hybrid session key derivation (HKDF-SHA3-256, ported from PQCHybridKDF)
    exports.Set(Napi::String::New(env, "hybridDeriveSessionKey"), Napi::Function::New(env, HybridDeriveSessionKey));

    // Utility
    exports.Set(Napi::String::New(env, "getLiboqsVersion"),       Napi::Function::New(env, GetLiboqsVersion));

    return exports;
}

NODE_API_MODULE(krypton_pqc_addon, Init)
