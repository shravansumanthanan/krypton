#include <napi.h>
#include <oqs/oqs.h>

#ifndef OQS_SIG_ml_dsa_65_sign
#define OQS_SIG_ml_dsa_65_sign OQS_SIG_ml_dsa_65_ipd_sign
#endif

#ifndef OQS_SIG_ml_dsa_65_verify
#define OQS_SIG_ml_dsa_65_verify OQS_SIG_ml_dsa_65_ipd_verify
#endif

#ifndef OQS_SIG_ml_dsa_65_length_signature
#define OQS_SIG_ml_dsa_65_length_signature OQS_SIG_ml_dsa_65_ipd_length_signature
#endif

// --- ML-KEM-768 ---

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

// --- ML-DSA-65 ---

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
    Napi::Buffer<uint8_t> sk = info[1].As<Napi::Buffer<uint8_t>>();

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
        Napi::Buffer<uint8_t> actual_sig = Napi::Buffer<uint8_t>::Copy(env, sig.Data(), sig_len);
        return actual_sig;
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
    Napi::Buffer<uint8_t> pk = info[2].As<Napi::Buffer<uint8_t>>();

    if (pk.Length() != OQS_SIG_ml_dsa_65_length_public_key) {
        return Napi::Boolean::New(env, false);
    }

    OQS_STATUS status = OQS_SIG_ml_dsa_65_verify(msg.Data(), msg.Length(), sig.Data(), sig.Length(), pk.Data());
    
    return Napi::Boolean::New(env, status == OQS_SUCCESS);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // KEM
    exports.Set(Napi::String::New(env, "kemKeygen"), Napi::Function::New(env, KemKeygen));
    exports.Set(Napi::String::New(env, "kemEncapsulate"), Napi::Function::New(env, KemEncapsulate));
    exports.Set(Napi::String::New(env, "kemDecapsulate"), Napi::Function::New(env, KemDecapsulate));

    // DSA
    exports.Set(Napi::String::New(env, "dsaKeygen"), Napi::Function::New(env, DsaKeygen));
    exports.Set(Napi::String::New(env, "dsaSign"), Napi::Function::New(env, DsaSign));
    exports.Set(Napi::String::New(env, "dsaVerify"), Napi::Function::New(env, DsaVerify));

    return exports;
}

NODE_API_MODULE(krypton_pqc_addon, Init)
