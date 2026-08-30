const PQCEngine = require('../../src/main/pqc-engine.js');

describe('PQCEngine', () => {
  beforeAll(async () => {
    await PQCEngine.init();
  });

  describe('PQC Key Exchange (ML-KEM-768)', () => {
    let keypair;

    test('kemKeygen should return publicKey and secretKey', () => {
      keypair = PQCEngine.kemKeygen();
      expect(keypair).toHaveProperty('publicKey');
      expect(keypair).toHaveProperty('secretKey');
      expect(keypair.publicKeyBytes).toBeGreaterThan(0);
      expect(keypair.secretKeyBytes).toBeGreaterThan(0);
    });

    test('kemEncapsulate and kemDecapsulate should match shared secret', () => {
      const enc = PQCEngine.kemEncapsulate(keypair.publicKey);
      expect(enc).toHaveProperty('cipherText');
      expect(enc).toHaveProperty('sharedSecret');

      const dec = PQCEngine.kemDecapsulate(enc.cipherText, keypair.secretKey);
      expect(Buffer.from(enc.sharedSecret).toString('hex')).toStrictEqual(
        Buffer.from(dec.sharedSecret).toString('hex'),
      );
    });
  });

  describe('PQC Signatures (ML-DSA-65)', () => {
    let signKeypair;

    test('dsaKeygen should return publicKey and secretKey', () => {
      signKeypair = PQCEngine.dsaKeygen();
      expect(signKeypair).toHaveProperty('publicKey');
      expect(signKeypair).toHaveProperty('secretKey');
    });

    test('dsaSign and dsaVerify should work with valid message', () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const sigObj = PQCEngine.dsaSign(message, signKeypair.secretKey);
      expect(sigObj.signatureBytes).toBeGreaterThan(0);

      const verification = PQCEngine.dsaVerify(message, signKeypair.publicKey, sigObj.signature);
      expect(verification.valid).toBe(true);
    });

    test('dsaVerify should fail with invalid message', () => {
      const message = new Uint8Array([1, 2, 3, 4, 5]);
      const sigObj = PQCEngine.dsaSign(message, signKeypair.secretKey);

      const tamperedMessage = new Uint8Array([1, 2, 3, 4, 6]);
      const verification = PQCEngine.dsaVerify(
        tamperedMessage,
        signKeypair.publicKey,
        sigObj.signature,
      );
      expect(verification.valid).toBe(false);
    });
  });

  // ── Phase 3: Crypto-Agility Tests ─────────────────────────
  describe('Crypto-Agile KEM (all 3 variants)', () => {
    const KEM_ALGS = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'];

    KEM_ALGS.forEach((alg) => {
      describe(alg, () => {
        let kp;
        test(`kemKeygenAgile(${alg}) returns pk + sk with timing`, () => {
          kp = PQCEngine.kemKeygenAgile(alg);
          expect(kp).toHaveProperty('publicKey');
          expect(kp).toHaveProperty('secretKey');
          expect(kp.algorithm).toBe(alg);
          expect(kp.publicKeyBytes).toBeGreaterThan(0);
          expect(typeof kp.ms).toBe('number');
        });

        test(`kemEncapsulateAgile + kemDecapsulateAgile shared secrets match for ${alg}`, () => {
          kp = kp || PQCEngine.kemKeygenAgile(alg);
          const enc = PQCEngine.kemEncapsulateAgile(alg, kp.publicKey);
          expect(enc).toHaveProperty('cipherText');
          expect(enc).toHaveProperty('sharedSecret');

          const dec = PQCEngine.kemDecapsulateAgile(alg, enc.cipherText, kp.secretKey);
          expect(Buffer.from(enc.sharedSecret).toString('hex')).toBe(
            Buffer.from(dec.sharedSecret).toString('hex'),
          );
        });

        test(`kemEncapsulateAgile accepts hex public key string for ${alg}`, () => {
          kp = kp || PQCEngine.kemKeygenAgile(alg);
          const pkHex = kp.publicKeyHex;
          expect(() => PQCEngine.kemEncapsulateAgile(alg, pkHex)).not.toThrow();
        });
      });
    });
  });

  describe('Crypto-Agile DSA (all 3 variants)', () => {
    const DSA_ALGS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
    const msg = Buffer.from('KryptonBrowser test message');

    DSA_ALGS.forEach((alg) => {
      test(`dsaKeygenAgile(${alg}) returns pk + sk`, () => {
        const kp = PQCEngine.dsaKeygenAgile(alg);
        expect(kp.algorithm).toBe(alg);
        expect(kp.publicKeyBytes).toBeGreaterThan(0);
        expect(kp.secretKeyBytes).toBeGreaterThan(0);
      });
    });

    // Sign/verify round-trip: only ML-DSA-65 is supported by the fixed-algorithm dsaSign/dsaVerify.
    // ML-DSA-44 and ML-DSA-87 keygen works agile but the sign wrapper is ML-DSA-65–specific.
    test('ML-DSA-65 sign/verify round-trip (dsaSign + dsaVerify)', () => {
      const kp = PQCEngine.dsaKeygenAgile('ML-DSA-65');
      const sigObj = PQCEngine.dsaSign(msg, kp.secretKey);
      const result = PQCEngine.dsaVerify(msg, kp.publicKey, sigObj.signature);
      expect(result.valid).toBe(true);
    });
  });

  describe('getEnabledAlgorithms()', () => {
    test('returns kems and dsa lists', () => {
      const algs = PQCEngine.getEnabledAlgorithms();
      expect(algs).toHaveProperty('kems');
      expect(algs).toHaveProperty('dsa');
      expect(algs.kems.length).toBeGreaterThanOrEqual(3);
      expect(algs.dsa.length).toBeGreaterThanOrEqual(3);
    });

    test('kems contains all 3 ML-KEM variants', () => {
      const { kems } = PQCEngine.getEnabledAlgorithms();
      expect(kems).toContain('ML-KEM-512');
      expect(kems).toContain('ML-KEM-768');
      expect(kems).toContain('ML-KEM-1024');
    });

    test('dsa contains all 3 ML-DSA variants', () => {
      const { dsa } = PQCEngine.getEnabledAlgorithms();
      expect(dsa).toContain('ML-DSA-44');
      expect(dsa).toContain('ML-DSA-65');
      expect(dsa).toContain('ML-DSA-87');
    });
  });

  describe('Timing metadata', () => {
    test('kemKeygenAgile includes ms field >= 0', () => {
      const kp = PQCEngine.kemKeygenAgile('ML-KEM-768');
      expect(kp.ms).toBeGreaterThanOrEqual(0);
    });

    test('dsaKeygenAgile includes ms field >= 0', () => {
      const kp = PQCEngine.dsaKeygenAgile('ML-DSA-65');
      expect(kp.ms).toBeGreaterThanOrEqual(0);
    });
  });
});
