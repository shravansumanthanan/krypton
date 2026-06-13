const PQCEngine = require('../pqc-engine.js');

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
            expect(Buffer.from(enc.sharedSecret).toString('hex')).toStrictEqual(Buffer.from(dec.sharedSecret).toString('hex'));
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
            const verification = PQCEngine.dsaVerify(tamperedMessage, signKeypair.publicKey, sigObj.signature);
            expect(verification.valid).toBe(false);
        });
    });
});
