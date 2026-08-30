'use strict';

module.exports = function registerPqcHandlers(ipcMain, services) {
  const { pqcEngine } = services;

  // PQC Engine — Self-Test
  ipcMain.handle('pqc-selftest', async () => {
    return pqcEngine.runSelfTest();
  });

  // PQC Engine — Real Keygen
  ipcMain.handle('pqc-keygen', async () => {
    const result = pqcEngine.kemKeygen();
    return {
      publicKeyHex: result.publicKeyHex,
      publicKeyBytes: result.publicKeyBytes,
      secretKeyBytes: result.secretKeyBytes,
      ms: result.ms,
    };
  });

  // PQC Engine — Encapsulate
  ipcMain.handle('pqc-encapsulate', async (e, publicKeyHex) => {
    if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]+$/.test(publicKeyHex)) {
      throw new Error('Invalid public key: must be a hex string');
    }
    // ML-KEM-768 public key is 1184 bytes = 2368 hex chars
    if (publicKeyHex.length !== 2368) {
      throw new Error('Invalid public key length for ML-KEM-768');
    }
    const result = pqcEngine.kemEncapsulate(publicKeyHex);
    return {
      cipherTextHex: result.cipherTextHex,
      sharedSecretHex: result.sharedSecretHex,
      cipherTextBytes: result.cipherTextBytes,
      ms: result.ms,
    };
  });

  // PQC Engine — DSA Keygen
  ipcMain.handle('pqc-dsa-keygen', async () => {
    const result = pqcEngine.dsaKeygen();
    return {
      publicKeyHex: result.publicKeyHex,
      publicKeyBytes: result.publicKeyBytes,
      secretKeyBytes: result.secretKeyBytes,
      ms: result.ms,
    };
  });

  // PQC Hybrid Key Pool (pre-generate keypairs for 0-RTT)
  ipcMain.handle('pqc-get-key-pool', async (e, count) => {
    const n = Math.min(parseInt(count) || 5, 10);
    return pqcEngine.hybridKeygenPool(n);
  });

  // Crypto-agile KEM
  ipcMain.handle('pqc-keygen-agile', async (e, algorithm) => {
    return pqcEngine.kemKeygenAgile(algorithm || 'ML-KEM-768');
  });

  ipcMain.handle('pqc-get-algorithms', async () => {
    return pqcEngine.getEnabledAlgorithms();
  });

  ipcMain.handle('pqc-dsa-keygen-agile', async (e, algorithm) => {
    return pqcEngine.dsaKeygenAgile(algorithm || 'ML-DSA-65');
  });

  // Crypto-agile encapsulate — used by benchmark runner
  ipcMain.handle('pqc-encapsulate-agile', async (e, algorithm, publicKeyHex) => {
    if (typeof publicKeyHex !== 'string' || !/^[0-9a-fA-F]+$/.test(publicKeyHex)) {
      throw new Error('Invalid public key: must be a hex string');
    }
    const result = pqcEngine.kemEncapsulateAgile(algorithm || 'ML-KEM-768', publicKeyHex);
    // SECURITY: never return sharedSecretHex across IPC — return only ciphertext bytes + timing
    return {
      cipherTextHex: result.cipherTextHex,
      cipherTextBytes: result.cipherTextBytes,
      ms: result.ms,
    };
  });

  // Crypto-agile decapsulate — used by benchmark runner only
  ipcMain.handle('pqc-decapsulate-agile', async (e, algorithm, cipherTextHex, secretKeyHex) => {
    if (typeof cipherTextHex !== 'string' || typeof secretKeyHex !== 'string') {
      throw new Error('Invalid inputs: must be hex strings');
    }
    const t0 = Date.now();
    pqcEngine.kemDecapsulateAgile(algorithm || 'ML-KEM-768', cipherTextHex, secretKeyHex);
    // SECURITY: shared secret never returned over IPC; only timing
    return { ms: Date.now() - t0 };
  });

  // PQC liboqs version
  ipcMain.handle('pqc-get-liboqs-version', async () => pqcEngine.getLiboqsVersion());
};
