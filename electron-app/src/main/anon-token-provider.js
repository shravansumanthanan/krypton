'use strict';

/**
 * AnonTokenProvider — ML-DSA-65 signed anonymous access tokens.
 *
 * Design (approved plan):
 *   ISSUE:  SHA3-256(nonce || sessionId) is signed by ML-DSA-65 signing key.
 *           Only the nonce + signature (token) is returned to renderer.
 *           sessionId NEVER leaves main process. Anti-correlation by design.
 *
 *   REDEEM: Verifier checks sig with the stored public key, then marks
 *           the token `redeemed = 1` (replay prevention via SQLite).
 *
 * Security constraints (AGENTS.md):
 *   - No raw key material crosses IPC (only token nonce + signature hex)
 *   - SQLite lives in persistentDataPath, NOT burnerTempDir
 *   - Token table is managed by PQCSessionService (injected at startup)
 *
 * Token format (returned to renderer):
 *   { nonce: hexString, signature: hexString, issuedAt: isoString }
 */

const crypto = require('crypto');

// Lazy-loaded — PQCEngine is set after addon init
let _pqcEngine = null;
// Signing keypair (generated once per process lifetime, in-memory)
let _signingPublicKey = null;
let _signingSecretKey = null;
let _ready = false;

// SQLite session service (injected, provides token table methods)
let _sessionService = null;
const _inMemoryTokens = new Map();

function hashCommitment(nonce, sessionId) {
  try {
    return crypto.createHash('sha3-256').update(nonce).update(sessionId).digest();
  } catch {
    return crypto.createHash('sha256').update(nonce).update(sessionId).digest();
  }
}

const AnonTokenProvider = {
  /**
   * Wire dependencies. Must be called once at startup after PQCEngine.init().
   */
  init(pqcEngine, sessionService) {
    _pqcEngine = pqcEngine;
    _sessionService = sessionService;
    try {
      const kp = _pqcEngine.dsaKeygen();
      // Store raw buffers (not hex) — never cross IPC
      _signingPublicKey = Buffer.from(kp.publicKey);
      _signingSecretKey = Buffer.from(kp.secretKey);
      _ready = true;
    } catch (err) {
      console.error('[AnonTokenProvider] DSA keygen failed:', err.message);
      _ready = false;
    }
  },

  get ready() {
    return _ready;
  },

  /**
   * Issue a new anonymous token for a given session.
   * The sessionId is hashed with a random nonce — neither is exposed individually.
   *
   * @param {string} sessionId - internal session UUID (stays in main process)
   * @returns {{ nonce: string, signature: string, issuedAt: string } | { error: string }}
   */
  issueToken(sessionId) {
    if (!_ready) return { error: 'AnonTokenProvider not initialised' };
    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      return { error: 'Invalid sessionId' };
    }

    try {
      // Generate random 32-byte nonce
      const nonce = crypto.randomBytes(32);

      // Commitment = SHA3-256(nonce || sessionId) (or SHA-256 fallback in BoringSSL)
      const commitment = hashCommitment(nonce, sessionId);

      // Sign the commitment with ML-DSA-65
      const { signature } = _pqcEngine.dsaSign(commitment, _signingSecretKey);

      const nonceHex = nonce.toString('hex');
      const sigHex = Buffer.from(signature).toString('hex');
      const issuedAt = new Date().toISOString();

      // Persist to memory as safe fallback
      _inMemoryTokens.set(nonceHex, {
        nonce: nonceHex,
        signature: sigHex,
        sessionId,
        issuedAt,
        redeemed: false,
      });

      // Persist to DB if session service is available
      if (_sessionService && _sessionService.ready && _sessionService.issueToken) {
        _sessionService.issueToken({
          nonce: nonceHex,
          signature: sigHex,
          sessionId,
          issuedAt,
        });
      }

      // Return ONLY nonce + signature — sessionId stays here
      return { nonce: nonceHex, signature: sigHex, issuedAt };
    } catch (err) {
      return { error: err.message };
    }
  },

  /**
   * Redeem (verify + consume) a token.
   * Checks ML-DSA-65 signature and ensures nonce hasn't been replayed.
   *
   * @param {string} nonce - hex nonce from issueToken
   * @param {string} signature - hex signature from issueToken
   * @param {string} sessionId - session to verify against (stays in main)
   * @returns {{ valid: boolean, error?: string }}
   */
  redeemToken(nonce, signature, sessionId) {
    if (!_ready) return { valid: false, error: 'AnonTokenProvider not initialised' };

    try {
      const nonceBytes = Buffer.from(nonce, 'hex');
      const sigBytes = Buffer.from(signature, 'hex');

      // Recompute commitment
      const commitment = hashCommitment(nonceBytes, sessionId);

      // Verify ML-DSA-65 signature
      const { valid } = _pqcEngine.dsaVerify(commitment, _signingPublicKey, sigBytes);
      if (!valid) return { valid: false, error: 'Signature verification failed' };

      if (_inMemoryTokens.has(nonce)) {
        const memToken = _inMemoryTokens.get(nonce);
        if (memToken.redeemed)
          return { valid: false, error: 'Token already redeemed or not found' };
        memToken.redeemed = true;
      }

      // Anti-replay: mark redeemed in DB
      if (_sessionService && _sessionService.ready && _sessionService.redeemToken) {
        const redeemed = _sessionService.redeemToken(nonce);
        if (!redeemed && !_inMemoryTokens.has(nonce))
          return { valid: false, error: 'Token already redeemed or not found' };
      }

      return { valid: true };
    } catch (err) {
      return { valid: false, error: err.message };
    }
  },

  /**
   * Count unredeemed tokens (for UI display).
   */
  getTokenCount() {
    if (_sessionService && _sessionService.ready && _sessionService.getTokenCount) {
      const dbCount = _sessionService.getTokenCount();
      if (dbCount > 0) return dbCount;
    }
    let memCount = 0;
    for (const [, t] of _inMemoryTokens.entries()) {
      if (!t.redeemed) memCount++;
    }
    return memCount;
  },
};

module.exports = AnonTokenProvider;
