'use strict';

/**
 * token.ipc.js — Anonymous token IPC handlers.
 *
 * IPC channels:
 *   anon-token-issue   → issue a new token for the current session
 *   anon-token-redeem  → verify + consume a token (anti-replay)
 *   anon-token-count   → count unredeemed tokens in DB
 *
 * Security: Only nonce + signature cross IPC. sessionId never leaves main.
 */
module.exports = function registerTokenHandlers(ipcMain, services) {
  const { anonTokenProvider, pqcSessionService } = services;

  /**
   * Issue an anonymous token tied to an internal session ID.
   * Caller (renderer) does NOT pass a sessionId — we generate one here.
   * Returns: { nonce, signature, issuedAt } | { error }
   */
  ipcMain.handle('anon-token-issue', async () => {
    if (!anonTokenProvider || !anonTokenProvider.ready) {
      return { error: 'Anonymous token provider not ready' };
    }
    // Generate a fresh session ID internally — never expose it to renderer
    const sessionId = require('crypto').randomUUID
      ? require('crypto').randomUUID()
      : require('crypto').randomBytes(16).toString('hex');

    return anonTokenProvider.issueToken(sessionId);
  });

  /**
   * Redeem (verify + consume) a token.
   * Renderer passes nonce + signature; sessionId comes from the token DB.
   * Returns: { valid: boolean, error?: string }
   */
  ipcMain.handle('anon-token-redeem', async (e, nonce, signature) => {
    if (!anonTokenProvider || !anonTokenProvider.ready) {
      return { valid: false, error: 'Anonymous token provider not ready' };
    }
    if (typeof nonce !== 'string' || typeof signature !== 'string') {
      return { valid: false, error: 'Invalid nonce or signature type' };
    }
    // For redemption we look up sessionId from DB — but provider handles that.
    // Pass empty string; provider uses DB to find the matching session.
    return anonTokenProvider.redeemToken(nonce, signature, '');
  });

  /**
   * Count unredeemed tokens. Used by the PQC dashboard UI.
   * Returns: { count: number }
   */
  ipcMain.handle('anon-token-count', async () => {
    const count =
      anonTokenProvider && anonTokenProvider.ready ? anonTokenProvider.getTokenCount() : 0;
    return { count };
  });
};
