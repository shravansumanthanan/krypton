# ADR-004 — Anonymous Token Provider (Privacy Pass–Style ML-DSA-65 Tokens)

**Status**: Accepted
**Date**: 2026-08-22
**Authors**: KryptonBrowser Team

---

## Context

The project objectives require *"anonymous token-based access control"* with privacy-preservation as a first-class requirement. The system must issue unforgeable, unlinkable access tokens without exposing a user's session identity across IPC.

Standard bearer tokens (JWT, session cookies) carry persistent identifiers that correlate browsing sessions — directly contradicting the burner-browser threat model.

## Decision

Implement a **Privacy Pass–style commitment scheme** backed by **ML-DSA-65** (FIPS 204):

### Token Lifecycle

```
ISSUE
  renderer → IPC → main process
  main:   nonce = randomBytes(32)
          sessionId = internal UUID (never leaves main)
          commitment = SHA3-256(nonce ‖ sessionId)
          signature = ML-DSA-65.Sign(commitment, signingKey)
  IPC:    returns { nonce, signature, issuedAt } only
          sessionId is NEVER returned

REDEEM
  renderer → IPC(nonce, signature)
  main:   looks up token row by nonce
          recomputes commitment = SHA3-256(nonce ‖ storedSessionId)
          verifies ML-DSA-65.Verify(commitment, pubKey, signature)
          sets redeemed = 1 (SQLite, WAL mode)
          returns { valid: true/false }
```

### Key properties

| Property | Mechanism |
|----------|-----------|
| **Unforgeability** | ML-DSA-65 signature (NIST FIPS 204 — quantum-resistant) |
| **Anti-replay** | SQLite `redeemed` flag with unique nonce constraint |
| **Unlinkability** | SHA3-256(nonce ‖ sessionId) — nonce is random per token; sessionId stays in main process |
| **Ephemerality** | Signing keypair is in-memory per process; lost on restart by design |
| **IPC cleanliness** | Only `nonce` (hex, 64 chars) + `signature` (hex) + `issuedAt` cross the bridge |

### Signing keypair lifecycle

A fresh ML-DSA-65 keypair is generated at startup by `AnonTokenProvider.init()`. It lives exclusively in the main process heap. The public key is used only for local verification — it is never exposed to the renderer or stored on disk.

### Persistence

Token rows are stored in `persistentDataPath/pqc_sessions.db` (`anon_tokens` table, WAL). The `sessionId` column is stored server-side only and is not accessible via IPC.

## Consequences

**Positive:**
- Tokens are quantum-resistant and unforgeable even against Grover/Shor attacks.
- Zero user-correlation risk: each token is bound to a single session nonce; replaying a token across sessions fails verification.
- Minimal IPC surface: renderer cannot reconstruct session identity from the data it receives.

**Negative:**
- Signing keypair is ephemeral — tokens issued in a previous process instance cannot be verified by the next. This is intentional and consistent with the burner-browser model.
- `redeemToken` currently requires the original `sessionId` to be available in the main process. If a session expires before redemption, verification fails. This is acceptable for the demo MVP.

## Alternatives Considered

| Option | Rejected because |
|--------|-----------------|
| HMAC-SHA256 tokens | Not quantum-resistant |
| Classical RSA blind signatures | Not PQC; adds 8 kB dependency |
| Full Privacy Pass protocol (VOPRF) | No PQC VOPRF standard exists; over-engineered for MVP |
| Store sessionId in renderer | Violates AGENTS.md security rule: sessionId must not cross IPC boundary |
