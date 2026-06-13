# ADR 2: Asynchronous Initialization for Pure ESM PQC Libraries

## Status
Accepted

## Context
KryptonBrowser relies on `@noble/post-quantum` for implementing FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65). This library is written and distributed as a pure ES Module (ESM). However, the Electron main process typically runs in a CommonJS (`require()`) context.

Attempting to `require()` an ESM package results in an `ERR_REQUIRE_ESM` crash in Node.js. Converting the entire Electron backend to ESM using `"type": "module"` in `package.json` often introduces cascading compatibility issues with other existing CommonJS packages, native node modules, and Electron's internal require logic.

## Decision
We implemented a **Lazy Async-Init Pattern** in `pqc-engine.js`.

1.  `pqc-engine.js` remains a CommonJS module.
2.  It exposes an `init()` method returning a Promise.
3.  Inside `init()`, we use dynamic import (`await import('@noble/post-quantum/ml-kem.js')`) to load the ESM dependencies at runtime.
4.  The loaded modules are stored in module-scoped variables (`_ml_kem768`, `_ml_dsa65`), and all subsequent crypto operations (`kemKeygen`, `kemEncapsulate`, `dsaVerify`, etc.) remain synchronous.

## Consequences

**Positive:**
*   **Compatibility:** We successfully integrate a highly audited, modern pure-ESM cryptographic library without forcing the entire Electron main process into `"type": "module"`.
*   **Performance:** Cryptographic operations remain synchronous after initialization, ensuring they don't force all calling methods to become asynchronous unnecessarily.
*   **Stability:** Avoids deep refactoring of legacy CommonJS dependencies.

**Negative:**
*   **Startup Dependency:** The Electron application lifecycle must `await pqcEngine.init()` explicitly in `app.whenReady()` before any cryptographic functions can be used or tested.
*   **Testing Complexity:** Jest requires explicit `--experimental-vm-modules` flags and configurations to properly evaluate the dynamic imports inside `pqc-engine.test.js`. We mitigated this by setting `NODE_OPTIONS=--experimental-vm-modules jest` in the NPM script.
