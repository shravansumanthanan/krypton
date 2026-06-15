# Contributing to KryptonBrowser

First off, thank you for considering contributing to KryptonBrowser! It's people like you that make KryptonBrowser such a great tool for privacy-first, post-quantum cryptography browsing.

## Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally.
3. **Install dependencies**:
   ```bash
   cd electron-app
   npm install
   ```

## Development Commands

All development commands are run from the `electron-app` directory:

- **Build native addon:** `npm run build:native`
- **Build UI:** `npm run build:ui`
- **Run the app:** `npm start`
- **Run unit tests:** `npm run test:unit`
- **Run E2E tests:** `npm run test:e2e`
- **Lint code:** `npm run lint`

## Architecture & IPC Flow

```text
Renderer (browser-chrome.js)
  → preload.js (contextBridge: window.kryptonBrowser)
    → main.js (ipcMain.handle)
      → pqc-engine.js (wraps native addon)
        → krypton_pqc_addon.node (liboqs C++)
```

## Security & Architecture Constraints

KryptonBrowser has strict security boundaries. **Pull requests that violate these constraints will not be accepted.**

1. **Burner Session Data:** `userData` is stored in an ephemeral, randomized temporary directory (`burnerTempDir`) which is 3-pass wiped upon exit. Do **not** store persistent data here.
2. **Persistent Data:** Any data that *must* survive restarts (like PQC connection histories) must live in the `persistentDataPath` (`app.getPath('appData')/KryptonBrowser/`), managed carefully via SQLite.
3. **ESM/CJS Boundaries:** `@noble/post-quantum` is strictly ESM. You must use dynamic `import()` to load it inside the CommonJS main process. Never use `require()`.
4. **Native Code Boundaries:** The C++ code in `native-core/` is Chromium-patch-level code and **cannot** be compiled as a Node.js N-API addon. Only port the logic (algorithms and data structures) into the existing `krypton_pqc_addon.cc`.
5. **No Key Material Over IPC:** Never expose raw private/public key material over the IPC bridge. The renderer should only ever receive session IDs, domain names, timing metadata, and status strings.
6. **Preload Bridge Requirement:** contextIsolation is strictly true and nodeIntegration is false. Any new IPC channel must be added to the `preload.js` bridge to be accessible from the renderer.
7. **IPC Config Allowlists:** New configuration settings must be explicitly added to the `ALLOWED_CONFIG_KEYS` array in `main.js`. Do not allow arbitrary config updates over IPC.
8. **Dependency Audits:** Ask before adding large dependencies. We are highly sensitive to bundle size and dependency chain supply attacks.

## Pull Request Process

1. Ensure your code conforms to the existing style and architecture constraints.
2. Run `npm run lint` to fix any formatting issues via Prettier and ESLint.
3. Run `npm run test:unit` and `npm run test:e2e` and ensure all tests pass.
4. Open a Pull Request detailing the problem you are solving, the technical approach, and what manual verification steps should be performed.
