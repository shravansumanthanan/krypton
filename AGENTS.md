# KryptonBrowser — Agent Context Rules

## Project
Privacy-first, post-quantum cryptography (PQC) Electron browser.
Repo: `/path/to/krypton`

## Tech Stack
- **Runtime**: Electron 42 + Node.js 22 (CommonJS main process), Vite 8 (renderer bundler)
- **PQC**: `@noble/post-quantum` (ESM — lazy-dynamic-import only), native C++ N-API addon wrapping `liboqs` via cmake-js
- **DB**: `better-sqlite3` for PQC session persistence (to be added)
- **Tests**: Playwright (E2E), Jest (unit)
- **CI**: GitHub Actions macOS-latest

## Commands
- Build native addon: `cd electron-app && npm run build:native`
- Build UI: `cd electron-app && npm run build:ui`
- Run app: `cd electron-app && npm start`
- Unit tests: `cd electron-app && npm run test:unit`
- E2E tests: `cd electron-app && npm run test:e2e`
- Lint: `cd electron-app && npm run lint`

## Key Files
| File | Purpose |
|---|---|
| `electron-app/src/main/main.js` | Electron main process (961 lines), all IPC handlers |
| `electron-app/src/main/pqc-engine.js` | JS wrapper for native PQC addon; in-memory session log |
| `electron-app/src/main/preload.js` | contextBridge IPC bridge to renderer |
| `electron-app/native/src/krypton_pqc_addon.cc` | N-API C++ addon (KEM + DSA operations) |
| `electron-app/native/CMakeLists.txt` | cmake build config for liboqs addon |
| `native-core/net/pqc/quantum_security_module.cc` | C++ QSM — full PQC logic, RecordSession/GetRecentSessions are TODO stubs |
| `native-core/net/pqc/pqc_session_record.{h,cc}` | PQCSessionRecord data structure |
| `native-core/net/pqc/pqc_key_manager.{h,cc}` | Pre-generated keypair pool, 0-RTT optimization |
| `native-core/net/pqc/pqc_handshake_state_machine.{h,cc}` | 9-state TLS handshake state machine |
| `electron-app/src/renderer/browser-chrome.js` | All UI/browser chrome (3197 lines) |

## Architecture: IPC Flow
```
Renderer (browser-chrome.js)
  → preload.js (contextBridge: window.kryptonBrowser)
    → main.js (ipcMain.handle)
      → pqc-engine.js (wraps native addon)
        → krypton_pqc_addon.node (liboqs C++)
```

## Critical Constraints
1. **ESM-CJS Boundary**: `@noble/post-quantum` is ESM-only. It must ONLY be loaded via dynamic `import()` inside an async function. Never `require()` it.
2. **native-core ≠ shipping addon**: The `native-core/` directory is Chromium-patch-level C++ (uses `base::`, `net::`, `OQS_*`, `BoringSSL`). It CANNOT be compiled as a Node N-API addon — those headers don't exist. The integration strategy is to port only the logic (algorithms + data structures) into the existing `krypton_pqc_addon.cc`.
3. **Session Log is in-memory**: `pqcSessionLog` in `pqc-engine.js` is a rolling 200-entry array, lost on restart. Persistence goes to `better-sqlite3` in a new `pqc-session-service.js`.
4. **Burner session userData**: `app.setPath('userData', burnerTempDir)` — user data is ephemeral by design. The PQC session SQLite DB must live in `persistentDataPath` (`app.getPath('appData')/KryptonBrowser/`), NOT in burnerTempDir.
5. **Security**: Never expose raw key material over IPC. Only session IDs, domain names, timing, and status cross the IPC bridge.
6. **Config keys**: Adding new config keys requires adding them to `ALLOWED_CONFIG_KEYS` in `main.js`.
7. **Preload bridge**: Any new IPC channel needs an entry in `preload.js` to be callable from renderer.

## Patterns
- New IPC handler: `ipcMain.handle('channel-name', async (e, arg) => { ... })` in `main.js`
- New preload exposure: `channelName: (arg) => ipcRenderer.invoke('channel-name', arg)` in `preload.js`
- Native addon function: sync, throws on error (Napi::Error), returns Napi::Object or Napi::Buffer

## Boundaries
- Never commit secrets, API keys, or private key material
- Never bypass contextIsolation (nodeIntegration must remain false)
- Never store PQC session data in burnerTempDir (ephemeral, gets shredded)
- Ask before changing the 3-pass wipe logic — it's a core security feature
- Ask before adding dependencies over 1MB (bundle size matters for distribution)
