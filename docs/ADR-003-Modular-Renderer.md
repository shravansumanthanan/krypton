# ADR-003 — Modular Renderer Architecture

**Status**: Accepted
**Date**: 2026-08-22
**Authors**: KryptonBrowser Team

---

## Context

`browser-chrome.js` had grown to 3 197 lines — a monolithic renderer module containing all UI logic, IPC invocations, state management, and DOM manipulation. This made fault isolation impossible: a bug in the tab system could silently corrupt the PQC badge, and there was no clear dependency graph.

The project's guiding constraint is *"changes must be structural and modular so that fault identification is easy."*

## Decision

Decompose `browser-chrome.js` into **27 ES module files** organised by domain, loaded via a thin `index.js` bootstrap. Each module owns a single concern.

```
src/renderer/
├── index.js                   ← bootstrap only
├── state/store.js             ← single reactive store
├── ipc/ipc-bridge.js          ← all window.kryptonBrowser calls
├── tabs/
│   ├── tab-manager.js
│   └── tab-context-menu.js
├── navigation/
│   ├── nav-controller.js
│   └── url-bar.js
├── webview/webview-factory.js
├── shields/shields-controller.js
├── security/
│   ├── security-indicator.js
│   └── permission-dialog.js
├── bookmarks/bookmarks-manager.js
├── history/history-manager.js
├── sidebar/sidebar-controller.js
├── downloads/downloads-panel.js
├── pages/
│   ├── ntp.js
│   ├── history-page.js
│   ├── settings-page.js
│   ├── extensions-page.js
│   ├── reader-mode.js
│   └── private-mode.js
├── ui/
│   ├── browser-menu.js
│   ├── extensions-popup.js
│   ├── find-bar.js
│   ├── context-menu.js
│   └── status-bar.js
└── utils/
    ├── utils.js
    └── shortcuts.js
```

Simultaneously the main process was split from a single 961-line `main.js` into domain-specific IPC modules:

```
src/main/ipc/
├── index.js           ← registers all handlers
├── config.ipc.js
├── pqc.ipc.js
├── session.ipc.js
├── security.ipc.js
├── downloads.ipc.js
├── shields.ipc.js
├── token.ipc.js
└── benchmark.ipc.js
```

## Consequences

**Positive:**
- Any module can be opened in isolation; its imports declare its dependency surface.
- Bugs are bounded — a crash in `tab-manager.js` cannot affect `security-indicator.js`.
- Each domain can be unit-tested without loading the entire renderer.
- Vite tree-shakes unused modules; bundle stayed at 96 kB gzip-28 kB.

**Negative:**
- Initial refactor cost: ~4 hours of careful extraction and cross-reference audit.
- ES module boundaries require explicit `export`/`import`; mixing with legacy CJS patterns requires care.

## Alternatives Considered

| Option | Rejected because |
|--------|-----------------|
| Single-file with JSDoc regions | Does not enforce boundaries; IDE-only, not tooling-enforceable |
| Full React/Vue component model | 1 MB+ dependency; violates bundle-size constraint in AGENTS.md |
| Web Components | Polyfill overhead; Electron already bundles a capable DOM |
