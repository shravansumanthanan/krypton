# ADR 1: Vite Integration for Frontend Bundling

## Status
Accepted

## Context
The KryptonBrowser UI was previously structured as a monolithic `browser-chrome.js` file and inline HTML handlers. As the application grows to support more complex PQC visualizers, secure password managers, and a modular architecture, the codebase became difficult to maintain. Using ES Modules natively in Electron renderer processes via `file://` protocol can be problematic, and manual dependency management is error-prone.

## Decision
We decided to adopt **Vite** as our frontend build tool.

1.  **Entry Point:** The main entry point is now `src/index.html`.
2.  **Modularization:** `browser-chrome.js` has been modularized into `src/js/utils.js` and other logical units.
3.  **Build Output:** Vite bundles all CSS, JS, and HTML into the `build/` directory.
4.  **Electron integration:** The Electron main process (`main.js`) now loads the UI directly from `build/index.html`.

## Consequences

**Positive:**
*   **Modularity:** UI logic is cleanly separated into reusable ES Modules.
*   **Performance:** Vite provides an extremely fast local development server (if HMR is configured in the future) and an optimized production bundle (minification, dead-code elimination, CSS extraction).
*   **Maintainability:** Easier to manage external UI dependencies and add new frontend frameworks if needed in the future.

**Negative:**
*   **Build Step Required:** Running the app now requires an explicit build step (`npm run build:ui`) before launching Electron, rather than just `electron .`. We mitigated this by setting `"start": "npm run build:ui && electron ."`.
*   **Configuration:** Added `vite.config.js` to manage the build process, increasing toolchain complexity slightly.
