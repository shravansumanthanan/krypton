# KryptonBrowser

> A privacy-first, zero-trust Electron browser built for the general public to defend against post-quantum surveillance and local forensic analysis.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/kryptonbrowser/krypton/actions/workflows/build.yml/badge.svg)](https://github.com/kryptonbrowser/krypton/actions/workflows/build.yml)

## Why This Exists

Classical cryptography is vulnerable to "Store-Now-Decrypt-Later" attacks, where adversaries harvest encrypted data today to decrypt once quantum computers become available. Furthermore, local device forensics can often expose browsing habits even after standard deletion. 

KryptonBrowser brings defense-in-depth to the general public. It seamlessly integrates post-quantum cryptography (PQC) alongside ephemeral burner sessions and multi-pass secure wiping, guaranteeing that sensitive communications and browsing data remain impenetrable against both current forensic tools and future quantum cryptographic threats.

## Key Features

- **Post-Quantum Cryptography:** Natively features FIPS-compliant ML-KEM-768 and ML-DSA-65 algorithms.
- **Ephemeral Burner Sessions:** User data (cache, cookies, local storage) is stored in a volatile directory isolated from your main system.
- **Panic Button:** Configurable global shortcut (default `CommandOrControl+Shift+Escape`) that instantly wipes data and terminates the application.
- **Multi-Pass Secure Wipe:** Performs asynchronous 3-pass wiping (zeros, ones, random data) with filename obfuscation to defeat advanced file recovery techniques.
- **Hardened Main Process:** Protected against Server-Side Request Forgery (SSRF), Path Traversal, and strict window management protocol limitations (restricting `file://`).
- **O(1) Content Blocking:** High-performance, categorized blocking for ads, trackes, malware, and fingerprinting domains.

## Quick Start

```bash
git clone https://github.com/kryptonbrowser/krypton.git
cd krypton/electron-app
npm install
npm start
```

## Installation

**Prerequisites**: Node.js 20+, npm 10+, macOS (for `dmg`/`app` packaging)

```bash
git clone https://github.com/kryptonbrowser/krypton.git
cd krypton/electron-app
npm install
```

## Usage

### Local Development

Run the browser in development mode with UI bundling and hot module replacement:

```bash
npm start
```

### Configuration

KryptonBrowser's security features are configurable via modular JSON files. Your preferences persist, while your browsing data remains ephemeral.

| Configuration File | Location | Description |
|--------|------|-------------|
| `krypton_config.json` | `~/Library/Application Support/KryptonBrowser/` | User preferences including the Panic Button shortcut and HTTPS Upgrades. |
| `blocklist.json` | `electron-app/blocklist.json` | O(1) hostname blocking definitions categorized by `ads`, `trackers`, `malware`, and `fingerprinting`. |

### Advanced Usage: Building for Production

Package the application into a redistributable, production-ready format using `electron-builder`.

```bash
# Build the Mac app directory (for testing the production bundle without packaging)
npm run build:dir

# Build the final Mac packaged application (.dmg / .app)
npm run build
```

### Running with Docker

You can run KryptonBrowser in a fully containerized environment using Docker. This isolates the browser's execution and is excellent for reproducible testing or CI/CD pipelines.

1. **Build and Run (X11 Forwarding):**
   ```bash
   # Make sure X11 server is running and accessible (e.g. xhost +local:docker)
   docker-compose up --build
   ```
   
   If `DISPLAY` is not accessible, the container will automatically fall back to headless mode using `Xvfb`.

2. **Manual Docker Build (Headless / Testing):**
   ```bash
   docker build -t krypton-browser .
   docker run --rm -it krypton-browser
   ```

## Testing

KryptonBrowser is validated through rigorous automated testing covering the cryptographic engine, URL blocking, ephemeral session management, and end-to-end browser flows.

### Unit Tests
Tests the pure ESM Post-Quantum Cryptography implementations, memory-leak-free blocklist parsers, and path validators.
```bash
npm run test:unit
```

### End-to-End (E2E) Tests
Simulates real browser usage, UI state transitions, and verifies the Panic Button and secure wipe handlers using Playwright.
```bash
npm run test:e2e
```

## Architecture & API Reference

KryptonBrowser relies on asynchronous initialization for pure ESM PQC libraries and modern Vite bundling. See our Architectural Decision Records (ADRs) for deep-dives into our technical choices:

- [ADR-001: Vite Integration for Frontend Bundling](electron-app/docs/ADR-001-Vite-Integration.md)
- [ADR-002: Asynchronous Initialization for Pure ESM PQC Libraries](electron-app/docs/ADR-002-PQC-Engine.md)

## Contributing

We welcome contributions to improve our PQC implementations and security guards. Please ensure all new code includes corresponding Jest or Playwright tests and follows our strict zero-trust paradigm. 

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

MIT © [KryptonBrowserTeam](https://github.com/kryptonbrowser)
