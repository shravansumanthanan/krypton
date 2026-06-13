# KryptonBrowser

> A hardened, zero-trust Electron browser built for post-quantum security environments featuring FIPS-compliant ML-KEM-768 and ML-DSA-65.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/shravansumanthanan/krypton/actions/workflows/build.yml/badge.svg)](https://github.com/shravansumanthanan/krypton/actions/workflows/build.yml)

## Why This Exists

Classical cryptography is vulnerable to "Store-Now-Decrypt-Later" attacks where adversaries harvest encrypted data today to decrypt once quantum computers become available. KryptonBrowser provides an Army-grade, defense-in-depth enclave that natively integrates post-quantum cryptography (PQC) alongside strict zero-trust runtime restrictions. It guarantees that highly sensitive communications and data remain impenetrable against both current and future cryptographic threats.

## Quick Start

```bash
git clone https://github.com/shravansumanthanan/krypton.git
cd krypton/electron-app
npm install
npm start
```

## Installation

**Prerequisites**: Node.js 20+, npm 10+, macOS (for `dmg`/`app` packaging)

```bash
git clone https://github.com/shravansumanthanan/krypton.git
cd krypton/electron-app
npm install
```

## Usage

### Local Development

Run the browser in development mode with UI bundling and hot module replacement:

```bash
npm start
```

### Code Quality & Formatting

Maintain production-grade code quality using the built-in linting and formatting tools:

```bash
npm run lint    # Run ESLint to identify code quality issues
npm run format  # Run Prettier to automatically format code
```

### Configuration

KryptonBrowser's security features are configurable via modular JSON files and environment constraints.

| Configuration File | Location | Description |
|--------|------|-------------|
| `blocklist.json` | `electron-app/blocklist.json` | O(1) hostname blocking definitions categorized by `ads`, `trackers`, `malware`, and `fingerprinting`. |
| `vite.config.js` | `electron-app/vite.config.js` | UI bundling rules, dead-code elimination, and asset minification settings. |

### Advanced Usage: Building for Production

Package the application into a redistributable, production-ready format using `electron-builder`.

```bash
# Build the Mac app directory (for testing the production bundle without packaging)
npm run build:dir

# Build the final Mac packaged application (.dmg / .app)
npm run build
```

## Testing

KryptonBrowser is validated through rigorous automated testing covering the cryptographic engine, URL blocking, and end-to-end browser flows.

### Unit Tests
Tests the pure ESM Post-Quantum Cryptography implementations and memory-leak-free blocklist parsers.
```bash
npm run test:unit
```

### End-to-End (E2E) Tests
Simulates real browser usage, UI state transitions, and context menu behaviors using Playwright.
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

MIT © [Shravan Sumanthanan](https://github.com/shravansumanthanan)
