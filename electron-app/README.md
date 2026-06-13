# KryptonBrowser — The Army-Grade PQC Browser

KryptonBrowser is a hardened, Electron-based web browser built for post-quantum security environments. It implements **FIPS 203 (ML-KEM-768)** for key encapsulation and **FIPS 204 (ML-DSA-65)** for digital signatures, ensuring communications remain secure against future quantum computing attacks (Store-Now-Decrypt-Later). 

## 🛡️ Key Features

### 1. Hybrid Post-Quantum Cryptography
- **ML-KEM-768 (Kyber)**: Natively integrated via `@noble/post-quantum` for robust key exchange.
- **ML-DSA-65 (Dilithium)**: Supports offline digital signatures and certificate verification.
- **TLS 1.3 Integration**: Supports Chromium's native `UseMLKEM` alongside `X25519Kyber768Draft00`.

### 2. Zero-Trust Security Architecture
- **DOMPurify Sanitization**: Strict XSS prevention in Reader Mode and internally generated content.
- **Content Security Policy (CSP)**: Hardened inline styles and scripts disabled.
- **Strict Permission Handling**: Denies sensitive APIs (camera, mic, location, USB) by default.
- **File System Guard**: Blocks arbitrary path traversal during file downloads.

### 3. Integrated Privacy Shields
- Built-in URL filtering based on a bundled `blocklist.json`.
- O(1) hostname blocking categorizing ads, trackers, malware, and fingerprinting domains.
- Automatic HTTP-to-HTTPS upgrades.
- Force-injects `DNT` and `Sec-GPC` headers on all outbound requests.

### 4. Modern UI & Modular Core
- UI is built with ES Modules, bundled with **Vite** for performance and dead-code elimination.
- Fast `index.html` loading and modular utilities.

## 🚀 Getting Started

### Prerequisites
- Node.js v20+
- npm v10+

### Installation & Development
```bash
# Install dependencies
npm install

# Run the app locally (bundles UI with Vite automatically)
npm start
```

### Build & Release
We use `electron-builder` to package the application.

```bash
# Build Mac app directory (for testing without packaging)
npm run build:dir

# Build Mac packaged application (.dmg / .app)
npm run build
```

## 🧪 Testing

We employ both Unit and End-to-End (E2E) testing.

```bash
# Run Jest Unit Tests (PQC engine, Blocklist parsing)
npm run test:unit

# Run Playwright E2E Tests (App launching, UI state)
npm run test:e2e
```

## 📚 Architecture

Refer to the Architectural Decision Records (ADRs) for deep-dives into our technical choices:
- [ADR-001: Vite Integration for Frontend Bundling](docs/ADR-001-Vite-Integration.md)
- [ADR-002: Asynchronous Initialization for Pure ESM PQC Libraries](docs/ADR-002-PQC-Engine.md)

## 🪖 Defense-in-Depth

KryptonBrowser is designed for high-assurance scenarios. It provides robust protection against tracking, unencrypted data transit, and XSS vulnerabilities, serving as a dependable enclave for sensitive network operations.
