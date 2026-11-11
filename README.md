# JSI BOM Actions: Multi-Language SBOM, CBOM & PQC Cryptographic Governance

[![Release](https://img.shields.io/github/v/release/jsoehner/jsi-bom-actions?color=blue&logo=github)](https://github.com/jsoehner/jsi-bom-actions/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Composite-orange?logo=githubactions)](action.yml)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6%20JSON-blue)](https://cyclonedx.org)
[![SPDX](https://img.shields.io/badge/SPDX-2.3%20JSON-brightgreen)](https://spdx.dev)

A drop-in GitHub Action that scans any repository across 25+ programming languages, generates Software Bills of Materials (SBOM) and Cryptographic Bills of Materials (CBOM), assimilates open-source third-party cryptographic profiles, and audits Post-Quantum Cryptography (PQC) readiness.

---

## Quick Start: Drop-in File Setup

Add one workflow file to your repository at `.github/workflows/sbom-cbom.yml`:

```yaml
name: Software & Cryptographic Bill of Materials (SBOM & CBOM)

on:
  push:
    branches: [main, master]
    tags: ['v*']
  pull_request:
    branches: [main, master]
  workflow_dispatch:

permissions:
  contents: write
  id-token: write
  pull-requests: write

jobs:
  generate-and-verify-boms:
    name: Generate, Verify, and Upload BOMs
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - name: Run Multi-Language SBOM, CBOM & PQC Governance
        uses: jsoehner/jsi-bom-actions@v1.1.0 # Pinned to v1.1.0
        with:
          target-dir: '.'
          output-dir: 'oss'
          publish-audit-report: 'true'
          comment-pr: 'true'
          upload-artifacts: 'true'
          retention-days: '90'
```

No local scripts or installation commands required. The action runs self-contained in GitHub Actions runners.

---

## Automated Updates with Dependabot

Add `.github/dependabot.yml` to have Dependabot automatically open Pull Requests when a new version of this action is published:

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot detects releases on `jsoehner/jsi-bom-actions` and updates the 40-character commit SHA while preserving the semantic version comment.

---

## What the Action Does

Every run executes automated discovery, reconciliation, and audit steps:

1. **Dual SBOM Generation (Syft)**: Creates both CycloneDX (`oss/sbom.cyclonedx.json`) and SPDX (`oss/sbom.spdx.json`) software inventories.
2. **Multi-Ecosystem Manifest Enrichment**: Discovers direct and transitive dependencies across 12+ package manager ecosystems:
   - Python (`requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`)
   - Node.js / TypeScript (`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)
   - Swift / iOS (`Package.swift`, `Package.resolved`, `Podfile.lock`)
   - Go (`go.mod`, `go.sum`)
   - Rust (`Cargo.toml`, `Cargo.lock`)
   - Java / Kotlin / JVM (`pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`, `libs.versions.toml`)
   - C# / .NET (`packages.lock.json`, `*.csproj`, `Directory.Packages.props`, `packages.config`)
   - Ruby (`Gemfile.lock`, `Gemfile`)
   - PHP (`composer.lock`, `composer.json`)
   - Dart / Flutter (`pubspec.lock`, `pubspec.yaml`)
   - Elixir (`mix.lock`, `mix.exs`)
   - C / C++ (`vcpkg.json`, `conanfile.txt`, `conan.lock`)
3. **Multi-Language AST Cryptographic Discovery (25+ Languages)**: Scans source code and configs for cryptographic call sites across all four CycloneDX 1.6 crypto asset types:
   - `algorithm` (ciphers, asymmetric primitives, PQC KEMs/signatures, KDFs like Argon2id/PBKDF2/scrypt/bcrypt, hashes, CSPRNGs)
   - `protocol` (TLS 1.3, hybrid X25519MLKEM768, deprecated TLS 1.0/1.1)
   - `certificate` (X.509 certs, Apple Keychain, PEM/CRT bundles)
   - `related-crypto-material` (KMS keys, keystores, public/private key material)
4. **Upstream Open Source CBOM Catalog Assimilation (105+ Profiles)**:
   - Assimilates known cryptographic profiles for 105+ open-source libraries across all major ecosystems into third-party supply chain assessments.
   - Calculates an **Audit Confidence Score** based on first-party AST coverage and third-party dependency assimilation.
5. **PQC Scorecard & Modernization Roadmap**:
   - Compares findings against NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 (FN-DSA), and stateful hash signatures (LMS/XMSS).
   - Generates an actionable Cryptographic Algorithm Replacement Matrix and multi-language implementation recipes.
   - Generates and commits `docs/security/CRYPTOGRAPHIC_AUDIT.md` on branch pushes.
   - Posts a PQC scorecard comment directly on Pull Requests.
   - Uploads all artifacts (`oss/`) to the workflow summary.

---

## Post-Quantum Cryptography (PQC) Replacement Matrix

| Classical Primitive | Threat Mechanism | Post-Quantum Replacement | NIST Standard | Migration Guidance |
|---|---|---|---|---|
| **RSA / DH / ECDH / X25519** (Key Exchange / KEM) | Broken by Shor's algorithm | **ML-KEM-768 / ML-KEM-1024** or Hybrid **X25519MLKEM768** | NIST FIPS 203 | Primary general-purpose key encapsulation. For TLS 1.3 and SSH, deploy hybrid `X25519MLKEM768` for seamless backward compatibility. |
| **RSA-PSS / ECDSA / Ed25519** (Digital Signatures) | Broken by Shor's algorithm | **ML-DSA-65 / ML-DSA-87** | NIST FIPS 204 | Primary general-purpose lattice signatures for PKI, X.509 certs, code signing, and API tokens. |
| **High-Assurance Root / CA Signatures** | Broken by Shor's algorithm | **SLH-DSA** (SPHINCS+) | NIST FIPS 205 | Stateless hash-based signatures with zero lattice-algebra assumptions; ideal for long-lived root trust stores. |
| **Firmware / Secure Boot Signing** | Broken by Shor's algorithm | **LMS / XMSS** | NIST SP 800-208 / RFC 8554 / RFC 8391 | Stateful hash-based signatures with minimal memory/code overhead; optimal for microcontrollers. |
| **AES-128 (Symmetric Encryption)** | Halved by Grover's (effective 64-bit security) | **AES-256-GCM** or **ChaCha20-Poly1305** | NIST SP 800-38D / RFC 8439 | Upgrade symmetric key lengths from 128-bit to 256-bit to preserve Grover resistance. |
| **SHA-1 / MD5 (Hash Functions)** | Broken classical collisions + quantum Grover | **SHA-256 / SHA-384 / SHA-512 / SHA-3-256** | NIST FIPS 180-4 / FIPS 202 | Deprecate weak digests immediately. Use SHA-256 or SHA-3-256 as quantum-safe baseline. |

---

## Open Source CBOM Intelligence & Supply Chain Attestation Locators

Third-party dependencies represent the vast majority of cryptographic attack surface. When third-party packages do not publish explicit Cryptographic Bills of Materials (CBOMs), use the following authoritative sources and workflows to locate cryptographic attestations:

1. **OCI 1.1 / Sigstore Cosign Attestations (`application/vnd.cyclonedx+json`)**:
   Modern container images and package registries publish signed CycloneDX CBOM attestations via Sigstore Cosign:
   ```bash
   # Download signed CycloneDX attestation attached to an OCI artifact
   cosign download attestation --predicate-type https://cyclonedx.org/bom ghcr.io/org/repo:tag | jq -r .payload | base64 -d | jq .
   ```
2. **OpenSSF Security Insights (`SECURITY-INSIGHTS.yml`)**:
   Repositories following OpenSSF standards publish cryptographic dependencies and key management policies in their repository root:
   - Check `/.github/SECURITY-INSIGHTS.yml` or `/SECURITY-INSIGHTS.yml` for declared encryption algorithms, key lengths, and compliance certifications.
3. **Package Registry Provenance & Hash Attestations**:
   - **PyPI (PEP 740)**: Inspect cryptographic provenance via `https://pypi.org/pypi/<package>/json` (`attestations` block).
   - **npm Provenance**: Inspect build provenance and cryptographic sign-off via `npm view <package> --json`.
   - **Swift Package Index**: Discover cryptography framework dependencies directly from SwiftPM manifests and DocC metadata.
4. **Direct CBOM Assimilation (`--external-cbom`)**:
   If an upstream vendor or dependency provides a CBOM file (`*.cbom.json` or `*.cyclonedx.json`), feed it directly into `jsi-bom-actions` via:
   ```bash
   python scripts/analyze_cbom.py cbom.json --sbom sbom.json --external-cbom path/to/upstream.cbom.json
   ```
   This automatically credits the dependency in the scorecard and elevates your repository's **Audit Confidence Score**.

---

## Action Inputs & Outputs

### Inputs

| Input | Description | Default | Required |
| :--- | :--- | :--- | :--- |
| `target-dir` | Path to target repository directory | `.` | No |
| `output-dir` | Directory where BOM artifacts and reports are saved | `oss` | No |
| `python-version` | Python runtime version for AST scanning | `3.11` | No |
| `publish-audit-report` | Commit and push audit report to repository on push | `true` | No |
| `audit-report-path` | Repository path for the markdown audit report | `docs/security/CRYPTOGRAPHIC_AUDIT.md` | No |
| `comment-pr` | Post PQC scorecard summary comment on Pull Requests | `true` | No |
| `upload-artifacts` | Upload BOM artifacts to workflow run | `true` | No |
| `artifact-name` | Name of the uploaded workflow artifact bundle | `bom-artifacts` | No |
| `retention-days` | Days to retain uploaded workflow artifacts | `90` | No |

### Outputs

| Output | Description |
| :--- | :--- |
| `sbom-cyclonedx` | Path to generated CycloneDX SBOM JSON (`oss/sbom.cyclonedx.json`) |
| `sbom-spdx` | Path to generated SPDX SBOM JSON (`oss/sbom.spdx.json`) |
| `cbom` | Path to AST-reconciled CycloneDX CBOM JSON (`oss/cbom.json`) |
| `crypto-analysis` | Path to structured JSON cryptographic analysis (`oss/crypto-analysis.json`) |
| `crypto-summary` | Path to Markdown cryptographic audit summary (`oss/crypto-summary.md`) |

---

## Permissions & Concurrency Resilience

### Required Permissions

To allow the workflow to commit the generated cryptographic audit report and comment on pull requests, configure the following job-level permissions:

```yaml
permissions:
  contents: write      # Required to commit docs/security/CRYPTOGRAPHIC_AUDIT.md
  pull-requests: write # Required to comment PQC migration scorecards on PRs
  id-token: write      # Required for OIDC signing (if applicable)
```

If your repository enforces strict branch protection (e.g. required approvals or signed commits) or uses read-only tokens:
- Set `publish-audit-report: 'false'` and/or `comment-pr: 'false'`.
- All generated SBOM, CBOM, and markdown audit reports will still be generated and preserved as downloadable workflow artifacts (`oss/`).

### Concurrency & Rebase Resilience

When automated jobs (such as Dependabot merges or parallel CI runs) commit to the default branch at the same time as this action, the action automatically:
1. Catches non-fast-forward push rejections.
2. Fetches the latest remote branch state and performs an in-memory `git rebase`.
3. Retries pushing the single audit documentation commit up to 3 times before gracefully emitting a warning without failing the build.

---

## Alternative: Call as a Reusable Workflow

If your organization standardizes on `workflow_call`, invoke the reusable workflow directly:

```yaml
name: SBOM & CBOM Audit

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  audit:
    uses: jsoehner/jsi-bom-actions/.github/workflows/sbom-cbom.yml@v1
    permissions:
      contents: write
      id-token: write
      pull-requests: write
    with:
      target_dir: '.'
      output_dir: 'oss'
      docs_path: 'docs/security'
      publish_audit: true
      comment_pr: true
```

---

## Supported Languages & Ecosystems

| Language / File Type | Coverage |
| :--- | :--- |
| **Swift & Apple Ecosystem** | Apple `CryptoKit` (`MLKEM1024/768/512`, `MLDSA87/65/44`, `Curve25519`, `P256/384/521`, `AES.GCM`, `ChaChaPoly`, `SHA256`), Apple `Security.framework` (`SecKey*`, `SecCertificate*`, Keychain), `CommonCrypto` (`CCCrypt`, `CC_SHA256`, `CCKeyDerivationPBKDF`), `apple/swift-crypto`, `CryptoSwift`, `Package.swift` discovery |
| **Python** | Native `ast` inspection + `cryptography` (44.0+ / 45.0+ `X25519MLKEM768`), `hashlib`, `hmac`, `ssl`, `secrets`, `PyJWT`, `PyCryptodome`, `bcrypt`, `argon2`, `liboqs-python` |
| **JavaScript / TypeScript** | Node `crypto`, WebCrypto `crypto.subtle`, `jose`, `jsonwebtoken`, `@noble/post-quantum`, `@noble/ciphers`, `tweetnacl`, `bcrypt`, `argon2` |
| **Go** | `crypto/mlkem` (Go 1.24+ `GenerateKey768`), `crypto/tls` (`X25519MLKEM768`), `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/ecdh`, `crypto/aes`, `crypto/sha*`, `circl`, `gnark-crypto` |
| **Java / Kotlin / Scala** | JCA/JCE/JSSE (`Cipher`, `KEM.getInstance("ML-KEM")`, `SSLContext`, `KeyStore`, `X509Certificate`), Bouncy Castle 1.78+ (`MLKEMKeyGenParameterSpec`, `MLDSAKeyGenParameterSpec`), Spring Security |
| **Rust** | `ml-kem`, `ml-dsa`, `slh-dsa`, `pqcrypto-kyber`, `pqcrypto-dilithium`, `oqs`, `ring`, `aws-lc-rs`, `rustls-pqc`, `aes-gcm`, `chacha20poly1305`, `sha2`, `sha3`, `ed25519-dalek` |
| **C# / .NET** | `System.Security.Cryptography` (.NET 9+ `MLKem`, `MLDsa`, `SlhDsa`, `RSA`, `ECDsa`, `AesGcm`, `ChaCha20Poly1305`, `SHA256/384/512`), BouncyCastle.Cryptography |
| **C / C++** | OpenSSL 3.5+ / BoringSSL `EVP_*` (hybrid KEMs), `liboqs`, `libsodium`, `mbedTLS`, `wolfSSL` |
| **Ruby, PHP, Dart, Elixir** | Swift `CryptoKit`, PHP `sodium`/`openssl`, Ruby `OpenSSL`, Dart `cryptography`/`pointycastle`, Elixir `:crypto`/`:public_key` |
| **Solidity / Vyper, Haskell, Zig, Perl, Lua, R, Julia** | EVM `keccak256`/`ecrecover`, Haskell `Cryptonite`/`Crypto.PubKey`, Zig `std.crypto.*`, Perl `Crypt::*`, Lua `openssl`, R `sodium`/`openssl`, Julia `OpenSSL.jl`/`Nettle.jl` |
| **IaC, Configs & Certificates** | SQL `pgcrypto`/`AES_ENCRYPT`, Terraform KMS/TLS resources, NGINX/Envoy TLS configs, X.509 `.pem`/`.crt`/`.cer` certificates, `.env`, `.yaml`, `.json` configuration files |

---

## License

This project is licensed under the [MIT License](LICENSE).
