# JSI BOM Actions: Multi-Language SBOM, CBOM & PQC Cryptographic Governance

[![Release](https://img.shields.io/github/v/release/jsoehner/jsi-bom-actions?color=blue&logo=github)](https://github.com/jsoehner/jsi-bom-actions/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Composite-orange?logo=githubactions)](action.yml)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6%20JSON-blue)](https://cyclonedx.org)
[![SPDX](https://img.shields.io/badge/SPDX-2.3%20JSON-brightgreen)](https://spdx.dev)

A drop-in GitHub Action that scans any repository, generates Software Bills of Materials (SBOM) and Cryptographic Bills of Materials (CBOM), and audits Post-Quantum Cryptography (PQC) readiness.

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
        uses: jsoehner/jsi-bom-actions@35ab259e0cb4baebe3a1490700f9d17a9303c2f8 # v1.0.2
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

Every run executes four automated steps:

1. **Dual SBOM Generation (Syft)**: Creates both CycloneDX (`oss/sbom.cyclonedx.json`) and SPDX (`oss/sbom.spdx.json`) software inventories.
2. **Multi-Ecosystem Manifest Enrichment**: Discovers direct and transitive dependencies across 12+ package manager ecosystems (Pip, Poetry, uv, npm, yarn, pnpm, Go modules, Cargo, Maven, Gradle, NuGet, Gem, Composer, Pub, Swift, Hex, and vcpkg).
3. **Multi-Language AST Cryptographic Discovery**: Scans 18+ programming languages for cryptographic call sites across all four CycloneDX 1.6 crypto asset types:
   - `algorithm` (ciphers, asymmetric primitives, PQC KEMs/signatures, KDFs like Argon2id/PBKDF2/scrypt/bcrypt, hashes, CSPRNGs)
   - `protocol` (TLS 1.3, deprecated TLS 1.0/1.1)
   - `certificate` (X.509 certs, CA bundles)
   - `related-crypto-material` (KMS keys, keystores, public/private keys)
4. **PQC Scorecard & Reporting**:
   - Compares findings against NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
   - Generates and commits `docs/security/CRYPTOGRAPHIC_AUDIT.md` on branch pushes.
   - Posts a PQC scorecard comment directly on Pull Requests.
   - Uploads all artifacts (`oss/`) to the workflow summary.

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
| **Python** | Native `ast` inspection + `cryptography`, `hashlib`, `hmac`, `ssl`, `secrets`, `PyJWT`, `PyCryptodome`, `bcrypt`, `argon2`, `liboqs` |
| **JavaScript / TypeScript** | Node `crypto`, WebCrypto `crypto.subtle`, `jose`, `jsonwebtoken`, `@noble/*`, `tweetnacl`, `bcrypt`, `argon2` |
| **Go** | `crypto/mlkem` (Go 1.24+), `crypto/tls`, `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/ecdh`, `crypto/aes`, `crypto/sha*`, `circl` |
| **Java / Kotlin / Scala** | JCA/JCE/JSSE (`Cipher`, `KEM.getInstance("ML-KEM")`, `SSLContext`, `KeyStore`, `X509Certificate`), Bouncy Castle (PQC), Spring Security |
| **Rust** | `ml-kem`, `ml-dsa`, `slh-dsa`, `pqcrypto`, `oqs`, `ring`, `aws-lc-rs`, `rustls`, `aes-gcm`, `chacha20poly1305`, `sha2`, `sha3`, `ed25519-dalek` |
| **C# / .NET** | `System.Security.Cryptography` (.NET 9+ `MLKem`, `MLDsa`, `SlhDsa`, `RSA`, `ECDsa`, `AesGcm`, `ChaCha20Poly1305`, `SHA256/384/512`), BouncyCastle |
| **C / C++** | OpenSSL / BoringSSL `EVP_*`, `liboqs`, `libsodium`, `mbedTLS`, `wolfSSL` |
| **Ruby, PHP, Swift, Dart, Elixir** | Native crypto engines: Swift `CryptoKit` (`MLKEM`, `MLDSA`), PHP `sodium`/`openssl`, Ruby `OpenSSL`, Dart `cryptography`, Elixir `:crypto` |
| **IaC, Configs & Certificates** | SQL `pgcrypto`/`AES_ENCRYPT`, Terraform KMS/TLS resources, NGINX/Envoy TLS configs, X.509 `.pem`/`.crt`/`.cer` certificates |

---

## License

This project is licensed under the [MIT License](LICENSE).
