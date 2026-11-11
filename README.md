# SBOM & CBOM Workflow & GitHub Action

A reusable, self-contained GitHub Action and Reusable Workflow for generating Software Bills of Materials (SBOM) and Cryptographic Bills of Materials (CBOM) with automated Post-Quantum Cryptography (PQC) readiness scoring.

## Supported Modes & Features

- **Composite GitHub Action (`action.yml`)**: Compatible with **Dependabot** (`package-ecosystem: "github-actions"`). Runs self-contained via `${{ github.action_path }}` without requiring scripts to be copied into caller repositories.
- **Reusable Workflow (`.github/workflows/sbom-cbom.yml`)**: Supports `workflow_call` for centralized organization workflows.
- **Multi-Language AST Cryptographic Discovery**: Scans 18+ programming languages (Python AST, JS/TS/WebCrypto, Go 1.24+ `crypto/mlkem`, Java JCA/BouncyCastle, Rust, C#, C/C++, Ruby, PHP, Swift CryptoKit, Dart, Elixir, SQL, Shell, Terraform, and X.509 certificates).
- **All 4 CycloneDX 1.6 Cryptographic Asset Types**: Detects and categorizes `algorithm`, `protocol`, `certificate`, and `related-crypto-material`.
- **Universal Multi-Ecosystem SBOM Enrichment**: Resolves direct and transitive dependencies across 12+ package managers (Pip, Poetry, uv, npm, yarn, pnpm, Go modules, Cargo, Maven, Gradle, NuGet, Gem, Composer, Pub, Swift, Hex, and vcpkg).
- **Automated PQC Scorecard & Migration Progress**: Flags quantum-vulnerable public key algorithms (RSA, ECDSA, ECDH, Ed25519) and tracks migration to NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
- **PR Feedback & Repository Audits**: Posts a concise PQC scorecard directly on Pull Requests and commits a full `docs/security/CRYPTOGRAPHIC_AUDIT.md` report on push.

---

## Usage

### Option 1: As a Composite GitHub Action (Recommended for Dependabot)

Add to `.github/workflows/sbom-cbom.yml` in your repository:

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
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - name: Generate & Verify SBOMs and CBOMs
        uses: jsoehner/sbom-cbom-workflow@v1
        with:
          target-dir: '.'
          output-dir: 'oss'
          publish-audit-report: 'true'
          comment-pr: 'true'
```

### Option 2: As a Reusable Workflow

```yaml
name: SBOM & CBOM Audit

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  audit:
    uses: jsoehner/sbom-cbom-workflow/.github/workflows/sbom-cbom.yml@v1
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

## Dependabot Configuration

To have Dependabot automatically keep your workflow pinned to the latest release SHA:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

## Action Inputs

| Input | Description | Default |
| :--- | :--- | :--- |
| `target-dir` | Path to target code or directory | `.` |
| `output-dir` | Directory where JSON & Markdown BOMs are saved | `oss` |
| `python-version` | Python runtime version for AST scanning | `3.11` |
| `publish-audit-report` | Commit and push audit report to repository on push | `true` |
| `audit-report-path` | Path to save the markdown audit report | `docs/security/CRYPTOGRAPHIC_AUDIT.md` |
| `comment-pr` | Post PQC scorecard as a comment on Pull Requests | `true` |
| `upload-artifacts` | Upload BOM artifacts to workflow run | `true` |
| `retention-days` | Artifact retention period in days | `90` |
