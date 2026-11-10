# SBOM & CBOM Workflow

A reusable GitHub Action for generating Software Bills of Materials (SBOM) and Cryptographic Bills of Materials (CBOM) with a focus on Post-Quantum Cryptography (PQC) readiness.

## Features

- **Dual SBOM Generation**: Generates both CycloneDX and SPDX formats using [Anchore Syft](https://github.com/anchore/syft).
- **Cryptographic Inventory**: Scans your source code for cryptographic primitives (RSA, ECDSA, AES, etc.) using a custom AST-based scanner.
- **CBOM Reconciliation**: Maps discovered call sites to known cryptographic profiles to identify "unassimilated" (unknown) crypto usage.
- **PQC Readiness**: Automatically identifies "Quantum-Vulnerable" algorithms and provides a migration score based on NIST FIPS 203, 204, and 205.
- **Automated Reporting**: Generates a `CRYPTOGRAPHIC_AUDIT.md` report and uploads it to your repository.
- **PR Integration**: Automatically posts a summary of the cryptographic audit and PQC migration scorecard directly onto your Pull Request for immediate visibility.

## Quick Start

To add this workflow to your repository, add the following to your `.github/workflows/` directory:

```yaml
name: SBOM & CBOM Audit

on:
  push:
    branches:
      - main
      - master
    tags:
      - 'v*'
  pull_request:
    branches:
      - main
      - master
  workflow_dispatch:

jobs:
  audit:
    uses: jsoehner/sbom-cbom-workflow@main
    with:
      output_dir: "oss"
      scripts_dir: "scripts"
      docs_path: "docs/security"
      requirements_path: "requirements.txt"
    secrets:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## How it Works

1.  **SBOM Generation**: Uses Syft to create a full inventory of your software components.
2.  **Python Enrichment**: Specifically scans `requirements.txt` to ensure all Python libraries are correctly included in the CycloneDX format.
3.  **CBOM Generation**: Uses `cbomkit` to generate a Cryptographic Bill of Materials.
4.  **AST Scanning**: Runs `scan_crypto_ast.py` to find every place you use crypto in your code.
5.  **Reconciliation**: Compares the code findings against the CBOM. If your code uses a crypto library that isn't in the CBOM, it's flagged as "Unassimilated."
6.  **Reporting**: Compiles all findings into a markdown report in `docs/security/CRYPTOGRAPHIC_AUDIT.md`.

## Technical Stack

- **Language**: Python 3.11
- **SBOM Tools**: Anchore Syft
- **CBOM Tools**: cbomkit
- **Analysis**: Custom AST scanner (`scan_crypto_ast.py`)

## Versioning
The current version is `v1.0.0`.

## Contributing
Please see [ROADMAP.md](ROADMAP.md) for planned improvements.
