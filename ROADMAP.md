# Roadmap: SBOM & CBOM Workflow Improvement

## Overview
This repository provides a reusable GitHub Action for generating Software Bills of Materials (SBOM) and Cryptographic Bills of Materials (CBOM), with a focus on Post-Quantum Cryptography (PQC) readiness.

## Goals
- **Automation**: Seamlessly integrate into any repository.
- **Accuracy**: High-fidelity discovery of cryptographic assets.
- **Actionability**: Provide clear remediation paths for vulnerable assets.

## Improvement Phases

### Phase 1: Documentation & Onboarding (Current)
- [ ] Create a comprehensive `README.md`.
- [ ] Create a `docs/` directory for detailed technical specifications.
- [ ] Create a "Quick Start" guide for repository owners.

### Phase 2: Feature Enhancement
- [ ] **PR Integration**: Automatically post the cryptographic audit summary as a comment on Pull Requests.
- [ ] **Risk Scoring**: Implement a "Risk Score" for each cryptographic asset based on its primitive and key length.
- [ ] **Language Expansion**: Extend `scan_crypto_ast.py` to support Rust, C#, and Java.

### Phase 3: Maturity & Governance
- [ ] **Versioning**: Implement semantic versioning for the reusable workflow.
- [ ] **Customization**: Allow users to define custom "Critical" algorithms or "Safe" primitives via inputs.
- [ ] **Fail-on-Risk**: Add an optional flag to fail the CI build if high-risk vulnerabilities are detected.

## Technical Stack
- **Language**: Python 3.11
- **SBOM Tools**: Anchore Syft (CycloneDX, SPDX)
- **CBOM Tools**: cbomkit
- **Analysis**: Custom AST scanner (`scan_crypto_ast.py`)
