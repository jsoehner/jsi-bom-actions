# Changelog

All notable changes to `jsi-bom-actions` composite action and reusable workflows will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-11-11

### Changed
- **Repository Rename**: Renamed repository to `jsi-bom-actions` to reflect the expanded scope as a suite of Bill of Materials actions and workflows across the JSI portfolio.
- Upgraded `actions/upload-artifact` to `cf430e030ddbb5b0abf93d22962f4752f3646cd9` (`v7.0.2`).
- Standardized `VERSION` to `1.0.2`.
- Updated documentation with troubleshooting advice and branch protection configuration guidance.

### Fixed
- **YAML Syntax in Composite Action**: Resolved YAML block scalar indentation parsing error in `action.yml` within the `Post PR Summary Comment` step. Replaced raw multi-line strings with structured `printf` formatting to prevent `---` from being misparsed as a document boundary.
- **Concurrent Git Push Resiliency**: Added a 3-attempt exponential rebase-and-retry mechanism (`git fetch origin "$TARGET_BRANCH"` followed by `git rebase`) in the `Publish Cryptographic Audit Report to Repository` step to eliminate race conditions when concurrent commits (e.g. Dependabot PR merges) advance the target branch.
- **Detached HEAD Push Safety**: Updated git push commands to target `HEAD:$TARGET_BRANCH` explicitly, resolving non-fast-forward failures on runners checking out detached commit references.
- **Graceful Permission Degradation**: Added non-blocking warning annotations if repository permissions or branch protection rules prohibit automatic bot pushes, ensuring that BOM artifacts and summary outputs are always preserved without failing the CI pipeline.

## [1.0.1] - 2026-11-11

### Fixed
- Fixed YAML indentation and parsing in `action.yml` PR comment step.

## [1.0.0] - 2026-11-11

### Added
- Initial standalone release of `jsi-bom-actions` composite action and reusable workflow.
- Consolidated multi-language AST crypto scanner (`scan_crypto_ast.py`) supporting 18+ languages across all four CycloneDX 1.6 crypto asset categories (`algorithm`, `protocol`, `certificate`, `related-crypto-material`).
- Multi-ecosystem manifest enrichment (`enrich_sbom_python.py`, `enrich_sbom_gradle.py`) across 12+ package manager ecosystems.
- Post-Quantum Cryptography (PQC) scorecard auditing engine against NIST FIPS 203, FIPS 204, and FIPS 205.
- Automated CycloneDX and SPDX SBOM generation powered by Anchore Syft.
- Automated CBOMkit container execution with fallback.
- Automated PR comment reporting and `docs/security/CRYPTOGRAPHIC_AUDIT.md` synchronization.
- Dependabot configuration template for SHA-pinned workflow updates.
