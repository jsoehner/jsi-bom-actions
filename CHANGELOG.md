# Changelog

All notable changes to `jsi-bom-actions` composite action and reusable workflows will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-11

### Added
- **First-Class Swift & Apple Ecosystem Cryptographic AST Scanning**:
  - Full AST call-site discovery for Apple `CryptoKit` (`Curve25519.Signing`, `Curve25519.KeyAgreement`, `P256`/`P384`/`P521`, `AES.GCM`, `ChaChaPoly`, `SHA256`, `Insecure.MD5`, `Insecure.SHA1`).
  - Next-generation Post-Quantum Cryptography (PQC) primitives in Swift 6.1+ / macOS 15+ / iOS 18+ (`CryptoKit.MLKEM768`, `MLKEM1024`, `MLKEM512`, `MLDSA65`, `MLDSA87`, `MLDSA44`).
  - Apple `Security.framework` key material and certificate management (`SecKeyCreateRandomKey`, `SecKeyGeneratePair`, `SecKeyCreateSignature`, `SecCertificateRef`, `kSecClassCertificate`, `kSecAttrKeyTypeRSA`, `kSecAttrKeyTypeEC`).
  - Apple `CommonCrypto` legacy C-APIs (`CCCrypt`, `CCCryptorCreate`, `CC_SHA256`, `CCKeyDerivationPBKDF`).
  - Open-source Swift cryptography libraries (`CryptoSwift`, `apple/swift-crypto`, `secp256k1.swift`, `liboqs-swift`).
- **Unbuilt Swift Package Manager Manifest Discovery**: Added native `Package.swift` parsing in `enrich_sbom_python.py` using regex-based package dependency extractors (`.package(url: ..., from: ...)`), enabling complete dependency discovery even in repositories without checked-in `Package.resolved` lockfiles.
- **Multi-Language AST Scanner Expansion (25+ Languages & Configs)**: Expanded `scan_crypto_ast.py` with native AST and regex scanning rules for:
  - Solidity / Vyper EVM smart contracts (`keccak256`, `ecrecover`).
  - Haskell (`Cryptonite`, `Crypto.PubKey`, `Crypto.Cipher`).
  - Zig (`std.crypto.aead`, `std.crypto.sign`, `std.crypto.hash`).
  - Clojure / Groovy (JVM cryptographic interop).
  - Perl (`Crypt::OpenSSL`, `Crypt::PK`, `Crypt::Digest`).
  - Lua & R (`openssl`, `sodium`).
  - Julia (`OpenSSL.jl`, `Nettle.jl`).
  - Configuration & Secret hygiene formats (`.json`, `.yaml`, `.yml`, `.toml`, `.env`, `.properties`).
- **Expanded Open Source CBOM Catalog (105+ Profiles)**:
  - Doubled pre-vetted catalog from 56 to 105 components across 12+ package ecosystems.
  - Added profiles for Swift (`swift-crypto`, `CryptoSwift`), Go (`cloudflare/circl`, `consensys/gnark-crypto`), Python, Rust, Node, Java, .NET, Ruby, PHP.
- **Open Source CBOM Intelligence & Supply Chain Attestation Locators**:
  - Detailed methods to locate external upstream CBOM data: Sigstore Cosign OCI 1.1 attestations (`cosign download attestation --predicate-type https://cyclonedx.org/bom`), OpenSSF Security Insights (`SECURITY-INSIGHTS.yml`), Package Registry Provenance (PEP 740, npm provenance, Swift Package Index).
  - Direct assimilation support using `--external-cbom <file>` in `analyze_cbom.py` to ingest vendor CBOMs directly into the confidence scorecard.
- **Post-Quantum Cryptography Modernization Roadmap & Replacement Matrix**:
  - Full cryptographic algorithm replacement mapping:
    - Classical Key Exchange / KEM (RSA, DH, ECDH, X25519) -> NIST FIPS 203 (ML-KEM-768/1024) or Hybrid X25519MLKEM768.
    - Classical Signatures (RSA-PSS, ECDSA, Ed25519) -> NIST FIPS 204 (ML-DSA-65/87).
    - Long-Lived Root / PKI Signatures -> NIST FIPS 205 (SLH-DSA / SPHINCS+).
    - Embedded Firmware / Microcontroller Secure Boot -> NIST SP 800-208 / RFC 8554 / RFC 8391 (LMS, XMSS).
    - Symmetric Ciphers (AES-128 -> AES-256-GCM / ChaCha20-Poly1305) to counter Grover's algorithm key halving.
  - Multi-language implementation recipes for Swift, Go (1.24+ `crypto/mlkem`), Python (`cryptography` 44.0+ & `liboqs`), Rust (`pqcrypto`), Java/Kotlin (Bouncy Castle 1.78+), and TypeScript (`@noble/post-quantum`).

### Fixed
- **YAML Scalar Indentation in Composite Actions**: Eliminated setup failure caused by unindented markdown dividers (`---`) at column 0 in GitHub composite action steps.
- **Concurrent Git Push Race Condition**: Added exponential backoff fetch & rebase retry loop preventing `[rejected] (fetch first)` CI errors when PR merges race with audit job completion.
- **Detached HEAD Push Failures**: Updated git push commands to target `HEAD:$TARGET_BRANCH` cleanly across detached runner states.
- **Action Deprecation Warnings**: Upgraded `actions/upload-artifact` to `v7.0.2` SHA-pinned release to eliminate runner deprecation notices.

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
