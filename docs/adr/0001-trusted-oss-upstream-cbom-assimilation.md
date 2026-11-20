# ADR 0001: Upstream Signed CBOM Assimilation from Trusted OSS Registry

- **Status:** Accepted
- **Date:** 2026-11-20

## Context and Problem Statement

`jsi-bom-actions` reconciles first-party AST cryptographic scans with third-party dependency profiles from `scripts/known_cbom_catalog.json`. Any third-party dependency absent from the static catalog is reported under **Unassimilated Third-Party Binaries & Cryptographic Blind Spots**, lowering the repository's Audit Confidence Score—even when the organization's self-hosted `trusted-oss-harbor` appliance has already downloaded, scanned, and dual-signed that exact dependency.

Additionally:
1. `action.yml` referenced `oss/upstream_cbom.json` when invoking `analyze_cbom.py`, but no workflow step fetched upstream CBOMs from `trusted-oss-harbor`.
2. `scripts/analyze_cbom.py` expected `--external-cbom` files to place `purl` and `cryptoProperties` on the same component object rather than standard CycloneDX 1.6 CBOM layout (`metadata.component.purl` + `type: "cryptographic-asset"` components), and did not credit `VERIFIED_INERT` attestations (0 crypto assets).

## Decision

1. **Opt-In Trusted OSS Resolution in `action.yml`:**
   - Add optional inputs (`trusted-oss-url`, `trusted-oss-mtls-cert`, `trusted-oss-mtls-key`, `trusted-oss-verify-signatures`, `trusted-oss-strict-pqc`, `trusted-oss-warm-missing`). When `trusted-oss-url` is unset, the step is skipped and public standalone behavior is preserved.
   - Load mTLS credentials into an ephemeral `0700` temp directory (`$RUNNER_TEMP/oss-tls.XXXXXX`) with `trap` cleanup.
2. **Batch PURL Resolver & Cryptographic Verification Gate (`scripts/fetch_trusted_oss_cbom.py`):**
   - Extract all dependency PURLs from `oss/sbom.cyclonedx.json` and call `POST <trusted-oss-url>/bom/batch` over HTTPS + mTLS in a single round-trip.
   - Fetch `/keys/trusted-oss-pubkey.asc` and `/keys/trusted-oss-mldsa65.pub` and verify detached GPG and/or NIST FIPS 204 ML-DSA-65 signatures on every returned CBOM before accepting it into `oss/trusted_oss_cboms.json`.
   - Extend `scripts/fetch_oci_cbom.py` with `--mtls-cert`, `--mtls-key`, `--ca-cert`, and direct OCI 1.1 Referrers API fallback.
3. **CycloneDX 1.6 & `VERIFIED_INERT` Assimilation Precedence (`scripts/analyze_cbom.py`):**
   - Parse `TrustedOSS-CBOM-Bundle`, standard CycloneDX 1.6 CBOMs (`metadata.component.purl`), and legacy flat external CBOMs.
   - Give verified Trusted OSS CBOMs precedence over static `known_cbom_catalog.json` heuristics, credit `VERIFIED_INERT` packages in `verified_inert_components`, and surface Trusted OSS vs. static catalog coverage in `CRYPTOGRAPHIC_AUDIT.md`.

## Consequences

- **Positive:** Eliminates cryptographic blind spots for all dependencies cached in `trusted-oss-harbor`, raises Audit Confidence Scores with cryptographically verified (GPG + ML-DSA-65) provenance, and degrades gracefully if the registry is unreachable.
- **Negative:** Requires configuring `vars.TRUSTED_OSS_CACHE_URL` and mTLS secrets (`OSS_MTLS_CLIENT_CERT` / `OSS_MTLS_CLIENT_KEY`) in repositories that opt in.
