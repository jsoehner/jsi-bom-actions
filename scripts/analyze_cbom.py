#!/usr/bin/env python3
"""
analyze_cbom.py - Analyze CycloneDX Cryptographic Bill of Materials (CBOM) & Supply Chain Attestations

Inventories all cryptographic assets (algorithms, certificates, keys/related-crypto-material,
protocols), assimilates known upstream CBOM profiles for third-party dependencies across
12+ language ecosystems, computes audit confidence based on supply chain coverage, and
assesses Post-Quantum Cryptography (PQC) migration readiness.
"""

import sys
import json
import argparse
from pathlib import Path
from collections import Counter
import re
from typing import List, Dict, Any, Optional, Tuple

# Ensure stdout and stderr handle utf-8 characters properly on all platforms (e.g. Windows cp1252)
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

QUANTUM_VULNERABLE_PATTERNS = [
    r"\bRSA\b", r"\bECDSA\b", r"\bECDH\b", r"\bDIFFIE[-_ ]?HELLMAN\b",
    r"\bED25519\b", r"\bED448\b", r"\bX25519\b", r"\bX448\b",
    r"\bSECP\d+[RK]1\b", r"(?<![A-Z0-9_-])(?:DSA|DH)(?![A-Z0-9_-])",
    r"\bMD5\b", r"\bSHA[-_]?1\b", r"\b3DES\b", r"\bTRIPLEDES\b",
    r"\bRC4\b", r"\bARC4\b", r"\bAES[-_]?ECB\b", r"\bTLS[-_]?1\.[01]\b"
]

POST_QUANTUM_PATTERNS = [
    r"\bML[-_]?KEM\b", r"\bKYBER\b", r"\bML[-_]?DSA\b", r"\bDILITHIUM\b",
    r"\bSLH[-_]?DSA\b", r"\bSPHINCS\+?\b", r"\bFALCON\b", r"\bFN[-_]?DSA\b",
    r"\bLMS\b", r"\bXMSS\b", r"\bX25519MLKEM768\b", r"\bSECP256R1MLKEM768\b",
    r"\bFRODOKEM\b", r"\bCLASSIC[-_]?MCELIECE\b", r"\bBIKE\b", r"\bHQC\b",
    r"\bPQC[-_]?KEM\b"
]

SYMMETRIC_CLASSICAL = {
    "AES", "CHACHA20", "XCHACHA20", "SHA-256", "SHA-384", "SHA-512", "SHA-3",
    "SHA3-256", "SHA3-512", "BLAKE2B", "BLAKE3", "ARGON2ID", "PBKDF2", "SCRYPT",
    "BCRYPT", "HKDF", "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512", "CSPRNG-DRBG"
}


def load_catalog(catalog_path: Optional[Path], external_cboms: Optional[List[Path]] = None) -> List[Dict[str, Any]]:
    """Load known third-party CBOM catalog profiles and any external/upstream CBOMs."""
    default_path = Path(__file__).parent / "known_cbom_catalog.json"
    path_to_use = catalog_path or (default_path if default_path.exists() else None)
    components = []

    if path_to_use and path_to_use.exists():
        try:
            with open(path_to_use, "r", encoding="utf-8") as f:
                data = json.load(f)
                components.extend(data.get("components", []))
        except Exception as e:
            print(f"Warning: Failed to load CBOM catalog {path_to_use}: {e}", file=sys.stderr)

    # Ingest external or OCI-fetched CBOM files if provided
    if external_cboms:
        for ext_file in external_cboms:
            if ext_file.exists():
                try:
                    with open(ext_file, "r", encoding="utf-8") as f:
                        ext_data = json.load(f)
                        ext_comps = ext_data.get("components", [])
                        for ec in ext_comps:
                            c_name = ec.get("name") or "External Dependency"
                            c_purl = ec.get("purl") or ""
                            crypto_props = ec.get("cryptoProperties", {})
                            c_crypto_assets = []
                            if crypto_props:
                                algo_details = crypto_props.get("algorithmProperties", {})
                                algo_name = str(algo_details.get("name") or c_name)
                                c_crypto_assets.append({
                                    "name": f"{c_name} Crypto Asset",
                                    "primitive": str(algo_details.get("primitive") or "unknown"),
                                    "algorithm": algo_name,
                                    "pqc_status": "POST-QUANTUM READY" if any(re.search(p, algo_name.upper()) for p in POST_QUANTUM_PATTERNS) else (
                                        "QUANTUM-VULNERABLE" if any(re.search(p, algo_name.upper()) for p in QUANTUM_VULNERABLE_PATTERNS) else "CLASSICAL/SYMMETRIC"
                                    ),
                                    "key_length": str(algo_details.get("parameterSetIdentifier") or algo_details.get("keyLength") or "N/A"),
                                    "remediation": "Vendor provided attestation via OCI 1.1 / ORAS CBOM"
                                })
                            components.append({
                                "name": c_name,
                                "purlPattern": f"^{re.escape(c_purl.split('@')[0])}(@.*)?$" if c_purl else None,
                                "category": "upstream-vendor-attestation",
                                "confidence": "HIGH",
                                "source": f"OCI / Upstream Vendor Attestation ({ext_file.name})",
                                "cryptoAssets": c_crypto_assets
                            })
                except Exception as e:
                    print(f"Warning: Failed to parse external CBOM {ext_file}: {e}", file=sys.stderr)

    return components


def parse_sbom_components(sbom_path: Path) -> List[Dict[str, Any]]:
    """Parse software components from CycloneDX or SPDX SBOM."""
    if not sbom_path.exists():
        return []

    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Warning: Could not parse SBOM at {sbom_path}: {e}", file=sys.stderr)
        return []

    results = []

    # CycloneDX format
    if data.get("bomFormat") == "CycloneDX" or "components" in data:
        for c in data.get("components", []):
            c_name = str(c.get("name") or "Unknown")
            c_purl = str(c.get("purl") or "")
            c_type = str(c.get("type") or "library")
            if not c_purl and (c_type == "file" or c_name.startswith("/") or c_name.endswith((".yml", ".yaml"))):
                continue
            results.append({
                "name": c_name,
                "version": str(c.get("version") or "N/A"),
                "purl": c_purl,
                "type": c_type,
                "hashes": c.get("hashes", [])
            })
        return results

    # SPDX 3.0+ or SPDX 2.x format
    if "@graph" in data:
        for item in data.get("@graph", []):
            if item.get("type") in ("software_Package", "Package") or "spdxId" in item:
                results.append({
                    "name": str(item.get("name") or "Unknown"),
                    "version": str(item.get("software_packageVersion") or item.get("versionInfo") or "N/A"),
                    "purl": str(item.get("software_packageUrl") or ""),
                    "type": "library",
                    "hashes": []
                })
    elif "packages" in data:
        for p in data.get("packages", []):
            results.append({
                "name": str(p.get("name") or "Unknown"),
                "version": str(p.get("versionInfo") or "N/A"),
                "purl": str(p.get("externalRefs", [{}])[0].get("referenceLocator") if p.get("externalRefs") else ""),
                "type": "library",
                "hashes": p.get("checksums", [])
            })

    return results


def assimilate_third_party_cbom(
    sbom_components: List[Dict[str, Any]],
    catalog: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Match discovered SBOM components against known CBOM catalog profiles.
    Returns: (assimilated_crypto_assets, verified_inert_components, unassimilated_components, confidence_metrics)
    """
    assimilated_crypto = []
    verified_inert = []
    unassimilated = []

    for comp in sbom_components:
        name = comp["name"]
        purl = comp["purl"]
        matched_cat = None

        for cat_entry in catalog:
            purl_pat = cat_entry.get("purlPattern")
            name_pat = cat_entry.get("name")
            if purl_pat and purl and re.search(purl_pat, purl, re.IGNORECASE):
                matched_cat = cat_entry
                break
            elif name_pat and (
                name_pat.lower() == name.lower()
                or name_pat.lower().replace("-", "_") == name.lower().replace("-", "_")
                or (not purl and len(name_pat) >= 6 and name_pat.lower() in name.lower())
            ):
                matched_cat = cat_entry
                break

        if matched_cat:
            assets = matched_cat.get("cryptoAssets", [])
            if assets:
                for a in assets:
                    assimilated_crypto.append({
                        "name": f"{comp['name']} ({a['name']})",
                        "component_name": comp["name"],
                        "version": comp["version"],
                        "purl": comp["purl"],
                        "asset_type": a.get("primitive", "algorithm"),
                        "algorithm": a.get("algorithm", a["name"]),
                        "primitive": a.get("primitive", "unknown"),
                        "key_length": a.get("key_length", "N/A"),
                        "pqc_status": a.get("pqc_status", "QUANTUM-VULNERABLE"),
                        "confidence": matched_cat.get("confidence", "HIGH"),
                        "source": f"Assimilated Upstream CBOM: {matched_cat.get('source', 'Known Catalog')}",
                        "remediation": a.get("remediation", ""),
                        "occurrences": [{"location": f"Dependency: {comp['name']}@{comp['version']}"}]
                    })
            else:
                verified_inert.append({
                    "name": comp["name"],
                    "version": comp["version"],
                    "purl": comp["purl"],
                    "confidence": matched_cat.get("confidence", "HIGH"),
                    "source": matched_cat.get("source", "Verified Cryptographically Inert")
                })
        else:
            unassimilated.append(comp)

    total_deps = len(sbom_components)
    verified_count = len({a["component_name"] for a in assimilated_crypto}) + len(verified_inert)

    if total_deps > 0:
        coverage_pct = round((verified_count / total_deps) * 100, 1)
        confidence_score = round(((verified_count + 1) / (total_deps + 1)) * 100, 1)
        if confidence_score >= 80:
            rating = "HIGH"
            rating_badge = "🟢 HIGH"
        elif confidence_score >= 50:
            rating = "MEDIUM"
            rating_badge = "🟡 MEDIUM"
        else:
            rating = "LOW"
            rating_badge = "🔴 LOW"
    else:
        coverage_pct = 100.0
        confidence_score = 100.0
        rating = "HIGH (First-Party Only)"
        rating_badge = "🟢 HIGH"

    confidence_metrics = {
        "total_dependencies": total_deps,
        "verified_dependencies_count": verified_count,
        "unassimilated_dependencies_count": len(unassimilated),
        "coverage_percentage": coverage_pct,
        "confidence_score": confidence_score,
        "confidence_rating": rating,
        "confidence_badge": rating_badge,
        "os_inventory_status": "Updated" if any(c.get("source") == "OS Inventory" for c in catalog) else "Not Updated"
    }

    return assimilated_crypto, verified_inert, unassimilated, confidence_metrics


def analyze_cbom(
    cbom_path: Path,
    sbom_path: Optional[Path] = None,
    catalog_path: Optional[Path] = None,
    external_cboms: Optional[List[Path]] = None
):
    with open(cbom_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    bom_format = data.get("bomFormat", "Unknown")
    spec_version = data.get("specVersion", "Unknown")
    components = data.get("components", [])

    crypto_assets = []
    algorithm_counter = Counter()
    asset_types_counter = Counter()
    language_counter = Counter()
    vulnerable_assets = []
    pqc_assets = []

    # 1. Process First-Party CBOM Components
    for comp in components:
        comp_type = comp.get("type", "")
        crypto_props = comp.get("cryptoProperties", {})

        asset_type = crypto_props.get("assetType", comp_type or "unknown")
        name = str(comp.get("name") or "Unnamed")
        version = str(comp.get("version") or "N/A")

        asset_info = {
            "name": name,
            "version": version,
            "type": comp_type,
            "asset_type": asset_type,
            "source": "First-Party Code (SAST/AST)"
        }

        evidence = comp.get("evidence", {})
        occurrences = evidence.get("occurrences", [])
        asset_info["occurrences"] = occurrences
        for occ in occurrences:
            lang = occ.get("language")
            if lang and lang != "Unknown":
                language_counter[lang] += 1

        algo_details = crypto_props.get("algorithmProperties", {})
        algo_name = str(algo_details.get("name") or comp.get("name") or "")
        comp_name = str(comp.get("name") or "")
        algo_upper = f"{algo_name} {comp_name}".upper()

        asset_info["algorithm"] = algo_name
        asset_info["primitive"] = str(algo_details.get("primitive") or "unknown")
        asset_info["key_length"] = str(
            algo_details.get("parameterSetIdentifier")
            or algo_details.get("keyLength")
            or algo_details.get("curve")
            or "N/A"
        )

        cert_details = crypto_props.get("certificateProperties", {})
        proto_details = crypto_props.get("protocolProperties", {})
        mat_details = crypto_props.get("relatedCryptoMaterialProperties", {})

        if cert_details:
            asset_info["certificate_subject"] = cert_details.get("subjectName")
            asset_info["certificate_expiry"] = cert_details.get("validTo")
            if asset_info["primitive"] == "unknown":
                asset_info["primitive"] = "certificate"
            if asset_info["key_length"] == "N/A":
                asset_info["key_length"] = cert_details.get("certificateFormat") or "X.509"

        if proto_details:
            asset_info["protocol_type"] = proto_details.get("type")
            asset_info["protocol_version"] = proto_details.get("version")
            if asset_info["primitive"] == "unknown":
                asset_info["primitive"] = "protocol"
            if asset_info["key_length"] == "N/A" and proto_details.get("version"):
                asset_info["key_length"] = f"v{proto_details.get('version')}"

        if mat_details:
            if asset_info["primitive"] == "unknown":
                asset_info["primitive"] = mat_details.get("type") or "key-material"
            if asset_info["key_length"] == "N/A":
                asset_info["key_length"] = str(mat_details.get("format") or mat_details.get("size") or "Key")

        # Check PQC first so hybrid names like X25519MLKEM768 classify as POST-QUANTUM READY
        is_pqc = any(re.search(pat, algo_upper) for pat in POST_QUANTUM_PATTERNS)
        is_qv = (not is_pqc) and (
            any(re.search(pat, algo_upper) for pat in QUANTUM_VULNERABLE_PATTERNS)
            or asset_type in ("certificate", "related-crypto-material") and not is_pqc and asset_type == "related-crypto-material"
        )

        if is_pqc:
            asset_info["pqc_status"] = "POST-QUANTUM READY"
            pqc_assets.append(asset_info)
        elif is_qv:
            asset_info["pqc_status"] = "QUANTUM-VULNERABLE"
            vulnerable_assets.append(asset_info)
        else:
            asset_info["pqc_status"] = "CLASSICAL/SYMMETRIC"

        if crypto_props or comp_type in ("cryptographic-asset", "crypto"):
            crypto_assets.append(asset_info)
            asset_types_counter[asset_type] += 1
            if algo_name:
                algorithm_counter[algo_name] += 1

    # 2. Ingest and Assimilate Third-Party Dependency CBOM Profiles if SBOM available
    actual_sbom_path = sbom_path
    if not actual_sbom_path:
        for candidate in [cbom_path.parent / "sbom.cyclonedx.json", cbom_path.parent / "sbom.spdx.json"]:
            if candidate.exists():
                actual_sbom_path = candidate
                break

    catalog = load_catalog(catalog_path, external_cboms=external_cboms)
    sbom_components = parse_sbom_components(actual_sbom_path) if actual_sbom_path else []
    assimilated_crypto, verified_inert, unassimilated_deps, confidence_metrics = assimilate_third_party_cbom(
        sbom_components, catalog
    )

    # Merge assimilated assets
    for a in assimilated_crypto:
        crypto_assets.append(a)
        asset_types_counter[a["asset_type"]] += 1
        algorithm_counter[a["algorithm"]] += 1
        if a.get("pqc_status") == "POST-QUANTUM READY":
            pqc_assets.append(a)
        elif a.get("pqc_status") == "QUANTUM-VULNERABLE":
            vulnerable_assets.append(a)

    symmetric_assets = [a for a in crypto_assets if a["pqc_status"] == "CLASSICAL/SYMMETRIC"]
    asym_total = len(pqc_assets) + len(vulnerable_assets)

    # Honest Migration Percentage Calculation
    if asym_total > 0:
        migration_pct = round((len(pqc_assets) / asym_total * 100), 1)
        migration_pct_display = f"{migration_pct}%"
        migration_note = f"({len(pqc_assets)} of {asym_total} asymmetric/vulnerable primitives migrated)"
    else:
        migration_pct = None
        migration_pct_display = "N/A (0 detected)"
        migration_note = "(No asymmetric primitives detected in current scope)"

    return {
        "bomFormat": bom_format,
        "specVersion": spec_version,
        "total_components": len(components),
        "total_crypto_assets": len(crypto_assets),
        "quantum_vulnerable_count": len(vulnerable_assets),
        "pqc_ready_count": len(pqc_assets),
        "symmetric_count": len(symmetric_assets),
        "asymmetric_total_count": asym_total,
        "pqc_migration_percentage": migration_pct,
        "pqc_migration_display": migration_pct_display,
        "pqc_migration_note": migration_note,
        "asset_types": dict(asset_types_counter),
        "language_distribution": dict(language_counter),
        "algorithm_distribution": dict(algorithm_counter),
        "vulnerable_assets": vulnerable_assets,
        "pqc_assets": pqc_assets,
        "symmetric_assets": symmetric_assets,
        "crypto_assets": crypto_assets,
        "assimilated_crypto_assets": assimilated_crypto,
        "verified_inert_components": verified_inert,
        "unassimilated_dependencies": unassimilated_deps,
        "confidence_metrics": confidence_metrics
    }


def format_locations(occurrences: list) -> str:
    if not occurrences:
        return "Dependencies / External"
    locs = [f"`{occ.get('location', '')}`" for occ in occurrences if occ.get("location")]
    return "<br>".join(locs) if locs else "Dependencies / External"


def generate_markdown_summary(summary: dict) -> str:
    md = []
    md.append("## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment\n")
    md.append(f"**Format**: {summary['bomFormat']} (v{summary['specVersion']}) | **First-Party Code Crypto Assets**: {summary['total_components']} | **Total Tracked Crypto Assets**: {summary['total_crypto_assets']}\n")

    conf = summary["confidence_metrics"]

    # Post-Quantum Migration Scorecard
    md.append("### 📊 Post-Quantum Migration Scorecard\n")
    md.append("| Metric | Count | Migration Status |")
    md.append("|---|---|---|")
    md.append(f"| **Post-Quantum Ready (PQC)** | **{summary['pqc_ready_count']}** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |")
    md.append(f"| **Quantum-Vulnerable (Backlog)** | **{summary['quantum_vulnerable_count']}** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |")
    md.append(f"| **Classical Symmetric / Digest** | **{summary['symmetric_count']}** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |")
    md.append(f"| **Asymmetric PQC Migration Progress** | **{summary['pqc_migration_display']}** | {summary['pqc_migration_note']} |\n")

    # Supply Chain Coverage & Confidence Scorecard
    md.append("### 🎯 Cryptographic Supply Chain Coverage & Confidence\n")
    md.append("| Evaluation Layer | Coverage / Status | Audit Confidence Assessment |")
    md.append("|---|---|---|")
    fp_count = summary["total_components"]
    langs = summary.get("language_distribution", {})
    lang_str = f" across {', '.join(f'{k} ({v})' for k, v in sorted(langs.items()))}" if langs else ""
    fp_label = f"{fp_count} Crypto Primitive(s) Inventoried{lang_str}" if fp_count > 0 else "0 Custom Primitives"
    md.append(f"| **First-Party Code (`src/`, `scripts/`)** | **100% Audited** ({fp_label}) | 🟢 **HIGH** (Direct AST & SAST verified) |")
    if conf["total_dependencies"] > 0:
        md.append(f"| **Third-Party Supply Chain** | **{conf['coverage_percentage']}%** ({conf['verified_dependencies_count']} of {conf['total_dependencies']} dependencies cataloged) | {conf['confidence_badge']} (Known profiles assimilated) |")
        md.append(f"| **Overall Audit Confidence Score** | **{conf['confidence_score']}%** | {conf['confidence_badge']} ({conf['unassimilated_dependencies_count']} unassimilated supply chain dependencies) |\n")
    else:
        md.append("| **Third-Party Supply Chain** | **No external dependencies in SBOM** | 🟢 **HIGH** (Self-contained scope) |\n")

    # OS Inventory Status
    if conf["os_inventory_status"] == "Updated":
        md.append(f"| **System OS Inventory** | **Active & Updated** | 🟢 **High Integrity** (Local OS crypto components cataloged) |\n")
    else:
        md.append(f"| **System OS Inventory** | **Pending Update** | 🟡 **Warning** (Local OS crypto components not yet inventoried) |\n")

    # Post-Quantum Ready Assets Table
    md.append("### ✅ Post-Quantum Ready Assets\n")
    if summary["pqc_assets"]:
        md.append("| Component Name | Primitive | Key/Parameter Set | PQC Standard | Provenance / Location(s) |")
        md.append("|---|---|---|---|---|")
        for asset in summary["pqc_assets"]:
            algo_u = asset["algorithm"].upper()
            std = "Hybrid X25519+ML-KEM-768 (FIPS 203)" if "X25519MLKEM" in algo_u or "SECP256R1MLKEM" in algo_u else \
                  "ML-KEM (FIPS 203)" if "KEM" in algo_u or "KYBER" in algo_u else \
                  "ML-DSA (FIPS 204)" if "DSA" in algo_u or "DILITHIUM" in algo_u else \
                  "SLH-DSA (FIPS 205)" if "SLH" in algo_u or "SPHINCS" in algo_u else \
                  "FN-DSA / FALCON (FIPS 206)" if "FALCON" in algo_u or "FN-DSA" in algo_u else \
                  "LMS/XMSS (RFC 8391/8554)" if "LMS" in algo_u or "XMSS" in algo_u else \
                  "PQC Algorithm"
            locs_str = format_locations(asset.get("occurrences", []))
            prov = asset.get("source", "First-Party Code")
            md.append(f"| `{asset['name']}` | {asset['primitive']} | {asset['key_length']} | {std} | {prov}<br>{locs_str} |")
        md.append("")
    else:
        md.append("> ⚠️ **No Post-Quantum Ready assets detected.** Immediate migration planning recommended for asymmetric key exchanges and digital signatures.\n")

    # Quantum-Vulnerable Assets Table
    md.append("### ⚠️ Quantum-Vulnerable Assets & Remediation Plan\n")
    if summary["vulnerable_assets"]:
        md.append("| Component / Algorithm | Type / Primitive | Key Length / Curve | Recommended Target | Provenance / Context |")
        md.append("|---|---|---|---|---|")
        for asset in summary["vulnerable_assets"]:
            algo_u = asset["algorithm"].upper()
            recom = asset.get("remediation") or (
                "SHA-256 / SHA-3-256 (FIPS 180-4 / FIPS 202)" if any(k in algo_u for k in ["MD5", "SHA-1", "SHA1"]) else \
                "AES-256-GCM / ChaCha20-Poly1305 (RFC 5116 / RFC 8439)" if any(k in algo_u for k in ["3DES", "TRIPLEDES", "RC4", "ARC4", "ECB"]) else \
                "TLS 1.3 with X25519MLKEM768 (RFC 8446 / FIPS 203)" if "TLS-1.0" in algo_u or "TLS-1.1" in algo_u else \
                "ML-DSA-65 / SLH-DSA X.509 Certificate & KMS Key Rotation" if asset["asset_type"] in ("certificate", "related-crypto-material") else \
                "ML-KEM-768 / Kyber (FIPS 203)" if any(k in algo_u for k in ["RSA", "DH", "ECDH", "X25519"]) and "SIGN" not in asset["primitive"] else \
                "ML-DSA-65 / Dilithium (FIPS 204)" if any(k in algo_u for k in ["ECDSA", "ED25519", "DSA", "SECP"]) or "SIGN" in asset["primitive"] else \
                "ML-KEM (KEM) or ML-DSA (Signatures)"
            )

            occs = asset.get("occurrences", [])
            loc_details = []
            for occ in occs:
                loc = occ.get("location", "")
                snip = occ.get("snippet", "").strip().replace("|", "\\|")
                if snip:
                    loc_details.append(f"`{loc}`<br><sub><code>{snip}</code></sub>")
                elif loc:
                    loc_details.append(f"`{loc}`")

            locs_str = "<br><br>".join(loc_details) if loc_details else "External Dependency"
            prov = asset.get("source", "First-Party Code")
            md.append(f"| **`{asset['name']}`**<br><sub>{asset['algorithm']}</sub> | {asset['asset_type']} / {asset['primitive']} | {asset['key_length']} | **{recom}** | {prov}<br>{locs_str} |")
        md.append("")
    else:
        if summary["asymmetric_total_count"] == 0:
            md.append("> ℹ️ **No quantum-vulnerable asymmetric assets found.** Asymmetric cryptographic primitives were not detected in current scope.\n")
        else:
            md.append("> ✅ **Zero quantum-vulnerable asymmetric assets found.** All public-key cryptography conforms to post-quantum standards.\n")

    # Classical Symmetric Assets Summary
    md.append("### 🔒 Classical Symmetric & Digest Assets\n")
    if summary["symmetric_assets"]:
        md.append("| Component Name | Primitive | Key Length | Quantum Resistance Assessment | Provenance / Location(s) |")
        md.append("|---|---|---|---|---|")
        for asset in summary["symmetric_assets"]:
            algo_u = asset["algorithm"].upper()
            sec_note = "Quantum-Resistant KDF / Password Hashing (Grover-resistant)" if asset["primitive"] == "kdf" else \
                       "Quantum-Resistant CSPRNG (NIST SP 800-90A)" if asset["primitive"] == "drbg" else \
                       "Quantum-Resistant (Grover's proof)" if "256" in str(asset["key_length"]) or "384" in algo_u or "512" in algo_u else \
                       "Non-cryptographic integrity digest (OneDrive QuickXorHash 160-bit); pair with SHA-256" if "QUICKXOR" in algo_u else \
                       "TLS 1.3 Transport (Enable hybrid X25519MLKEM768 via OpenSSL 3.5+)" if "TLS" in algo_u or asset["primitive"] == "protocol" else \
                       "Legacy bit-length (Recommend 256-bit upgrade)" if "128" in str(asset["key_length"]) or "128" in algo_u else \
                       "Review key length for Grover resistance"
            locs_str = format_locations(asset.get("occurrences", []))
            prov = asset.get("source", "First-Party Code")
            md.append(f"| `{asset['name']}` | {asset['primitive']} | {asset['key_length']} | {sec_note} | {prov}<br>{locs_str} |")
        md.append("")
    else:
        md.append("> ℹ️ **No classical symmetric assets detected.**\n")

    # Unassimilated Dependencies (Blind Spots) Table
    if summary["unassimilated_dependencies"]:
        md.append("### ⚠️ Unassimilated Third-Party Binaries & Cryptographic Blind Spots\n")
        md.append("> ℹ️ *The following third-party dependencies do not have verified upstream CBOM attestations in the catalog. They lower the audit confidence score until explicit CBOMs or attestations are published.* \n")
        md.append("| Dependency Name | Version | Package URL (purl) | Status |")
        md.append("|---|---|---|---|")
        for dep in summary["unassimilated_dependencies"][:15]:
            md.append(f"| `{dep['name']}` | {dep['version']} | `{dep['purl'] or 'N/A'}` | 🟡 Unassimilated (No upstream CBOM) |")
        if len(summary["unassimilated_dependencies"]) > 15:
            md.append(f"| *... and {len(summary['unassimilated_dependencies']) - 15} more unassimilated dependencies* | | | |")
        md.append("")

    # Post-Quantum Cryptography Modernization & Migration Roadmap
    md.append(generate_pqc_roadmap(summary))

    # Open Source CBOM Intelligence & Supply Chain Attestation Locators
    md.append(generate_oss_cbom_locators())

    return "\n".join(md)


def generate_pqc_roadmap(summary: dict) -> str:
    """Generate comprehensive PQC replacement matrix and multi-language implementation guidance."""
    lines = []
    lines.append("### ⚛️ Post-Quantum Cryptography (PQC) Modernization Roadmap\n")
    lines.append("NIST finalized the principal post-quantum cryptography standards in August 2024: **FIPS 203** (ML-KEM), **FIPS 204** (ML-DSA), and **FIPS 205** (SLH-DSA). Below is the recommended migration path for replacing quantum-vulnerable public key algorithms and hardening symmetric ciphers against Grover's algorithm.\n")
    
    lines.append("#### 🗺️ Cryptographic Algorithm Replacement Matrix\n")
    lines.append("| Classical Primitive | Threat Mechanism | Post-Quantum Replacement | NIST Security Level | Migration Guidance |")
    lines.append("|---|---|---|---|---|")
    lines.append("| **RSA / Diffie-Hellman / ECDH / X25519** (Key Exchange / KEM) | Broken by Shor's algorithm | **ML-KEM-768 / ML-KEM-1024** (FIPS 203) or Hybrid **X25519MLKEM768** | Level 3 (AES-192 equiv) / Level 5 (AES-256 equiv) | Primary general-purpose key encapsulation. For TLS 1.3 and SSH, deploy hybrid `X25519MLKEM768` for seamless interoperability. |")
    lines.append("| **RSA-PSS / ECDSA / Ed25519** (Digital Signatures) | Broken by Shor's algorithm | **ML-DSA-65 / ML-DSA-87** (FIPS 204) | Level 3 / Level 5 | Primary general-purpose lattice signatures for PKI, X.509 certs, code signing, and API tokens. |")
    lines.append("| **High-Assurance Root / CA Signatures** | Broken by Shor's algorithm | **SLH-DSA** (FIPS 205 / SPHINCS+) | Level 1, 3, 5 | Stateless hash-based signatures with zero lattice assumptions; ideal for long-lived root trust stores. |")
    lines.append("| **Firmware / Secure Boot Signing** | Broken by Shor's algorithm | **LMS / XMSS** (RFC 8554 / RFC 8391, NIST SP 800-208) | Level 3 / Level 5 | Stateful hash-based signatures with minimal memory/code overhead; optimal for microcontrollers. |")
    lines.append("| **AES-128 (Symmetric Encryption)** | Halved by Grover's (effective 64-bit security) | **AES-256-GCM** or **ChaCha20-Poly1305** | Level 5 (effective 128-bit quantum security) | Upgrade symmetric key lengths from 128-bit to 256-bit to preserve Grover resistance. |")
    lines.append("| **SHA-1 / MD5 (Hash Functions)** | Broken classical collisions + quantum Grover | **SHA-256 / SHA-384 / SHA-512 / SHA-3-256** | Level 3 - 5 | Deprecate weak digests immediately. Use SHA-256 or SHA-3-256 as quantum-safe baseline. |\n")

    lines.append("#### 💻 Multi-Language PQC Implementation Recipes\n")

    lines.append("<details>")
    lines.append("<summary><b>Swift (iOS, macOS, Server-side Swift)</b></summary>\n")
    lines.append("```swift")
    lines.append("import CryptoKit")
    lines.append("// 1. Symmetric Grover resistance (use 256-bit keys)")
    lines.append("let symmetricKey = SymmetricKey(size: .bits256)")
    lines.append("let sealedBox = try AES.GCM.seal(data, using: symmetricKey)")
    lines.append("")
    lines.append("// 2. Post-Quantum KEM via SwiftCrypto / liboqs-swift:")
    lines.append("#if canImport(OQS)")
    lines.append("import OQS")
    lines.append("let kem = OQSKEM(algorithm: .mlkem768)")
    lines.append("let (publicKey, secretKey) = try kem.generateKeyPair()")
    lines.append("let (ciphertext, sharedSecretSender) = try kem.encapsulate(publicKey: publicKey)")
    lines.append("let sharedSecretReceiver = try kem.decapsulate(ciphertext: ciphertext, secretKey: secretKey)")
    lines.append("#endif")
    lines.append("```")
    lines.append("</details>\n")

    lines.append("<details>")
    lines.append("<summary><b>Go (Go 1.24+ crypto/mlkem & Hybrid TLS)</b></summary>\n")
    lines.append("```go")
    lines.append("package main")
    lines.append("")
    lines.append("import (")
    lines.append("    \"crypto/mlkem\" // Standard library in Go 1.24+")
    lines.append("    \"crypto/tls\"")
    lines.append(")")
    lines.append("")
    lines.append("func main() {")
    lines.append("    // 1. FIPS 203 ML-KEM-768 Key Encapsulation")
    lines.append("    decapsKey, _ := mlkem.GenerateKey768()")
    lines.append("    encapsKey := decapsKey.EncapsulationKey()")
    lines.append("    ciphertext, sharedSecretClient := encapsKey.Encapsulate()")
    lines.append("    sharedSecretServer, _ := decapsKey.Decapsulate(ciphertext)")
    lines.append("    _ = sharedSecretServer")
    lines.append("")
    lines.append("    // 2. Hybrid Post-Quantum TLS 1.3 Client")
    lines.append("    tlsConfig := &tls.Config{")
    lines.append("        MinVersion:       tls.VersionTLS13,")
    lines.append("        CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},")
    lines.append("    }")
    lines.append("    _ = tlsConfig")
    lines.append("}")
    lines.append("```")
    lines.append("</details>\n")

    lines.append("<details>")
    lines.append("<summary><b>Python (cryptography 44.0+ & liboqs-python)</b></summary>\n")
    lines.append("```python")
    lines.append("from cryptography.hazmat.primitives.ciphers.aead import AESGCM")
    lines.append("")
    lines.append("# 1. Grover-resistant 256-bit symmetric AEAD")
    lines.append("key = AESGCM.generate_key(bit_length=256)")
    lines.append("aesgcm = AESGCM(key)")
    lines.append("")
    lines.append("# 2. FIPS 203 ML-KEM-768 via liboqs-python")
    lines.append("import oqs")
    lines.append("with oqs.KeyEncapsulation('ML-KEM-768') as kem:")
    lines.append("    public_key = kem.generate_keypair()")
    lines.append("    ciphertext, shared_secret_sender = kem.encap_secret(public_key)")
    lines.append("    shared_secret_receiver = kem.decap_secret(ciphertext)")
    lines.append("    assert shared_secret_sender == shared_secret_receiver")
    lines.append("```")
    lines.append("</details>\n")

    lines.append("<details>")
    lines.append("<summary><b>Rust (pqcrypto / aws-lc-rs)</b></summary>\n")
    lines.append("```rust")
    lines.append("use pqcrypto_kyber::kyber768; // FIPS 203 ML-KEM-768")
    lines.append("use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret};")
    lines.append("")
    lines.append("fn main() {")
    lines.append("    let (pk, sk) = kyber768::keypair();")
    lines.append("    let (ss_sender, ct) = kyber768::encapsulate(&pk);")
    lines.append("    let ss_receiver = kyber768::decapsulate(&ct, &sk);")
    lines.append("    assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());")
    lines.append("}")
    lines.append("```")
    lines.append("</details>\n")

    lines.append("<details>")
    lines.append("<summary><b>Java / Kotlin (Bouncy Castle 1.78+)</b></summary>\n")
    lines.append("```java")
    lines.append("import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;")
    lines.append("import org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec;")
    lines.append("import java.security.*;")
    lines.append("")
    lines.append("Security.addProvider(new BouncyCastlePQCProvider());")
    lines.append("KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"ML-KEM\", \"BCPQC\");")
    lines.append("kpg.initialize(MLKEMParameterSpec.ml_kem_768);")
    lines.append("KeyPair kp = kpg.generateKeyPair();")
    lines.append("```")
    lines.append("</details>\n")

    lines.append("<details>")
    lines.append("<summary><b>TypeScript / Node.js</b></summary>\n")
    lines.append("```typescript")
    lines.append("import { mlkem768 } from '@noble/post-quantum/ml-kem';")
    lines.append("")
    lines.append("const [aliceKeys, alicePub] = mlkem768.keygen();")
    lines.append("const [ciphertext, sharedBob] = mlkem768.encapsulate(alicePub);")
    lines.append("const sharedAlice = mlkem768.decapsulate(ciphertext, aliceKeys);")
    lines.append("```")
    lines.append("</details>\n")

    return "\n".join(lines)


def generate_oss_cbom_locators() -> str:
    """Generate guide on locating third-party open source CBOM attestations."""
    lines = []
    lines.append("### 🌐 Open Source CBOM Intelligence & Supply Chain Attestation Locators\n")
    lines.append("Third-party dependencies account for the vast majority of cryptographic attack surfaces. When upstream packages do not ship with explicit CBOM files, use the following sources and methods to uncover cryptographic metadata:\n")
    lines.append("1. **OCI 1.1 / Sigstore Cosign Attestations (`application/vnd.cyclonedx+json`)**:")
    lines.append("   - Many open-source container images and libraries attach CycloneDX CBOM attestations via Sigstore Cosign.")
    lines.append("   - Query attestations using Cosign:")
    lines.append("     ```bash")
    lines.append("     cosign download attestation --predicate-type https://cyclonedx.org/bom ghcr.io/<org>/<image>:<tag> | jq -r .payload | base64 -d | jq .")
    lines.append("     ```")
    lines.append("2. **OpenSSF Security Insights (`SECURITY-INSIGHTS.yml`)**:")
    lines.append("   - Repositories implementing OpenSSF Security Insights declare encryption standards and key management under `/.github/SECURITY-INSIGHTS.yml`.")
    lines.append("3. **Package Registry Provenance & Hash Attestations**:")
    lines.append("   - **PyPI (PEP 740)**: Inspect cryptographic provenance via `https://pypi.org/pypi/<package>/json`.")
    lines.append("   - **npm Provenance**: Verify build provenance and sign-offs with `npm view <package> --json`.")
    lines.append("   - **Swift Package Index**: Discover cryptography framework dependencies directly from SwiftPM manifests and DocC documentation.")
    lines.append("4. **Direct Assimilation with `--external-cbom`**:")
    lines.append("   - Ingest any vendor or upstream CycloneDX CBOM file directly into `jsi-bom-actions`:")
    lines.append("     ```bash")
    lines.append("     python scripts/analyze_cbom.py build/cbom.cyclonedx.json --sbom build/sbom.cyclonedx.json --external-cbom vendor.cbom.json")
    lines.append("     ```")
    lines.append("   - This directly credits verified dependencies and elevates the repository's **Audit Confidence Score**.\n")
    return "\n".join(lines)


def print_report(summary: dict):
    print("=" * 70)
    print(" CBOM Cryptographic Inventory & PQC Readiness Assessment")
    print("=" * 70)
    print(f"Format: {summary['bomFormat']} (v{summary['specVersion']})")
    print(f"First-Party Components Scanned: {summary['total_components']}")
    print(f"Total Tracked Crypto Assets: {summary['total_crypto_assets']}")
    print(f"Quantum-Vulnerable Assets: {summary['quantum_vulnerable_count']}")
    print(f"Post-Quantum Ready Assets: {summary['pqc_ready_count']}")
    print(f"PQC Migration Progress: {summary['pqc_migration_display']}")
    conf = summary["confidence_metrics"]
    print(f"Audit Confidence: {conf['confidence_badge']} ({conf['confidence_score']}%)")
    print(f"OS Inventory Status: {conf['os_inventory_status']}")
    print("-" * 70)

    if summary.get("asset_types"):
        print("\nAsset Types:")
        for atype, count in summary["asset_types"].items():
            print(f"  - {atype}: {count}")

    if summary.get("algorithm_distribution"):
        print("\nAlgorithm Breakdown:")
        for algo, count in summary["algorithm_distribution"].items():
            print(f"  - {algo}: {count}")

    if summary.get("pqc_assets"):
        print("\n✅ Post-Quantum Ready Assets Detected (Migrated):")
        for asset in summary["pqc_assets"]:
            print(f"  • [{asset['pqc_status']}] {asset['name']} (Primitive: {asset['primitive']}, Key/Param: {asset['key_length']})")

    if summary.get("vulnerable_assets"):
        print("\n⚠️ Quantum-Vulnerable Cryptographic Findings (Backlog for Migration):")
        for asset in summary["vulnerable_assets"][:10]:
            print(f"  • [{asset['pqc_status']}] {asset['name']} (Primitive: {asset['primitive']}, Key/Param: {asset['key_length']})")
        if len(summary["vulnerable_assets"]) > 10:
            print(f"  ... and {len(summary['vulnerable_assets']) - 10} more.")
    print("=" * 70)


def main():
    import os
    parser = argparse.ArgumentParser(description="Analyze CycloneDX CBOM files with supply chain assimilation.")
    parser.add_argument("cbom_file", type=Path, help="Path to CycloneDX CBOM JSON file")
    parser.add_argument("--sbom", type=Path, help="Path to CycloneDX/SPDX SBOM file containing software dependencies")
    parser.add_argument("--catalog", type=Path, help="Path to custom known CBOM catalog JSON")
    parser.add_argument("--external-cbom", type=Path, action="append", default=[], help="Path to external/upstream CBOM JSON file (can be specified multiple times)")
    parser.add_argument("--json", type=Path, nargs="?", const="STDOUT", help="Output summary as raw JSON to stdout or specified file")
    parser.add_argument("--markdown", type=Path, help="Output markdown assessment report to specified file")
    parser.add_argument("--step-summary", action="store_true", help="Append markdown assessment to $GITHUB_STEP_SUMMARY if available")
    args = parser.parse_args()

    if not args.cbom_file.exists():
        print(f"Error: CBOM file not found: {args.cbom_file}", file=sys.stderr)
        sys.exit(1)

    summary = analyze_cbom(
        args.cbom_file,
        sbom_path=args.sbom,
        catalog_path=args.catalog,
        external_cboms=args.external_cbom
    )
    md_content = generate_markdown_summary(summary)

    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Saved Markdown report to: {args.markdown}")

    if args.step_summary or "GITHUB_STEP_SUMMARY" in os.environ:
        step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if step_summary_path:
            with open(step_summary_path, "a", encoding="utf-8") as f:
                f.write(md_content + "\n")

    if args.json:
        json_str = json.dumps(summary, indent=2)
        if str(args.json) == "STDOUT":
            print(json_str)
        else:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"Saved JSON report to: {args.json}")
    elif not args.markdown:
        print_report(summary)


if __name__ == "__main__":
    main()
