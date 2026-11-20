#!/usr/bin/env python3
"""
fetch_trusted_oss_cbom.py - Fetch & Verify Signed Upstream CBOM Attestations from Trusted OSS

Queries a Trusted OSS Gatekeeper registry (POST /bom/batch) over optional mTLS for all
dependency PURLs discovered in the project's CycloneDX/SPDX SBOM, verifies detached GPG
and/or NIST FIPS 204 ML-DSA-65 signatures against the registry's public keys, and writes
a consolidated verified CBOM bundle for assimilation by analyze_cbom.py.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional


def extract_sbom_purls(sbom_path: Path) -> list[str]:
    """Extract unique Package URLs (purls) from a CycloneDX or SPDX SBOM."""
    if not sbom_path.exists():
        return []
    try:
        data = json.loads(sbom_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[-] Warning: could not parse SBOM {sbom_path}: {exc}", file=sys.stderr)
        return []

    purls: list[str] = []
    seen: set[str] = set()

    def _add(p: Any) -> None:
        val = str(p or "").strip()
        if val.startswith("pkg:") and val not in seen:
            seen.add(val)
            purls.append(val)

    if data.get("bomFormat") == "CycloneDX" or "components" in data:
        for comp in data.get("components", []):
            _add(comp.get("purl"))
    elif "@graph" in data:
        for item in data.get("@graph", []):
            _add(item.get("software_packageUrl"))
    elif "packages" in data:
        for pkg in data.get("packages", []):
            for ref in pkg.get("externalRefs") or []:
                if ref.get("referenceType") == "purl":
                    _add(ref.get("referenceLocator"))

    return purls


def build_ssl_context(
    mtls_cert: Optional[Path] = None,
    mtls_key: Optional[Path] = None,
    ca_cert: Optional[Path] = None,
) -> ssl.SSLContext:
    """Create an HTTPS SSLContext with optional mTLS client certificate and custom CA."""
    ctx = ssl.create_default_context(
        cafile=str(ca_cert) if ca_cert and ca_cert.exists() else None
    )
    if mtls_cert and mtls_key and mtls_cert.exists() and mtls_key.exists():
        ctx.load_cert_chain(certfile=str(mtls_cert), keyfile=str(mtls_key))
    return ctx


def http_get_text(url: str, ssl_ctx: ssl.SSLContext, timeout: float = 20.0) -> Optional[str]:
    """Perform an HTTPS GET returning decoded UTF-8 text, or None on error."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
            if resp.status == 200:
                return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        print(f"[-] GET {url} failed: {exc}", file=sys.stderr)
    return None


def http_post_json(
    url: str,
    payload: dict[str, Any],
    ssl_ctx: ssl.SSLContext,
    timeout: float = 30.0,
) -> Optional[dict[str, Any]]:
    """Perform an HTTPS POST with JSON body and return parsed JSON response."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        print(f"[-] POST {url} returned HTTP {exc.code}: {exc.reason}", file=sys.stderr)
    except Exception as exc:
        print(f"[-] POST {url} failed: {exc}", file=sys.stderr)
    return None


def _dearmor_mldsa(text: str) -> bytes:
    """Extract raw binary bytes from an ASCII-armored ML-DSA-65 key or signature."""
    if "-----BEGIN " in text and "-----END " in text:
        lines = [ln.strip() for ln in text.strip().splitlines() if not ln.startswith("-----")]
        return base64.b64decode("".join(lines))
    return text.encode("utf-8")


def verify_gpg_detached(
    raw_bytes: bytes,
    asc_sig: str,
    gnupghome: Path,
) -> bool:
    """Verify a detached ASCII-armored GPG signature using an isolated GNUPGHOME."""
    if not asc_sig or not shutil.which("gpg"):
        return False
    with tempfile.TemporaryDirectory(prefix="oss-gpg-ver-") as tmp:
        tmp_path = Path(tmp)
        data_file = tmp_path / "payload.cbom.json"
        sig_file = tmp_path / "payload.cbom.json.asc"
        data_file.write_bytes(raw_bytes)
        sig_file.write_text(asc_sig, encoding="utf-8")
        env = {**os.environ, "GNUPGHOME": str(gnupghome)}
        proc = subprocess.run(
            ["gpg", "--batch", "--verify", str(sig_file), str(data_file)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0


def verify_mldsa65_detached(
    raw_bytes: bytes,
    mldsa_sig: str,
    mldsa_pubkey_armored: str,
) -> Optional[bool]:
    """Verify a detached NIST FIPS 204 ML-DSA-65 signature if dilithium-py is installed.

    Returns True (valid), False (invalid), or None (verifier library unavailable).
    """
    if not mldsa_sig or not mldsa_pubkey_armored:
        return False
    try:
        from dilithium_py.dilithium import Dilithium3  # type: ignore
    except ImportError:
        return None
    try:
        pk = _dearmor_mldsa(mldsa_pubkey_armored)
        sig = _dearmor_mldsa(mldsa_sig)
        return bool(Dilithium3.verify(pk, raw_bytes, sig))
    except Exception:
        return False


def fetch_and_verify_trusted_oss_cboms(
    registry_url: str,
    sbom_path: Path,
    output_path: Path,
    mtls_cert: Optional[Path] = None,
    mtls_key: Optional[Path] = None,
    ca_cert: Optional[Path] = None,
    verify_signatures: bool = True,
    strict_pqc: bool = False,
    warm_missing: bool = False,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Query Trusted OSS /bom/batch, verify signatures, and write consolidated bundle."""
    base_url = registry_url.rstrip("/")
    purls = extract_sbom_purls(sbom_path)
    if not purls:
        print("[*] No PURLs found in SBOM; skipping Trusted OSS CBOM lookup.", file=sys.stderr)
        return {"queried": 0, "found": 0, "verified": 0, "rejected": 0, "missing": 0}

    ssl_ctx = build_ssl_context(mtls_cert=mtls_cert, mtls_key=mtls_key, ca_cert=ca_cert)

    # Fetch public signing keys if verification is enabled
    gpg_pubkey: Optional[str] = None
    mldsa_pubkey: Optional[str] = None
    gnupg_tmp_dir: Optional[tempfile.TemporaryDirectory[str]] = None
    gnupghome: Optional[Path] = None

    if verify_signatures:
        gpg_pubkey = http_get_text(f"{base_url}/keys/trusted-oss-pubkey.asc", ssl_ctx, timeout=timeout)
        mldsa_pubkey = http_get_text(f"{base_url}/keys/trusted-oss-mldsa65.pub", ssl_ctx, timeout=timeout)
        if gpg_pubkey and shutil.which("gpg"):
            gnupg_tmp_dir = tempfile.TemporaryDirectory(prefix="trusted-oss-gnupg-")
            gnupghome = Path(gnupg_tmp_dir.name)
            os.chmod(gnupghome, 0o700)
            env = {**os.environ, "GNUPGHOME": str(gnupghome)}
            subprocess.run(
                ["gpg", "--batch", "--import"],
                input=gpg_pubkey,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

    try:
        print(f"[*] Querying Trusted OSS ({base_url}/bom/batch) for {len(purls)} dependency PURLs...", file=sys.stderr)
        response = http_post_json(
            f"{base_url}/bom/batch",
            {
                "purls": purls,
                "bom_type": "cbom",
                "include_signatures": verify_signatures,
                "trigger_pull_on_miss": warm_missing,
            },
            ssl_ctx=ssl_ctx,
            timeout=timeout,
        )
        if response is None:
            print(f"[-] Warning: Trusted OSS batch CBOM lookup unavailable at {base_url}.", file=sys.stderr)
            return {"queried": len(purls), "found": 0, "verified": 0, "rejected": 0, "missing": len(purls)}

        found_map: dict[str, dict[str, Any]] = response.get("found") or {}
        missing_list: list[str] = response.get("missing") or []

        verified_entries: dict[str, dict[str, Any]] = {}
        rejected_count = 0

        for purl, item in found_map.items():
            cbom_doc = item.get("cbom")
            raw_b64 = item.get("cbom_raw_b64") or ""
            raw_bytes = (
                base64.b64decode(raw_b64)
                if raw_b64
                else (json.dumps(cbom_doc, indent=2, sort_keys=True) + "\n").encode("utf-8")
            )
            gpg_sig = item.get("signature_gpg") or ""
            mldsa_sig = item.get("signature_mldsa65") or ""

            gpg_ok = False
            mldsa_ok: Optional[bool] = None

            if verify_signatures:
                if gnupghome and gpg_sig:
                    gpg_ok = verify_gpg_detached(raw_bytes, gpg_sig, gnupghome)
                if mldsa_pubkey and mldsa_sig:
                    mldsa_ok = verify_mldsa65_detached(raw_bytes, mldsa_sig, mldsa_pubkey)

                if strict_pqc:
                    if mldsa_ok is not True:
                        print(f"[-] Rejecting {purl}: strict PQC ML-DSA-65 verification failed (result={mldsa_ok}).", file=sys.stderr)
                        rejected_count += 1
                        continue
                else:
                    # Require at least one valid cryptographic signature when verification is enabled
                    if not gpg_ok and mldsa_ok is not True:
                        print(f"[-] Rejecting {purl}: signature verification failed (gpg={gpg_ok}, mldsa65={mldsa_ok}).", file=sys.stderr)
                        rejected_count += 1
                        continue

            verified_entries[purl] = {
                "purl": purl,
                "cbom": cbom_doc,
                "artifact_sha256": item.get("artifact_sha256", ""),
                "verified_gpg": gpg_ok,
                "verified_mldsa65": mldsa_ok is True,
                "source_registry": base_url,
            }

        bundle = {
            "bundleFormat": "TrustedOSS-CBOM-Bundle",
            "bundleVersion": "1.0",
            "registryUrl": base_url,
            "verifiedSignatures": verify_signatures,
            "strictPqc": strict_pqc,
            "entries": verified_entries,
            "missing": missing_list,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
        print(
            f"[+] Trusted OSS CBOM resolution complete: {len(verified_entries)} verified, "
            f"{rejected_count} rejected, {len(missing_list)} missing -> {output_path}",
            file=sys.stderr,
        )
        return {
            "queried": len(purls),
            "found": len(found_map),
            "verified": len(verified_entries),
            "rejected": rejected_count,
            "missing": len(missing_list),
        }
    finally:
        if gnupg_tmp_dir is not None:
            gnupg_tmp_dir.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch and verify signed upstream CBOM attestations from a Trusted OSS registry."
    )
    parser.add_argument("--url", required=True, help="Trusted OSS base URL (e.g. https://jsigroup.ddns.net)")
    parser.add_argument("--sbom", type=Path, required=True, help="Path to CycloneDX/SPDX SBOM JSON")
    parser.add_argument("-o", "--output", type=Path, default=Path("oss/trusted_oss_cboms.json"), help="Output bundle path")
    parser.add_argument("--mtls-cert", type=Path, help="Path to mTLS client certificate PEM")
    parser.add_argument("--mtls-key", type=Path, help="Path to mTLS client private key PEM")
    parser.add_argument("--ca-cert", type=Path, help="Optional custom CA bundle PEM")
    parser.add_argument("--no-verify", action="store_true", help="Skip GPG/ML-DSA-65 signature verification")
    parser.add_argument("--strict-pqc", action="store_true", help="Require valid NIST FIPS 204 ML-DSA-65 signature")
    parser.add_argument("--warm-missing", action="store_true", help="Ask Trusted OSS to enqueue missing packages for background warming")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")
    args = parser.parse_args()

    stats = fetch_and_verify_trusted_oss_cboms(
        registry_url=args.url,
        sbom_path=args.sbom,
        output_path=args.output,
        mtls_cert=args.mtls_cert,
        mtls_key=args.mtls_key,
        ca_cert=args.ca_cert,
        verify_signatures=not args.no_verify,
        strict_pqc=args.strict_pqc,
        warm_missing=args.warm_missing,
        timeout=args.timeout,
    )
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
