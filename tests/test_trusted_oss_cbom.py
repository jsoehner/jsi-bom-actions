"""Unit tests for Trusted OSS upstream CBOM fetching, signature verification, and CycloneDX 1.6 assimilation."""

from __future__ import annotations

import base64
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_cbom  # noqa: E402
import fetch_trusted_oss_cbom  # noqa: E402


def _make_sample_cbom(purl: str, name: str, version: str, crypto_components: list[dict]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
            },
            "properties": [
                {
                    "name": "trusted-oss:crypto-scan-status",
                    "value": "CRYPTO_ASSETS_DETECTED" if crypto_components else "VERIFIED_INERT",
                }
            ],
        },
        "components": crypto_components,
    }


def test_analyze_cbom_assimilates_trusted_oss_bundle_and_inert_packages(tmp_path: Path):
    # First-party empty CBOM
    fp_cbom = tmp_path / "cbom.json"
    fp_cbom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}))

    # SBOM with 3 obscure third-party dependencies (none in static catalog)
    sbom_path = tmp_path / "sbom.cyclonedx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {"type": "library", "name": "obscure-pqc", "version": "1.0.0", "purl": "pkg:pypi/obscure-pqc@1.0.0"},
                    {"type": "library", "name": "obscure-inert", "version": "2.0.0", "purl": "pkg:pypi/obscure-inert@2.0.0"},
                    {"type": "library", "name": "still-missing", "version": "0.1.0", "purl": "pkg:pypi/still-missing@0.1.0"},
                ],
            }
        )
    )

    pqc_cbom = _make_sample_cbom(
        "pkg:pypi/obscure-pqc@1.0.0",
        "obscure-pqc",
        "1.0.0",
        [
            {
                "type": "cryptographic-asset",
                "name": "ML-KEM-768",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "name": "ML-KEM-768",
                        "primitive": "kem",
                        "parameterSetIdentifier": "768",
                    },
                },
            }
        ],
    )
    inert_cbom = _make_sample_cbom("pkg:pypi/obscure-inert@2.0.0", "obscure-inert", "2.0.0", [])

    bundle_path = tmp_path / "trusted_oss_cboms.json"
    bundle_path.write_text(
        json.dumps(
            {
                "bundleFormat": "TrustedOSS-CBOM-Bundle",
                "bundleVersion": "1.0",
                "registryUrl": "https://oss.example.test",
                "verifiedSignatures": True,
                "entries": {
                    "pkg:pypi/obscure-pqc@1.0.0": {
                        "purl": "pkg:pypi/obscure-pqc@1.0.0",
                        "cbom": pqc_cbom,
                        "verified_gpg": True,
                        "verified_mldsa65": True,
                    },
                    "pkg:pypi/obscure-inert@2.0.0": {
                        "purl": "pkg:pypi/obscure-inert@2.0.0",
                        "cbom": inert_cbom,
                        "verified_gpg": True,
                        "verified_mldsa65": False,
                    },
                },
                "missing": ["pkg:pypi/still-missing@0.1.0"],
            }
        )
    )

    # Without Trusted OSS bundle -> all 3 unassimilated
    baseline = analyze_cbom.analyze_cbom(fp_cbom, sbom_path=sbom_path)
    assert baseline["confidence_metrics"]["unassimilated_dependencies_count"] == 3

    # With Trusted OSS bundle -> 2 verified (1 PQC crypto + 1 VERIFIED_INERT), only 1 unassimilated
    enriched = analyze_cbom.analyze_cbom(
        fp_cbom, sbom_path=sbom_path, external_cboms=[bundle_path]
    )
    conf = enriched["confidence_metrics"]
    assert conf["verified_dependencies_count"] == 2
    assert conf["trusted_oss_verified_count"] == 2
    assert conf["unassimilated_dependencies_count"] == 1
    assert enriched["pqc_ready_count"] == 1
    assert len(enriched["verified_inert_components"]) == 1

    md = analyze_cbom.generate_markdown_summary(enriched)
    assert "2 Trusted OSS signed CBOM" in md
    assert "Trusted OSS Signed CBOM (GPG + ML-DSA-65 verified)" in md


def test_fetch_trusted_oss_cbom_batch_and_rejects_bad_signature(tmp_path: Path):
    sbom_path = tmp_path / "sbom.cyclonedx.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [
                    {"name": "demo-pkg", "version": "1.0.0", "purl": "pkg:pypi/demo-pkg@1.0.0"},
                ],
            }
        )
    )
    sample_cbom = _make_sample_cbom("pkg:pypi/demo-pkg@1.0.0", "demo-pkg", "1.0.0", [])
    raw_b64 = base64.b64encode(json.dumps(sample_cbom).encode("utf-8")).decode("ascii")

    class _MockHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: A002
            return

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            resp = {
                "found": {
                    body["purls"][0]: {
                        "cbom": sample_cbom,
                        "cbom_raw_b64": raw_b64,
                        "signature_gpg": "INVALID-SIG",
                        "signature_mldsa65": "INVALID-PQC-SIG",
                        "artifact_sha256": "deadbeef",
                    }
                },
                "missing": [],
            }
            payload = json.dumps(resp).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # 1. With verification enabled, invalid signature must be rejected
        out_strict = tmp_path / "out_strict.json"
        stats_strict = fetch_trusted_oss_cbom.fetch_and_verify_trusted_oss_cboms(
            registry_url=f"http://127.0.0.1:{port}",
            sbom_path=sbom_path,
            output_path=out_strict,
            verify_signatures=True,
        )
        assert stats_strict["found"] == 1
        assert stats_strict["verified"] == 0
        assert stats_strict["rejected"] == 1

        # 2. With verification disabled, bundle includes the entry
        out_noverify = tmp_path / "out_noverify.json"
        stats_nv = fetch_trusted_oss_cbom.fetch_and_verify_trusted_oss_cboms(
            registry_url=f"http://127.0.0.1:{port}",
            sbom_path=sbom_path,
            output_path=out_noverify,
            verify_signatures=False,
        )
        assert stats_nv["verified"] == 1
        bundle = json.loads(out_noverify.read_text(encoding="utf-8"))
        assert "pkg:pypi/demo-pkg@1.0.0" in bundle["entries"]
    finally:
        server.shutdown()
        server.server_close()
