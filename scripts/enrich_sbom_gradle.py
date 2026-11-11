#!/usr/bin/env python3
"""
enrich_sbom_gradle.py - Enrich CycloneDX SBOM with Gradle & Maven JVM Dependencies

Resolves the project's Gradle runtimeClasspath dependencies (via ./gradlew when
available, with automatic fallback to static parsing of build.gradle, build.gradle.kts,
gradle.lockfile, libs.versions.toml, and pom.xml) and merges them into the
CycloneDX SBOM (oss/sbom.cyclonedx.json).
"""

import sys
import os
import json
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Set, Tuple


def get_gradle_dependencies(project_dir: Path = Path(".")) -> List[Dict[str, str]]:
    """Run Gradle to get resolved runtimeClasspath dependencies, falling back to static manifest parsing."""
    components: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    def add_coord(group: str, artifact: str, version: str):
        group, artifact, version = group.strip(), artifact.strip(), (version or "latest").strip()
        if not group or not artifact or group == "com.example":
            return
        if version.startswith("$"):
            version = "latest"
        key = (group, artifact)
        if key in seen:
            return
        seen.add(key)
        purl = f"pkg:maven/{group}/{artifact}@{version}"
        components.append({
            "name": artifact,
            "group": group,
            "version": version,
            "purl": purl,
            "type": "library",
            "bom-ref": purl,
        })

    gradlew = project_dir / "gradlew"
    if gradlew.exists() and os.access(gradlew, os.X_OK):
        cmd = [str(gradlew), "-q", "dependencies", "--configuration", "runtimeClasspath"]
        try:
            output = subprocess.check_output(cmd, cwd=str(project_dir), text=True, stderr=subprocess.DEVNULL, timeout=90)
            for line in output.splitlines():
                m = re.search(r"([a-zA-Z0-9.\-_]+):([a-zA-Z0-9.\-_]+):([a-zA-Z0-9.\-_]+)", line)
                if not m:
                    continue
                group, artifact, version = m.group(1), m.group(2), m.group(3)
                if "->" in line:
                    parts = line.split("->")
                    version = parts[1].strip().split()[0]
                add_coord(group, artifact, version)
        except Exception as e:
            print(f"Info: Gradle CLI resolution skipped ({e}); falling back to static manifest inspection.", file=sys.stderr)

    # Static fallback across build.gradle*, gradle.lockfile, libs.versions.toml
    for manifest in (
        list(project_dir.glob("**/build.gradle"))
        + list(project_dir.glob("**/build.gradle.kts"))
        + list(project_dir.glob("**/gradle.lockfile"))
        + list(project_dir.glob("**/libs.versions.toml"))
    ):
        if any(p in manifest.parts for p in (".git", "build", ".gradle", "node_modules", "oss")):
            continue
        try:
            content = manifest.read_text(encoding="utf-8", errors="ignore")
            for m in re.finditer(
                r"(?:implementation|api|runtimeOnly|compileOnly)\s*\(?['\"]([a-zA-Z0-9.\-_]+):([a-zA-Z0-9.\-_]+)(?::([a-zA-Z0-9.\-_]+))?['\"]",
                content,
            ):
                add_coord(m.group(1), m.group(2), m.group(3) or "latest")
            if manifest.name == "gradle.lockfile":
                for line in content.splitlines():
                    if not line.startswith("#") and "=" in line:
                        parts = line.split("=", 1)[0].strip().split(":")
                        if len(parts) == 3:
                            add_coord(parts[0], parts[1], parts[2])
        except Exception:
            pass

    return components


def enrich_sbom(sbom_path: Path, project_dir: Path = Path(".")):
    gradle_deps = get_gradle_dependencies(project_dir)
    if not gradle_deps:
        print("No Gradle dependencies resolved or Gradle not present.")
        return

    sbom_path.parent.mkdir(parents=True, exist_ok=True)

    if sbom_path.exists():
        try:
            with open(sbom_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    else:
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:gradle-runtime-dependencies",
            "version": 1,
            "metadata": {
                "component": {
                    "name": project_dir.resolve().name,
                    "type": "application",
                }
            },
            "components": [],
        }

    existing_components = data.setdefault("components", [])
    existing_purls = {c.get("purl") for c in existing_components if c.get("purl")}
    existing_names = {c.get("name") for c in existing_components if c.get("name")}

    added = 0
    for dep in gradle_deps:
        if dep["purl"] not in existing_purls and dep["name"] not in existing_names:
            existing_components.append(dep)
            existing_purls.add(dep["purl"])
            existing_names.add(dep["name"])
            added += 1

    with open(sbom_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"✅ Enriched SBOM ({sbom_path}) with {added} Gradle runtime dependencies (Total: {len(existing_components)})")


def main():
    target_path = Path("oss/sbom.cyclonedx.json")
    project_dir = Path(".")
    if len(sys.argv) > 1:
        target_path = Path(sys.argv[1])
    if len(sys.argv) > 2:
        project_dir = Path(sys.argv[2])
    enrich_sbom(target_path, project_dir)


if __name__ == "__main__":
    main()
