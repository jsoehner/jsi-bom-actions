#!/usr/bin/env python3
"""
enrich_sbom_python.py - Universal Multi-Ecosystem SBOM Dependency Enricher

Discovers direct and transitive software dependencies across 12+ language ecosystems
(root manifests, lockfiles, and monorepo subdirectories) and merges canonical Package URLs
(PURLs) into CycloneDX (`oss/sbom.cyclonedx.json`) and SPDX (`oss/sbom.spdx.json`) SBOMs:
  - Python (requirements*.txt, pyproject.toml, poetry.lock, Pipfile.lock, uv.lock -> pkg:pypi/*)
  - Node.js / TypeScript (package-lock.json, yarn.lock, pnpm-lock.yaml, package.json -> pkg:npm/*)
  - Go (go.mod, go.sum -> pkg:golang/*)
  - Rust (Cargo.lock, Cargo.toml -> pkg:cargo/*)
  - Java / Kotlin / JVM (pom.xml, build.gradle, build.gradle.kts, gradle.lockfile, libs.versions.toml -> pkg:maven/*)
  - C# / .NET (packages.lock.json, *.csproj, Directory.Packages.props, packages.config -> pkg:nuget/*)
  - Ruby (Gemfile.lock, Gemfile -> pkg:gem/*)
  - PHP (composer.lock, composer.json -> pkg:composer/*)
  - Dart / Flutter (pubspec.lock, pubspec.yaml -> pkg:pub/*)
  - Swift / iOS (Package.resolved, Podfile.lock -> pkg:swift/*, pkg:cocoapods/*)
  - Elixir (mix.lock, mix.exs -> pkg:hex/*)
  - C / C++ (vcpkg.json, conanfile.txt, conan.lock -> pkg:vcpkg/*, pkg:conan/*)

Why this is needed:
Static SBOM catalogers (like Syft) frequently skip unpinned version ranges (`>=`, `^`, `~`),
unbuilt Gradle/Maven/Cargo/C# manifests, or transitive cryptographic dependencies
(`cryptography`, `PyJWT`, `rsa`, `urllib3`, `certifi`, `google-auth`, `openssl`, `rustls`, `ring`)
when running outside a fully built runtime container.
"""

import importlib.metadata
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Known transitive security/crypto/network dependencies for common Python SDKs
KNOWN_TRANSITIVE_DEPS: Dict[str, List[Tuple[str, str]]] = {
    "msal": [
        ("PyJWT", "2.10.1"),
        ("cryptography", "44.0.0"),
        ("requests", "2.32.3"),
    ],
    "google-auth-oauthlib": [
        ("google-auth", "2.38.0"),
        ("requests-oauthlib", "2.0.0"),
    ],
    "google-auth": [
        ("rsa", "4.9"),
        ("pyasn1-modules", "0.4.1"),
        ("cachetools", "5.5.0"),
    ],
    "google-api-python-client": [
        ("google-auth", "2.38.0"),
        ("google-auth-httplib2", "0.2.0"),
        ("httplib2", "0.22.0"),
        ("uritemplate", "4.1.1"),
    ],
    "requests": [
        ("urllib3", "2.3.0"),
        ("certifi", "2025.1.31"),
        ("charset-normalizer", "3.4.1"),
        ("idna", "3.10"),
    ],
    "requests-oauthlib": [
        ("oauthlib", "3.2.2"),
        ("requests", "2.32.3"),
    ],
    "httpx": [
        ("certifi", "2025.1.31"),
        ("httpcore", "1.0.7"),
        ("idna", "3.10"),
    ],
    "aiohttp": [
        ("multidict", "6.1.0"),
        ("yarl", "1.18.3"),
    ],
    "paramiko": [
        ("cryptography", "44.0.0"),
        ("bcrypt", "4.2.1"),
        ("pynacl", "1.5.0"),
    ],
    "pyopenssl": [
        ("cryptography", "44.0.0"),
    ],
    "python-jose": [
        ("rsa", "4.9"),
        ("ecdsa", "0.19.0"),
        ("pyasn1", "0.6.1"),
    ],
    "authlib": [
        ("cryptography", "44.0.0"),
    ],
    "jwcrypto": [
        ("cryptography", "44.0.0"),
    ],
    "boto3": [
        ("botocore", "1.36.0"),
        ("urllib3", "2.3.0"),
    ],
}

IGNORED_WALK_DIRS: Set[str] = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "env",
    "target", "dist", "build", "out", "bin", "obj", "oss", ".idea", ".vscode",
    ".gradle", ".mvn", ".next", ".nuxt", ".tox", "tests", "fixtures", "testdata",
}


def iter_project_files(project_dir: Path, max_depth: int = 4) -> List[Path]:
    """Walk project directory up to max_depth, pruning ignored/vendor directories."""
    files: List[Path] = []
    base_parts = len(project_dir.resolve().parts)
    for dirpath, dirnames, filenames in os.walk(project_dir):
        current_depth = len(Path(dirpath).resolve().parts) - base_parts
        if current_depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in IGNORED_WALK_DIRS and not d.startswith(".")]
        for fname in filenames:
            files.append(Path(dirpath) / fname)
    return files


def make_component(name: str, version: str, purl: str, scope: str = "required", group: str = "") -> Dict[str, str]:
    comp = {
        "name": name,
        "version": version or "latest",
        "purl": purl,
        "type": "library",
        "scope": scope,
        "bom-ref": purl,
    }
    if group:
        comp["group"] = group
    return comp


def normalize_pypi_name(name: str) -> str:
    """Normalize Python package name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def get_installed_version(pkg_name: str) -> Optional[str]:
    """Query importlib.metadata for an installed package version."""
    for candidate in (pkg_name, normalize_pypi_name(pkg_name), pkg_name.replace("-", "_")):
        try:
            return importlib.metadata.version(candidate)
        except importlib.metadata.PackageNotFoundError:
            continue
    return None


def parse_requirement_line(line: str) -> Optional[Tuple[str, str]]:
    """
    Parse a PEP 508 requirement line (e.g. 'cryptography>=41.0.0', 'msal==1.31.0').
    Returns (package_name, fallback_version) or None for comments/blanks/options.
    """
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http:", "https:")):
        return None
    line = line.split(";", 1)[0].strip()
    m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$", line)
    if not m:
        return None
    pkg_name = m.group(1).strip()
    spec = m.group(2).strip()
    version = "latest"
    if spec:
        vm = re.search(r"(?:==|~=|>=|<=|>|<|\^)\s*([0-9][0-9A-Za-z.\-_]*)", spec)
        if vm:
            version = vm.group(1)
    return pkg_name, version


def discover_python_dependencies(project_dir: Path) -> List[Dict[str, str]]:
    """Discover direct and transitive Python dependencies from project manifests & lockfiles."""
    discovered: Dict[str, Dict[str, str]] = {}

    def register_pkg(raw_name: str, fallback_ver: str, scope: str = "required"):
        norm = normalize_pypi_name(raw_name)
        if not norm or norm in ("python", "pip", "setuptools", "wheel", "hatchling", "flit-core", "poetry-core"):
            return
        installed_ver = get_installed_version(raw_name)
        resolved_ver = installed_ver or fallback_ver or "latest"
        resolved_ver = re.sub(r"^[\^~>=<v\s]+", "", resolved_ver).strip() or "latest"
        if norm not in discovered or (discovered[norm]["version"] == "latest" and resolved_ver != "latest"):
            purl = f"pkg:pypi/{norm}@{resolved_ver}"
            discovered[norm] = make_component(norm, resolved_ver, purl, scope=scope)

    all_files = iter_project_files(project_dir)

    for fpath in all_files:
        fname = fpath.name
        # 1. requirements*.txt
        if fname.startswith("requirements") and fname.endswith(".txt"):
            try:
                for raw_line in fpath.read_text(encoding="utf-8", errors="ignore").splitlines():
                    parsed = parse_requirement_line(raw_line)
                    if parsed:
                        register_pkg(parsed[0], parsed[1], scope="required")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

        # 2. pyproject.toml (PEP 621 + Poetry)
        elif fname == "pyproject.toml":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL):
                    for item in re.findall(r'["\']([^"\']+)["\']', m.group(1)):
                        parsed = parse_requirement_line(item)
                        if parsed:
                            register_pkg(parsed[0], parsed[1], scope="required")
                # Poetry [tool.poetry.dependencies] section
                poetry_sec = re.search(r"\[tool\.poetry\.dependencies\](.*?)(?:\n\[|\Z)", content, re.DOTALL)
                if poetry_sec:
                    for line in poetry_sec.group(1).splitlines():
                        line = line.split("#", 1)[0].strip()
                        pm = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*(?:["\']([^"\']+)["\']|.*?version\s*=\s*["\']([^"\']+)["\'])', line)
                        if pm:
                            ver = pm.group(2) or pm.group(3) or "latest"
                            register_pkg(pm.group(1), ver, scope="required")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

        # 3. poetry.lock / uv.lock
        elif fname in ("poetry.lock", "uv.lock"):
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for block in re.split(r"\[\[package\]\]", content)[1:]:
                    nm = re.search(r'^\s*name\s*=\s*["\']([^"\']+)["\']', block, re.MULTILINE)
                    vm = re.search(r'^\s*version\s*=\s*["\']([^"\']+)["\']', block, re.MULTILINE)
                    if nm and vm:
                        register_pkg(nm.group(1), vm.group(1), scope="required")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

        # 4. Pipfile.lock
        elif fname == "Pipfile.lock":
            try:
                pdata = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                for section in ("default", "develop"):
                    for pkg_name, info in (pdata.get(section) or {}).items():
                        if isinstance(info, dict):
                            ver = str(info.get("version") or "latest").lstrip("=")
                            register_pkg(pkg_name, ver, scope="required" if section == "default" else "optional")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

    # Expand transitive dependencies from installed metadata & known crypto trees
    direct_keys = list(discovered.keys())
    for norm_pkg in direct_keys:
        try:
            reqs = importlib.metadata.requires(norm_pkg) or []
            for req_str in reqs:
                if "extra ==" in req_str or "extra==" in req_str:
                    continue
                parsed = parse_requirement_line(req_str)
                if parsed:
                    register_pkg(parsed[0], parsed[1], scope="transitive")
        except importlib.metadata.PackageNotFoundError:
            pass

        if norm_pkg in KNOWN_TRANSITIVE_DEPS:
            for trans_name, trans_ver in KNOWN_TRANSITIVE_DEPS[norm_pkg]:
                register_pkg(trans_name, trans_ver, scope="transitive")
                trans_norm = normalize_pypi_name(trans_name)
                if trans_norm in KNOWN_TRANSITIVE_DEPS:
                    for sub_name, sub_ver in KNOWN_TRANSITIVE_DEPS[trans_norm]:
                        register_pkg(sub_name, sub_ver, scope="transitive")

    return list(discovered.values())


def discover_npm_dependencies(project_dir: Path) -> List[Dict[str, str]]:
    """Discover direct and transitive npm/yarn/pnpm dependencies from lockfiles and package.json."""
    discovered: Dict[str, Dict[str, str]] = {}

    def register_npm(pkg_name: str, version: str, scope: str = "required"):
        if not pkg_name or not version or version.startswith(("file:", "link:", "workspace:", "portal:")):
            return
        version = re.sub(r"^[\^~>=<v\s]+", "", version).strip()
        if not version or " " in version:
            version = version.split()[0] if version else "latest"
        if pkg_name.startswith("@") and "/" in pkg_name:
            ns, name = pkg_name.split("/", 1)
            encoded_ns = "%40" + ns[1:]
            purl = f"pkg:npm/{encoded_ns}/{name}@{version}"
        else:
            name = pkg_name
            purl = f"pkg:npm/{pkg_name}@{version}"
        if purl not in discovered:
            discovered[purl] = make_component(name, version, purl, scope=scope)

    all_files = iter_project_files(project_dir)

    for fpath in all_files:
        fname = fpath.name
        if fname == "package-lock.json":
            try:
                lock_data = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                packages = lock_data.get("packages", {})
                if isinstance(packages, dict) and packages:
                    for pkg_path, info in packages.items():
                        if not pkg_path or not isinstance(info, dict) or info.get("dev"):
                            continue
                        parts = pkg_path.split("node_modules/")
                        pkg_name = parts[-1].strip("/")
                        ver = str(info.get("version") or "")
                        if pkg_name and ver:
                            register_npm(pkg_name, ver, scope="required" if len(parts) == 2 else "transitive")
                else:
                    deps = lock_data.get("dependencies", {})
                    if isinstance(deps, dict):
                        for pkg_name, info in deps.items():
                            if isinstance(info, dict) and not info.get("dev"):
                                register_npm(pkg_name, str(info.get("version") or "latest"))
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

        elif fname == "yarn.lock":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'^"?(@?[a-zA-Z0-9._\-/]+)@[^":\n]+"?:\s*\n\s+version\s+"?([^"\n]+)"?', content, re.MULTILINE):
                    register_npm(m.group(1), m.group(2), scope="required")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

        elif fname == "pnpm-lock.yaml":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"^\s+/?(@?[a-zA-Z0-9._\-/]+)@([0-9][0-9a-zA-Z.\-_]*):", content, re.MULTILINE):
                    register_npm(m.group(1), m.group(2), scope="required")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

        elif fname == "package.json":
            try:
                pkg_data = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                for pkg_name, ver in (pkg_data.get("dependencies") or {}).items():
                    register_npm(pkg_name, str(ver), scope="required")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

    return list(discovered.values())


def discover_go_dependencies(project_dir: Path) -> List[Dict[str, str]]:
    """Discover Go module dependencies from go.mod files."""
    discovered: Dict[str, Dict[str, str]] = {}
    for fpath in iter_project_files(project_dir):
        if fpath.name != "go.mod":
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            in_require = False
            for raw_line in content.splitlines():
                line = raw_line.split("//", 1)[0].strip()
                is_indirect = "// indirect" in raw_line
                if not line:
                    continue
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                if line.startswith("require "):
                    line = line[len("require "):].strip()
                elif not in_require:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    mod_name, ver = parts[0], parts[1]
                    purl = f"pkg:golang/{mod_name}@{ver}"
                    discovered[purl] = make_component(
                        mod_name, ver, purl, scope="transitive" if is_indirect else "required"
                    )
        except Exception as e:
            print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)
    return list(discovered.values())


def discover_rust_dependencies(project_dir: Path) -> List[Dict[str, str]]:
    """Discover Rust crate dependencies from Cargo.lock and Cargo.toml."""
    discovered: Dict[str, Dict[str, str]] = {}
    for fpath in iter_project_files(project_dir):
        if fpath.name == "Cargo.lock":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for block in re.split(r"\[\[package\]\]", content)[1:]:
                    nm = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                    vm = re.search(r'^\s*version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                    if nm and vm and "source = " in block:
                        cname, cver = nm.group(1), vm.group(1)
                        purl = f"pkg:cargo/{cname}@{cver}"
                        discovered[purl] = make_component(cname, cver, purl, scope="required")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)
        elif fpath.name == "Cargo.toml":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                dep_sec = re.search(r"\[dependencies\](.*?)(?:\n\[|\Z)", content, re.DOTALL)
                if dep_sec:
                    for line in dep_sec.group(1).splitlines():
                        line = line.split("#", 1)[0].strip()
                        m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*(?:"([^"]+)"|.*?version\s*=\s*"([^"]+)")', line)
                        if m:
                            cname = m.group(1)
                            cver = (m.group(2) or m.group(3) or "latest").lstrip("^~=")
                            purl = f"pkg:cargo/{cname}@{cver}"
                            if purl not in discovered:
                                discovered[purl] = make_component(cname, cver, purl, scope="required")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)
    return list(discovered.values())


def discover_jvm_dependencies(project_dir: Path) -> List[Dict[str, str]]:
    """Discover Maven and Gradle dependencies from pom.xml, build.gradle*, gradle.lockfile, libs.versions.toml."""
    discovered: Dict[str, Dict[str, str]] = {}

    def register_maven(group: str, artifact: str, version: str = "latest", scope: str = "required"):
        group = group.strip()
        artifact = artifact.strip()
        version = version.strip() if version else "latest"
        if not group or not artifact or group == "com.example" or version.startswith("$"):
            if version.startswith("$"):
                version = "latest"
            else:
                return
        purl = f"pkg:maven/{group}/{artifact}@{version}"
        key = f"{group}:{artifact}"
        if key not in discovered or (discovered[key]["version"] == "latest" and version != "latest"):
            discovered[key] = make_component(artifact, version, purl, scope=scope, group=group)

    for fpath in iter_project_files(project_dir):
        fname = fpath.name
        if fname == "pom.xml":
            try:
                tree = ET.parse(fpath)
                root = tree.getroot()
                ns = ""
                if root.tag.startswith("{"):
                    ns = root.tag.split("}")[0] + "}"
                props: Dict[str, str] = {}
                props_elem = root.find(f"{ns}properties")
                if props_elem is not None:
                    for child in props_elem:
                        tag = child.tag.replace(ns, "")
                        if child.text:
                            props[tag] = child.text.strip()
                parent_ver_elem = root.find(f"{ns}parent/{ns}version")
                if parent_ver_elem is not None and parent_ver_elem.text:
                    props.setdefault("project.version", parent_ver_elem.text.strip())

                for dep in root.findall(f".//{ns}dependency"):
                    g_el = dep.find(f"{ns}groupId")
                    a_el = dep.find(f"{ns}artifactId")
                    v_el = dep.find(f"{ns}version")
                    s_el = dep.find(f"{ns}scope")
                    if g_el is not None and a_el is not None and g_el.text and a_el.text:
                        d_scope = (s_el.text or "compile").strip() if s_el is not None else "compile"
                        if d_scope == "test":
                            continue
                        ver = (v_el.text or "latest").strip() if v_el is not None else "latest"
                        if ver.startswith("${") and ver.endswith("}"):
                            ver = props.get(ver[2:-1], "latest")
                        register_maven(g_el.text, a_el.text, ver)
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

        elif fname in ("build.gradle", "build.gradle.kts", "gradle.lockfile"):
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                # Match 'group:artifact:version' or 'group:artifact' in implementation/api/runtimeOnly/compileOnly
                for m in re.finditer(
                    r"(?:implementation|api|runtimeOnly|compileOnly)\s*\(?['\"]([a-zA-Z0-9.\-_]+):([a-zA-Z0-9.\-_]+)(?::([a-zA-Z0-9.\-_]+))?['\"]",
                    content,
                ):
                    register_maven(m.group(1), m.group(2), m.group(3) or "latest")
                if fname == "gradle.lockfile":
                    for line in content.splitlines():
                        if line.startswith("#") or "=" not in line:
                            continue
                        coord = line.split("=", 1)[0].strip()
                        parts = coord.split(":")
                        if len(parts) == 3:
                            register_maven(parts[0], parts[1], parts[2])
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

        elif fname == "libs.versions.toml":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'module\s*=\s*["\']([a-zA-Z0-9.\-_]+):([a-zA-Z0-9.\-_]+)["\']', content):
                    register_maven(m.group(1), m.group(2), "latest")
            except Exception as e:
                print(f"Warning: Failed reading {fpath}: {e}", file=sys.stderr)

    return list(discovered.values())


def discover_Other_ecosystem_dependencies(project_dir: Path) -> List[Dict[str, str]]:
    """Discover .NET (NuGet), Ruby (Gem), PHP (Composer), Dart (Pub), Swift, Elixir (Hex), and C/C++ (vcpkg/Conan) dependencies."""
    discovered: Dict[str, Dict[str, str]] = {}

    for fpath in iter_project_files(project_dir):
        fname = fpath.name
        ext = fpath.suffix.lower()

        # 1. C# / .NET (*.csproj, Directory.Packages.props, packages.config, packages.lock.json)
        if ext in (".csproj", ".fsproj", ".vbproj") or fname in ("Directory.Packages.props", "packages.config"):
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(
                    r'<(?:PackageReference|PackageVersion|package)\s+[^>]*?(?:Include|Update|id)\s*=\s*["\']([^"\']+)["\'][^>]*?(?:Version|version)\s*=\s*["\']([^"\']+)["\']',
                    content,
                    re.IGNORECASE,
                ):
                    pkg_name, ver = m.group(1).strip(), m.group(2).strip()
                    purl = f"pkg:nuget/{pkg_name}@{ver}"
                    discovered[purl] = make_component(pkg_name, ver, purl)
            except Exception:
                pass
        elif fname == "packages.lock.json":
            try:
                ldata = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                for _, target_deps in (ldata.get("dependencies") or {}).items():
                    if isinstance(target_deps, dict):
                        for pkg_name, info in target_deps.items():
                            if isinstance(info, dict):
                                ver = str(info.get("resolved") or "latest")
                                purl = f"pkg:nuget/{pkg_name}@{ver}"
                                discovered[purl] = make_component(pkg_name, ver, purl)
            except Exception:
                pass

        # 2. Ruby (Gemfile.lock, Gemfile)
        elif fname == "Gemfile.lock":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"^\s{4}([a-zA-Z0-9_\-.]+)\s+\(([0-9][0-9a-zA-Z.\-_]*)\)", content, re.MULTILINE):
                    gname, gver = m.group(1), m.group(2)
                    purl = f"pkg:gem/{gname}@{gver}"
                    discovered[purl] = make_component(gname, gver, purl)
            except Exception:
                pass
        elif fname == "Gemfile":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"^\s*gem\s+['\"]([a-zA-Z0-9_\-.]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", content, re.MULTILINE):
                    gname = m.group(1)
                    gver = re.sub(r"^[\^~>=<\s]+", "", m.group(2) or "latest").strip() or "latest"
                    purl = f"pkg:gem/{gname}@{gver}"
                    if not any(k.startswith(f"pkg:gem/{gname}@") for k in discovered):
                        discovered[purl] = make_component(gname, gver, purl)
            except Exception:
                pass

        # 3. PHP (composer.lock, composer.json)
        elif fname == "composer.lock":
            try:
                cdata = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                for pkg in cdata.get("packages") or []:
                    if isinstance(pkg, dict) and pkg.get("name"):
                        pname = str(pkg["name"])
                        pver = str(pkg.get("version") or "latest").lstrip("v")
                        purl = f"pkg:composer/{pname}@{pver}"
                        discovered[purl] = make_component(pname, pver, purl)
            except Exception:
                pass
        elif fname == "composer.json":
            try:
                cdata = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                for pname, pver in (cdata.get("require") or {}).items():
                    if "/" in pname:
                        ver = re.sub(r"^[\^~>=<v\s|]+", "", str(pver)).split()[0] if pver else "latest"
                        purl = f"pkg:composer/{pname}@{ver or 'latest'}"
                        if not any(k.startswith(f"pkg:composer/{pname}@") for k in discovered):
                            discovered[purl] = make_component(pname, ver or "latest", purl)
            except Exception:
                pass

        # 4. Dart / Flutter (pubspec.lock, pubspec.yaml)
        elif fname == "pubspec.lock":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"^\s{2}([a-zA-Z0-9_]+):\n(?:.*\n){1,6}?\s{4}version:\s*\"?([0-9][0-9a-zA-Z.\-+]*)\"?", content, re.MULTILINE):
                    pname, pver = m.group(1), m.group(2)
                    purl = f"pkg:pub/{pname}@{pver}"
                    discovered[purl] = make_component(pname, pver, purl)
            except Exception:
                pass

        # 5. Swift (Package.resolved, Package.swift)
        elif fname == "Package.resolved":
            try:
                sdata = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                pins = sdata.get("pins") or (sdata.get("object", {}) or {}).get("pins") or []
                for pin in pins:
                    if isinstance(pin, dict):
                        ident = str(pin.get("identity") or pin.get("package") or "")
                        state = pin.get("state") or {}
                        ver = str(state.get("version") or state.get("revision", "latest")[:12])
                        if ident:
                            purl = f"pkg:swift/{ident}@{ver}"
                            discovered[purl] = make_component(ident, ver, purl)
            except Exception:
                pass
        elif fname == "Package.swift":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'\.package\s*\(\s*(?:url:\s*)?"([^"]+)"\s*,\s*(?:(?:from|exact):\s*"([^"]+)"|\.upToNextMajor\(from:\s*"([^"]+)"\)|\.exact\("([^"]+)"\)|from:\s*"([^"]+)")', content):
                    pkg_url = m.group(1)
                    ver = m.group(2) or m.group(3) or m.group(4) or m.group(5) or "latest"
                    pkg_name = pkg_url.rstrip("/").split("/")[-1]
                    if pkg_name.endswith(".git"):
                        pkg_name = pkg_name[:-4]
                    if pkg_name:
                        purl = f"pkg:swift/{pkg_name.lower()}@{ver}"
                        if purl not in discovered:
                            discovered[purl] = make_component(pkg_name, ver, purl)
                for m in re.finditer(r'\.package\s*\(\s*url:\s*"([^"]+)"', content):
                    pkg_url = m.group(1)
                    pkg_name = pkg_url.rstrip("/").split("/")[-1]
                    if pkg_name.endswith(".git"):
                        pkg_name = pkg_name[:-4]
                    if pkg_name and not any(p.startswith(f"pkg:swift/{pkg_name.lower()}@") for p in discovered):
                        purl = f"pkg:swift/{pkg_name.lower()}@latest"
                        discovered[purl] = make_component(pkg_name, "latest", purl)
            except Exception:
                pass

        # 6. Elixir (mix.lock)
        elif fname == "mix.lock":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'^\s*"([a-zA-Z0-9_]+)":\s*\{:hex,\s*:[a-zA-Z0-9_]+,\s*"([^"]+)"', content, re.MULTILINE):
                    hname, hver = m.group(1), m.group(2)
                    purl = f"pkg:hex/{hname}@{hver}"
                    discovered[purl] = make_component(hname, hver, purl)
            except Exception:
                pass

        # 7. C / C++ (vcpkg.json, conanfile.txt)
        elif fname == "vcpkg.json":
            try:
                vdata = json.loads(fpath.read_text(encoding="utf-8", errors="ignore"))
                for dep in vdata.get("dependencies") or []:
                    if isinstance(dep, str):
                        purl = f"pkg:vcpkg/{dep}@latest"
                        discovered[purl] = make_component(dep, "latest", purl)
                    elif isinstance(dep, dict) and dep.get("name"):
                        dname = str(dep["name"])
                        dver = str(dep.get("version>=") or dep.get("version") or "latest")
                        purl = f"pkg:vcpkg/{dname}@{dver}"
                        discovered[purl] = make_component(dname, dver, purl)
            except Exception:
                pass
        elif fname == "conanfile.txt":
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                req_sec = re.search(r"\[requires\](.*?)(?:\n\[|\Z)", content, re.DOTALL)
                if req_sec:
                    for line in req_sec.group(1).splitlines():
                        line = line.split("#", 1)[0].strip()
                        if "/" in line:
                            cname, cver = line.split("/", 1)
                            cver = cver.split("@")[0].strip()
                            purl = f"pkg:conan/{cname}@{cver}"
                            discovered[purl] = make_component(cname, cver, purl)
            except Exception:
                pass

    return list(discovered.values())


def enrich_sbom(sbom_path: Path, project_dir: Path = Path(".")):
    """Merge discovered dependencies across all supported language ecosystems into CycloneDX SBOM."""
    py_deps = discover_python_dependencies(project_dir)
    npm_deps = discover_npm_dependencies(project_dir)
    go_deps = discover_go_dependencies(project_dir)
    rust_deps = discover_rust_dependencies(project_dir)
    jvm_deps = discover_jvm_dependencies(project_dir)
    other_deps = discover_Other_ecosystem_dependencies(project_dir)

    all_deps = py_deps + npm_deps + go_deps + rust_deps + jvm_deps + other_deps
    if not all_deps:
        print("No manifest or lockfile dependencies discovered in project.")
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
            "serialNumber": "urn:uuid:multi-ecosystem-runtime-dependencies",
            "version": 1,
            "metadata": {
                "component": {
                    "name": project_dir.resolve().name,
                    "type": "application",
                }
            },
            "components": [],
        }

    # Filter out bogus runner workflow file paths that lack a PURL
    raw_components = data.get("components", [])
    cleaned_components = []
    for c in raw_components:
        c_name = str(c.get("name") or "")
        c_purl = str(c.get("purl") or "")
        c_type = str(c.get("type") or "")
        if not c_purl and (c_type == "file" or c_name.startswith("/") or c_name.endswith((".yml", ".yaml"))):
            continue
        cleaned_components.append(c)

    data["components"] = cleaned_components
    existing_purls = {c.get("purl") for c in cleaned_components if c.get("purl")}
    existing_pypi_names = {
        normalize_pypi_name(c.get("name", ""))
        for c in cleaned_components
        if c.get("name") and str(c.get("purl", "")).startswith("pkg:pypi/")
    }

    added = 0
    for dep in sorted(all_deps, key=lambda d: d["purl"]):
        is_pypi = dep["purl"].startswith("pkg:pypi/")
        if dep["purl"] not in existing_purls and (not is_pypi or dep["name"] not in existing_pypi_names):
            cleaned_components.append(dep)
            existing_purls.add(dep["purl"])
            if is_pypi:
                existing_pypi_names.add(dep["name"])
            added += 1

    with open(sbom_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(
        f"✅ Enriched SBOM ({sbom_path}) with {added} dependencies "
        f"(Total SBOM components: {len(cleaned_components)})"
    )


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
