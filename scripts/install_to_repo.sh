#!/usr/bin/env bash
# ==============================================================================
# install_to_repo.sh - Install or Update Multi-Language SBOM/CBOM & PQC CI Suite
# ==============================================================================
# Installs or updates multi-language SBOM/CBOM generation scripts, AST crypto
# scanner, third-party CBOM catalog, verification test harness, Dependabot
# action config, and GitHub Actions CI workflow in any new or existing repo.
#
# Usage:
#   install_to_repo.sh [OPTIONS] <TARGET_REPO_PATH>
#
# Options:
#   -a, --app-name NAME     Application / Docker image name (default: auto-detected)
#   -t, --type TYPE         Scan type: 'docker' or 'dir' (default: auto-detected)
#   -m, --mode MODE         Workflow mode: 'standalone' (default) or 'composite'
#   -r, --action-ref REF    Composite action repo ref (default: jsoehner/sbom-cbom-action@main)
#   -h, --help              Show this help message and exit
# ==============================================================================

set -euo pipefail

SKILL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_REPO=""
APP_NAME=""
SCAN_TYPE=""
WORKFLOW_MODE="standalone"
ACTION_REF="jsoehner/sbom-cbom-action@0000000000000000000000000000000000000000 # v1.0.0"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <TARGET_REPO_PATH>

Arguments:
  <TARGET_REPO_PATH>      Path to the target repository (new or existing)

Options:
  -a, --app-name NAME     Application or Docker image tag name (default: auto-detect)
  -t, --type TYPE         Scan type: 'docker' or 'dir' (default: auto-detect from Dockerfile)
  -m, --mode MODE         Workflow mode: 'standalone' (default, bundles scripts) or 'composite' (Dependabot action)
  -r, --action-ref REF    Action reference for composite mode (e.g., jsoehner/sbom-cbom-action@<sha>)
  -h, --help              Show this help message and exit

Examples:
  $(basename "$0") .
  $(basename "$0") -m composite /path/to/existing-repo
  $(basename "$0") -a vault-demo -t docker /home/user/vaultpki-demo
EOF
    exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--app-name)
            APP_NAME="$2"
            shift 2
            ;;
        -t|--type)
            SCAN_TYPE="$2"
            shift 2
            ;;
        -m|--mode)
            WORKFLOW_MODE="$2"
            shift 2
            ;;
        -r|--action-ref)
            ACTION_REF="$2"
            shift 2
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            if [[ -z "$TARGET_REPO" ]]; then
                TARGET_REPO="$1"
                shift
            else
                echo "Error: Multiple target directories specified: '$TARGET_REPO' and '$1'" >&2
                usage 1
            fi
            ;;
    esac
done

if [[ -z "$TARGET_REPO" ]]; then
    echo "Error: Target repository path is required." >&2
    usage 1
fi

REPO_DIR="$(cd "$TARGET_REPO" && pwd)"

if [[ ! -d "$REPO_DIR" ]]; then
    echo "Error: Target directory does not exist: $TARGET_REPO" >&2
    exit 1
fi

echo "=================================================================="
echo " Installing / Updating Multi-Language SBOM & CBOM Suite in:"
echo " ${REPO_DIR}"
echo "=================================================================="

# Detect scan type if not specified
if [[ -z "$SCAN_TYPE" ]]; then
    if [[ -f "${REPO_DIR}/Dockerfile" ]]; then
        SCAN_TYPE="docker"
    else
        SCAN_TYPE="dir"
    fi
fi

# Detect app name if not specified
if [[ -z "$APP_NAME" ]]; then
    APP_NAME="$(basename "$REPO_DIR"):local"
fi

# Auto-detect languages and ecosystems in the target repository
DETECTED_ECOSYSTEMS=()
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "requirements*.txt" -o -name "pyproject.toml" -o -name "Pipfile.lock" -o -name "poetry.lock" -o -name "*.py" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Python")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "package.json" -o -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "*.ts" -o -name "*.js" \) -not -path "*/node_modules/*" -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Node.js/TypeScript")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "go.mod" -o -name "*.go" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Go")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "Cargo.toml" -o -name "Cargo.lock" -o -name "*.rs" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Rust")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" -o -name "*.java" -o -name "*.kt" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Java/Kotlin/JVM")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "*.csproj" -o -name "packages.lock.json" -o -name "*.cs" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("C#/.NET")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "Gemfile" -o -name "Gemfile.lock" -o -name "*.rb" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Ruby")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "composer.json" -o -name "composer.lock" -o -name "*.php" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("PHP")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "vcpkg.json" -o -name "conanfile.txt" -o -name "CMakeLists.txt" -o -name "*.c" -o -name "*.cpp" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("C/C++")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "Package.swift" -o -name "Package.resolved" -o -name "*.swift" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Swift")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "pubspec.yaml" -o -name "pubspec.lock" -o -name "*.dart" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Dart/Flutter")
[[ -n "$(find "$REPO_DIR" -maxdepth 3 \( -name "mix.exs" -o -name "mix.lock" -o -name "*.ex" \) -not -path "*/.*" 2>/dev/null | head -n 1)" ]] && DETECTED_ECOSYSTEMS+=("Elixir")

echo "Configuration:"
echo "  • Scan Type:           $SCAN_TYPE"
echo "  • Workflow Mode:       $WORKFLOW_MODE"
echo "  • App / Image Tag:     $APP_NAME"
echo "  • Detected Ecosystems: ${DETECTED_ECOSYSTEMS[*]:-Generic}"

# 1. Create target directories
mkdir -p "${REPO_DIR}/scripts"
mkdir -p "${REPO_DIR}/.github/workflows"
mkdir -p "${REPO_DIR}/docs/security"
mkdir -p "${REPO_DIR}/oss"

# 2. Copy/update scripts
echo -n "Installing/updating local generator, multi-language enrichers, AST scanner, and test harness ... "
cp "${SKILL_ROOT}/scripts/generate_boms.sh" "${REPO_DIR}/scripts/generate_boms.sh"
cp "${SKILL_ROOT}/scripts/analyze_cbom.py" "${REPO_DIR}/scripts/analyze_cbom.py"
cp "${SKILL_ROOT}/scripts/scan_crypto_ast.py" "${REPO_DIR}/scripts/scan_crypto_ast.py"
cp "${SKILL_ROOT}/scripts/test_boms.sh" "${REPO_DIR}/scripts/test_boms.sh"
if [[ -f "${SKILL_ROOT}/scripts/known_cbom_catalog.json" ]]; then
    cp "${SKILL_ROOT}/scripts/known_cbom_catalog.json" "${REPO_DIR}/scripts/known_cbom_catalog.json"
fi
if [[ -f "${SKILL_ROOT}/scripts/fetch_oci_cbom.py" ]]; then
    cp "${SKILL_ROOT}/scripts/fetch_oci_cbom.py" "${REPO_DIR}/scripts/fetch_oci_cbom.py"
    chmod +x "${REPO_DIR}/scripts/fetch_oci_cbom.py"
fi
if [[ -f "${SKILL_ROOT}/scripts/attach_oci_bom.sh" ]]; then
    cp "${SKILL_ROOT}/scripts/attach_oci_bom.sh" "${REPO_DIR}/scripts/attach_oci_bom.sh"
    chmod +x "${REPO_DIR}/scripts/attach_oci_bom.sh"
fi
if [[ -f "${SKILL_ROOT}/scripts/enrich_sbom_gradle.py" ]]; then
    cp "${SKILL_ROOT}/scripts/enrich_sbom_gradle.py" "${REPO_DIR}/scripts/enrich_sbom_gradle.py"
    chmod +x "${REPO_DIR}/scripts/enrich_sbom_gradle.py"
fi
if [[ -f "${SKILL_ROOT}/scripts/enrich_sbom_python.py" ]]; then
    cp "${SKILL_ROOT}/scripts/enrich_sbom_python.py" "${REPO_DIR}/scripts/enrich_sbom_python.py"
    chmod +x "${REPO_DIR}/scripts/enrich_sbom_python.py"
fi

chmod +x "${REPO_DIR}/scripts/generate_boms.sh" \
         "${REPO_DIR}/scripts/analyze_cbom.py" \
         "${REPO_DIR}/scripts/scan_crypto_ast.py" \
         "${REPO_DIR}/scripts/test_boms.sh"
echo "✅ Done"

# 3. Standardize workflow filename on sbom-cbom.yml and clean up legacy duplicate sbom.yml
WORKFLOW_FILE="${REPO_DIR}/.github/workflows/sbom-cbom.yml"
if [[ -f "${REPO_DIR}/.github/workflows/sbom.yml" ]]; then
    rm -f "${REPO_DIR}/.github/workflows/sbom.yml"
    echo "🧹 Migrated and removed legacy duplicate .github/workflows/sbom.yml"
fi

echo -n "Installing GitHub Actions workflow (${WORKFLOW_FILE}) ... "

if [[ "$WORKFLOW_MODE" == "composite" ]]; then
    cat <<EOF > "$WORKFLOW_FILE"
name: Software & Cryptographic Bill of Materials (SBOM & CBOM)

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

permissions:
  contents: write
  id-token: write

jobs:
  generate-and-verify-boms:
    name: Generate, Verify, and Upload BOMs
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - name: Run Multi-Language SBOM, CBOM & PQC Cryptographic Governance
        uses: ${ACTION_REF}
        with:
          target-dir: '.'
          output-dir: 'oss'
          publish-audit-report: 'true'
          upload-artifacts: 'true'
          retention-days: '90'
EOF
else
    GRADLE_SETUP=""
    if [[ -f "${REPO_DIR}/build.gradle" || -f "${REPO_DIR}/build.gradle.kts" ]]; then
        GRADLE_SETUP="
      - name: Setup Java
        uses: actions/setup-java@de7274f081f381c8f8158605e0321c36c376e2e6 # v6.0.1
        with:
          java-version: '25'
          distribution: 'temurin'
          cache: 'gradle'
"
    fi

    cat <<EOF > "$WORKFLOW_FILE"
name: Software & Cryptographic Bill of Materials (SBOM & CBOM)

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

permissions:
  contents: write
  id-token: write

jobs:
  generate-and-verify-boms:
    name: Generate, Verify, and Upload BOMs
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - name: Create output directory
        run: mkdir -p oss

      - name: Set up Python for Cryptographic Auditing & Multi-Ecosystem Resolution
        uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: '3.11'
${GRADLE_SETUP}
      # -------------------------------------------------------------
      # 1. Generate SBOM (CycloneDX and SPDX via Anchore / Syft)
      # -------------------------------------------------------------
      - name: Generate CycloneDX SBOM (Anchore / Syft)
        uses: anchore/sbom-action@006b7ce8314066bdf1765b4500370d40fa6917a3 # v0.24.2
        with:
          path: .
          format: cyclonedx-json
          output-file: oss/sbom.cyclonedx.json
          upload-artifact: false

      - name: Enrich SBOM Across All Language Ecosystems
        run: |
          if [ -f requirements.txt ]; then
            python3 -m pip install --quiet -r requirements.txt || true
          fi
          if [ -f scripts/enrich_sbom_python.py ]; then
            python3 scripts/enrich_sbom_python.py oss/sbom.cyclonedx.json .
          fi
          if [ -f scripts/enrich_sbom_gradle.py ] && ( [ -f build.gradle ] || [ -f build.gradle.kts ] ); then
            python3 scripts/enrich_sbom_gradle.py oss/sbom.cyclonedx.json . || true
          fi

      - name: Generate SPDX SBOM (Anchore / Syft)
        uses: anchore/sbom-action@006b7ce8314066bdf1765b4500370d40fa6917a3 # v0.24.2
        with:
          path: .
          format: spdx-json
          output-file: oss/sbom.spdx.json
          upload-artifact: false

      # -------------------------------------------------------------
      # 2. Generate CBOM (cbomkit-action)
      # -------------------------------------------------------------
      - name: Generate Cryptographic Bill of Materials (CBOM)
        uses: cbomkit/cbomkit-action@34a3d960625ae7f7f1b59455eff93a96df090eb7 # v2.3.0
        id: cbom
        continue-on-error: true
        env:
          CBOMKIT_OUTPUT_DIR: oss
          CBOMKIT_EXCLUDE: "(^|/)scripts/(scan_crypto_ast|analyze_cbom|fetch_oci_cbom|update_os_inventory|enrich_sbom).*|(^|/)tests/.*"

      - name: Fix permissions for container-generated artifacts
        run: sudo chown -R \$(id -u):\$(id -g) oss/ || true

      # -------------------------------------------------------------
      # 3. Multi-Language Semantic AST Crypto Discovery & Reconciliation
      # -------------------------------------------------------------
      - name: Semantic AST Cryptographic Scan & CBOM Reconciliation
        run: |
          if [ -f scripts/scan_crypto_ast.py ]; then
            python3 scripts/scan_crypto_ast.py . \\
              --cbom oss/cbom.json \\
              --output-json oss/crypto-callsites.json
          fi

      # -------------------------------------------------------------
      # 4. Automated Verification & Test Harness in CI
      # -------------------------------------------------------------
      - name: Run BOM Verification and Cryptographic Audit Harness
        run: |
          if [ -f scripts/test_boms.sh ]; then
            bash scripts/test_boms.sh oss
          fi

      # -------------------------------------------------------------
      # 5. Post-Quantum Cryptography (PQC) Readiness Assessment
      # -------------------------------------------------------------
      - name: Generate PQC Migration Dashboard & Step Summary
        run: |
          if [ -f scripts/analyze_cbom.py ]; then
            SBOM_ARG=""
            if [ -f oss/sbom.cyclonedx.json ]; then
              SBOM_ARG="--sbom oss/sbom.cyclonedx.json"
            elif [ -f oss/sbom.spdx.json ]; then
              SBOM_ARG="--sbom oss/sbom.spdx.json"
            fi
            EXT_ARG=""
            if [ -f oss/upstream_cbom.json ]; then
              EXT_ARG="--external-cbom oss/upstream_cbom.json"
            fi
            python3 scripts/analyze_cbom.py oss/cbom.json \\
              \$SBOM_ARG \\
              \$EXT_ARG \\
              --json oss/crypto-analysis.json \\
              --markdown oss/crypto-summary.md \\
              --step-summary
          fi

      # -------------------------------------------------------------
      # 6. Publish Cryptographic Audit Report to Repository (docs/security)
      # -------------------------------------------------------------
      - name: Publish Cryptographic Audit Report to Repository
        if: github.event_name == 'push' && !contains(github.event.head_commit.message, '[skip ci]')
        run: |
          if [ -f oss/crypto-summary.md ]; then
            mkdir -p docs/security
            cp oss/crypto-summary.md docs/security/CRYPTOGRAPHIC_AUDIT.md
            git config user.name "github-actions[bot]"
            git config user.email "github-actions[bot]@users.noreply.github.com"
            git add docs/security/CRYPTOGRAPHIC_AUDIT.md
            if git diff --staged --quiet; then
              echo "No changes in cryptographic audit report."
            else
              git commit -m "docs(security): update cryptographic audit & PQC migration report [skip ci]"
              git push
            fi
          fi

      # -------------------------------------------------------------
      # 7. Upload All BOM Artifacts
      # -------------------------------------------------------------
      - name: Upload BOM Artifacts
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: bom-artifacts
          path: oss/
          retention-days: 90
EOF
fi
echo "✅ Done"

# 4. Ensure .github/dependabot.yml includes github-actions ecosystem
DEPENDABOT_FILE="${REPO_DIR}/.github/dependabot.yml"
if [[ ! -f "$DEPENDABOT_FILE" ]]; then
    echo -n "Scaffolding .github/dependabot.yml for automated GitHub Actions updates ... "
    cat <<EOF > "$DEPENDABOT_FILE"
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
EOF
    echo "✅ Done"
fi

# 5. Generate Initial Local Audit & Documentation across all ecosystems
echo -n "Generating local multi-language cryptographic scan and updating documentation ... "
if [[ -f "${REPO_DIR}/scripts/enrich_sbom_python.py" ]]; then
    python3 "${REPO_DIR}/scripts/enrich_sbom_python.py" "${REPO_DIR}/oss/sbom.cyclonedx.json" "${REPO_DIR}" >/dev/null 2>&1 || true
fi
if [[ -f "${REPO_DIR}/scripts/enrich_sbom_gradle.py" && ( -f "${REPO_DIR}/build.gradle" || -f "${REPO_DIR}/build.gradle.kts" ) ]]; then
    python3 "${REPO_DIR}/scripts/enrich_sbom_gradle.py" "${REPO_DIR}/oss/sbom.cyclonedx.json" "${REPO_DIR}" >/dev/null 2>&1 || true
fi
python3 "${REPO_DIR}/scripts/scan_crypto_ast.py" "${REPO_DIR}" --cbom "${REPO_DIR}/oss/cbom.json" --output-json "${REPO_DIR}/oss/crypto-callsites.json" >/dev/null 2>&1 || true
SBOM_LOCAL_ARG=""
if [[ -f "${REPO_DIR}/oss/sbom.cyclonedx.json" ]]; then
    SBOM_LOCAL_ARG="--sbom ${REPO_DIR}/oss/sbom.cyclonedx.json"
elif [[ -f "${REPO_DIR}/oss/sbom.spdx.json" ]]; then
    SBOM_LOCAL_ARG="--sbom ${REPO_DIR}/oss/sbom.spdx.json"
fi
python3 "${REPO_DIR}/scripts/analyze_cbom.py" "${REPO_DIR}/oss/cbom.json" $SBOM_LOCAL_ARG --json "${REPO_DIR}/oss/crypto-analysis.json" --markdown "${REPO_DIR}/oss/crypto-summary.md" >/dev/null 2>&1 || true
if [[ -f "${REPO_DIR}/oss/crypto-summary.md" ]]; then
    cp "${REPO_DIR}/oss/crypto-summary.md" "${REPO_DIR}/docs/security/CRYPTOGRAPHIC_AUDIT.md"
fi
echo "✅ Done"

echo "=================================================================="
echo "🎉 Installation / Update Complete for ${REPO_DIR}!"
echo "=================================================================="
