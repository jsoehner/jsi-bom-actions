#!/usr/bin/env bash
# ==============================================================================
# generate_boms.sh - Automated Multi-Language SBOM & CBOM Generator
# ==============================================================================
# Generates Software Bill of Materials (SBOM) and Cryptographic Bill of
# Materials (CBOM) for container images or source directories across 18+
# programming languages and 12+ package manager ecosystems.
#
# Dependencies:
#   - syft (for SPDX/CycloneDX SBOM) or cdxgen / npx @cyclonedx/cdxgen
#   - cdxgen (or npx @cyclonedx/cdxgen) for CBOM with --include-crypto
#   - python3 (for multi-ecosystem SBOM enrichment and AST crypto reconciliation)
#   - docker (if target is a container image)
# ==============================================================================

set -euo pipefail

# Get the absolute path of the skill root directory
SKILL_DIR=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Resolve scripts directory (supports both skill root and target repo scripts/ folder)
if [[ -f "${SCRIPT_DIR}/scan_crypto_ast.py" ]]; then
    TOOLS_DIR="${SCRIPT_DIR}"
else
    TOOLS_DIR="${SKILL_DIR}/scripts"
fi

# Default settings
TARGET_TYPE="docker"      # "docker" or "dir"
TARGET=""
OUTPUT_DIR="oss"
SBOM_FORMAT="spdx-json"   # "spdx-json" or "cyclonedx-json"
VERBOSE=false
SCAN_OS=false

usage() {
    local exit_code="${1:-1}"
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <TARGET>

Arguments:
  <TARGET>              Container image name (e.g., my-app:latest) or directory path (e.g., .)

Options:
  -t, --type TYPE       Target type: 'docker' (default) or 'dir'
  -o, --output-dir DIR  Directory to store generated BOMs (default: oss)
  -f, --format FORMAT   SBOM format: 'spdx-json' (default), 'cyclonedx-json'
  -v, --verbose         Enable verbose log output
  -s, --scan-os         Scan and update OS cryptographic inventory (nightly update)
  -h, --help            Show this help message and exit

Examples:
  $(basename "$0") my-demo-app:local
  $(basename "$0") -t dir -o build/boms .
  $(basename "$0") -t docker -o artifacts my-registry.io/app:v1.0.0
  $(basename "$0") --scan-os
EOF
    exit "$exit_code"
}

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--type)
            TARGET_TYPE="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -f|--format)
            SBOM_FORMAT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -s|--scan-os)
            SCAN_OS=true
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        -*)
            echo "Error: Unknown option $1" >&2
            usage 1
            ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
                shift
            else
                echo "Error: Multiple targets provided: '$TARGET' and '$1'" >&2
                usage
            fi
            ;;
    esac
done

if [[ -z "$TARGET" ]] && [[ "$SCAN_OS" == "false" ]]; then
    echo "Error: Target is required unless --scan-os is provided." >&2
    usage
fi

# Auto-switch TARGET_TYPE to "dir" if TARGET is an existing filesystem directory
if [[ -n "$TARGET" && -d "$TARGET" && "$TARGET_TYPE" == "docker" ]]; then
    TARGET_TYPE="dir"
fi

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

# Resolve cdxgen runner (cdxgen in PATH, or npx -y @cyclonedx/cdxgen)
CDXGEN_CMD=()
if command -v cdxgen &>/dev/null; then
    CDXGEN_CMD=(cdxgen)
elif command -v npx &>/dev/null; then
    CDXGEN_CMD=(npx -y @cyclonedx/cdxgen)
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

SBOM_OUTPUT="${OUTPUT_DIR}/sbom.${SBOM_FORMAT%%-*}.json"
CYCLONEDX_SBOM_OUTPUT="${OUTPUT_DIR}/sbom.cyclonedx.json"
CBOM_OUTPUT="${OUTPUT_DIR}/cbom.json"

log "Target: $TARGET (type: $TARGET_TYPE)"
log "Output directory: $OUTPUT_DIR"

# ------------------------------------------------------------------------------
# 0. OS Inventory Update
# ------------------------------------------------------------------------------
if [[ "$SCAN_OS" == "true" ]]; then
    log "Running OS inventory update..."
    python3 "$TOOLS_DIR/update_os_inventory.py"
    log "OS inventory update complete."
    if [[ -z "$TARGET" ]]; then
        exit 0
    fi
fi

# ------------------------------------------------------------------------------
# 1. Generate SBOM (using syft if installed, else fallback to cdxgen/enricher)
# ------------------------------------------------------------------------------
log "Step 1: Generating Software Bill of Materials (SBOM)..."

if command -v syft &>/dev/null; then
    log "Using syft for SBOM generation..."
    if [[ "$TARGET_TYPE" == "docker" ]]; then
        syft "$TARGET" -o "$SBOM_FORMAT" > "$SBOM_OUTPUT"
    else
        syft "dir:$TARGET" -o "$SBOM_FORMAT" > "$SBOM_OUTPUT"
    fi
elif [[ ${#CDXGEN_CMD[@]} -gt 0 ]]; then
    log "Syft not found; using cdxgen (${CDXGEN_CMD[*]}) for SBOM generation..."
    if [[ "$TARGET_TYPE" == "docker" ]]; then
        "${CDXGEN_CMD[@]}" -t docker -o "$SBOM_OUTPUT" "$TARGET" || true
    else
        "${CDXGEN_CMD[@]}" -o "$SBOM_OUTPUT" "$TARGET" || true
    fi
elif [[ "$TARGET_TYPE" == "dir" && -f "${TOOLS_DIR}/enrich_sbom_python.py" ]]; then
    log "Initializing CycloneDX SBOM via Multi-Ecosystem Manifest Enricher..."
    python3 "${TOOLS_DIR}/enrich_sbom_python.py" "$CYCLONEDX_SBOM_OUTPUT" "$TARGET"
else
    echo "Error: Neither 'syft' nor 'cdxgen'/'npx' was found in PATH." >&2
    echo "Please install syft (curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh) or cdxgen (npm install -g @cyclonedx/cdxgen)." >&2
    exit 1
fi

# Always run Multi-Ecosystem Manifest & Lockfile Enricher when scanning a directory
if [[ "$TARGET_TYPE" == "dir" ]]; then
    if [[ -f "${TOOLS_DIR}/enrich_sbom_python.py" ]]; then
        log "Enriching CycloneDX SBOM across all project language manifests and lockfiles..."
        python3 "${TOOLS_DIR}/enrich_sbom_python.py" "$CYCLONEDX_SBOM_OUTPUT" "$TARGET" || true
    fi
    if [[ -f "${TOOLS_DIR}/enrich_sbom_gradle.py" && ( -f "${TARGET}/build.gradle" || -f "${TARGET}/build.gradle.kts" ) ]]; then
        log "Enriching CycloneDX SBOM with Gradle runtimeClasspath dependencies..."
        python3 "${TOOLS_DIR}/enrich_sbom_gradle.py" "$CYCLONEDX_SBOM_OUTPUT" "$TARGET" || true
    fi
fi

log "SBOM generated successfully: $SBOM_OUTPUT"

# ------------------------------------------------------------------------------
# 2. Discover or Generate CBOM (Cryptographic Bill of Materials)
# ------------------------------------------------------------------------------
log "Step 2: Resolving Cryptographic Bill of Materials (CBOM)..."

FETCHED_FROM_OCI=false
if [[ "$TARGET_TYPE" == "docker" ]]; then
    FETCH_SCRIPT="${TOOLS_DIR}/fetch_oci_cbom.py"
    if [[ -f "$FETCH_SCRIPT" ]]; then
        log "Checking OCI Distribution Spec v1.1+ registry referrers for pre-attached upstream CBOM..."
        if python3 "$FETCH_SCRIPT" "$TARGET" -o "$CBOM_OUTPUT" 2>/dev/null; then
            log "✅ Discovered and retrieved pre-attached upstream CBOM via OCI Referrers API / ORAS!"
            FETCHED_FROM_OCI=true
        fi
    fi
fi

if [[ "$FETCHED_FROM_OCI" == "false" ]]; then
    if [[ ${#CDXGEN_CMD[@]} -gt 0 ]]; then
        log "No pre-attached OCI CBOM found. Running deep cryptographic analysis (${CDXGEN_CMD[*]} --include-crypto)..."
        if [[ "$TARGET_TYPE" == "docker" ]]; then
            "${CDXGEN_CMD[@]}" -t docker --include-crypto -o "$CBOM_OUTPUT" "$TARGET" || true
        else
            "${CDXGEN_CMD[@]}" --include-crypto -o "$CBOM_OUTPUT" "$TARGET" || true
        fi
    elif [[ "$TARGET_TYPE" == "dir" && -f "${TOOLS_DIR}/scan_crypto_ast.py" ]]; then
        log "cdxgen not found; initializing CBOM via Multi-Language Semantic AST Cryptographic Scanner..."
        python3 "${TOOLS_DIR}/scan_crypto_ast.py" "$TARGET" --cbom "$CBOM_OUTPUT" --output-json "${OUTPUT_DIR}/crypto-callsites.json"
    else
        echo "Error: 'cdxgen' or 'npx' is required to generate CBOM with cryptographic inventory." >&2
        echo "Install via: npm install -g @cyclonedx/cdxgen" >&2
        exit 1
    fi
fi

if [[ "$TARGET_TYPE" == "dir" && -f "${TOOLS_DIR}/scan_crypto_ast.py" ]]; then
    log "Reconciling CBOM with Multi-Language Semantic AST Cryptographic Scanner..."
    python3 "${TOOLS_DIR}/scan_crypto_ast.py" "$TARGET" --cbom "$CBOM_OUTPUT" --output-json "${OUTPUT_DIR}/crypto-callsites.json"
fi

log "CBOM resolved successfully: $CBOM_OUTPUT"
log "BOM generation process complete."
