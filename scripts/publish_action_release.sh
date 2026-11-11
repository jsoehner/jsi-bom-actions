#!/usr/bin/env bash
# ==============================================================================
# publish_action_release.sh - Publish & Tag SBOM/CBOM GitHub Action for Dependabot
# ==============================================================================
# Syncs the Composite GitHub Action (`action.yml`, `scripts/`, `references/`,
# `tests/`) to a standalone GitHub Action repository (e.g. jsoehner/sbom-cbom-action)
# and creates an immutable semantic version tag (e.g. v1.2.0) + GitHub Release.
#
# Once tagged and released on GitHub, any consumer repository with
# `.github/dependabot.yml` (`package-ecosystem: "github-actions"`) will
# automatically receive a Dependabot Pull Request bumping the 40-char commit SHA!
# ==============================================================================

set -euo pipefail

SKILL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_TAG=""
ACTION_REPO_DIR=""
CREATE_GH_RELEASE=true

usage() {
    cat <<EOF
Usage: $(basename "$0") -v <VERSION_TAG> [-d <STANDALONE_ACTION_REPO_DIR>] [--no-release]

Options:
  -v, --version TAG       Semantic version tag to publish (e.g., v1.1.0)
  -d, --dest-repo DIR     Optional local checkout of standalone action repo (e.g., ../sbom-cbom-action)
                          If omitted, tags and releases in the current repository.
  --no-release            Create and push Git tags only (skip 'gh release create')
  -h, --help              Show this help message

Examples:
  $(basename "$0") -v v1.1.0
  $(basename "$0") -v v1.1.0 -d ~/repos/sbom-cbom-action
EOF
    exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--version)
            VERSION_TAG="$2"
            shift 2
            ;;
        -d|--dest-repo)
            ACTION_REPO_DIR="$2"
            shift 2
            ;;
        --no-release)
            CREATE_GH_RELEASE=false
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            echo "Error: Unknown argument '$1'" >&2
            usage 1
            ;;
    esac
done

if [[ -z "$VERSION_TAG" ]]; then
    echo "Error: Version tag (-v vX.Y.Z) is required." >&2
    usage 1
fi

if [[ ! "$VERSION_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version tag must follow semantic versioning format 'vX.Y.Z' (e.g., v1.1.0)." >&2
    exit 1
fi

MAJOR_TAG="${VERSION_TAG%%.*}"

# If a standalone destination repo is provided, sync the action files into its root
if [[ -n "$ACTION_REPO_DIR" ]]; then
    mkdir -p "$ACTION_REPO_DIR/scripts" "$ACTION_REPO_DIR/references" "$ACTION_REPO_DIR/tests"
    cp "$SKILL_ROOT/action.yml" "$ACTION_REPO_DIR/action.yml"
    cp "$SKILL_ROOT/SKILL.md" "$ACTION_REPO_DIR/README.md"
    cp -r "$SKILL_ROOT/scripts/"* "$ACTION_REPO_DIR/scripts/"
    cp -r "$SKILL_ROOT/references/"* "$SKILL_ROOT/references/" 2>/dev/null || true
    cp -r "$SKILL_ROOT/tests/"* "$ACTION_REPO_DIR/tests/"
    cd "$ACTION_REPO_DIR"
    git add -A
    if ! git diff --staged --quiet; then
        git commit -m "release: publish SBOM & CBOM Composite Action ${VERSION_TAG}"
        git push origin HEAD
    fi
else
    cd "$SKILL_ROOT"
fi

COMMIT_SHA="$(git rev-parse HEAD)"

echo "Tagging commit ${COMMIT_SHA} as ${VERSION_TAG} (and updating floating tag ${MAJOR_TAG})..."
git tag -a "$VERSION_TAG" -m "Release ${VERSION_TAG}" -f
git tag -a "$MAJOR_TAG" -m "Release ${VERSION_TAG} (${MAJOR_TAG})" -f
git push origin "$VERSION_TAG" --force
git push origin "$MAJOR_TAG" --force

if [[ "$CREATE_GH_RELEASE" == "true" ]] && command -v gh &>/dev/null; then
    gh release create "$VERSION_TAG" --title "$VERSION_TAG" --generate-notes || true
fi

echo "=================================================================="
echo "✅ Published ${VERSION_TAG}!"
echo "   Immutable Commit SHA : ${COMMIT_SHA}"
echo "   Dependabot Reference : uses: <owner>/<repo>@${COMMIT_SHA} # ${VERSION_TAG}"
echo "=================================================================="
