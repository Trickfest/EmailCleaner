#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build one EmailCleaner container image in the configured Azure Container Registry.

Usage:
  scripts/azure/build-image.sh --profile NAME [--tag TAG] [--env-file PATH]

Options:
  --profile NAME   Required instance profile used to resolve the shared ACR.
  --tag TAG        Image tag. Default: current Git short SHA.
  --env-file PATH  Optional profile env override; the embedded profile name must match.
  -h, --help       Show this help text.

Notes:
  - This script mutates only Azure Container Registry.
  - It does not deploy or update any EmailCleaner instance.
  - The resulting immutable image reference can be deployed to multiple profiles.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

PROFILE=""
CLI_ENV_FILE=""
IMAGE_TAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ $# -ge 2 ]] || fail "--profile requires a value."
      PROFILE="$2"
      shift 2
      ;;
    --env-file)
      [[ $# -ge 2 ]] || fail "--env-file requires a value."
      CLI_ENV_FILE="$2"
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 ]] || fail "--tag requires a value."
      IMAGE_TAG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

[[ -n "$PROFILE" ]] || fail "--profile NAME is required."

load_instance_profile "$PROFILE" "$CLI_ENV_FILE"
require_persistent_resource_names
validate_azure_config
require_command az

IMAGE="$(emailcleaner_image_tag "$IMAGE_TAG")"
print_config_summary
info "Building image in Azure Container Registry: ${IMAGE}"
az acr build \
  --registry "$AZURE_ACR_NAME" \
  --image "${AZURE_IMAGE_NAME}:${IMAGE##*:}" \
  --file "${AZURE_REPO_ROOT}/Dockerfile" \
  "$AZURE_REPO_ROOT"

info "Image build complete: ${IMAGE}"
