#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Show recent EmailCleaner Azure Container Apps job logs.

Usage:
  scripts/azure/logs.sh

Options:
  -h, --help  Show this help text.

Notes:
  - This script is read-only.
  - Historical logs are retained by the Container Apps environment Log Analytics
    workspace according to workspace retention settings.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

load_azure_env
require_persistent_resource_names
validate_azure_config
require_command az

az containerapp job logs show \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP"
