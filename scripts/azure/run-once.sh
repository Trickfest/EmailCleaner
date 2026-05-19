#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Start one EmailCleaner Azure Container Apps job execution.

Usage:
  scripts/azure/run-once.sh

Options:
  -h, --help  Show this help text.

Notes:
  - This script mutates Azure by starting a job execution.
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

az containerapp job start \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --output table
