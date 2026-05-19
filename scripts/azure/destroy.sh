#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Delete the EmailCleaner Azure resource group.

Usage:
  scripts/azure/destroy.sh --confirm RESOURCE_GROUP_NAME

Options:
  --confirm NAME  Required. Must exactly match AZURE_RESOURCE_GROUP.
  -h, --help      Show this help text.

Notes:
  - This script permanently deletes Azure resources, runtime files, and state.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

CONFIRM=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --confirm)
      [[ $# -ge 2 ]] || fail "--confirm requires a value."
      CONFIRM="$2"
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

load_azure_env
require_persistent_resource_names
validate_azure_config
require_command az

[[ -n "$CONFIRM" ]] || fail "--confirm ${AZURE_RESOURCE_GROUP} is required."
[[ "$CONFIRM" == "$AZURE_RESOURCE_GROUP" ]] || fail "--confirm must exactly match ${AZURE_RESOURCE_GROUP}."

info "Deleting resource group ${AZURE_RESOURCE_GROUP}."
az group delete \
  --name "$AZURE_RESOURCE_GROUP" \
  --yes
