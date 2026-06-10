#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Show shared Azure Container Registry status.

Usage:
  scripts/azure/status-shared-acr.sh [--env-file PATH]

Options:
  --env-file PATH  Shared ACR env file. Default: scripts/azure/shared-acr.local.
  -h, --help       Show this help text.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

SHARED_ENV_FILE="${SCRIPT_DIR}/shared-acr.local"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      [[ $# -ge 2 ]] || fail "--env-file requires a value."
      SHARED_ENV_FILE="$2"
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

[[ -f "$SHARED_ENV_FILE" ]] || fail "Missing shared ACR env file: ${SHARED_ENV_FILE}."
# shellcheck disable=SC1090
source "$SHARED_ENV_FILE"

AZURE_ACR_RESOURCE_GROUP="${AZURE_ACR_RESOURCE_GROUP:-rg-shared-container-registry-prod}"
[[ -n "${AZURE_ACR_NAME:-}" ]] || fail "AZURE_ACR_NAME is required."
require_command az

info "Azure account."
az account show --output table

info "Shared ACR resource group."
az group show \
  --name "$AZURE_ACR_RESOURCE_GROUP" \
  --query "{name:name,location:location,provisioningState:properties.provisioningState}" \
  --output table

info "Shared Azure Container Registry."
az acr show \
  --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
  --name "$AZURE_ACR_NAME" \
  --query "{name:name,resourceGroup:resourceGroup,location:location,sku:sku.name,loginServer:loginServer,adminUserEnabled:adminUserEnabled}" \
  --output table

info "Repositories."
az acr repository list \
  --name "$AZURE_ACR_NAME" \
  --output table
