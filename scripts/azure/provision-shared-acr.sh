#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Provision a shared Azure Container Registry for one or more automation jobs.

Usage:
  scripts/azure/provision-shared-acr.sh [--env-file PATH]

Options:
  --env-file PATH  Shared ACR env file. Default: scripts/azure/shared-acr.local.
  -h, --help       Show this help text.

Notes:
  - This script mutates Azure.
  - Run scripts/azure/init-shared-acr-env.sh first if shared-acr.local does not exist.
  - This creates only the shared registry resource group and ACR. App-specific
    Container Apps jobs, storage, secrets, and logs remain in each app deployment.
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

[[ -f "$SHARED_ENV_FILE" ]] || fail "Missing shared ACR env file: ${SHARED_ENV_FILE}. Run scripts/azure/init-shared-acr-env.sh."
# shellcheck disable=SC1090
source "$SHARED_ENV_FILE"

AZURE_LOCATION="${AZURE_LOCATION:-centralus}"
AZURE_ACR_RESOURCE_GROUP="${AZURE_ACR_RESOURCE_GROUP:-rg-shared-container-registry-prod}"
AZURE_ACR_SKU="${AZURE_ACR_SKU:-Basic}"
[[ -n "${AZURE_ACR_NAME:-}" ]] || fail "AZURE_ACR_NAME is required."
[[ "$AZURE_ACR_NAME" =~ ^[a-zA-Z0-9]{5,50}$ ]] || fail "AZURE_ACR_NAME must be 5-50 alphanumeric characters."
[[ "$AZURE_ACR_RESOURCE_GROUP" =~ ^[A-Za-z0-9._()/-]+$ ]] || fail "AZURE_ACR_RESOURCE_GROUP has invalid characters."

require_command az

cat <<EOF
Shared Azure Container Registry configuration:
  resource group: ${AZURE_ACR_RESOURCE_GROUP}
  location:       ${AZURE_LOCATION}
  ACR:            ${AZURE_ACR_NAME}
  SKU:            ${AZURE_ACR_SKU}
EOF

info "Checking Azure account."
az account show --output table

info "Registering Azure Container Registry provider."
az provider register --namespace Microsoft.ContainerRegistry --wait

info "Creating shared ACR resource group."
az group create \
  --name "$AZURE_ACR_RESOURCE_GROUP" \
  --location "$AZURE_LOCATION" \
  --output table

if az acr show \
  --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
  --name "$AZURE_ACR_NAME" \
  --output none >/dev/null 2>&1; then
  info "Shared Azure Container Registry already exists."
  az acr show \
    --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
    --name "$AZURE_ACR_NAME" \
    --query "{name:name,resourceGroup:resourceGroup,location:location,sku:sku.name,loginServer:loginServer,adminUserEnabled:adminUserEnabled}" \
    --output table
else
  info "Creating shared Azure Container Registry."
  az acr create \
    --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
    --name "$AZURE_ACR_NAME" \
    --sku "$AZURE_ACR_SKU" \
    --admin-enabled false \
    --output table
fi

info "Shared ACR provisioning complete."
