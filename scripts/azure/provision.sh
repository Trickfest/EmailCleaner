#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Provision Azure resources for EmailCleaner.

Usage:
  scripts/azure/provision.sh [--skip-runtime-upload]

Options:
  --skip-runtime-upload  Create infrastructure only; do not upload config/rules/state.
  -h, --help             Show this help text.

Notes:
  - This script mutates Azure. Do not run it during local-only implementation.
  - Run scripts/azure/init-env.sh first if scripts/azure/env.local does not exist.
  - Secrets are applied by scripts/azure/deploy.sh, not by this script.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

SKIP_RUNTIME_UPLOAD="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-runtime-upload)
      SKIP_RUNTIME_UPLOAD="1"
      shift
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

print_config_summary

info "Checking Azure account."
az account show --output table

info "Registering required Azure providers."
az provider register --namespace Microsoft.App --wait
az provider register --namespace Microsoft.OperationalInsights --wait
az provider register --namespace Microsoft.Storage --wait
az provider register --namespace Microsoft.ContainerRegistry --wait

info "Creating resource group."
az group create \
  --name "$AZURE_RESOURCE_GROUP" \
  --location "$AZURE_LOCATION" \
  --output table

if [[ "$AZURE_CREATE_ACR" == "true" && "$AZURE_ACR_RESOURCE_GROUP" != "$AZURE_RESOURCE_GROUP" ]]; then
  info "Creating Azure Container Registry resource group."
  az group create \
    --name "$AZURE_ACR_RESOURCE_GROUP" \
    --location "$AZURE_LOCATION" \
    --output table
fi

info "Creating Log Analytics workspace."
az monitor log-analytics workspace create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --workspace-name "$AZURE_LOG_WORKSPACE" \
  --location "$AZURE_LOCATION" \
  --output table

workspace_id="$(az monitor log-analytics workspace show \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --workspace-name "$AZURE_LOG_WORKSPACE" \
  --query customerId \
  --output tsv)"
workspace_key="$(az monitor log-analytics workspace get-shared-keys \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --workspace-name "$AZURE_LOG_WORKSPACE" \
  --query primarySharedKey \
  --output tsv)"

info "Creating Container Apps environment."
az containerapp env create \
  --name "$AZURE_CONTAINERAPPS_ENV" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --location "$AZURE_LOCATION" \
  --logs-workspace-id "$workspace_id" \
  --logs-workspace-key "$workspace_key" \
  --output table

if [[ "$AZURE_CREATE_ACR" == "true" ]]; then
  info "Creating Azure Container Registry."
  az acr create \
    --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
    --name "$AZURE_ACR_NAME" \
    --sku "$AZURE_ACR_SKU" \
    --admin-enabled false \
    --output table
else
  info "Using existing Azure Container Registry."
  az acr show \
    --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
    --name "$AZURE_ACR_NAME" \
    --output table
fi

info "Creating storage account and file share."
az storage account create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --name "$AZURE_STORAGE_ACCOUNT" \
  --location "$AZURE_LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --output table

az storage share-rm create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --storage-account "$AZURE_STORAGE_ACCOUNT" \
  --name "$AZURE_FILE_SHARE" \
  --quota 1 \
  --output table

storage_key="$(az storage account keys list \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --account-name "$AZURE_STORAGE_ACCOUNT" \
  --query '[0].value' \
  --output tsv)"

info "Registering Azure Files share with Container Apps environment."
az containerapp env storage set \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --name "$AZURE_CONTAINERAPPS_ENV" \
  --storage-name "$AZURE_STORAGE_MOUNT_NAME" \
  --azure-file-account-name "$AZURE_STORAGE_ACCOUNT" \
  --azure-file-account-key "$storage_key" \
  --azure-file-share-name "$AZURE_FILE_SHARE" \
  --access-mode ReadWrite \
  --output table

if [[ "$SKIP_RUNTIME_UPLOAD" == "0" ]]; then
  info "Uploading initial runtime files."
  "${SCRIPT_DIR}/sync-runtime-files.sh"
else
  info "Skipping runtime file upload."
fi

info "Provisioning complete."
