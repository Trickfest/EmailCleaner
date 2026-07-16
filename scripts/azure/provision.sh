#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Provision Azure resources for EmailCleaner.

Usage:
  scripts/azure/provision.sh --profile NAME [--skip-runtime-upload]

Options:
  --profile NAME         Required instance profile name.
  --env-file PATH        Optional profile env override; the embedded profile name must match.
  --skip-runtime-upload  Create infrastructure only; do not upload config/rules/state.
  -h, --help             Show this help text.

Notes:
  - This script mutates Azure. Do not run it during local-only implementation.
  - The profile controls whether shared infrastructure is created or only verified.
  - Secrets are applied by scripts/azure/deploy.sh, not by this script.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

SKIP_RUNTIME_UPLOAD="0"
PROFILE=""
CLI_ENV_FILE=""

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

[[ -n "$PROFILE" ]] || fail "--profile NAME is required."

load_instance_profile "$PROFILE" "$CLI_ENV_FILE"
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

if [[ "$AZURE_PROVISION_SHARED_INFRASTRUCTURE" == "true" ]]; then
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

  info "Creating storage account."
  az storage account create \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --name "$AZURE_STORAGE_ACCOUNT" \
    --location "$AZURE_LOCATION" \
    --sku Standard_LRS \
    --kind StorageV2 \
    --output table
else
  info "Verifying shared Azure infrastructure."
  az group show \
    --name "$AZURE_RESOURCE_GROUP" \
    --output table
  az monitor log-analytics workspace show \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --workspace-name "$AZURE_LOG_WORKSPACE" \
    --output table
  az containerapp env show \
    --name "$AZURE_CONTAINERAPPS_ENV" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --output table
  az acr show \
    --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
    --name "$AZURE_ACR_NAME" \
    --output table
  az storage account show \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --name "$AZURE_STORAGE_ACCOUNT" \
    --output table
fi

info "Creating instance Azure Files share."
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
  sync_args=(--profile "$PROFILE")
  if [[ -n "$CLI_ENV_FILE" ]]; then
    sync_args+=(--env-file "$CLI_ENV_FILE")
  fi
  "${SCRIPT_DIR}/sync-runtime-files.sh" "${sync_args[@]}"
else
  info "Skipping runtime file upload."
fi

info "Provisioning complete."
