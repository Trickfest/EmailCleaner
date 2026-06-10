#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Show EmailCleaner Azure deployment status.

Usage:
  scripts/azure/status.sh [--executions N]

Options:
  --executions N  Number of recent executions to list. Default: 10.
  -h, --help      Show this help text.

Notes:
  - This script is read-only.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

EXECUTIONS="10"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --executions)
      [[ $# -ge 2 ]] || fail "--executions requires a value."
      EXECUTIONS="$2"
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

[[ "$EXECUTIONS" =~ ^[0-9]+$ ]] || fail "--executions must be an integer."
(( EXECUTIONS >= 1 )) || fail "--executions must be >= 1."

load_azure_env
require_persistent_resource_names
validate_azure_config
require_command az

section() {
  echo
  echo "==> $*"
}

print_resource_config_summary() {
  cat <<EOF
Azure deployment resource configuration:
  resource group:        ${AZURE_RESOURCE_GROUP}
  location:              ${AZURE_LOCATION}
  container apps env:    ${AZURE_CONTAINERAPPS_ENV}
  job name:              ${AZURE_JOB_NAME}
  ACR:                   ${AZURE_ACR_NAME}
  ACR resource group:    ${AZURE_ACR_RESOURCE_GROUP}
  storage account:       ${AZURE_STORAGE_ACCOUNT}
  file share:            ${AZURE_FILE_SHARE}
  storage mount name:    ${AZURE_STORAGE_MOUNT_NAME}
  log workspace:         ${AZURE_LOG_WORKSPACE}
  image name:            ${AZURE_IMAGE_NAME}
EOF
}

section "Azure Account"
az account show --output table

section "Deployment Resource Configuration"
print_resource_config_summary

section "Resource Group"
az group show \
  --name "$AZURE_RESOURCE_GROUP" \
  --output table

section "Container Apps Job"
az containerapp job show \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --query "{name:name,location:location,trigger:properties.configuration.triggerType,cron:properties.configuration.scheduleTriggerConfig.cronExpression,image:properties.template.containers[0].image,replicaTimeout:properties.configuration.replicaTimeout,replicaRetryLimit:properties.configuration.replicaRetryLimit}" \
  --output table

section "Recent Executions"
az containerapp job execution list \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --query "reverse(sort_by(@, &properties.startTime))[:${EXECUTIONS}].{name:name,status:properties.status,start:properties.startTime,end:properties.endTime}" \
  --output table

section "Azure Files Runtime Files"
storage_key="$(az storage account keys list \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --account-name "$AZURE_STORAGE_ACCOUNT" \
  --query '[0].value' \
  --output tsv)"
for path in config.json rules.json accounts.json .email_cleaner_state.json; do
  exists="$(az storage file exists \
    --account-name "$AZURE_STORAGE_ACCOUNT" \
    --account-key "$storage_key" \
    --share-name "$AZURE_FILE_SHARE" \
    --path "$path" \
    --query exists \
    --output tsv)"
  printf '%s: %s\n' "$path" "$exists"
done
