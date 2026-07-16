#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Delete one EmailCleaner instance without deleting shared Azure infrastructure.

Usage:
  scripts/azure/destroy.sh --profile NAME --confirm NAME:JOB_NAME

Options:
  --profile NAME   Required instance profile name.
  --env-file PATH  Optional profile env override; the embedded profile name must match.
  --confirm VALUE  Required exact profile-and-job confirmation.
  -h, --help       Show this help text.

Notes:
  - This permanently deletes the selected job, its Azure Files mount registration,
    and its Azure Files share, including runtime configuration and state.
  - It never deletes the shared resource group, Container Apps environment,
    storage account, Log Analytics workspace, or Azure Container Registry.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

PROFILE=""
CLI_ENV_FILE=""
CONFIRM=""

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

[[ -n "$PROFILE" ]] || fail "--profile NAME is required."

load_instance_profile "$PROFILE" "$CLI_ENV_FILE"
require_persistent_resource_names
validate_azure_config
require_command az

EXPECTED_CONFIRM="${PROFILE}:${AZURE_JOB_NAME}"
[[ -n "$CONFIRM" ]] || fail "--confirm ${EXPECTED_CONFIRM} is required."
[[ "$CONFIRM" == "$EXPECTED_CONFIRM" ]] || fail "--confirm must exactly match ${EXPECTED_CONFIRM}."

print_config_summary

if az containerapp job show \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --output none >/dev/null 2>&1; then
  info "Deleting Container Apps job ${AZURE_JOB_NAME}."
  az containerapp job delete \
    --name "$AZURE_JOB_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --yes \
    --output none
else
  info "Container Apps job does not exist: ${AZURE_JOB_NAME}"
fi

if az containerapp env storage show \
  --name "$AZURE_CONTAINERAPPS_ENV" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --storage-name "$AZURE_STORAGE_MOUNT_NAME" \
  --output none >/dev/null 2>&1; then
  info "Removing environment storage registration ${AZURE_STORAGE_MOUNT_NAME}."
  az containerapp env storage remove \
    --name "$AZURE_CONTAINERAPPS_ENV" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --storage-name "$AZURE_STORAGE_MOUNT_NAME" \
    --yes \
    --output none
else
  info "Environment storage registration does not exist: ${AZURE_STORAGE_MOUNT_NAME}"
fi

if az storage share-rm show \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --storage-account "$AZURE_STORAGE_ACCOUNT" \
  --name "$AZURE_FILE_SHARE" \
  --output none >/dev/null 2>&1; then
  info "Deleting Azure Files share ${AZURE_FILE_SHARE}."
  az storage share-rm delete \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --storage-account "$AZURE_STORAGE_ACCOUNT" \
    --name "$AZURE_FILE_SHARE" \
    --include snapshots \
    --yes \
    --output none
else
  info "Azure Files share does not exist: ${AZURE_FILE_SHARE}"
fi

info "Instance teardown complete for profile ${PROFILE}."
