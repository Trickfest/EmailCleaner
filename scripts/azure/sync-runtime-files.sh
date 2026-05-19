#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Upload EmailCleaner runtime files to the Azure Files share.

Usage:
  scripts/azure/sync-runtime-files.sh [--include-accounts] [--config PATH] [--rules PATH] [--accounts PATH]

Options:
  --include-accounts  Also upload accounts.json. Use only if you intentionally
                      store account credentials in Azure Files.
  --config PATH       Config file to upload. Default: repo config.json.
  --rules PATH        Rules file to upload. Default: repo rules.json.
  --accounts PATH     Accounts file to upload. Default: repo accounts.json.
  -h, --help          Show this help text.

Notes:
  - This script mutates Azure.
  - config.json and rules.json are uploaded explicitly by this script, not by
    normal code deploys.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

INCLUDE_ACCOUNTS="0"
CONFIG_PATH=""
RULES_PATH=""
ACCOUNTS_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --include-accounts)
      INCLUDE_ACCOUNTS="1"
      shift
      ;;
    --config)
      [[ $# -ge 2 ]] || fail "--config requires a value."
      CONFIG_PATH="$2"
      shift 2
      ;;
    --rules)
      [[ $# -ge 2 ]] || fail "--rules requires a value."
      RULES_PATH="$2"
      shift 2
      ;;
    --accounts)
      [[ $# -ge 2 ]] || fail "--accounts requires a value."
      ACCOUNTS_PATH="$2"
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

CONFIG_PATH="${CONFIG_PATH:-${AZURE_REPO_ROOT}/config.json}"
RULES_PATH="${RULES_PATH:-${AZURE_REPO_ROOT}/rules.json}"
ACCOUNTS_PATH="${ACCOUNTS_PATH:-${AZURE_REPO_ROOT}/accounts.json}"

[[ -f "$CONFIG_PATH" ]] || fail "Missing config file: ${CONFIG_PATH}"
[[ -f "$RULES_PATH" ]] || fail "Missing rules file: ${RULES_PATH}"
if [[ "$INCLUDE_ACCOUNTS" == "1" ]]; then
  [[ -f "$ACCOUNTS_PATH" ]] || fail "Missing accounts file: ${ACCOUNTS_PATH}"
fi

storage_key="$(az storage account keys list \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --account-name "$AZURE_STORAGE_ACCOUNT" \
  --query '[0].value' \
  --output tsv)"

upload_file() {
  local source_path="$1"
  local dest_name="$2"
  info "Uploading ${dest_name}."
  az storage file upload \
    --account-name "$AZURE_STORAGE_ACCOUNT" \
    --account-key "$storage_key" \
    --share-name "$AZURE_FILE_SHARE" \
    --source "$source_path" \
    --path "$dest_name" \
    --output table
}

upload_file "$CONFIG_PATH" "config.json"
upload_file "$RULES_PATH" "rules.json"
if [[ "$INCLUDE_ACCOUNTS" == "1" ]]; then
  upload_file "$ACCOUNTS_PATH" "accounts.json"
else
  info "Skipping accounts.json upload. Azure deployment prefers secret-backed environment variables."
fi

state_exists="$(az storage file exists \
  --account-name "$AZURE_STORAGE_ACCOUNT" \
  --account-key "$storage_key" \
  --share-name "$AZURE_FILE_SHARE" \
  --path ".email_cleaner_state.json" \
  --query exists \
  --output tsv)"
if [[ "$state_exists" != "true" ]]; then
  tmp_state="$(mktemp)"
  printf '{}\n' >"$tmp_state"
  upload_file "$tmp_state" ".email_cleaner_state.json"
  rm -f "$tmp_state"
fi

info "Runtime file sync complete."
