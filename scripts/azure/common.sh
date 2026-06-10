#!/usr/bin/env bash

fail() {
  echo "Error: $*" >&2
  exit 1
}

warn() {
  echo "Warning: $*" >&2
}

info() {
  echo "==> $*"
}

azure_script_dir() {
  local source_path="${BASH_SOURCE[0]}"
  cd "$(dirname "$source_path")" && pwd
}

azure_repo_root() {
  local script_dir
  script_dir="$(azure_script_dir)"
  cd "$script_dir/../.." && pwd
}

require_command() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || fail "Required command not found: ${command_name}"
}

random_numeric_suffix() {
  python3 - <<'PY'
import random

print(random.SystemRandom().randrange(10_000_000, 100_000_000))
PY
}

load_azure_env() {
  AZURE_SCRIPT_DIR="$(azure_script_dir)"
  AZURE_REPO_ROOT="$(azure_repo_root)"
  AZURE_ENV_FILE="${1:-${AZURE_SCRIPT_DIR}/env.local}"
  local azure_config_vars=(
    AZURE_LOCATION
    AZURE_RESOURCE_GROUP
    AZURE_CONTAINERAPPS_ENV
    AZURE_JOB_NAME
    AZURE_LOG_WORKSPACE
    AZURE_FILE_SHARE
    AZURE_STORAGE_MOUNT_NAME
    AZURE_IMAGE_NAME
    AZURE_ACR_RESOURCE_GROUP
    AZURE_CREATE_ACR
    AZURE_SCAN_CRON
    AZURE_ACR_SKU
    AZURE_JOB_TRIGGER_TYPE
    AZURE_CPU
    AZURE_MEMORY
    AZURE_BOOTSTRAP_IMAGE
    AZURE_MAX_RUNTIME_SECONDS
    AZURE_REPLICA_TIMEOUT
    AZURE_REPLICA_RETRY_LIMIT
    AZURE_PARALLELISM
    AZURE_REPLICA_COMPLETION_COUNT
    AZURE_UNIQUE_SUFFIX
    AZURE_ACR_NAME
    AZURE_STORAGE_ACCOUNT
    AZURE_SECRET_ENV_VARS
    AZURE_SECRETS_FILE
    AZURE_ACCOUNTS_SECRET_FILE
  )
  local config_var

  for config_var in "${azure_config_vars[@]}"; do
    unset "$config_var"
  done

  if [[ -f "$AZURE_ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$AZURE_ENV_FILE"
  fi

  AZURE_LOCATION="${AZURE_LOCATION:-centralus}"
  AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-rg-emailcleaner-prod}"
  AZURE_CONTAINERAPPS_ENV="${AZURE_CONTAINERAPPS_ENV:-cae-emailcleaner-prod}"
  AZURE_JOB_NAME="${AZURE_JOB_NAME:-caj-emailcleaner-prod}"
  AZURE_LOG_WORKSPACE="${AZURE_LOG_WORKSPACE:-law-emailcleaner-prod}"
  AZURE_FILE_SHARE="${AZURE_FILE_SHARE:-emailcleaner-data}"
  AZURE_STORAGE_MOUNT_NAME="${AZURE_STORAGE_MOUNT_NAME:-emailcleaner-data}"
  AZURE_IMAGE_NAME="${AZURE_IMAGE_NAME:-emailcleaner}"
  AZURE_ACR_RESOURCE_GROUP="${AZURE_ACR_RESOURCE_GROUP:-${AZURE_RESOURCE_GROUP}}"
  AZURE_CREATE_ACR="${AZURE_CREATE_ACR:-true}"
  AZURE_SCAN_CRON="${AZURE_SCAN_CRON:-*/15 * * * *}"
  AZURE_ACR_SKU="${AZURE_ACR_SKU:-Basic}"
  AZURE_JOB_TRIGGER_TYPE="${AZURE_JOB_TRIGGER_TYPE:-Manual}"
  AZURE_CPU="${AZURE_CPU:-0.25}"
  AZURE_MEMORY="${AZURE_MEMORY:-0.5Gi}"
  AZURE_BOOTSTRAP_IMAGE="${AZURE_BOOTSTRAP_IMAGE:-mcr.microsoft.com/azuredocs/containerapps-helloworld:latest}"
  AZURE_MAX_RUNTIME_SECONDS="${AZURE_MAX_RUNTIME_SECONDS:-3600}"
  AZURE_REPLICA_TIMEOUT="${AZURE_REPLICA_TIMEOUT:-3600}"
  AZURE_REPLICA_RETRY_LIMIT="${AZURE_REPLICA_RETRY_LIMIT:-0}"
  AZURE_PARALLELISM="${AZURE_PARALLELISM:-1}"
  AZURE_REPLICA_COMPLETION_COUNT="${AZURE_REPLICA_COMPLETION_COUNT:-1}"
  AZURE_SECRET_ENV_VARS="${AZURE_SECRET_ENV_VARS:-OPENAI_API_KEY EMAIL_CLEANER_GMAIL_EMAIL_1 EMAIL_CLEANER_GMAIL_APP_PASSWORD_1 EMAIL_CLEANER_YAHOO_EMAIL_1 EMAIL_CLEANER_YAHOO_APP_PASSWORD_1}"
  AZURE_SECRETS_FILE="${AZURE_SECRETS_FILE:-${AZURE_SCRIPT_DIR}/secrets.local}"
  AZURE_ACCOUNTS_SECRET_FILE="${AZURE_ACCOUNTS_SECRET_FILE:-${AZURE_REPO_ROOT}/accounts.json}"

  if [[ -n "${AZURE_ACR_NAME:-}" && -n "${AZURE_STORAGE_ACCOUNT:-}" ]]; then
    AZURE_RESOURCE_NAMES_PERSISTED="1"
  else
    AZURE_RESOURCE_NAMES_PERSISTED="0"
  fi

  if [[ -z "${AZURE_UNIQUE_SUFFIX:-}" ]]; then
    AZURE_UNIQUE_SUFFIX="$(random_numeric_suffix)"
  fi
  AZURE_ACR_NAME="${AZURE_ACR_NAME:-acremailcleaner${AZURE_UNIQUE_SUFFIX}}"
  AZURE_STORAGE_ACCOUNT="${AZURE_STORAGE_ACCOUNT:-stemcleaner${AZURE_UNIQUE_SUFFIX}}"
  AZURE_ACR_SERVER="${AZURE_ACR_NAME}.azurecr.io"
}

require_persistent_resource_names() {
  if [[ "${AZURE_RESOURCE_NAMES_PERSISTED:-0}" != "1" ]]; then
    fail "AZURE_ACR_NAME and AZURE_STORAGE_ACCOUNT are not set persistently. Run scripts/azure/init-env.sh or export both names before running Azure commands."
  fi
}

validate_azure_config() {
  [[ "$AZURE_LOCATION" == "centralus" ]] || warn "AZURE_LOCATION is ${AZURE_LOCATION}; expected centralus for this deployment."
  [[ "$AZURE_ACR_NAME" =~ ^[a-zA-Z0-9]{5,50}$ ]] || fail "AZURE_ACR_NAME must be 5-50 alphanumeric characters."
  [[ "$AZURE_STORAGE_ACCOUNT" =~ ^[a-z0-9]{3,24}$ ]] || fail "AZURE_STORAGE_ACCOUNT must be 3-24 lowercase letters/numbers."
  [[ "$AZURE_JOB_NAME" =~ ^[a-z][a-z0-9-]{0,30}[a-z0-9]$ ]] || fail "AZURE_JOB_NAME must be lowercase, start with a letter, end with alphanumeric, and be <32 chars."
  [[ "$AZURE_CONTAINERAPPS_ENV" =~ ^[a-z][a-z0-9-]*[a-z0-9]$ ]] || fail "AZURE_CONTAINERAPPS_ENV must be lowercase alphanumeric/hyphen."
  [[ "$AZURE_RESOURCE_GROUP" =~ ^[A-Za-z0-9._()/-]+$ ]] || fail "AZURE_RESOURCE_GROUP has invalid characters."
  [[ "$AZURE_ACR_RESOURCE_GROUP" =~ ^[A-Za-z0-9._()/-]+$ ]] || fail "AZURE_ACR_RESOURCE_GROUP has invalid characters."
  [[ "$AZURE_CREATE_ACR" =~ ^(true|false)$ ]] || fail "AZURE_CREATE_ACR must be true or false."
  [[ "$AZURE_JOB_TRIGGER_TYPE" =~ ^(Manual|Schedule)$ ]] || fail "AZURE_JOB_TRIGGER_TYPE must be Manual or Schedule."
  [[ "$AZURE_REPLICA_TIMEOUT" =~ ^[0-9]+$ ]] || fail "AZURE_REPLICA_TIMEOUT must be an integer."
  [[ "$AZURE_REPLICA_RETRY_LIMIT" =~ ^[0-9]+$ ]] || fail "AZURE_REPLICA_RETRY_LIMIT must be an integer."
  [[ "$AZURE_PARALLELISM" =~ ^[0-9]+$ ]] || fail "AZURE_PARALLELISM must be an integer."
  [[ "$AZURE_REPLICA_COMPLETION_COUNT" =~ ^[0-9]+$ ]] || fail "AZURE_REPLICA_COMPLETION_COUNT must be an integer."
  (( AZURE_REPLICA_TIMEOUT >= 1 )) || fail "AZURE_REPLICA_TIMEOUT must be >= 1."
  (( AZURE_PARALLELISM >= 1 )) || fail "AZURE_PARALLELISM must be >= 1."
  (( AZURE_REPLICA_COMPLETION_COUNT >= 1 )) || fail "AZURE_REPLICA_COMPLETION_COUNT must be >= 1."
}

git_short_sha() {
  git -C "$AZURE_REPO_ROOT" rev-parse --short HEAD
}

emailcleaner_image_tag() {
  local tag="${1:-}"
  if [[ -z "$tag" ]]; then
    tag="$(git_short_sha)"
  fi
  printf '%s.azurecr.io/%s:%s\n' "$AZURE_ACR_NAME" "$AZURE_IMAGE_NAME" "$tag"
}

secret_name_for_env_var() {
  printf '%s\n' "$1" | tr '[:upper:]_' '[:lower:]-'
}

load_azure_secret_sources() {
  local env_name

  for env_name in $AZURE_SECRET_ENV_VARS; do
    unset "$env_name"
  done

  if [[ -f "$AZURE_SECRETS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$AZURE_SECRETS_FILE"
  fi

  if [[ -f "$AZURE_ACCOUNTS_SECRET_FILE" ]]; then
    eval "$(python3 - "$AZURE_ACCOUNTS_SECRET_FILE" <<'PY'
import json
import os
import re
import shlex
import sys
from pathlib import Path

accounts_path = Path(sys.argv[1])
data = json.loads(accounts_path.read_text(encoding="utf-8"))
sections = (
    ("gmail_accounts", "EMAIL_CLEANER_GMAIL_EMAIL_", "EMAIL_CLEANER_GMAIL_APP_PASSWORD_"),
    ("yahoo_accounts", "EMAIL_CLEANER_YAHOO_EMAIL_", "EMAIL_CLEANER_YAHOO_APP_PASSWORD_"),
)

for section, email_prefix, password_prefix in sections:
    for key, account in sorted(data.get(section, {}).items()):
        key = str(key).strip()
        if not re.fullmatch(r"[A-Za-z0-9_]+", key):
            continue
        values = (
            (f"{email_prefix}{key}", str(account.get("email", "")).strip()),
            (f"{password_prefix}{key}", str(account.get("app_password", "")).strip()),
        )
        for env_name, value in values:
            if value and not os.environ.get(env_name):
                print(f"export {env_name}={shlex.quote(value)}")
PY
)"
  fi
}

validate_secret_env_values() {
  local missing=()
  local env_name
  local value

  for env_name in $AZURE_SECRET_ENV_VARS; do
    value="${!env_name:-}"
    if [[ -z "$value" ]]; then
      missing+=("$env_name")
      continue
    fi
    if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
      fail "${env_name} must be a single-line secret value."
    fi
  done

  if (( ${#missing[@]} > 0 )); then
    printf 'Error: Missing required secret environment variable(s):\n' >&2
    printf '  - %s\n' "${missing[@]}" >&2
    echo "Set them in ${AZURE_SECRETS_FILE} or ${AZURE_ACCOUNTS_SECRET_FILE} before running deploy.sh." >&2
    exit 1
  fi
}

print_config_summary() {
  cat <<EOF
Azure deployment configuration:
  resource group:        ${AZURE_RESOURCE_GROUP}
  location:              ${AZURE_LOCATION}
  container apps env:    ${AZURE_CONTAINERAPPS_ENV}
  job name:              ${AZURE_JOB_NAME}
  ACR:                   ${AZURE_ACR_NAME}
  ACR resource group:    ${AZURE_ACR_RESOURCE_GROUP}
  create ACR:            ${AZURE_CREATE_ACR}
  storage account:       ${AZURE_STORAGE_ACCOUNT}
  file share:            ${AZURE_FILE_SHARE}
  storage mount name:    ${AZURE_STORAGE_MOUNT_NAME}
  log workspace:         ${AZURE_LOG_WORKSPACE}
  image name:            ${AZURE_IMAGE_NAME}
  trigger type:          ${AZURE_JOB_TRIGGER_TYPE}
  schedule cron:         ${AZURE_SCAN_CRON}
EOF
}

export_azure_render_env() {
  export AZURE_LOCATION
  export AZURE_RESOURCE_GROUP
  export AZURE_CONTAINERAPPS_ENV
  export AZURE_JOB_NAME
  export AZURE_ACR_NAME
  export AZURE_ACR_RESOURCE_GROUP
  export AZURE_STORAGE_MOUNT_NAME
  export AZURE_JOB_TRIGGER_TYPE
  export AZURE_SCAN_CRON
  export AZURE_CPU
  export AZURE_MEMORY
  export AZURE_MAX_RUNTIME_SECONDS
  export AZURE_REPLICA_TIMEOUT
  export AZURE_REPLICA_RETRY_LIMIT
  export AZURE_PARALLELISM
  export AZURE_REPLICA_COMPLETION_COUNT
  export AZURE_SECRET_ENV_VARS
}
