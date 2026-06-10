#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build and deploy the EmailCleaner Azure Container Apps job.

Usage:
  scripts/azure/deploy.sh [--env-file PATH] [--trigger manual|schedule] [--no-run]
  scripts/azure/deploy.sh --render-yaml-only [--env-file PATH] [--output PATH] [--image IMAGE]

Options:
  --env-file PATH     Nonsecret Azure settings file. Default: scripts/azure/env.local.
  --trigger VALUE      Job trigger type: manual or schedule. Default: Manual.
  --no-run            Do not start a manual execution after deploy.
  --image IMAGE       Override the image reference used in generated YAML.
  --tag TAG           Image tag to build. Default: current git short SHA.
  --render-yaml-only  Render safe YAML and exit without calling Azure.
  --output PATH       Output path for --render-yaml-only. Default: stdout.
  -h, --help          Show this help text.

Notes:
  - This script mutates Azure unless --render-yaml-only is used.
  - Images are built in Azure with az acr build; local Docker is not required.
  - Secret values are read from scripts/azure/secrets.local and root
    accounts.json, then applied to Container Apps secrets without printing.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

RENDER_YAML_ONLY="0"
OUTPUT_PATH=""
IMAGE_OVERRIDE=""
IMAGE_TAG=""
NO_RUN="0"
CLI_TRIGGER_TYPE=""
CLI_ENV_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-file)
      [[ $# -ge 2 ]] || fail "--env-file requires a value."
      CLI_ENV_FILE="$2"
      shift 2
      ;;
    --trigger)
      [[ $# -ge 2 ]] || fail "--trigger requires a value."
      case "$2" in
        manual|Manual) CLI_TRIGGER_TYPE="Manual" ;;
        schedule|Schedule) CLI_TRIGGER_TYPE="Schedule" ;;
        *) fail "--trigger must be manual or schedule." ;;
      esac
      shift 2
      ;;
    --no-run)
      NO_RUN="1"
      shift
      ;;
    --image)
      [[ $# -ge 2 ]] || fail "--image requires a value."
      IMAGE_OVERRIDE="$2"
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 ]] || fail "--tag requires a value."
      IMAGE_TAG="$2"
      shift 2
      ;;
    --render-yaml-only)
      RENDER_YAML_ONLY="1"
      shift
      ;;
    --output)
      [[ $# -ge 2 ]] || fail "--output requires a value."
      OUTPUT_PATH="$2"
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

load_azure_env "$CLI_ENV_FILE"
if [[ -n "$CLI_TRIGGER_TYPE" ]]; then
  AZURE_JOB_TRIGGER_TYPE="$CLI_TRIGGER_TYPE"
fi
validate_azure_config
export_azure_render_env

if [[ -n "$IMAGE_OVERRIDE" ]]; then
  IMAGE="$IMAGE_OVERRIDE"
else
  IMAGE="$(emailcleaner_image_tag "$IMAGE_TAG")"
fi

render_yaml() {
  python3 "${SCRIPT_DIR}/render-job-yaml.py" --image "$IMAGE" "$@"
}

if [[ "$RENDER_YAML_ONLY" == "1" ]]; then
  export AZURE_SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-00000000-0000-0000-0000-000000000000}"
  if [[ -n "$OUTPUT_PATH" ]]; then
    render_yaml >"$OUTPUT_PATH"
    info "Rendered ${OUTPUT_PATH}."
  else
    render_yaml
  fi
  exit 0
fi

require_persistent_resource_names
require_command az
load_azure_secret_sources
validate_secret_env_values

AZURE_SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-$(az account show --query id --output tsv)}"
export AZURE_SUBSCRIPTION_ID

print_config_summary
info "Building image in Azure Container Registry: ${IMAGE}"
az acr build \
  --registry "$AZURE_ACR_NAME" \
  --image "${AZURE_IMAGE_NAME}:${IMAGE##*:}" \
  --file "${AZURE_REPO_ROOT}/Dockerfile" \
  "$AZURE_REPO_ROOT"

tmp_yaml="$(mktemp)"
chmod 600 "$tmp_yaml"
trap 'rm -f "$tmp_yaml"' EXIT
render_yaml --include-secret-values >"$tmp_yaml"

job_exists="0"
if az containerapp job show \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --output none >/dev/null 2>&1; then
  job_exists="1"
fi

ensure_acr_pull() {
  info "Ensuring job managed identity has AcrPull on ${AZURE_ACR_NAME}."
  local principal_id
  local acr_id
  local assignment_count

  principal_id="$(az containerapp job show \
    --name "$AZURE_JOB_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --query identity.principalId \
    --output tsv)"
  [[ -n "$principal_id" && "$principal_id" != "null" ]] || fail "Container Apps job system-assigned identity is not available yet."
  acr_id="$(az acr show \
    --name "$AZURE_ACR_NAME" \
    --resource-group "$AZURE_ACR_RESOURCE_GROUP" \
    --query id \
    --output tsv)"
  assignment_count="$(az role assignment list \
    --assignee "$principal_id" \
    --scope "$acr_id" \
    --role AcrPull \
    --query 'length(@)' \
    --output tsv)"
  if [[ "$assignment_count" == "0" ]]; then
    az role assignment create \
      --assignee-object-id "$principal_id" \
      --assignee-principal-type ServicePrincipal \
      --role AcrPull \
      --scope "$acr_id" \
      --output table
  else
    info "AcrPull role assignment already exists."
  fi
}

if [[ "$job_exists" == "0" ]]; then
  info "Creating bootstrap Container Apps job to allocate managed identity."
  az containerapp job create \
    --name "$AZURE_JOB_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --environment "$AZURE_CONTAINERAPPS_ENV" \
    --trigger-type Manual \
    --replica-timeout "$AZURE_REPLICA_TIMEOUT" \
    --replica-retry-limit "$AZURE_REPLICA_RETRY_LIMIT" \
    --replica-completion-count "$AZURE_REPLICA_COMPLETION_COUNT" \
    --parallelism "$AZURE_PARALLELISM" \
    --image "$AZURE_BOOTSTRAP_IMAGE" \
    --cpu "$AZURE_CPU" \
    --memory "$AZURE_MEMORY" \
    --mi-system-assigned \
    --output table
fi

ensure_acr_pull

if [[ "$job_exists" == "1" ]]; then
  info "Updating Container Apps job."
else
  info "Applying EmailCleaner Container Apps job definition."
fi
az containerapp job update \
  --name "$AZURE_JOB_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --yaml "$tmp_yaml" \
  --output table

if [[ "$NO_RUN" == "0" ]]; then
  info "Starting one manual execution for validation."
  az containerapp job start \
    --name "$AZURE_JOB_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --output table
else
  info "Skipping manual execution because --no-run was provided."
fi

info "Deploy complete."
