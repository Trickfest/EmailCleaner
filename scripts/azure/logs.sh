#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Show recent EmailCleaner Azure Container Apps job logs.

Usage:
  scripts/azure/logs.sh [--execution NAME] [--replica NAME] [--tail N] [--follow]

Options:
  --execution NAME  Job execution to show. Default: latest execution.
  --replica NAME    Replica to show. Default: first replica for the execution.
  --tail N    Number of recent log lines to show. Default: 300.
  --follow    Stream logs after showing recent lines.
  -h, --help  Show this help text.

Notes:
  - This script is read-only.
  - Historical logs are retained by the Container Apps environment Log Analytics
    workspace according to workspace retention settings.
  - Without --follow, logs are read from Log Analytics so completed executions
    remain visible after Container Apps prunes replica metadata.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

TAIL_LINES="300"
FOLLOW="0"
EXECUTION_NAME=""
REPLICA_NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execution)
      [[ $# -ge 2 ]] || fail "--execution requires a value."
      EXECUTION_NAME="$2"
      shift 2
      ;;
    --replica)
      [[ $# -ge 2 ]] || fail "--replica requires a value."
      REPLICA_NAME="$2"
      shift 2
      ;;
    --tail)
      [[ $# -ge 2 ]] || fail "--tail requires a value."
      TAIL_LINES="$2"
      shift 2
      ;;
    --follow)
      FOLLOW="1"
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

[[ "$TAIL_LINES" =~ ^[0-9]+$ ]] || fail "--tail must be an integer."
(( TAIL_LINES <= 300 )) || fail "--tail must be <= 300."

load_azure_env
require_persistent_resource_names
validate_azure_config
require_command az

container_name="${AZURE_CONTAINER_NAME:-emailcleaner}"

validate_kql_value() {
  local value="$1"
  local label="$2"
  [[ "$value" != *"'"* ]] || fail "${label} must not contain a single quote."
}

validate_kql_value "$AZURE_JOB_NAME" "AZURE_JOB_NAME"
validate_kql_value "$container_name" "container name"

if [[ -z "$EXECUTION_NAME" ]]; then
  EXECUTION_NAME="$(az containerapp job execution list \
    --name "$AZURE_JOB_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --query "reverse(sort_by(@, &properties.startTime))[0].name" \
    --output tsv)"
  [[ -n "$EXECUTION_NAME" && "$EXECUTION_NAME" != "None" ]] || fail "No job executions found."
fi
validate_kql_value "$EXECUTION_NAME" "execution name"

if [[ "$FOLLOW" == "1" && -z "$REPLICA_NAME" ]]; then
  REPLICA_NAME="$(az containerapp job replica list \
    --name "$AZURE_JOB_NAME" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --execution "$EXECUTION_NAME" \
    --query "[0].name" \
    --output tsv)"
  [[ -n "$REPLICA_NAME" && "$REPLICA_NAME" != "None" ]] || fail "No replicas found for execution: ${EXECUTION_NAME}"
fi

if [[ "$FOLLOW" == "1" ]]; then
  log_command=(
    az containerapp job logs show
    --name "$AZURE_JOB_NAME"
    --resource-group "$AZURE_RESOURCE_GROUP"
    --execution "$EXECUTION_NAME"
    --replica "$REPLICA_NAME"
    --container "$container_name"
    --tail "$TAIL_LINES"
    --follow
  )
  "${log_command[@]}"
  exit 0
fi

workspace_id="$(az monitor log-analytics workspace show \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --workspace-name "$AZURE_LOG_WORKSPACE" \
  --query customerId \
  --output tsv)"
[[ -n "$workspace_id" && "$workspace_id" != "None" ]] || fail "Could not resolve Log Analytics workspace id."

if [[ -n "$REPLICA_NAME" ]]; then
  validate_kql_value "$REPLICA_NAME" "replica name"
  replica_filter="ContainerGroupName_s == '${REPLICA_NAME}'"
else
  replica_filter="ContainerGroupName_s startswith '${EXECUTION_NAME}-'"
fi

analytics_query="
ContainerAppConsoleLogs_CL
| where ContainerJobName_s == '${AZURE_JOB_NAME}'
| where ContainerName_s == '${container_name}'
| where ${replica_filter}
| top ${TAIL_LINES} by time_t desc
| order by time_t asc
| project time_t, Log_s
"

az monitor log-analytics query \
  --workspace "$workspace_id" \
  --analytics-query "$analytics_query" \
  --query "[].{time:time_t,log:Log_s}" \
  --output tsv
