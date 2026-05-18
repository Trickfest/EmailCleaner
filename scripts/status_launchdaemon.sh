#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Show EmailCleaner LaunchDaemon status, installed files, and recent logs.

Usage:
  scripts/status_launchdaemon.sh [--label LAUNCHD_LABEL] [--lines N]

Options:
  --label   LaunchDaemon label to inspect.
            Default: EC_LABEL env var or com.emailcleaner.daemon.
  --lines   Recent log lines to show from stdout and stderr. Default: 80.
  -h, --help
            Show this help text.

Notes:
  - This script does not read account credentials or API keys directly.
  - Recent logs may contain operational message summaries from prior runs.
  - If launchd status requires sudo and sudo is not already authenticated, the
    script prints the command to run instead of prompting for a password.
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

section() {
  echo
  echo "==> $*"
}

show_path_status() {
  local label="$1"
  local path="$2"

  if [[ -e "$path" ]]; then
    stat -f "%N | owner=%Su:%Sg mode=%Lp modified=%Sm" "$path"
  else
    echo "${label}: missing (${path})"
  fi
}

tail_log() {
  local path="$1"
  local lines="$2"

  if [[ -f "$path" ]]; then
    if [[ -s "$path" ]]; then
      tail -n "$lines" "$path" || echo "(could not read log: ${path})"
    else
      echo "(empty log: ${path})"
    fi
  else
    echo "(missing log: ${path})"
  fi
}

print_launchctl_status() {
  local label="$1"
  local status_file

  if [[ "$(id -u)" -eq 0 ]]; then
    launchctl print "system/${label}" || true
    return 0
  fi

  status_file="$(mktemp)"
  if launchctl print "system/${label}" >"$status_file" 2>&1; then
    cat "$status_file"
    rm -f "$status_file"
    return 0
  fi
  rm -f "$status_file"

  if sudo -n true 2>/dev/null; then
    sudo launchctl print "system/${label}" || true
  else
    echo "LaunchDaemon status needs sudo. Run:"
    echo "  sudo launchctl print system/${label}"
  fi
}

LABEL="${EC_LABEL:-com.emailcleaner.daemon}"
LOG_LINES="80"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      [[ $# -ge 2 ]] || fail "--label requires a value."
      LABEL="$2"
      shift 2
      ;;
    --lines)
      [[ $# -ge 2 ]] || fail "--lines requires a value."
      LOG_LINES="$2"
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

[[ "$LOG_LINES" =~ ^[0-9]+$ ]] || fail "--lines must be a positive integer."
(( LOG_LINES >= 1 )) || fail "--lines must be >= 1."

APP_NAME="EmailCleaner"
INSTALL_DIR="/usr/local/libexec/${APP_NAME}"
APP_SUPPORT_DIR="/Library/Application Support/${APP_NAME}"
LOG_OUT_PATH="/Library/Logs/email-cleaner.out.log"
LOG_ERR_PATH="/Library/Logs/email-cleaner.err.log"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
CONFIG_PATH="${APP_SUPPORT_DIR}/config.json"
STATE_PATH="${APP_SUPPORT_DIR}/.email_cleaner_state.json"
OPENAI_ENV_PATH="${APP_SUPPORT_DIR}/openai.env"

echo "EmailCleaner status"
echo "Label: system/${LABEL}"

section "Installed Files"
show_path_status "plist" "$PLIST_PATH"
show_path_status "code" "$INSTALL_DIR/email_cleaner.py"
show_path_status "support dir" "$APP_SUPPORT_DIR"
show_path_status "config" "$CONFIG_PATH"
show_path_status "state" "$STATE_PATH"
show_path_status "stdout log" "$LOG_OUT_PATH"
show_path_status "stderr log" "$LOG_ERR_PATH"
show_path_status "OpenAI env" "$OPENAI_ENV_PATH"

section "Runtime Config Summary"
if [[ -f "$CONFIG_PATH" || -f "$STATE_PATH" ]]; then
  /usr/bin/python3 - "$CONFIG_PATH" "$STATE_PATH" <<'PY'
import json
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
state_path = Path(sys.argv[2])

if config_path.exists():
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        openai = config.get("openai", {})
        daily_summary = config.get("daily_summary", {})
        print(f"openai.enabled={openai.get('enabled', False)}")
        print(f"daily_summary.enabled={daily_summary.get('enabled', False)}")
        print(f"daily_summary.summary_time={daily_summary.get('summary_time', '06:00')}")
        print(
            "daily_summary.summary_interval_minutes="
            f"{daily_summary.get('summary_interval_minutes', 1440)}"
        )
    except (OSError, json.JSONDecodeError) as error:
        print(f"Could not read config summary: {error}")
else:
    print(f"Missing config: {config_path}")

if state_path.exists() and state_path.stat().st_size > 0:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        summary_state = state.get("daily_summary", {})
        run_records = summary_state.get("run_records", [])
        print(f"daily_summary.last_sent_at={summary_state.get('last_sent_at', '')}")
        print(f"daily_summary.run_records={len(run_records) if isinstance(run_records, list) else 0}")
    except (OSError, json.JSONDecodeError) as error:
        print(f"Could not read state summary: {error}")
else:
    print(f"State file missing or empty: {state_path}")
PY
else
  echo "Runtime config/state files are not installed."
fi

section "LaunchDaemon"
print_launchctl_status "$LABEL"

section "Recent stdout (${LOG_LINES} lines)"
tail_log "$LOG_OUT_PATH" "$LOG_LINES"

section "Recent stderr (${LOG_LINES} lines)"
tail_log "$LOG_ERR_PATH" "$LOG_LINES"
