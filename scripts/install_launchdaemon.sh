#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Install EmailCleaner as a macOS LaunchDaemon.

Usage:
  scripts/install_launchdaemon.sh [--interval 15|30] [--user USERNAME] [--label LAUNCHD_LABEL] [--max-runtime-seconds SECONDS] [--watchdog-grace-seconds SECONDS]

Options:
  --interval  Run interval in minutes. Allowed values: 15 or 30. Default: 15.
  --user      Local macOS account to run EmailCleaner as. Default: current user.
  --label     LaunchDaemon label to install.
              Default: EC_LABEL env var or com.emailcleaner.daemon.
  --max-runtime-seconds
              Graceful wall-clock runtime cap passed to email_cleaner.py.
              Default: 3600.
  --watchdog-grace-seconds
              SIGTERM grace period before watchdog SIGKILL.
              Default: 15.
  -h, --help  Show this help text.

Notes:
  - Run this script as your normal user (not root). It will use sudo as needed.
  - OPENAI_API_KEY must be set in your current shell before running this script.
  - It expects local runtime files in the repo root:
      rules.json, config.json, accounts.json
  - If accounts.json is missing, the script will try to generate it from
    EMAIL_CLEANER_* environment variables.
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

info() {
  echo "==> $*"
}

if [[ "$(id -u)" -eq 0 ]]; then
  fail "Run this script as your normal user, not root."
fi

INTERVAL_MINUTES="15"
RUN_USER="$(id -un)"
LABEL="${EC_LABEL:-com.emailcleaner.daemon}"
MAX_RUNTIME_SECONDS="3600"
WATCHDOG_GRACE_SECONDS="15"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interval)
      [[ $# -ge 2 ]] || fail "--interval requires a value."
      INTERVAL_MINUTES="$2"
      shift 2
      ;;
    --user)
      [[ $# -ge 2 ]] || fail "--user requires a value."
      RUN_USER="$2"
      shift 2
      ;;
    --label)
      [[ $# -ge 2 ]] || fail "--label requires a value."
      LABEL="$2"
      shift 2
      ;;
    --max-runtime-seconds)
      [[ $# -ge 2 ]] || fail "--max-runtime-seconds requires a value."
      MAX_RUNTIME_SECONDS="$2"
      shift 2
      ;;
    --watchdog-grace-seconds)
      [[ $# -ge 2 ]] || fail "--watchdog-grace-seconds requires a value."
      WATCHDOG_GRACE_SECONDS="$2"
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

case "$INTERVAL_MINUTES" in
  15|30) ;;
  *)
    fail "--interval must be 15 or 30."
    ;;
esac

[[ "$MAX_RUNTIME_SECONDS" =~ ^[0-9]+$ ]] || fail "--max-runtime-seconds must be a positive integer."
[[ "$WATCHDOG_GRACE_SECONDS" =~ ^[0-9]+$ ]] || fail "--watchdog-grace-seconds must be a positive integer."
(( MAX_RUNTIME_SECONDS >= 1 )) || fail "--max-runtime-seconds must be >= 1."
(( WATCHDOG_GRACE_SECONDS >= 1 )) || fail "--watchdog-grace-seconds must be >= 1."

OPENAI_API_KEY_VALUE="${OPENAI_API_KEY:-}"
[[ -n "$OPENAI_API_KEY_VALUE" ]] || fail "OPENAI_API_KEY must be set before running this script."
if [[ "$OPENAI_API_KEY_VALUE" == *$'\n'* || "$OPENAI_API_KEY_VALUE" == *$'\r'* ]]; then
  fail "OPENAI_API_KEY must be a single-line value."
fi

id "$RUN_USER" >/dev/null 2>&1 || fail "User does not exist: $RUN_USER"
RUN_GROUP="$(id -gn "$RUN_USER")"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

APP_NAME="EmailCleaner"
INSTALL_DIR="/usr/local/libexec/${APP_NAME}"
APP_SUPPORT_DIR="/Library/Application Support/${APP_NAME}"
LOG_DIR="/Library/Logs/${APP_NAME}"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"
VENV_PYTHON="${INSTALL_DIR}/.venv/bin/python"
WATCHDOG_SCRIPT="${INSTALL_DIR}/email_cleaner_watchdog.py"
LAUNCHER_SCRIPT="${INSTALL_DIR}/run_email_cleaner_daemon.sh"
HARD_TIMEOUT_SECONDS="$((MAX_RUNTIME_SECONDS + WATCHDOG_GRACE_SECONDS))"
OPENAI_ENV_PATH="${APP_SUPPORT_DIR}/openai.env"

RULES_SRC="${REPO_ROOT}/rules.json"
CONFIG_SRC="${REPO_ROOT}/config.json"
ACCOUNTS_SRC="${REPO_ROOT}/accounts.json"

generate_accounts_json_from_env() {
  local target="$1"
  python3 - "$target" <<'PY'
import json
import os
import sys
from pathlib import Path

target = Path(sys.argv[1])

prefixes = {
    ("yahoo", "email"): "EMAIL_CLEANER_YAHOO_EMAIL_",
    ("yahoo", "app_password"): "EMAIL_CLEANER_YAHOO_APP_PASSWORD_",
    ("gmail", "email"): "EMAIL_CLEANER_GMAIL_EMAIL_",
    ("gmail", "app_password"): "EMAIL_CLEANER_GMAIL_APP_PASSWORD_",
}

data = {"yahoo_accounts": {}, "gmail_accounts": {}}

for (provider, field), prefix in prefixes.items():
    section = "yahoo_accounts" if provider == "yahoo" else "gmail_accounts"
    for env_name, env_value in os.environ.items():
        if not env_name.startswith(prefix):
            continue
        key = env_name[len(prefix):].strip()
        value = env_value.strip()
        if not key or not value:
            continue
        data[section].setdefault(key, {})[field] = value

incomplete = []
for section in ("yahoo_accounts", "gmail_accounts"):
    for key, fields in data[section].items():
        missing = [name for name in ("email", "app_password") if name not in fields]
        if missing:
            incomplete.append(f"{section}.{key} missing {', '.join(missing)}")

if incomplete:
    print("Cannot generate accounts.json due to incomplete env credentials:", file=sys.stderr)
    for row in incomplete:
        print(f"  - {row}", file=sys.stderr)
    sys.exit(1)

total_accounts = len(data["yahoo_accounts"]) + len(data["gmail_accounts"])
if total_accounts == 0:
    print("No EMAIL_CLEANER_* account credentials found in environment.", file=sys.stderr)
    sys.exit(2)

for section in ("yahoo_accounts", "gmail_accounts"):
    data[section] = {key: data[section][key] for key in sorted(data[section])}

target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(
    f"Generated {target} with yahoo_accounts={len(data['yahoo_accounts'])}, "
    f"gmail_accounts={len(data['gmail_accounts'])}"
)
PY
}

write_openai_env_file() {
  local target="$1"
  local tmp_env
  tmp_env="$(mktemp)"
  {
    echo "# Managed by install_launchdaemon.sh"
    printf 'export OPENAI_API_KEY=%q\n' "$OPENAI_API_KEY_VALUE"
  } >"$tmp_env"
  sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 "$tmp_env" "$target"
  rm -f "$tmp_env"
}

write_launcher_script() {
  local target="$1"
  local tmp_launcher
  tmp_launcher="$(mktemp)"
  cat >"$tmp_launcher" <<EOF
#!/bin/bash
set -euo pipefail

ENV_FILE="${OPENAI_ENV_PATH}"
if [[ ! -f "\$ENV_FILE" ]]; then
  echo "[launcher] missing env file: \$ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "\$ENV_FILE"
if [[ -z "\${OPENAI_API_KEY:-}" ]]; then
  echo "[launcher] OPENAI_API_KEY is missing in \$ENV_FILE" >&2
  exit 1
fi

exec "${VENV_PYTHON}" "${WATCHDOG_SCRIPT}" \
  --timeout-seconds "${HARD_TIMEOUT_SECONDS}" \
  --term-grace-seconds "${WATCHDOG_GRACE_SECONDS}" \
  -- \
  "${VENV_PYTHON}" "${INSTALL_DIR}/email_cleaner.py" \
  --max-runtime-seconds "${MAX_RUNTIME_SECONDS}" \
  --rules-file "${APP_SUPPORT_DIR}/rules.json" \
  --accounts-file "${APP_SUPPORT_DIR}/accounts.json" \
  --config-file "${APP_SUPPORT_DIR}/config.json" \
  --state-file "${APP_SUPPORT_DIR}/.email_cleaner_state.json"
EOF
  sudo install -o root -g wheel -m 755 "$tmp_launcher" "$target"
  rm -f "$tmp_launcher"
}

[[ -f "$RULES_SRC" ]] || fail "Missing ${RULES_SRC}. Create it from rules.example.json first."
[[ -f "$CONFIG_SRC" ]] || fail "Missing ${CONFIG_SRC}. Create it from config.example.json first."

if [[ ! -f "$ACCOUNTS_SRC" ]]; then
  info "accounts.json not found in repo root. Generating from EMAIL_CLEANER_* env vars."
  generate_accounts_json_from_env "$ACCOUNTS_SRC" || fail "Failed to generate accounts.json."
fi

[[ -f "$ACCOUNTS_SRC" ]] || fail "Missing ${ACCOUNTS_SRC}."

info "Requesting sudo access."
sudo -v

info "Creating install directories."
sudo install -d -o root -g wheel -m 755 "$INSTALL_DIR"
sudo install -d -o "$RUN_USER" -g "$RUN_GROUP" -m 700 "$APP_SUPPORT_DIR"
sudo install -d -o "$RUN_USER" -g "$RUN_GROUP" -m 755 "$LOG_DIR"

info "Deploying code to ${INSTALL_DIR}."
sudo rsync -a --delete \
  --exclude '.git/' \
  --exclude '.venv/' \
  --exclude '__pycache__/' \
  --exclude '.pytest_cache/' \
  --exclude '*.log' \
  --exclude 'rules.json' \
  --exclude 'accounts.json' \
  --exclude 'config.json' \
  --exclude '.email_cleaner_state.json' \
  "${REPO_ROOT}/" "${INSTALL_DIR}/"
sudo chown -R root:wheel "$INSTALL_DIR"
sudo chmod -R a+rX "$INSTALL_DIR"

info "Preparing Python virtual environment."
sudo /usr/bin/python3 -m venv "${INSTALL_DIR}/.venv"
sudo env PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore \
  "${VENV_PYTHON}" -m pip install --upgrade pip >/dev/null 2>&1
if [[ -f "${INSTALL_DIR}/requirements.txt" ]]; then
  info "Installing runtime requirements from requirements.txt."
  sudo env PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore \
    "${VENV_PYTHON}" -m pip install -r "${INSTALL_DIR}/requirements.txt"
fi

info "Copying runtime config files to ${APP_SUPPORT_DIR}."
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 "$RULES_SRC" "${APP_SUPPORT_DIR}/rules.json"
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 "$CONFIG_SRC" "${APP_SUPPORT_DIR}/config.json"
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 "$ACCOUNTS_SRC" "${APP_SUPPORT_DIR}/accounts.json"
if [[ ! -f "${APP_SUPPORT_DIR}/.email_cleaner_state.json" ]]; then
  sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 /dev/null "${APP_SUPPORT_DIR}/.email_cleaner_state.json"
fi

info "Writing OpenAI runtime environment file to ${OPENAI_ENV_PATH}."
write_openai_env_file "$OPENAI_ENV_PATH"

info "Writing daemon launcher script to ${LAUNCHER_SCRIPT}."
write_launcher_script "$LAUNCHER_SCRIPT"

tmp_plist="$(mktemp)"
if [[ "$INTERVAL_MINUTES" == "15" ]]; then
  cat >"$tmp_plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>UserName</key>
  <string>${RUN_USER}</string>
  <key>WorkingDirectory</key>
  <string>${INSTALL_DIR}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${LAUNCHER_SCRIPT}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartCalendarInterval</key>
  <array>
    <dict><key>Minute</key><integer>0</integer></dict>
    <dict><key>Minute</key><integer>15</integer></dict>
    <dict><key>Minute</key><integer>30</integer></dict>
    <dict><key>Minute</key><integer>45</integer></dict>
  </array>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/email-cleaner.out.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/email-cleaner.err.log</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
PLIST
else
  cat >"$tmp_plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>UserName</key>
  <string>${RUN_USER}</string>
  <key>WorkingDirectory</key>
  <string>${INSTALL_DIR}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${LAUNCHER_SCRIPT}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartCalendarInterval</key>
  <array>
    <dict><key>Minute</key><integer>0</integer></dict>
    <dict><key>Minute</key><integer>30</integer></dict>
  </array>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/email-cleaner.out.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/email-cleaner.err.log</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
PLIST
fi

info "Installing LaunchDaemon plist."
sudo install -o root -g wheel -m 644 "$tmp_plist" "$PLIST_PATH"
rm -f "$tmp_plist"

info "Running basic validation checks."
sudo "${VENV_PYTHON}" -m py_compile "${INSTALL_DIR}/email_cleaner.py"
sudo -u "$RUN_USER" "${VENV_PYTHON}" "${INSTALL_DIR}/email_cleaner.py" --help >/dev/null

info "Loading LaunchDaemon."
sudo launchctl enable "system/${LABEL}" >/dev/null 2>&1 || true
sudo launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true
sudo launchctl bootstrap system "$PLIST_PATH"
sudo launchctl kickstart -k "system/${LABEL}"

info "Install complete."
echo "Label: system/${LABEL}"
echo "Interval: every ${INTERVAL_MINUTES} minutes"
echo "Graceful runtime cap: ${MAX_RUNTIME_SECONDS}s"
echo "Watchdog hard timeout: ${HARD_TIMEOUT_SECONDS}s (grace ${WATCHDOG_GRACE_SECONDS}s)"
echo "Code: ${INSTALL_DIR}"
echo "Config: ${APP_SUPPORT_DIR}"
echo "OpenAI env file: ${OPENAI_ENV_PATH}"
echo "Launcher: ${LAUNCHER_SCRIPT}"
echo "Logs: ${LOG_DIR}/email-cleaner.out.log and ${LOG_DIR}/email-cleaner.err.log"
echo "Status check: sudo launchctl print system/${LABEL}"
echo
echo "Smoke test commands:"
echo "  1) Verify launchd job state:"
echo "     sudo launchctl print system/${LABEL}"
echo "  2) Check stdout log:"
echo "     tail -n 100 \"${LOG_DIR}/email-cleaner.out.log\""
echo "  3) Check stderr log:"
echo "     tail -n 100 \"${LOG_DIR}/email-cleaner.err.log\""
echo "  4) Trigger an immediate run:"
echo "     sudo launchctl kickstart -k system/${LABEL}"
echo "  5) Confirm OpenAI env file exists:"
echo "     sudo test -s \"${OPENAI_ENV_PATH}\" && echo \"openai env file present\""
