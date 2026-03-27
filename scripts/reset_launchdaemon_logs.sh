#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Reset EmailCleaner LaunchDaemon log files and restart the daemon.

Usage:
  scripts/reset_launchdaemon_logs.sh [--label LAUNCHD_LABEL] [--user USERNAME] [--no-restart]

Options:
  --label       LaunchDaemon label to target.
                Default: EC_LABEL env var or com.emailcleaner.daemon.
  --user        Local macOS account that should own the recreated log files.
                Default: infer from installed plist UserName, else current user.
  --no-restart  Recreate/truncate the log files without restarting the daemon.
  -h, --help    Show this help text.

Notes:
  - Run this script as your normal user (not root). It will use sudo as needed.
  - This recreates /Library/Logs/email-cleaner.out.log and
    /Library/Logs/email-cleaner.err.log with mode 644.
  - By default, if the LaunchDaemon plist exists, the script will bootstrap
    it if needed and then kickstart the job after resetting the logs.
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

LABEL="${EC_LABEL:-com.emailcleaner.daemon}"
RUN_USER=""
RESTART_DAEMON="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      [[ $# -ge 2 ]] || fail "--label requires a value."
      LABEL="$2"
      shift 2
      ;;
    --user)
      [[ $# -ge 2 ]] || fail "--user requires a value."
      RUN_USER="$2"
      shift 2
      ;;
    --no-restart)
      RESTART_DAEMON="0"
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

LOG_OUT_PATH="/Library/Logs/email-cleaner.out.log"
LOG_ERR_PATH="/Library/Logs/email-cleaner.err.log"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"

if [[ -z "$RUN_USER" && -f "$PLIST_PATH" ]]; then
  RUN_USER="$(plutil -extract UserName raw -o - "$PLIST_PATH" 2>/dev/null || true)"
fi
if [[ -z "$RUN_USER" ]]; then
  RUN_USER="$(id -un)"
fi

id "$RUN_USER" >/dev/null 2>&1 || fail "User does not exist: $RUN_USER"
RUN_GROUP="$(id -gn "$RUN_USER")"

info "Requesting sudo access."
sudo -v

info "Resetting log files."
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 644 /dev/null "$LOG_OUT_PATH"
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 644 /dev/null "$LOG_ERR_PATH"

if [[ "$RESTART_DAEMON" == "1" ]]; then
  if [[ -f "$PLIST_PATH" ]]; then
    info "Restarting LaunchDaemon."
    sudo launchctl enable "system/${LABEL}" >/dev/null 2>&1 || true
    sudo launchctl bootstrap system "$PLIST_PATH" >/dev/null 2>&1 || true
    sudo launchctl kickstart -k "system/${LABEL}"
  else
    info "LaunchDaemon plist not found at ${PLIST_PATH}; skipped restart."
  fi
fi

info "Reset complete."
echo "Label: ${LABEL}"
echo "Run user: ${RUN_USER}"
echo "Logs reset: ${LOG_OUT_PATH} and ${LOG_ERR_PATH}"
if [[ "$RESTART_DAEMON" == "1" ]]; then
  echo "Daemon restart attempted: system/${LABEL}"
fi
echo
echo "Verification:"
echo "  ls -l \"${LOG_OUT_PATH}\" \"${LOG_ERR_PATH}\""
echo "  tail -n 50 \"${LOG_ERR_PATH}\""
if [[ "$RESTART_DAEMON" == "1" && -f "$PLIST_PATH" ]]; then
  echo "  sudo launchctl print system/${LABEL}"
fi
