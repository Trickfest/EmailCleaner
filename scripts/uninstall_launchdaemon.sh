#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Uninstall EmailCleaner LaunchDaemon and remove installed runtime files.

Usage:
  scripts/uninstall_launchdaemon.sh [--label LAUNCHD_LABEL]

Options:
  --label    LaunchDaemon label to remove.
             Default: EC_LABEL env var or com.emailcleaner.daemon.
  -h, --help Show this help text.

What this removes:
  - /Library/LaunchDaemons/<label>.plist
  - /usr/local/libexec/EmailCleaner
  - /Library/Application Support/EmailCleaner (includes openai.env, rules/config/accounts, state)
  - /Library/Logs/email-cleaner.out.log and /Library/Logs/email-cleaner.err.log
  - optional rotated archives for those log files

Notes:
  - Run this script as your normal user (not root). It will use sudo as needed.
  - If you installed with a custom label, pass the same label here.
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      [[ $# -ge 2 ]] || fail "--label requires a value."
      LABEL="$2"
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

APP_NAME="EmailCleaner"
INSTALL_DIR="/usr/local/libexec/${APP_NAME}"
APP_SUPPORT_DIR="/Library/Application Support/${APP_NAME}"
LOG_OUT_PATH="/Library/Logs/email-cleaner.out.log"
LOG_ERR_PATH="/Library/Logs/email-cleaner.err.log"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"

info "Requesting sudo access."
sudo -v

info "Stopping and disabling LaunchDaemon if present."
sudo launchctl disable "system/${LABEL}" >/dev/null 2>&1 || true
sudo launchctl bootout system "$PLIST_PATH" >/dev/null 2>&1 || true

info "Removing LaunchDaemon plist and runtime directories."
sudo rm -f "$PLIST_PATH"
sudo rm -rf "$INSTALL_DIR"
sudo rm -rf "$APP_SUPPORT_DIR"
sudo rm -f "$LOG_OUT_PATH" "$LOG_ERR_PATH" "$LOG_OUT_PATH".[0-9]* "$LOG_ERR_PATH".[0-9]*

info "Uninstall complete."
echo "Removed label: ${LABEL}"
echo "Removed: ${PLIST_PATH}"
echo "Removed: ${INSTALL_DIR}"
echo "Removed: ${APP_SUPPORT_DIR}"
echo "Removed logs: ${LOG_OUT_PATH} and ${LOG_ERR_PATH}"
echo
echo "Post-uninstall checks:"
echo "  1) Confirm launchd no longer has the job:"
echo "     sudo launchctl print system/${LABEL}"
echo "     # Expected: not found / no such process"
echo "  2) Confirm plist is removed:"
echo "     test ! -e \"${PLIST_PATH}\" && echo \"plist removed\""
echo "  3) Confirm installed code is removed:"
echo "     test ! -e \"${INSTALL_DIR}\" && echo \"code removed\""
echo "  4) Confirm runtime config/state is removed:"
echo "     test ! -e \"${APP_SUPPORT_DIR}\" && echo \"config/state removed\""
echo "  5) Confirm log files are removed:"
echo "     test ! -e \"${LOG_OUT_PATH}\" && test ! -e \"${LOG_ERR_PATH}\" && echo \"logs removed\""
