# EmailCleaner macOS LaunchDaemon Setup

This guide explains two installation paths and two uninstall paths:

1. One-shot install with `scripts/install_launchdaemon.sh`
2. Full manual install (every step by hand)
3. One-shot uninstall with `scripts/uninstall_launchdaemon.sh`
4. Full manual uninstall (every step by hand)

Use this if you want EmailCleaner to run automatically as a system background task on macOS.

## What You Get

- Code installed to `/usr/local/libexec/EmailCleaner`
- Runtime config and state in `/Library/Application Support/EmailCleaner`
- OpenAI env file in `/Library/Application Support/EmailCleaner/openai.env` (mode `600`)
- Logs in `/Library/Logs/EmailCleaner`
- LaunchDaemon plist in `/Library/LaunchDaemons/com.emailcleaner.daemon.plist`

## How LaunchDaemon Behaves

- Runs as a system job (not tied to a desktop login session)
- Can run at the login window
- Continues across user logout
- Uses a fixed schedule (15 or 30 minutes in this guide)

## Prerequisites

1. macOS machine with admin access (`sudo`).
2. Repo cloned locally.
3. Python 3 available at `/usr/bin/python3`.
4. `OPENAI_API_KEY` is exported in your current shell before you run install commands.
5. You have runtime files in repo root:
- `rules.json`
- `config.json`
- `accounts.json` (or env vars to generate it)

Supported env var format for account generation:

- `EMAIL_CLEANER_YAHOO_EMAIL_<KEY>`
- `EMAIL_CLEANER_YAHOO_APP_PASSWORD_<KEY>`
- `EMAIL_CLEANER_GMAIL_EMAIL_<KEY>`
- `EMAIL_CLEANER_GMAIL_APP_PASSWORD_<KEY>`

## Option A: One-Shot Installer Script

From repo root (installer fails fast if `OPENAI_API_KEY` is missing):

```bash
cd /path/to/repo
export OPENAI_API_KEY="your_openai_api_key_here"
./scripts/install_launchdaemon.sh --interval 15
```

For 30-minute interval:

```bash
cd /path/to/repo
export OPENAI_API_KEY="your_openai_api_key_here"
./scripts/install_launchdaemon.sh --interval 30
```

Default runtime guardrails:

- Graceful wall-clock cap: 3600 seconds (1 hour) via `--max-runtime-seconds`.
- Hard watchdog timeout: cap + grace period.

Optional custom daemon label:

```bash
cd /path/to/repo
# Default label if omitted: com.emailcleaner.daemon
export OPENAI_API_KEY="your_openai_api_key_here"
EC_LABEL="com.example.emailcleaner" ./scripts/install_launchdaemon.sh --interval 15
```

Equivalent explicit flag form:

```bash
cd /path/to/repo
export OPENAI_API_KEY="your_openai_api_key_here"
./scripts/install_launchdaemon.sh --interval 15 --label com.example.emailcleaner
```

Override graceful and hard-timeout behavior:

```bash
cd /path/to/repo
export OPENAI_API_KEY="your_openai_api_key_here"
./scripts/install_launchdaemon.sh \
  --interval 15 \
  --max-runtime-seconds 3600 \
  --watchdog-grace-seconds 15
```

## Option B: Full Manual Install (No Script)

This section mirrors what the script does.

### 0) Open terminal in repo

```bash
cd /path/to/repo
```

### 1) Set install variables

Pick your schedule and label once. Keep these values consistent for install, updates, and operations.

```bash
export REPO_ROOT="$(pwd)"
export EC_APP_NAME="EmailCleaner"
export EC_LABEL="com.emailcleaner.daemon"  # use your custom label if desired
export EC_INTERVAL_MINUTES="15"   # allowed: 15 or 30
export EC_MAX_RUNTIME_SECONDS="3600"  # graceful wall-clock cap in seconds
export EC_WATCHDOG_GRACE_SECONDS="15" # SIGTERM grace before SIGKILL
export EC_WATCHDOG_TIMEOUT_SECONDS="$((EC_MAX_RUNTIME_SECONDS + EC_WATCHDOG_GRACE_SECONDS))"
export OPENAI_API_KEY="your_openai_api_key_here"
export RUN_USER="$(id -un)"
export RUN_GROUP="$(id -gn "$RUN_USER")"

export EC_INSTALL_DIR="/usr/local/libexec/${EC_APP_NAME}"
export EC_SUPPORT_DIR="/Library/Application Support/${EC_APP_NAME}"
export EC_LOG_DIR="/Library/Logs/${EC_APP_NAME}"
export EC_PLIST_PATH="/Library/LaunchDaemons/${EC_LABEL}.plist"
export EC_VENV_PYTHON="${EC_INSTALL_DIR}/.venv/bin/python"
export EC_WATCHDOG_SCRIPT="${EC_INSTALL_DIR}/email_cleaner_watchdog.py"
export EC_OPENAI_ENV_FILE="${EC_SUPPORT_DIR}/openai.env"
export EC_LAUNCHER_SCRIPT="${EC_INSTALL_DIR}/run_email_cleaner_daemon.sh"
```

### 2) Create or verify local runtime files

If needed, seed from examples:

```bash
[ -f "$REPO_ROOT/rules.json" ] || cp "$REPO_ROOT/rules.example.json" "$REPO_ROOT/rules.json"
[ -f "$REPO_ROOT/config.json" ] || cp "$REPO_ROOT/config.example.json" "$REPO_ROOT/config.json"
[ -f "$REPO_ROOT/accounts.json" ] || cp "$REPO_ROOT/accounts.example.json" "$REPO_ROOT/accounts.json"
```

If you prefer generating `accounts.json` from env vars instead of copying from example, use:

```bash
python3 - <<'PY'
import json
import os
from pathlib import Path

target = Path("accounts.json")
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
        if env_name.startswith(prefix):
            key = env_name[len(prefix):].strip()
            val = env_value.strip()
            if key and val:
                data[section].setdefault(key, {})[field] = val
for section in ("yahoo_accounts", "gmail_accounts"):
    data[section] = {k: data[section][k] for k in sorted(data[section])}
target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"Wrote {target}")
PY
```

Validate required files exist:

```bash
test -f "$REPO_ROOT/rules.json"
test -f "$REPO_ROOT/config.json"
test -f "$REPO_ROOT/accounts.json"
```

### 3) Preflight validation in repo

```bash
python3 -m py_compile "$REPO_ROOT/email_cleaner.py"
python3 "$REPO_ROOT/email_cleaner.py" --help >/dev/null
```

### 4) Authenticate for admin commands

```bash
sudo -v
```

### 5) Create install directories

```bash
sudo install -d -o root -g wheel -m 755 "$EC_INSTALL_DIR"
sudo install -d -o "$RUN_USER" -g "$RUN_GROUP" -m 700 "$EC_SUPPORT_DIR"
sudo install -d -o "$RUN_USER" -g "$RUN_GROUP" -m 755 "$EC_LOG_DIR"
```

### 6) Copy code to `/usr/local/libexec/EmailCleaner`

This copies the repo into the install directory, excluding local secrets/state.

```bash
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
  "${REPO_ROOT}/" "${EC_INSTALL_DIR}/"

sudo chown -R root:wheel "$EC_INSTALL_DIR"
sudo chmod -R a+rX "$EC_INSTALL_DIR"
```

### 7) Create Python virtual environment

```bash
sudo /usr/bin/python3 -m venv "${EC_INSTALL_DIR}/.venv"
sudo "${EC_VENV_PYTHON}" -m pip install --upgrade pip
```

If your deployment copy has a runtime `requirements.txt`, install it:

```bash
if [ -f "${EC_INSTALL_DIR}/requirements.txt" ]; then
  sudo "${EC_VENV_PYTHON}" -m pip install -r "${EC_INSTALL_DIR}/requirements.txt"
fi
```

### 8) Copy runtime files into `/Library/Application Support/EmailCleaner`

```bash
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 "$REPO_ROOT/rules.json" "${EC_SUPPORT_DIR}/rules.json"
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 "$REPO_ROOT/config.json" "${EC_SUPPORT_DIR}/config.json"
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 "$REPO_ROOT/accounts.json" "${EC_SUPPORT_DIR}/accounts.json"
```

Create state file if it does not exist yet:

```bash
if [ ! -f "${EC_SUPPORT_DIR}/.email_cleaner_state.json" ]; then
  sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 /dev/null "${EC_SUPPORT_DIR}/.email_cleaner_state.json"
fi
```

Create OpenAI env file (required by launcher wrapper):

```bash
[ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY is not set"; exit 1; }
TMP_OPENAI_ENV="$(mktemp)"
{
  echo "# Managed for EmailCleaner LaunchDaemon runtime"
  printf 'export OPENAI_API_KEY=%q\n' "$OPENAI_API_KEY"
} > "$TMP_OPENAI_ENV"
sudo install -o "$RUN_USER" -g "$RUN_GROUP" -m 600 "$TMP_OPENAI_ENV" "$EC_OPENAI_ENV_FILE"
rm -f "$TMP_OPENAI_ENV"
```

### 9) Create launcher script and LaunchDaemon plist

Write launcher wrapper to a temp file first:

```bash
TMP_LAUNCHER="$(mktemp)"
cat >"$TMP_LAUNCHER" <<LAUNCHER
#!/bin/bash
set -euo pipefail

ENV_FILE="${EC_OPENAI_ENV_FILE}"
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

exec "${EC_VENV_PYTHON}" "${EC_WATCHDOG_SCRIPT}" \
  --timeout-seconds "${EC_WATCHDOG_TIMEOUT_SECONDS}" \
  --term-grace-seconds "${EC_WATCHDOG_GRACE_SECONDS}" \
  -- \
  "${EC_VENV_PYTHON}" "${EC_INSTALL_DIR}/email_cleaner.py" \
  --max-runtime-seconds "${EC_MAX_RUNTIME_SECONDS}" \
  --rules-file "${EC_SUPPORT_DIR}/rules.json" \
  --accounts-file "${EC_SUPPORT_DIR}/accounts.json" \
  --config-file "${EC_SUPPORT_DIR}/config.json" \
  --state-file "${EC_SUPPORT_DIR}/.email_cleaner_state.json"
LAUNCHER
sudo install -o root -g wheel -m 755 "$TMP_LAUNCHER" "$EC_LAUNCHER_SCRIPT"
rm -f "$TMP_LAUNCHER"
```

Write plist to a temp file:

```bash
TMP_PLIST="$(mktemp)"
```

For 15-minute schedule:

```bash
cat >"$TMP_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${EC_LABEL}</string>
  <key>UserName</key>
  <string>${RUN_USER}</string>
  <key>WorkingDirectory</key>
  <string>${EC_INSTALL_DIR}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${EC_LAUNCHER_SCRIPT}</string>
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
  <string>${EC_LOG_DIR}/email-cleaner.out.log</string>
  <key>StandardErrorPath</key>
  <string>${EC_LOG_DIR}/email-cleaner.err.log</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
PLIST
```

For 30-minute schedule, replace the `StartCalendarInterval` block with:

```xml
  <key>StartCalendarInterval</key>
  <array>
    <dict><key>Minute</key><integer>0</integer></dict>
    <dict><key>Minute</key><integer>30</integer></dict>
  </array>
```

Install plist:

```bash
sudo install -o root -g wheel -m 644 "$TMP_PLIST" "$EC_PLIST_PATH"
rm -f "$TMP_PLIST"
```

Optional plist syntax check:

```bash
plutil -lint "$EC_PLIST_PATH"
```

### 10) Validate deployed runtime

```bash
sudo "${EC_VENV_PYTHON}" -m py_compile "${EC_INSTALL_DIR}/email_cleaner.py"
sudo -u "$RUN_USER" "${EC_VENV_PYTHON}" "${EC_INSTALL_DIR}/email_cleaner.py" --help >/dev/null
```

### 11) Load and start daemon

These commands are safe to run repeatedly during updates.

```bash
sudo launchctl enable "system/${EC_LABEL}" >/dev/null 2>&1 || true
sudo launchctl bootout system "$EC_PLIST_PATH" >/dev/null 2>&1 || true
sudo launchctl bootstrap system "$EC_PLIST_PATH"
sudo launchctl kickstart -k "system/${EC_LABEL}"
```

### 12) Verify daemon state and logs

```bash
sudo launchctl print "system/${EC_LABEL}"
tail -n 100 "${EC_LOG_DIR}/email-cleaner.out.log"
tail -n 100 "${EC_LOG_DIR}/email-cleaner.err.log"
sudo test -s "${EC_OPENAI_ENV_FILE}" && echo "openai env file present"
```

## Daily Operations

If you are opening a new terminal, set these first:

```bash
export EC_LABEL="com.emailcleaner.daemon"  # use your custom label if you installed with one
export EC_PLIST_PATH="/Library/LaunchDaemons/${EC_LABEL}.plist"
```

Stop now:

```bash
sudo launchctl bootout system "$EC_PLIST_PATH"
```

Start again:

```bash
sudo launchctl bootstrap system "$EC_PLIST_PATH"
sudo launchctl kickstart -k "system/${EC_LABEL}"
```

Disable across reboots:

```bash
sudo launchctl disable "system/${EC_LABEL}"
sudo launchctl bootout system "$EC_PLIST_PATH"
```

Re-enable later:

```bash
sudo launchctl enable "system/${EC_LABEL}"
sudo launchctl bootstrap system "$EC_PLIST_PATH"
sudo launchctl kickstart -k "system/${EC_LABEL}"
```

## Updating After Repo Changes

Simplest path:

```bash
cd /path/to/repo
./scripts/install_launchdaemon.sh --interval 15
```

If you installed manually, re-run manual steps:

1. Step 6 (sync code)
2. Step 7 (venv/pip if needed)
3. Step 8 (copy runtime files)
4. Step 9 (launcher/plist if schedule/label/runtime settings changed)
5. Step 11 (reload daemon)

## Uninstall EmailCleaner

### Option A: One-Shot Uninstall Script

From repo root:

```bash
cd /path/to/repo
./scripts/uninstall_launchdaemon.sh
```

Optional custom daemon label:

```bash
cd /path/to/repo
# Default label if omitted: com.emailcleaner.daemon
EC_LABEL="com.example.emailcleaner" ./scripts/uninstall_launchdaemon.sh
```

Equivalent explicit flag form:

```bash
cd /path/to/repo
./scripts/uninstall_launchdaemon.sh --label com.example.emailcleaner
```

What the script removes:

1. `/Library/LaunchDaemons/<label>.plist`
2. `/usr/local/libexec/EmailCleaner`
3. `/Library/Application Support/EmailCleaner` (includes `openai.env`, config files, and state)
4. `/Library/Logs/EmailCleaner`

### Option B: Full Manual Uninstall (No Script)

Set variables first:

```bash
export EC_LABEL="com.emailcleaner.daemon"  # use your custom label if you installed with one
export EC_PLIST_PATH="/Library/LaunchDaemons/${EC_LABEL}.plist"
export EC_INSTALL_DIR="/usr/local/libexec/EmailCleaner"
export EC_SUPPORT_DIR="/Library/Application Support/EmailCleaner"
export EC_LOG_DIR="/Library/Logs/EmailCleaner"
```

Stop/disable daemon (if present):

```bash
sudo launchctl disable "system/${EC_LABEL}" >/dev/null 2>&1 || true
sudo launchctl bootout system "$EC_PLIST_PATH" >/dev/null 2>&1 || true
```

Remove daemon plist and installed runtime directories:

```bash
sudo rm -f "$EC_PLIST_PATH"
sudo rm -rf "$EC_INSTALL_DIR"
sudo rm -rf "$EC_SUPPORT_DIR"
sudo rm -rf "$EC_LOG_DIR"
```

Optional post-checks:

```bash
test ! -e "$EC_PLIST_PATH" && echo "plist removed"
test ! -e "$EC_INSTALL_DIR" && echo "code removed"
test ! -e "$EC_SUPPORT_DIR" && echo "config/state removed"
test ! -e "$EC_LOG_DIR" && echo "logs removed"
```

## Security Notes

1. `accounts.json` contains app passwords; keep permissions restrictive.
2. `openai.env` contains `OPENAI_API_KEY`; keep it mode `600` and owned by the run user.
3. Runtime files in `/Library/Application Support/EmailCleaner` should stay mode `600` and owned by the run user.
4. Keep FileVault enabled for at-rest encryption.
5. Keep your daemon label consistent across install, operations, and uninstall.

## Reboot Note

- LaunchDaemon runs at login window and after logout.
- If FileVault is locked after certain reboot paths, one unlock may still be required before jobs resume.
