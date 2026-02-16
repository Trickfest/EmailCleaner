# EmailCleaner

Scan email accounts and delete suspected spam and junk email.

## Yahoo Mail proof of concept

This repo now includes a Python proof-of-concept scanner:

- Script: `yahoo_new_mail_poc.py`
- Purpose: log in to Yahoo Mail over IMAP and pull only **new unread** messages
- Folder scope: scans Inbox and other folders, while skipping Spam/Trash
- Rules: loads filtering config from `rules.json` (default)
- Delete candidates are moved to `Quarantine` by default (folder is auto-created if needed)
- `--hard-delete` is available as a future switch, but is currently a no-op placeholder
- `--dry-run` simulates actions without moving/deleting messages or updating state

### 1. Create a Yahoo app password

Yahoo IMAP login typically requires an app password.

1. Sign in to Yahoo account security settings.
2. Generate an app password for this script.
3. Keep it handy for account configuration.

### 2. Configure Yahoo accounts

You can configure credentials using environment variables, `accounts.json`, or both.
The scanner merges by account key suffix and requires a complete pair (`email` + `app_password`)
for every discovered key.

Environment variable format:

- `EMAIL_CLEANER_YAHOO_EMAIL_<KEY>`
- `EMAIL_CLEANER_YAHOO_APP_PASSWORD_<KEY>`

Example (multiple accounts):

```bash
export EMAIL_CLEANER_YAHOO_EMAIL_JOHN="john@yahoo.com"
export EMAIL_CLEANER_YAHOO_APP_PASSWORD_JOHN="john_app_password"
export EMAIL_CLEANER_YAHOO_EMAIL_SALLY="sally@yahoo.com"
export EMAIL_CLEANER_YAHOO_APP_PASSWORD_SALLY="sally_app_password"
```

Optional `accounts.json` format (see also `/Users/markharris/src/EmailCleaner/accounts.example.json`):

```json
{
  "yahoo_accounts": {
    "JOHN": {
      "email": "john@yahoo.com",
      "app_password": "john_app_password"
    },
    "SALLY": {
      "email": "sally@yahoo.com",
      "app_password": "sally_app_password"
    }
  }
}
```

`accounts.json` is gitignored so local credentials stay out of source control.

You can split credentials across env vars and `accounts.json` by account key.
For example, `EMAIL_CLEANER_YAHOO_EMAIL_JOHN` in env and
`yahoo_accounts.JOHN.app_password` in `accounts.json` is valid.

Configuration errors are fatal when:

- A key has only email or only app password after merging all sources
- The same key/field is defined more than once (for example env + `accounts.json` both define email for `JOHN`)

### 3. Run the scanner

```bash
python3 yahoo_new_mail_poc.py
```

The same `rules.json` is applied to all configured Yahoo accounts.

Optional output and state controls:

```bash
python3 yahoo_new_mail_poc.py \
  --rules-file rules.json \
  --accounts-file accounts.json \
  --state-file .yahoo_mail_state.json \
  --json-output /tmp/new_messages.json
```

Reset local app state (delete state file and exit):

```bash
python3 yahoo_new_mail_poc.py --reset-app
```

`--reset-app` is standalone mode: use only `--reset-app` and optional `--state-file`.

Hard-delete placeholder mode (currently no-op for delete candidates):

```bash
python3 yahoo_new_mail_poc.py --hard-delete
```

Dry-run mode (show what would happen, but make no mailbox/state changes):

```bash
python3 yahoo_new_mail_poc.py --dry-run
```

### Rules file (`rules.json`)

Use `/Users/markharris/src/EmailCleaner/rules.example.json` as a template and copy it to a local `rules.json`.
`rules.json` is gitignored so personal addresses/domains stay local.

Current rules support:

- `never_filter`: specific sender addresses or sender domains that should never be filtered/deleted
- `always_delete`: sender addresses or sender domains that should always be marked as delete candidates
- `delete_patterns.auth_triple_fail`: marks as delete candidate only when `Authentication-Results` reports `spf=fail`, `dkim=fail`, and `dmarc=fail` with no conflicting status values
- `delete_patterns.malformed_from`: marks as delete candidate when the `From` header is missing, malformed, or cannot be parsed to a sender email address
- `delete_patterns`: regex rules for sender (`From`), subject, and message body that mark messages as delete candidates

Example:

```json
{
  "never_filter": {
    "senders": [
      "johnsmith.1@gmail.com",
      "johnhsmith@yahoo.com"
    ],
    "domains": [
      "bestbank.com",
      "acmebrokerage.com",
      "letsgoshopping.com"
    ]
  },
  "always_delete": {
    "senders": [
      "promotions@deals-now.example",
      "noreply@marketblast.example"
    ],
    "domains": [
      "coupons.example",
      "promo-outlet.example"
    ]
  },
  "delete_patterns": {
    "auth_triple_fail": true,
    "malformed_from": false,
    "from_regex": [
      "(?i)promo\\s+alerts",
      "(?i)noreply@deals-now\\.example"
    ],
    "subject_regex": [
      "(?i)limited\\s+time\\s+offer",
      "(?i)act\\s+now\\s+and\\s+save"
    ],
    "body_regex": [
      "(?i)click\\s+here\\s+to\\s+claim\\s+your\\s+gift\\s+card",
      "(?i)final\\s+notice:\\s+your\\s+account\\s+will\\s+be\\s+suspended"
    ]
  }
}
```

Regex notes:

- Uses Python regex syntax
- Matching uses `re.search` (pattern can match anywhere in the field)
- You can embed flags inline (for example `(?i)` for case-insensitive)
- `delete_patterns.from_regex` checks both sender display name and sender email address
- `delete_patterns.auth_triple_fail` only matches when all of SPF, DKIM, and DMARC are explicitly `fail`
- `delete_patterns.auth_triple_fail` is conservative: if any mechanism has no value or mixed values (for example both `fail` and `pass` in different headers), it does not match
- `delete_patterns.malformed_from` matches missing/defective `From` headers and cases where no sender email can be parsed

Rule precedence:

1. `never_filter` (highest priority)
2. `always_delete`
3. `delete_patterns.auth_triple_fail`
4. `delete_patterns.malformed_from`
5. `delete_patterns.from_regex`
6. `delete_patterns.subject_regex`
7. `delete_patterns.body_regex`

When new unread messages are pulled, each message is labeled as one of:

- `NEVER_FILTER` (matches a protected sender/domain)
- `DELETE_CANDIDATE` (matches always-delete, auth-triple-fail, or regex delete rule)
- `FILTER_ELIGIBLE` (no rule match)

Delete-candidate actions:

- Default: message is moved to `Quarantine`
- `--hard-delete`: no-op placeholder (message is not deleted in this POC)
- `--dry-run`: no message move/delete; output shows what would happen in normal mode

### How "new messages" are handled

- The script searches each folder for `UNSEEN` messages.
- It stores processed message UIDs in a local state file, namespaced by account key and folder.
- In `--dry-run` mode, it does not update the local state file.
- On later runs, it only returns unread messages with UIDs it has not already returned.
- If a folder's `UIDVALIDITY` changes, that folder's processed UID history is reset automatically.

### Notes

- Default IMAP host: `imap.mail.yahoo.com`
- Default port: `993`
- Excluded folders include `Quarantine`, Yahoo `Bulk`, and folders identified as spam/trash/junk by IMAP flags or folder names containing `spam`, `trash`, `bulk`, or `junk` (case-insensitive).
