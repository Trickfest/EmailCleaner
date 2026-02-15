# EmailCleaner

Scan email accounts and delete suspected spam and junk email.

## Yahoo Mail proof of concept

This repo now includes a Python proof-of-concept scanner:

- Script: `yahoo_new_mail_poc.py`
- Purpose: log in to Yahoo Mail over IMAP and pull only **new unread** messages
- Folder scope: scans Inbox and other folders, while skipping Spam/Trash
- Safety: uses read-only mailbox access (`SELECT ... READONLY`) so it does not modify or delete messages

### 1. Create a Yahoo app password

Yahoo IMAP login typically requires an app password.

1. Sign in to Yahoo account security settings.
2. Generate an app password for this script.
3. Keep it handy for `YAHOO_APP_PASSWORD_1`.

### 2. Set credentials

```bash
export YAHOO_EMAIL_1="your_address@yahoo.com"
export YAHOO_APP_PASSWORD_1="your_generated_app_password"
```

### 3. Run the scanner

```bash
python3 yahoo_new_mail_poc.py
```

Optional output and state controls:

```bash
python3 yahoo_new_mail_poc.py \
  --state-file .yahoo_mail_state.json \
  --json-output /tmp/new_messages.json
```

### How "new messages" are handled

- The script searches each folder for `UNSEEN` messages.
- It stores processed message UIDs in a local state file.
- On later runs, it only returns unread messages with UIDs it has not already returned.
- If a folder's `UIDVALIDITY` changes, that folder's processed UID history is reset automatically.

### Notes

- Default IMAP host: `imap.mail.yahoo.com`
- Default port: `993`
- Excluded folders are identified by names containing `spam`, `trash`, or `bulk mail` (case-insensitive).
