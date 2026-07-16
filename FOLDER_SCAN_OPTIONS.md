# Folder Scan Options

## Purpose

EmailCleaner scans all discovered folders except excluded folders such as
`Quarantine`, Spam, Trash, Junk, and Bulk by default.

It also supports per-account folder selection so each configured account can
either:

- scan all allowed folders, or
- scan only an explicit list of folders.

The primary motivation is Gmail. Gmail exposes one underlying message through
multiple IMAP mailboxes such as `INBOX`, `[Gmail]/All Mail`, and
`[Gmail]/Important`. Scanning every allowed mailbox can therefore make one
visible Inbox message appear as multiple newly processed messages. Configuring a
Gmail account to scan only `INBOX` avoids that duplicate folder exposure.

## Configuration

Put folder scan settings in `config.json`, not `accounts.json`. Folder selection
is non-secret runtime behavior, and Azure supplies account credentials through
secrets/env vars rather than uploading `accounts.json`.

For standalone/macOS use, that file is repo-root `config.json`. For Azure, edit
`instances/NAME.local/config.json`, then upload it with
`scripts/azure/sync-runtime-files.sh --profile NAME`.

Example:

```json
{
  "account_scans": {
    "gmail:MAIN": {
      "folders": ["INBOX"]
    },
    "yahoo:MAIN": {
      "folders": "all"
    }
  }
}
```

Rules:

- `account_scans` is optional.
- Account keys use the same `provider:ACCOUNT_KEY` form used by daily
  summaries, for example `gmail:MAIN` or `yahoo:MAIN`.
- If an account has no `account_scans` entry, it scans all allowed folders.
- `folders` may be the string `"all"` or a non-empty array of folder names.
- `"all"` means current behavior: scan every discovered folder except excluded
  folders.
- An array means scan only the listed folders, after validating that each listed
  folder exists and is not excluded.

## Folder Name Matching

IMAP has awkward mailbox-name semantics. RFC 9051 says `INBOX` is
case-insensitive, but it takes no position on case sensitivity for non-`INBOX`
mailboxes; server implementations vary.

Implemented matching behavior:

- Match `INBOX` case-insensitively.
- Match all other configured folder names exactly against names returned by
  IMAP `LIST`.
- If exact matching fails, report a clear error and include close
  case-insensitive suggestions when available.
- Do not silently treat non-`INBOX` folders as case-insensitive. That avoids
  selecting the wrong mailbox on servers where two names can differ only by
  case.

Source: [RFC 9051, section 5.1 mailbox naming](https://www.rfc-editor.org/rfc/rfc9051.html#section-5.1).

## Validation And Error Handling

Configuration validation is strict enough to catch common mistakes before
messages are moved.

Configuration errors:

- `account_scans` is not an object.
- an account key is not in `provider:ACCOUNT_KEY` form.
- the provider is unsupported.
- an account key references no configured account.
- `folders` is missing.
- `folders` is neither `"all"` nor an array.
- `folders` is an empty array.
- a folder entry is not a non-empty string.
- the same folder is listed more than once.

Runtime account errors:

- a configured folder does not exist in the account's discovered folder list.
- a configured folder exists but is excluded from scanning, such as
  `Quarantine`, Spam, Trash, Junk, or Bulk.
- all configured folders are filtered out or unavailable, leaving no folder to
  scan.

Implemented behavior:

- Treat invalid top-level config as a startup configuration error and exit with
  code `2`, consistent with other config validation failures.
- Treat runtime folder-selection failures as account-level errors: skip that
  account, continue other accounts, return a non-zero exit if any account
  failed, and record the error in daily summary history.
- Include available folder names in the error output, capped if needed to keep
  logs readable.

Example errors:

```text
Folder scan config for gmail:MAIN references missing folder 'Important'. Available folders include: INBOX, [Gmail]/All Mail, [Gmail]/Important. Did you mean [Gmail]/Important?
```

```text
Folder scan config for yahoo:MAIN selects excluded folder(s): Spam, Trash. Excluded folders cannot be scanned.
```

## Reporting

Per-account run output makes the selected folder policy visible:

```text
Folder scan mode: configured list (1 folder): INBOX.
Scanned 1 folder(s).
```

For default behavior:

```text
Folder scan mode: all allowed folders.
Scanned 9 folder(s).
```

Daily summaries use the existing `scanned_folders`, messages-processed, and
error fields. Folder-selection failures are recorded as account errors; there
is no separate folder-policy field in the summary.

## State Behavior

No state migration is required. State is namespaced by provider, account key,
and folder.

Changing an account from `"all"` to `["INBOX"]` simply stops updating state for
the unscanned folders. If the account later switches back to `"all"`, unread
messages in those folders may be processed if their folder-local UIDs are not in
state.

## Implementation Summary

The implementation:

1. Adds an `AccountScanConfig` dataclass and an `account_scans` field to
   `AppConfig`.
2. Parses `account_scans` from `config.json`.
3. Validates account references after accounts are resolved, because config
   validation needs the actual configured account set.
4. Selects folders after IMAP login and quarantine-folder setup.
5. Passes the selected folder list into `scan_new_messages`.
6. Prints the active folder scan mode in each account report.
7. Records account-level folder-selection errors in daily summary history.

## Test Coverage

Focused tests cover:

- default config scans all allowed folders.
- `folders: "all"` preserves current behavior.
- `folders: ["INBOX"]` scans only Inbox.
- `INBOX` matching is case-insensitive.
- non-`INBOX` folder matching is exact.
- missing configured folder produces an account error.
- excluded configured folder produces an account error.
- empty folder list is a config error.
- unknown account reference is a config error.
- daily summary records account-level folder-selection errors.

## Current Scope Boundaries

- There are no provider-specific defaults. Every account scans all allowed
  folders unless `config.json` explicitly selects folders.
- Folder glob and pattern matching are not supported. Exact lists are easier to
  reason about and safer for mailbox mutations.
- Folder selection is configured only in `config.json`; there is no environment
  variable equivalent.
