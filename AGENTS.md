# AGENTS.md

## Scope
These instructions apply to the entire repository.

## Project Purpose
EmailCleaner is a Python IMAP scanner (Yahoo POC) that:
- Loads one or more Yahoo accounts from environment variables and/or `accounts.json`
- Pulls unread messages from allowed folders
- Evaluates delete/keep rules from `rules.json`
- Optionally applies OpenAI post-filtering from `config.json`
- Moves delete candidates to `Quarantine` by default

## Primary Files
- `yahoo_new_mail_poc.py`: main implementation
- `README.md`: user-facing behavior and examples
- `rules.example.json`: safe template for rules
- `accounts.example.json`: safe template for account configuration
- `config.example.json`: safe template for optional OpenAI settings

## Privacy And Data Rules
- Never commit personal/local data files:
  - `rules.json`
  - `accounts.json`
  - `config.json`
  - `.yahoo_mail_state.json`
- Keep examples in `rules.example.json` and `accounts.example.json` fictional/sanitized.
- If docs need examples, use fictional values only.

## Behavioral Invariants
Keep these semantics unless explicitly asked to change them:
- Default delete action is move-to-`Quarantine` (create folder if missing).
- Optional `quarantine_cleanup_days` deletes old messages from `Quarantine`; if unset/null, cleanup is disabled.
- `--hard-delete` is currently a no-op placeholder for delete candidates.
- `--dry-run` performs no mailbox mutations and does not write state.
- `--reset-app` is standalone mode and may only be combined with optional `--state-file`.
- `Quarantine`/Bulk/Spam/Trash/Junk-style folders are excluded from scanning.

## Rules Engine Expectations
Current precedence:
1. `never_filter`
2. `always_delete`
3. `delete_patterns.auth_triple_fail`
4. `delete_patterns.malformed_from`
5. `delete_patterns.from_regex`
6. `delete_patterns.subject_regex`
7. `delete_patterns.body_regex`

OpenAI post-filter behavior:
- OpenAI classification is optional and configured in `config.json`.
- It runs only after deterministic rules do not match.
- It requires `openai.enabled=true` and `OPENAI_API_KEY` to be set.
- Do not let OpenAI override `never_filter`.

When changing rule behavior:
- Update `README.md` and `rules.example.json` in the same change.
- Preserve backward-compatible behavior where possible.

## Accounts And State
- Accounts are merged by account key from env + `accounts.json`.
- Duplicate definitions for the same account field are treated as configuration errors.
- State is namespaced by account key and folder.
- Maintain legacy-state compatibility behavior unless intentionally removed.

## Development Workflow
Before finalizing changes:
- Run `python3 -m py_compile yahoo_new_mail_poc.py`
- Run `python3 -m pytest -q`
- Check CLI help for new flags: `python3 yahoo_new_mail_poc.py --help`
- Prefer safe validation paths (`--dry-run`, temp state files) over live mailbox mutation.

## Style
- Keep implementation in Python stdlib unless explicitly approved.
- Keep user-facing messages clear and operationally specific.
- Prefer small, focused edits and keep docs aligned with code.
