# AGENTS.md

## Scope
These instructions apply to the entire repository.

## Project Purpose
EmailCleaner is a Python IMAP scanner that currently supports Yahoo Mail and Gmail, and:
- Loads one or more accounts from environment variables and/or `accounts.json`
- Supports targeted scans via `--provider` and `--account-key`
- Pulls unread messages from allowed folders
- Evaluates delete/keep rules from `rules.json`
- Optionally applies OpenAI post-filtering from `config.json`
- Moves delete candidates to `Quarantine` by default

## Primary Files
- `email_cleaner.py`: main implementation
- `README.md`: user-facing behavior and examples
- `rules.example.json`: safe template for rules
- `accounts.example.json`: safe template for account configuration
- `config.example.json`: safe template for optional OpenAI settings

## Privacy And Data Rules
- Never commit personal/local data files:
  - `rules.json`
  - `accounts.json`
  - `config.json`
  - `.email_cleaner_state.json`
- Keep examples in `rules.example.json` and `accounts.example.json` fictional/sanitized.
- If docs need examples, use fictional values only.

## Behavioral Invariants
Keep these semantics unless explicitly asked to change them:
- Default delete action is move-to-`Quarantine` (create folder if missing).
- Default IMAP host is provider-specific (`yahoo` -> `imap.mail.yahoo.com`, `gmail` -> `imap.gmail.com`) unless `--host` override is set.
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

## LLM Integration Guardrails
- Treat `openai.system_prompt` as configuration. When behavior assumptions change, update `config.example.json` and `README.md` in the same change.
- Keep `confidence` semantics stable: it is the estimated probability that a message is spam, in `[0,1]`.
- Only mark as delete candidate when OpenAI returns `decision=delete_candidate` and `confidence >= openai.confidence_threshold`.
- Fail safe on API/network/response-parse errors: keep the message (do not auto-delete/quarantine from error states).
- Preserve data minimization: send only configured excerpts (`max_subject_chars`, `max_body_chars`) and required metadata.
- `--dry-run` may call OpenAI, but must never mutate mailbox state or local state files.
- Keep report output audit-friendly: include compact model decision/context, but do not print full email bodies.
- Any OpenAI prompt/parsing/threshold behavior change must include test updates in `tests/test_openai_config.py` and relevant routing tests.

When changing rule behavior:
- Update `README.md` and `rules.example.json` in the same change.
- Preserve backward-compatible behavior where possible.

## Accounts And State
- Accounts are merged by provider + account key from env + `accounts.json`.
- `accounts.json` provider sections are `yahoo_accounts` and `gmail_accounts`.
- Duplicate definitions for the same account field are treated as configuration errors.
- State is namespaced by provider, account key, and folder.
- Legacy state compatibility is intentionally removed; use `.email_cleaner_state.json`.

## Development Workflow
Before finalizing changes:
- Assume dev dependencies are already installed in the active Python environment.
- Run `python3 -m py_compile email_cleaner.py`
- Run `python3 -m pytest -q`
- Check CLI help for new flags: `python3 email_cleaner.py --help`
- Prefer safe validation paths (`--dry-run`, temp state files) over live mailbox mutation.

Anti-regression checklist:
- Deterministic rule precedence is unchanged (`never_filter` before any delete path; OpenAI last).
- `--dry-run` still performs no mailbox mutations and no state writes.
- OpenAI failures default to keep, and threshold gating is still enforced.
- `--hard-delete` behavior remains no-op placeholder for delete candidates.
- `README.md`, `rules.example.json`, and `config.example.json` remain aligned with runtime behavior.

## Style
- Keep implementation in Python stdlib unless explicitly approved.
- Keep user-facing messages clear and operationally specific.
- Prefer small, focused edits and keep docs aligned with code.
