#!/usr/bin/env python3
"""Proof-of-concept Yahoo mail scanner for new unread messages."""

from __future__ import annotations

import argparse
import email
import imaplib
import json
import os
import re
import ssl
import sys
from dataclasses import asdict, dataclass
from email.utils import parseaddr
from pathlib import Path
from typing import Iterable


DEFAULT_IMAP_HOST = "imap.mail.yahoo.com"
DEFAULT_IMAP_PORT = 993
DEFAULT_STATE_FILE = ".yahoo_mail_state.json"
DEFAULT_RULES_FILE = "rules.json"
DEFAULT_ACCOUNTS_FILE = "accounts.json"
DEFAULT_MAX_TRACKED_UIDS = 5000
DEFAULT_QUARANTINE_FOLDER = "Quarantine"
ENV_YAHOO_EMAIL_PREFIX = "EMAIL_CLEANER_YAHOO_EMAIL_"
ENV_YAHOO_APP_PASSWORD_PREFIX = "EMAIL_CLEANER_YAHOO_APP_PASSWORD_"
LEGACY_STATE_KEY = "__legacy_single_account__"


@dataclass
class FolderInfo:
    name: str
    flags: set[str]


@dataclass(frozen=True)
class NeverFilterRules:
    senders: set[str]
    domains: set[str]


@dataclass(frozen=True)
class AlwaysDeleteRules:
    senders: set[str]
    domains: set[str]


@dataclass(frozen=True)
class RegexRule:
    source: str
    pattern_text: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class DeletePatternRules:
    from_regex: tuple[RegexRule, ...]
    subject_regex: tuple[RegexRule, ...]
    body_regex: tuple[RegexRule, ...]


@dataclass(frozen=True)
class ScannerRules:
    never_filter: NeverFilterRules
    always_delete: AlwaysDeleteRules
    delete_patterns: DeletePatternRules


@dataclass(frozen=True)
class YahooAccountCredentials:
    account_key: str
    email: str
    app_password: str


@dataclass
class PartialYahooAccountCredentials:
    email: str | None = None
    app_password: str | None = None
    email_source: str = ""
    app_password_source: str = ""


@dataclass
class MessageSummary:
    account_key: str
    account_email: str
    folder: str
    uid: str
    sender: str
    sender_name: str
    sender_email: str
    sender_domain: str
    recipient: str
    subject: str
    date: str
    message_id: str
    size_bytes: int | None
    never_filter_match: bool
    never_filter_reason: str
    delete_candidate: bool
    delete_reason: str
    action: str
    action_reason: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Log in to Yahoo Mail via IMAP and pull only newly discovered unread "
            "messages from all folders except Spam/Trash."
        )
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_IMAP_HOST,
        help=f"IMAP host (default: {DEFAULT_IMAP_HOST}).",
    )
    parser.add_argument(
        "--port",
        default=DEFAULT_IMAP_PORT,
        type=int,
        help=f"IMAP port (default: {DEFAULT_IMAP_PORT}).",
    )
    parser.add_argument(
        "--state-file",
        default=DEFAULT_STATE_FILE,
        help=f"Path to scanner state file (default: {DEFAULT_STATE_FILE}).",
    )
    parser.add_argument(
        "--rules-file",
        default=DEFAULT_RULES_FILE,
        help=f"Path to filtering rules JSON file (default: {DEFAULT_RULES_FILE}).",
    )
    parser.add_argument(
        "--accounts-file",
        default=DEFAULT_ACCOUNTS_FILE,
        help=(
            "Path to Yahoo accounts JSON file (default: accounts.json). "
            "File is optional."
        ),
    )
    parser.add_argument(
        "--max-tracked-uids",
        default=DEFAULT_MAX_TRACKED_UIDS,
        type=int,
        help=(
            "Max processed UID history per folder to keep in state "
            f"(default: {DEFAULT_MAX_TRACKED_UIDS})."
        ),
    )
    parser.add_argument(
        "--json-output",
        default="",
        help="Optional path to write fetched message summaries as JSON.",
    )
    parser.add_argument(
        "--hard-delete",
        action="store_true",
        help=(
            "Placeholder for future permanent deletion path. "
            "Current POC behavior: no-op for delete candidates."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Do not move/delete messages and do not write updated local state. "
            "Print what actions would have happened."
        ),
    )
    parser.add_argument(
        "--reset-app",
        action="store_true",
        help=(
            "Reset local app state by deleting the state file "
            "(from --state-file) and then exit. "
            "Use only with --state-file."
        ),
    )
    return parser.parse_args()


def decode_header_value(value: str | None) -> str:
    if not value:
        return ""
    decoded_fragments = []
    for fragment, encoding in email.header.decode_header(value):
        if isinstance(fragment, bytes):
            decoded_fragments.append(fragment.decode(encoding or "utf-8", errors="replace"))
        else:
            decoded_fragments.append(fragment)
    return "".join(decoded_fragments).strip()


def cli_option_was_set(option_name: str, argv: list[str]) -> bool:
    option_prefix = f"{option_name}="
    return any(arg == option_name or arg.startswith(option_prefix) for arg in argv)


def normalize_account_key(raw_key: str, source: str) -> str:
    key = raw_key.strip()
    if not key:
        raise ValueError(f"{source} has an empty account key suffix.")
    if not re.fullmatch(r"[A-Za-z0-9_]+", key):
        raise ValueError(
            f"{source} has invalid account key {raw_key!r}. "
            "Use only letters, numbers, and underscores."
        )
    return key.upper()


def normalize_credential_value(raw_value: object, source: str, field_name: str) -> str:
    if not isinstance(raw_value, str):
        raise ValueError(f"{source} must be a string.")
    value = raw_value.strip()
    if not value:
        raise ValueError(f"{source} cannot be empty.")
    if field_name == "email":
        return value.lower()
    return value


def set_account_credential(
    accounts: dict[str, PartialYahooAccountCredentials],
    account_key: str,
    field_name: str,
    field_value: str,
    source: str,
) -> None:
    partial = accounts.setdefault(account_key, PartialYahooAccountCredentials())

    if field_name == "email":
        if partial.email is not None:
            raise ValueError(
                f"Duplicate email for Yahoo account key {account_key!r}. "
                f"Already set from {partial.email_source}; duplicate from {source}."
            )
        partial.email = field_value
        partial.email_source = source
        return

    if field_name == "app_password":
        if partial.app_password is not None:
            raise ValueError(
                f"Duplicate app_password for Yahoo account key {account_key!r}. "
                f"Already set from {partial.app_password_source}; duplicate from {source}."
            )
        partial.app_password = field_value
        partial.app_password_source = source
        return

    raise ValueError(f"Unsupported account credential field: {field_name}")


def load_accounts_from_env(
    accounts: dict[str, PartialYahooAccountCredentials],
) -> None:
    for env_name, env_value in sorted(os.environ.items()):
        if env_name.startswith(ENV_YAHOO_EMAIL_PREFIX):
            key_suffix = env_name[len(ENV_YAHOO_EMAIL_PREFIX) :]
            account_key = normalize_account_key(key_suffix, f"env var {env_name}")
            email_address = normalize_credential_value(env_value, f"env var {env_name}", "email")
            set_account_credential(
                accounts,
                account_key=account_key,
                field_name="email",
                field_value=email_address,
                source=f"env var {env_name}",
            )
        elif env_name.startswith(ENV_YAHOO_APP_PASSWORD_PREFIX):
            key_suffix = env_name[len(ENV_YAHOO_APP_PASSWORD_PREFIX) :]
            account_key = normalize_account_key(key_suffix, f"env var {env_name}")
            app_password = normalize_credential_value(
                env_value,
                f"env var {env_name}",
                "app_password",
            )
            set_account_credential(
                accounts,
                account_key=account_key,
                field_name="app_password",
                field_value=app_password,
                source=f"env var {env_name}",
            )


def load_accounts_from_file(
    accounts_file_path: Path,
    accounts: dict[str, PartialYahooAccountCredentials],
) -> None:
    if not accounts_file_path.exists():
        return

    try:
        with accounts_file_path.open("r", encoding="utf-8") as file:
            raw = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read accounts file {accounts_file_path}: {error}") from error

    if not isinstance(raw, dict):
        raise ValueError(f"Accounts file {accounts_file_path} must contain a JSON object.")

    yahoo_accounts = raw.get("yahoo_accounts", {})
    if yahoo_accounts is None:
        yahoo_accounts = {}
    if not isinstance(yahoo_accounts, dict):
        raise ValueError(f"Accounts file {accounts_file_path} has invalid yahoo_accounts section.")

    for raw_key, raw_account in yahoo_accounts.items():
        if not isinstance(raw_key, str):
            raise ValueError(
                f"Accounts file {accounts_file_path} has non-string yahoo_accounts key."
            )
        if not isinstance(raw_account, dict):
            raise ValueError(
                f"Accounts file {accounts_file_path} yahoo_accounts.{raw_key} must be an object."
            )

        has_email = "email" in raw_account
        has_password = "app_password" in raw_account
        if not has_email and not has_password:
            raise ValueError(
                f"Accounts file {accounts_file_path} yahoo_accounts.{raw_key} must include "
                "email and/or app_password."
            )

        account_key = normalize_account_key(raw_key, f"{accounts_file_path} yahoo_accounts.{raw_key}")
        if has_email:
            email_address = normalize_credential_value(
                raw_account.get("email"),
                f"{accounts_file_path} yahoo_accounts.{raw_key}.email",
                "email",
            )
            set_account_credential(
                accounts,
                account_key=account_key,
                field_name="email",
                field_value=email_address,
                source=f"{accounts_file_path} yahoo_accounts.{raw_key}.email",
            )
        if has_password:
            app_password = normalize_credential_value(
                raw_account.get("app_password"),
                f"{accounts_file_path} yahoo_accounts.{raw_key}.app_password",
                "app_password",
            )
            set_account_credential(
                accounts,
                account_key=account_key,
                field_name="app_password",
                field_value=app_password,
                source=f"{accounts_file_path} yahoo_accounts.{raw_key}.app_password",
            )


def resolve_yahoo_accounts(accounts_file_path: Path) -> list[YahooAccountCredentials]:
    partial_accounts: dict[str, PartialYahooAccountCredentials] = {}
    load_accounts_from_env(partial_accounts)
    load_accounts_from_file(accounts_file_path, partial_accounts)

    if not partial_accounts:
        raise ValueError(
            "No Yahoo accounts configured. Set env vars with prefixes "
            f"{ENV_YAHOO_EMAIL_PREFIX} and {ENV_YAHOO_APP_PASSWORD_PREFIX}, "
            f"or define yahoo_accounts in {accounts_file_path}."
        )

    unresolved: list[str] = []
    resolved_accounts: list[YahooAccountCredentials] = []
    for account_key in sorted(partial_accounts):
        partial = partial_accounts[account_key]
        missing_fields: list[str] = []
        if partial.email is None:
            missing_fields.append("email")
        if partial.app_password is None:
            missing_fields.append("app_password")
        if missing_fields:
            unresolved.append(f"{account_key} (missing {', '.join(missing_fields)})")
            continue

        resolved_accounts.append(
            YahooAccountCredentials(
                account_key=account_key,
                email=partial.email,
                app_password=partial.app_password,
            )
        )

    if unresolved:
        unresolved_text = ", ".join(unresolved)
        raise ValueError(
            "Invalid Yahoo account configuration. Every discovered account key must have both "
            f"email and app_password. Unresolved account keys: {unresolved_text}."
        )

    return resolved_accounts


def normalize_string_set(values: object) -> set[str]:
    if not isinstance(values, list):
        return set()

    normalized: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip().lower()
        if cleaned:
            normalized.add(cleaned)
    return normalized


def compile_regex_rules(values: object, source_prefix: str) -> tuple[RegexRule, ...]:
    if values is None:
        return ()
    if not isinstance(values, list):
        raise ValueError(f"{source_prefix} must be a list of regex strings.")

    compiled_rules: list[RegexRule] = []
    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise ValueError(f"{source_prefix}[{index}] must be a string regex.")
        try:
            compiled_pattern = re.compile(value)
        except re.error as error:
            raise ValueError(
                f"Invalid regex at {source_prefix}[{index}] ({value!r}): {error}"
            ) from error
        compiled_rules.append(
            RegexRule(
                source=f"{source_prefix}[{index}]",
                pattern_text=value,
                pattern=compiled_pattern,
            )
        )
    return tuple(compiled_rules)


def parse_contact_rules(section: object, section_name: str) -> tuple[set[str], set[str]]:
    if section is None:
        return set(), set()
    if not isinstance(section, dict):
        raise ValueError(f"Rules file has invalid {section_name} section.")

    return (
        normalize_string_set(section.get("senders", [])),
        normalize_string_set(section.get("domains", [])),
    )


def load_scanner_rules(path: Path) -> ScannerRules:
    if not path.exists():
        return ScannerRules(
            never_filter=NeverFilterRules(senders=set(), domains=set()),
            always_delete=AlwaysDeleteRules(senders=set(), domains=set()),
            delete_patterns=DeletePatternRules(from_regex=(), subject_regex=(), body_regex=()),
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            raw = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read rules file {path}: {error}") from error

    if not isinstance(raw, dict):
        raise ValueError(f"Rules file {path} must contain a JSON object.")

    never_filter_senders, never_filter_domains = parse_contact_rules(
        raw.get("never_filter", {}),
        "never_filter",
    )
    always_delete_senders, always_delete_domains = parse_contact_rules(
        raw.get("always_delete", {}),
        "always_delete",
    )

    delete_patterns = raw.get("delete_patterns", {})
    if delete_patterns is None:
        delete_patterns = {}
    if not isinstance(delete_patterns, dict):
        raise ValueError(f"Rules file {path} has invalid delete_patterns section.")

    return ScannerRules(
        never_filter=NeverFilterRules(
            senders=never_filter_senders,
            domains=never_filter_domains,
        ),
        always_delete=AlwaysDeleteRules(
            senders=always_delete_senders,
            domains=always_delete_domains,
        ),
        delete_patterns=DeletePatternRules(
            from_regex=compile_regex_rules(
                delete_patterns.get("from_regex", []),
                "delete_patterns.from_regex",
            ),
            subject_regex=compile_regex_rules(
                delete_patterns.get("subject_regex", []),
                "delete_patterns.subject_regex",
            ),
            body_regex=compile_regex_rules(
                delete_patterns.get("body_regex", []),
                "delete_patterns.body_regex",
            ),
        ),
    )


def evaluate_contact_rules(
    sender_email: str,
    sender_domain: str,
    senders: set[str],
    domains: set[str],
    reason_prefix: str,
) -> tuple[bool, str]:
    if sender_email and sender_email in senders:
        return True, f"{reason_prefix}.sender:{sender_email}"
    if sender_domain and sender_domain in domains:
        return True, f"{reason_prefix}.domain:{sender_domain}"
    return False, ""


def evaluate_never_filter(
    sender_email: str,
    sender_domain: str,
    never_filter_rules: NeverFilterRules,
) -> tuple[bool, str]:
    return evaluate_contact_rules(
        sender_email,
        sender_domain,
        never_filter_rules.senders,
        never_filter_rules.domains,
        "never_filter",
    )


def evaluate_delete_candidate(
    summary: MessageSummary,
    body_text: str,
    scanner_rules: ScannerRules,
) -> tuple[bool, str]:
    always_delete_match, always_delete_reason = evaluate_contact_rules(
        summary.sender_email,
        summary.sender_domain,
        scanner_rules.always_delete.senders,
        scanner_rules.always_delete.domains,
        "always_delete",
    )
    if always_delete_match:
        return True, always_delete_reason

    for rule in scanner_rules.delete_patterns.from_regex:
        if summary.sender_name and rule.pattern.search(summary.sender_name):
            return True, f"{rule.source}:{rule.pattern_text} [sender_name]"
        if summary.sender_email and rule.pattern.search(summary.sender_email):
            return True, f"{rule.source}:{rule.pattern_text} [sender_email]"

    for rule in scanner_rules.delete_patterns.subject_regex:
        if rule.pattern.search(summary.subject):
            return True, f"{rule.source}:{rule.pattern_text}"

    if body_text:
        for rule in scanner_rules.delete_patterns.body_regex:
            if rule.pattern.search(body_text):
                return True, f"{rule.source}:{rule.pattern_text}"

    return False, ""


def extract_sender_email(sender_header: str) -> str:
    _sender_name, sender_email = parseaddr(sender_header)
    return sender_email.strip().lower()


def extract_sender_name(sender_header: str) -> str:
    sender_name, _sender_email = parseaddr(sender_header)
    return sender_name.strip()


def extract_domain(email_address: str) -> str:
    if "@" not in email_address:
        return ""
    return email_address.split("@", 1)[1].strip().lower()


def parse_folder_line(line: bytes) -> FolderInfo | None:
    text = line.decode("utf-8", errors="replace")
    match = re.match(r"^\((?P<flags>[^)]*)\)\s+\"(?P<delim>[^\"]*)\"\s+(?P<name>.+)$", text)
    if not match:
        return None

    flags = {token.strip() for token in match.group("flags").split() if token.strip()}
    raw_name = match.group("name").strip()
    if raw_name.startswith('"') and raw_name.endswith('"'):
        # IMAP quoted string escaping.
        name = raw_name[1:-1].replace(r"\\", "\\").replace(r'\"', '"')
    else:
        name = raw_name
    return FolderInfo(name=name, flags=flags)


def is_excluded_folder(folder: FolderInfo, quarantine_folder: str = DEFAULT_QUARANTINE_FOLDER) -> bool:
    name_lower = folder.name.lower()
    flags_lower = {flag.lower() for flag in folder.flags}
    if "\\noselect" in flags_lower:
        return True

    if folder.name.casefold() == quarantine_folder.casefold():
        return True

    if any(flag in flags_lower for flag in ("\\junk", "\\spam", "\\trash")):
        return True

    excluded_tokens = ("spam", "trash", "bulk", "junk")
    return any(token in name_lower for token in excluded_tokens)


def discover_folders(imap: imaplib.IMAP4_SSL) -> list[FolderInfo]:
    status, data = imap.list()
    if status != "OK" or data is None:
        return [FolderInfo(name="INBOX", flags=set())]

    folders: list[FolderInfo] = []
    for line in data:
        if not line:
            continue
        folder = parse_folder_line(line)
        if folder:
            folders.append(folder)

    if not any(folder.name.upper() == "INBOX" for folder in folders):
        folders.append(FolderInfo(name="INBOX", flags=set()))

    folders.sort(key=lambda f: (f.name.upper() != "INBOX", f.name.lower()))
    return folders


def find_mailbox_name(imap: imaplib.IMAP4_SSL, folder_name: str) -> str | None:
    for folder in discover_folders(imap):
        if folder.name.casefold() == folder_name.casefold():
            return folder.name
    return None


def quote_mailbox_name(folder_name: str) -> str:
    escaped = folder_name.replace("\\", "\\\\").replace('"', r'\"')
    return f'"{escaped}"'


def decode_imap_response(data: object) -> str:
    if not isinstance(data, list):
        return ""
    parts: list[str] = []
    for item in data:
        if item is None:
            continue
        if isinstance(item, bytes):
            parts.append(item.decode("utf-8", errors="replace"))
        else:
            parts.append(str(item))
    return " | ".join(parts).strip()


def ensure_mailbox_exists(imap: imaplib.IMAP4_SSL, folder_name: str) -> str:
    existing_mailbox = find_mailbox_name(imap, folder_name)
    if existing_mailbox:
        return existing_mailbox

    status, data = imap.create(quote_mailbox_name(folder_name))
    if status != "OK":
        detail = decode_imap_response(data) or "unknown create failure"
        raise ValueError(f"Could not create mailbox {folder_name}: {detail}")

    existing_mailbox = find_mailbox_name(imap, folder_name)
    if existing_mailbox:
        return existing_mailbox
    return folder_name


def move_uid_to_mailbox(imap: imaplib.IMAP4_SSL, uid: str, target_folder: str) -> tuple[bool, str]:
    target_mailbox = quote_mailbox_name(target_folder)

    move_status, move_data = imap.uid("MOVE", uid, target_mailbox)
    if move_status == "OK":
        return True, f"moved to {target_folder}"

    copy_status, copy_data = imap.uid("COPY", uid, target_mailbox)
    if copy_status != "OK":
        detail = decode_imap_response(copy_data) or decode_imap_response(move_data) or "copy failed"
        return False, detail

    store_status, store_data = imap.uid("STORE", uid, "+FLAGS.SILENT", r"(\Deleted)")
    if store_status != "OK":
        detail = decode_imap_response(store_data) or "store-delete flag failed"
        return False, detail

    expunge_status, expunge_data = imap.expunge()
    if expunge_status != "OK":
        detail = decode_imap_response(expunge_data) or "expunge failed"
        return False, detail

    return True, f"copied+expunged to {target_folder}"


def load_state(path: Path) -> dict[str, dict[str, dict[str, object]]]:
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as file:
            raw = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}

    if not isinstance(raw, dict):
        return {}

    accounts_section = raw.get("accounts")
    if isinstance(accounts_section, dict):
        accounts_state: dict[str, dict[str, dict[str, object]]] = {}
        for account_key, account_payload in accounts_section.items():
            if not isinstance(account_key, str) or not isinstance(account_payload, dict):
                continue
            folders = account_payload.get("folders", {})
            if isinstance(folders, dict):
                accounts_state[account_key] = folders
        return accounts_state

    folders = raw.get("folders", {})
    if isinstance(folders, dict):
        # Backward compatibility with the pre-multi-account state format.
        return {LEGACY_STATE_KEY: folders}

    return {}


def save_state(
    path: Path,
    accounts_state: dict[str, dict[str, dict[str, object]]],
    accounts: list[YahooAccountCredentials],
) -> None:
    account_email_by_key = {account.account_key: account.email for account in accounts}
    payload_accounts: dict[str, dict[str, object]] = {}
    for account_key in sorted(accounts_state):
        payload_accounts[account_key] = {
            "email": account_email_by_key.get(account_key, ""),
            "folders": accounts_state[account_key],
        }

    payload = {"accounts": payload_accounts}
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)


def get_uidvalidity(imap: imaplib.IMAP4_SSL) -> str | None:
    _code, data = imap.response("UIDVALIDITY")
    if data and data[0]:
        try:
            return data[0].decode("utf-8", errors="replace")
        except AttributeError:
            return str(data[0])
    return None


def search_unseen_uids(imap: imaplib.IMAP4_SSL) -> list[str]:
    status, data = imap.uid("SEARCH", None, "UNSEEN")
    if status != "OK" or not data or not data[0]:
        return []
    return [uid.decode("ascii", errors="ignore") for uid in data[0].split()]


def parse_fetch_parts(fetch_data: Iterable[object]) -> tuple[bytes | None, int | None]:
    headers: bytes | None = None
    size_bytes: int | None = None

    for part in fetch_data:
        if not isinstance(part, tuple) or len(part) < 2:
            continue
        meta, body = part
        if isinstance(body, bytes):
            headers = body
        if isinstance(meta, bytes):
            size_match = re.search(rb"RFC822\.SIZE\s+(\d+)", meta)
            if size_match:
                size_bytes = int(size_match.group(1))

    return headers, size_bytes


def parse_fetch_body_text(fetch_data: Iterable[object]) -> str:
    for part in fetch_data:
        if not isinstance(part, tuple) or len(part) < 2:
            continue
        _meta, body = part
        if isinstance(body, bytes):
            return body.decode("utf-8", errors="replace")
    return ""


def fetch_message_body_text(imap: imaplib.IMAP4_SSL, uid: str) -> str:
    status, fetch_data = imap.uid("FETCH", uid, "(BODY.PEEK[TEXT])")
    if status != "OK" or fetch_data is None:
        return ""
    return parse_fetch_body_text(fetch_data)


def fetch_message_summary(
    imap: imaplib.IMAP4_SSL,
    account: YahooAccountCredentials,
    folder_name: str,
    uid: str,
) -> MessageSummary | None:
    status, fetch_data = imap.uid(
        "FETCH",
        uid,
        "(BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)] RFC822.SIZE)",
    )
    if status != "OK" or fetch_data is None:
        return None

    headers_raw, size_bytes = parse_fetch_parts(fetch_data)
    if not headers_raw:
        return None

    message = email.message_from_bytes(headers_raw)
    sender = decode_header_value(message.get("From"))
    sender_name = extract_sender_name(sender)
    sender_email = extract_sender_email(sender)
    sender_domain = extract_domain(sender_email)
    return MessageSummary(
        account_key=account.account_key,
        account_email=account.email,
        folder=folder_name,
        uid=uid,
        sender=sender,
        sender_name=sender_name,
        sender_email=sender_email,
        sender_domain=sender_domain,
        recipient=decode_header_value(message.get("To")),
        subject=decode_header_value(message.get("Subject")),
        date=decode_header_value(message.get("Date")),
        message_id=decode_header_value(message.get("Message-ID")),
        size_bytes=size_bytes,
        never_filter_match=False,
        never_filter_reason="",
        delete_candidate=False,
        delete_reason="",
        action="NONE",
        action_reason="",
    )


def trim_uid_history(uids: set[str], max_items: int) -> list[str]:
    if len(uids) <= max_items:
        return sorted(uids, key=lambda value: int(value))

    trimmed = sorted(uids, key=lambda value: int(value))[-max_items:]
    return trimmed


def select_folder(imap: imaplib.IMAP4_SSL, folder_name: str, readonly: bool) -> bool:
    status, _ = imap.select(quote_mailbox_name(folder_name), readonly=readonly)
    return status == "OK"


def scan_new_messages(
    imap: imaplib.IMAP4_SSL,
    account: YahooAccountCredentials,
    folders_state: dict[str, dict[str, object]],
    max_tracked_uids: int,
    scanner_rules: ScannerRules,
    hard_delete: bool,
    dry_run: bool,
    quarantine_folder: str,
    quarantine_will_be_created: bool,
) -> tuple[list[MessageSummary], dict[str, dict[str, object]], int]:
    messages: list[MessageSummary] = []
    scanned_folder_count = 0

    for folder in discover_folders(imap):
        if is_excluded_folder(folder, quarantine_folder=quarantine_folder):
            continue

        folder_writable = False
        if hard_delete:
            if not select_folder(imap, folder.name, readonly=True):
                continue
        else:
            if select_folder(imap, folder.name, readonly=False):
                folder_writable = True
            elif not select_folder(imap, folder.name, readonly=True):
                continue

        scanned_folder_count += 1
        current_uidvalidity = get_uidvalidity(imap)

        folder_state = folders_state.get(folder.name, {})
        previous_uidvalidity = str(folder_state.get("uidvalidity", "")) or None
        processed_uids = {
            str(uid)
            for uid in folder_state.get("processed_uids", [])
            if isinstance(uid, (str, int))
        }

        if previous_uidvalidity and current_uidvalidity and previous_uidvalidity != current_uidvalidity:
            processed_uids = set()

        unseen_uids = search_unseen_uids(imap)
        new_uids = [uid for uid in unseen_uids if uid not in processed_uids]

        for uid in new_uids:
            should_mark_processed = True
            summary = fetch_message_summary(imap, account, folder.name, uid)
            if summary:
                is_protected, protection_reason = evaluate_never_filter(
                    summary.sender_email,
                    summary.sender_domain,
                    scanner_rules.never_filter,
                )
                summary.never_filter_match = is_protected
                summary.never_filter_reason = protection_reason
                if is_protected:
                    summary.action = "SKIP_NEVER_FILTER"
                    summary.action_reason = protection_reason
                else:
                    is_delete_candidate, delete_reason = evaluate_delete_candidate(
                        summary,
                        "",
                        scanner_rules,
                    )
                    if not is_delete_candidate and scanner_rules.delete_patterns.body_regex:
                        body_text = fetch_message_body_text(imap, uid)
                        is_delete_candidate, delete_reason = evaluate_delete_candidate(
                            summary,
                            body_text,
                            scanner_rules,
                        )
                    summary.delete_candidate = is_delete_candidate
                    summary.delete_reason = delete_reason
                    if is_delete_candidate:
                        if hard_delete:
                            summary.action = "WOULD_HARD_DELETE_NOOP" if dry_run else "HARD_DELETE_NOOP"
                            summary.action_reason = "hard-delete path not implemented in this POC"
                        elif folder.name.casefold() == quarantine_folder.casefold():
                            summary.action = "ALREADY_IN_QUARANTINE"
                            summary.action_reason = quarantine_folder
                        elif not folder_writable:
                            summary.action = "WOULD_QUARANTINE_FAILED" if dry_run else "QUARANTINE_FAILED"
                            summary.action_reason = f"folder {folder.name} is read-only"
                            should_mark_processed = False
                        else:
                            if dry_run:
                                summary.action = "WOULD_QUARANTINE"
                                if quarantine_will_be_created:
                                    summary.action_reason = f"would create {quarantine_folder} and move message"
                                else:
                                    summary.action_reason = f"would move to {quarantine_folder}"
                            else:
                                moved, move_reason = move_uid_to_mailbox(imap, uid, quarantine_folder)
                                if moved:
                                    summary.action = "QUARANTINED"
                                    summary.action_reason = move_reason
                                else:
                                    summary.action = "QUARANTINE_FAILED"
                                    summary.action_reason = move_reason
                                    should_mark_processed = False
                messages.append(summary)
            if should_mark_processed:
                processed_uids.add(uid)

        folders_state[folder.name] = {
            "uidvalidity": current_uidvalidity,
            "processed_uids": trim_uid_history(processed_uids, max_tracked_uids),
        }

    return messages, folders_state, scanned_folder_count


def print_report(
    account: YahooAccountCredentials,
    messages: list[MessageSummary],
    scanned_folder_count: int,
    scanner_rules: ScannerRules,
    hard_delete: bool,
    dry_run: bool,
    quarantine_folder: str,
    quarantine_will_be_created: bool,
) -> None:
    protected_count = sum(1 for message in messages if message.never_filter_match)
    delete_candidate_count = sum(
        1 for message in messages if not message.never_filter_match and message.delete_candidate
    )
    quarantined_count = sum(1 for message in messages if message.action == "QUARANTINED")
    hard_delete_noop_count = sum(1 for message in messages if message.action == "HARD_DELETE_NOOP")
    quarantine_failed_count = sum(1 for message in messages if message.action == "QUARANTINE_FAILED")
    would_quarantine_count = sum(1 for message in messages if message.action == "WOULD_QUARANTINE")
    would_hard_delete_noop_count = sum(1 for message in messages if message.action == "WOULD_HARD_DELETE_NOOP")
    would_quarantine_failed_count = sum(1 for message in messages if message.action == "WOULD_QUARANTINE_FAILED")
    filter_eligible_count = len(messages) - protected_count - delete_candidate_count

    print(f"Account {account.account_key}: {account.email}")
    print(f"Scanned {scanned_folder_count} folder(s).")
    print(f"Found {len(messages)} new unread message(s).")
    if dry_run:
        print("Mode: DRY_RUN (no mailbox changes and no state-file updates).")
    print(
        "Loaded never-filter rules: "
        f"{len(scanner_rules.never_filter.senders)} sender(s), "
        f"{len(scanner_rules.never_filter.domains)} domain(s)."
    )
    print(
        "Loaded always-delete rules: "
        f"{len(scanner_rules.always_delete.senders)} sender(s), "
        f"{len(scanner_rules.always_delete.domains)} domain(s)."
    )
    print(
        "Loaded regex delete rules: "
        f"{len(scanner_rules.delete_patterns.from_regex)} from regex, "
        f"{len(scanner_rules.delete_patterns.subject_regex)} subject regex, "
        f"{len(scanner_rules.delete_patterns.body_regex)} body regex."
    )
    print(f"Never-filter protected message(s): {protected_count}")
    print(f"Delete-candidate message(s): {delete_candidate_count}")
    if hard_delete and dry_run:
        print(f"Would-hard-delete no-op message(s): {would_hard_delete_noop_count}")
    elif hard_delete:
        print(f"Hard-delete no-op message(s): {hard_delete_noop_count}")
    elif dry_run:
        print(f"Would-quarantine message(s): {would_quarantine_count} (target folder: {quarantine_folder})")
        if quarantine_will_be_created:
            print(f"Quarantine folder would be created: {quarantine_folder}")
        print(f"Would-quarantine failures: {would_quarantine_failed_count}")
    else:
        print(f"Quarantined message(s): {quarantined_count} (target folder: {quarantine_folder})")
        print(f"Quarantine failures (will retry next run): {quarantine_failed_count}")
    print(f"Filter-eligible message(s): {filter_eligible_count}")
    if not messages:
        return

    for msg in messages:
        subject = msg.subject or "(no subject)"
        sender = msg.sender or "(unknown sender)"
        if msg.never_filter_match:
            status = "NEVER_FILTER"
            reason = msg.never_filter_reason
        elif msg.delete_candidate:
            status = "DELETE_CANDIDATE"
            reason = msg.delete_reason
        else:
            status = "FILTER_ELIGIBLE"
            reason = ""

        detail_parts: list[str] = []
        if reason:
            detail_parts.append(reason)
        if msg.action != "NONE":
            action_detail = f"action:{msg.action}"
            if msg.action_reason:
                action_detail += f" ({msg.action_reason})"
            detail_parts.append(action_detail)
        reason_suffix = f" | {' | '.join(detail_parts)}" if detail_parts else ""
        print(
            f"- [{msg.account_key}] [{status}] [{msg.folder}] UID {msg.uid} | {subject} | "
            f"{sender}{reason_suffix}"
        )


def main() -> int:
    args = parse_args()
    state_path = Path(args.state_file)

    if args.reset_app:
        argv = sys.argv[1:]
        disallowed_with_reset = [
            "--host",
            "--port",
            "--rules-file",
            "--accounts-file",
            "--max-tracked-uids",
            "--json-output",
            "--hard-delete",
            "--dry-run",
        ]
        conflicting_options = [opt for opt in disallowed_with_reset if cli_option_was_set(opt, argv)]
        if conflicting_options:
            options_text = ", ".join(conflicting_options)
            print(
                "Invalid arguments: --reset-app cannot be combined with "
                f"{options_text}. Use only --reset-app and optional --state-file.",
                file=sys.stderr,
            )
            return 2

        try:
            if state_path.exists():
                state_path.unlink()
                print(f"Reset complete. Removed state file: {state_path}")
            else:
                print(f"Reset complete. State file does not exist: {state_path}")
        except OSError as error:
            print(f"Could not reset app state at {state_path}: {error}", file=sys.stderr)
            return 1
        return 0

    rules_path = Path(args.rules_file)
    accounts_path = Path(args.accounts_file)

    try:
        scanner_rules = load_scanner_rules(rules_path)
        yahoo_accounts = resolve_yahoo_accounts(accounts_path)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    accounts_state = load_state(state_path)
    if LEGACY_STATE_KEY in accounts_state:
        if len(yahoo_accounts) == 1 and yahoo_accounts[0].account_key not in accounts_state:
            accounts_state[yahoo_accounts[0].account_key] = accounts_state.pop(LEGACY_STATE_KEY)
        else:
            accounts_state.pop(LEGACY_STATE_KEY, None)

    print(f"Configured Yahoo accounts: {len(yahoo_accounts)}")

    all_messages: list[MessageSummary] = []
    account_errors: list[str] = []
    context = ssl.create_default_context()

    for index, account in enumerate(yahoo_accounts):
        if index:
            print()

        account_folders_state = accounts_state.get(account.account_key, {})
        if not isinstance(account_folders_state, dict):
            account_folders_state = {}

        try:
            with imaplib.IMAP4_SSL(args.host, args.port, ssl_context=context) as imap:
                imap.login(account.email, account.app_password)

                quarantine_folder = DEFAULT_QUARANTINE_FOLDER
                quarantine_will_be_created = False
                if not args.hard_delete:
                    if args.dry_run:
                        existing_mailbox = find_mailbox_name(imap, DEFAULT_QUARANTINE_FOLDER)
                        if existing_mailbox:
                            quarantine_folder = existing_mailbox
                        else:
                            quarantine_will_be_created = True
                    else:
                        try:
                            quarantine_folder = ensure_mailbox_exists(imap, DEFAULT_QUARANTINE_FOLDER)
                        except ValueError as error:
                            print(
                                f"[{account.account_key}] {error}",
                                file=sys.stderr,
                            )
                            account_errors.append(
                                f"{account.account_key} ({account.email}): {error}"
                            )
                            continue

                messages, updated_state, scanned_count = scan_new_messages(
                    imap,
                    account=account,
                    folders_state=account_folders_state,
                    max_tracked_uids=max(1, args.max_tracked_uids),
                    scanner_rules=scanner_rules,
                    hard_delete=args.hard_delete,
                    dry_run=args.dry_run,
                    quarantine_folder=quarantine_folder,
                    quarantine_will_be_created=quarantine_will_be_created,
                )
                accounts_state[account.account_key] = updated_state
                all_messages.extend(messages)
                print_report(
                    account=account,
                    messages=messages,
                    scanned_folder_count=scanned_count,
                    scanner_rules=scanner_rules,
                    hard_delete=args.hard_delete,
                    dry_run=args.dry_run,
                    quarantine_folder=quarantine_folder,
                    quarantine_will_be_created=quarantine_will_be_created,
                )
        except imaplib.IMAP4.error as error:
            print(
                f"IMAP error for account {account.account_key} ({account.email}): {error}",
                file=sys.stderr,
            )
            account_errors.append(f"{account.account_key} ({account.email}): IMAP error: {error}")
        except OSError as error:
            print(
                f"Network or file error for account {account.account_key} ({account.email}): {error}",
                file=sys.stderr,
            )
            account_errors.append(
                f"{account.account_key} ({account.email}): network or file error: {error}"
            )

    if args.dry_run:
        print("Dry run enabled. Skipping state-file write.")
    else:
        try:
            save_state(state_path, accounts_state, yahoo_accounts)
        except OSError as error:
            print(f"Could not write state file {state_path}: {error}", file=sys.stderr)
            return 1

    if args.json_output:
        output_path = Path(args.json_output)
        try:
            output_path.write_text(
                json.dumps([asdict(msg) for msg in all_messages], indent=2),
                encoding="utf-8",
            )
            print(f"Wrote JSON output to {output_path}")
        except OSError as error:
            print(f"Could not write JSON output at {output_path}: {error}", file=sys.stderr)
            return 1

    if account_errors:
        print(
            "One or more accounts failed: "
            + "; ".join(account_errors),
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
