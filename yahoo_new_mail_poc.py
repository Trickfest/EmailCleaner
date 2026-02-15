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
from pathlib import Path
from typing import Iterable


DEFAULT_IMAP_HOST = "imap.mail.yahoo.com"
DEFAULT_IMAP_PORT = 993
DEFAULT_STATE_FILE = ".yahoo_mail_state.json"
DEFAULT_MAX_TRACKED_UIDS = 5000


@dataclass
class FolderInfo:
    name: str
    flags: set[str]


@dataclass
class MessageSummary:
    folder: str
    uid: str
    sender: str
    recipient: str
    subject: str
    date: str
    message_id: str
    size_bytes: int | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Log in to Yahoo Mail via IMAP and pull only newly discovered unread "
            "messages from all folders except Spam/Trash."
        )
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("YAHOO_EMAIL_1"),
        help="Yahoo email address. Defaults to YAHOO_EMAIL_1 env var.",
    )
    parser.add_argument(
        "--app-password",
        default=os.environ.get("YAHOO_APP_PASSWORD_1"),
        help="Yahoo app password. Defaults to YAHOO_APP_PASSWORD_1 env var.",
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


def is_excluded_folder(folder: FolderInfo) -> bool:
    name_lower = folder.name.lower()
    if "\\noselect" in {flag.lower() for flag in folder.flags}:
        return True

    excluded_tokens = ("spam", "trash", "bulk mail")
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


def load_state(path: Path) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as file:
            raw = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}

    folders = raw.get("folders", {})
    if not isinstance(folders, dict):
        return {}
    return folders


def save_state(path: Path, folders_state: dict[str, dict[str, object]]) -> None:
    payload = {"folders": folders_state}
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


def fetch_message_summary(imap: imaplib.IMAP4_SSL, folder_name: str, uid: str) -> MessageSummary | None:
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
    return MessageSummary(
        folder=folder_name,
        uid=uid,
        sender=decode_header_value(message.get("From")),
        recipient=decode_header_value(message.get("To")),
        subject=decode_header_value(message.get("Subject")),
        date=decode_header_value(message.get("Date")),
        message_id=decode_header_value(message.get("Message-ID")),
        size_bytes=size_bytes,
    )


def trim_uid_history(uids: set[str], max_items: int) -> list[str]:
    if len(uids) <= max_items:
        return sorted(uids, key=lambda value: int(value))

    trimmed = sorted(uids, key=lambda value: int(value))[-max_items:]
    return trimmed


def select_folder(imap: imaplib.IMAP4_SSL, folder_name: str) -> bool:
    # Wrap in quotes so names with spaces work reliably.
    mailbox = folder_name.replace("\\", "\\\\").replace('"', r'\"')
    status, _ = imap.select(f'"{mailbox}"', readonly=True)
    return status == "OK"


def scan_new_messages(
    imap: imaplib.IMAP4_SSL,
    folders_state: dict[str, dict[str, object]],
    max_tracked_uids: int,
) -> tuple[list[MessageSummary], dict[str, dict[str, object]], int]:
    messages: list[MessageSummary] = []
    scanned_folder_count = 0

    for folder in discover_folders(imap):
        if is_excluded_folder(folder):
            continue

        if not select_folder(imap, folder.name):
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
            summary = fetch_message_summary(imap, folder.name, uid)
            if summary:
                messages.append(summary)
            processed_uids.add(uid)

        folders_state[folder.name] = {
            "uidvalidity": current_uidvalidity,
            "processed_uids": trim_uid_history(processed_uids, max_tracked_uids),
        }

    return messages, folders_state, scanned_folder_count


def print_report(messages: list[MessageSummary], scanned_folder_count: int) -> None:
    print(f"Scanned {scanned_folder_count} folder(s).")
    print(f"Found {len(messages)} new unread message(s).")
    if not messages:
        return

    for msg in messages:
        subject = msg.subject or "(no subject)"
        sender = msg.sender or "(unknown sender)"
        print(
            f"- [{msg.folder}] UID {msg.uid} | {subject} | {sender}"
        )


def main() -> int:
    args = parse_args()

    if not args.email or not args.app_password:
        print(
            "Missing credentials. Provide --email and --app-password, or set "
            "YAHOO_EMAIL_1 and YAHOO_APP_PASSWORD_1.",
            file=sys.stderr,
        )
        return 2

    state_path = Path(args.state_file)
    folders_state = load_state(state_path)

    try:
        context = ssl.create_default_context()
        with imaplib.IMAP4_SSL(args.host, args.port, ssl_context=context) as imap:
            imap.login(args.email, args.app_password)
            messages, updated_state, scanned_count = scan_new_messages(
                imap,
                folders_state,
                max_tracked_uids=max(1, args.max_tracked_uids),
            )
            save_state(state_path, updated_state)
            print_report(messages, scanned_count)

            if args.json_output:
                output_path = Path(args.json_output)
                output_path.write_text(
                    json.dumps([asdict(msg) for msg in messages], indent=2),
                    encoding="utf-8",
                )
                print(f"Wrote JSON output to {output_path}")

            imap.logout()

    except imaplib.IMAP4.error as error:
        print(f"IMAP error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Network or file error: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
