from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import email_cleaner as app
from tests.helpers import make_scanner_rules, make_summary


ACCOUNT = app.AccountCredentials(
    provider="gmail",
    account_key="MAIN",
    email="main@example.test",
    app_password="app-password",
)


def clear_account_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_name in list(os.environ):
        if env_name.startswith("EMAIL_CLEANER_YAHOO_") or env_name.startswith("EMAIL_CLEANER_GMAIL_"):
            monkeypatch.delenv(env_name, raising=False)


def folder_names(plan: app.FolderScanPlan) -> tuple[str, ...]:
    return tuple(folder.name for folder in plan.folders)


def test_default_folder_scan_selects_all_allowed_folders() -> None:
    folders = [
        app.FolderInfo(name="INBOX", flags=set()),
        app.FolderInfo(name="[Gmail]/All Mail", flags=set()),
        app.FolderInfo(name="Spam", flags=set()),
        app.FolderInfo(name="Quarantine", flags=set()),
    ]

    plan = app.select_scan_folders(
        account=ACCOUNT,
        discovered_folders=folders,
        account_scan_config=None,
        quarantine_folder="Quarantine",
    )

    assert plan.mode == "all"
    assert folder_names(plan) == ("INBOX", "[Gmail]/All Mail")


def test_explicit_all_folder_scan_preserves_default_behavior() -> None:
    folders = [
        app.FolderInfo(name="INBOX", flags=set()),
        app.FolderInfo(name="Archive", flags=set()),
    ]

    plan = app.select_scan_folders(
        account=ACCOUNT,
        discovered_folders=folders,
        account_scan_config=app.AccountScanConfig(folders=None),
        quarantine_folder="Quarantine",
    )

    assert plan.mode == "all"
    assert folder_names(plan) == ("INBOX", "Archive")


def test_configured_inbox_matching_is_case_insensitive() -> None:
    folders = [app.FolderInfo(name="INBOX", flags=set())]

    plan = app.select_scan_folders(
        account=ACCOUNT,
        discovered_folders=folders,
        account_scan_config=app.AccountScanConfig(folders=("inbox",)),
        quarantine_folder="Quarantine",
    )

    assert plan.mode == "configured"
    assert folder_names(plan) == ("INBOX",)


def test_configured_non_inbox_matching_is_exact() -> None:
    folders = [app.FolderInfo(name="[Gmail]/Important", flags=set())]

    plan = app.select_scan_folders(
        account=ACCOUNT,
        discovered_folders=folders,
        account_scan_config=app.AccountScanConfig(folders=("[Gmail]/Important",)),
        quarantine_folder="Quarantine",
    )

    assert folder_names(plan) == ("[Gmail]/Important",)

    with pytest.raises(app.AccountFolderSelectionError, match=r"\[Gmail\]/important"):
        app.select_scan_folders(
            account=ACCOUNT,
            discovered_folders=folders,
            account_scan_config=app.AccountScanConfig(folders=("[Gmail]/important",)),
            quarantine_folder="Quarantine",
        )


def test_missing_configured_folder_reports_available_folders_and_suggestion() -> None:
    folders = [
        app.FolderInfo(name="INBOX", flags=set()),
        app.FolderInfo(name="[Gmail]/Important", flags=set()),
    ]

    with pytest.raises(app.AccountFolderSelectionError) as error_info:
        app.select_scan_folders(
            account=ACCOUNT,
            discovered_folders=folders,
            account_scan_config=app.AccountScanConfig(folders=("Important",)),
            quarantine_folder="Quarantine",
        )

    message = str(error_info.value)
    assert 'missing folder "Important"' in message or "missing folder 'Important'" in message
    assert "Available folders include: INBOX, [Gmail]/Important" in message
    assert "Did you mean [Gmail]/Important?" in message


def test_configured_excluded_folder_is_account_error() -> None:
    folders = [
        app.FolderInfo(name="INBOX", flags=set()),
        app.FolderInfo(name="Spam", flags=set()),
    ]

    with pytest.raises(app.AccountFolderSelectionError, match="excluded folder"):
        app.select_scan_folders(
            account=ACCOUNT,
            discovered_folders=folders,
            account_scan_config=app.AccountScanConfig(folders=("Spam",)),
            quarantine_folder="Quarantine",
        )


def test_describe_folder_scan_plan_reports_configured_list() -> None:
    plan = app.FolderScanPlan(
        mode="configured",
        folders=(app.FolderInfo(name="INBOX", flags=set()),),
    )

    assert app.describe_folder_scan_plan(plan) == "configured list (1 folder): INBOX"


def test_scan_new_messages_uses_preselected_folder_list(monkeypatch: pytest.MonkeyPatch) -> None:
    selected_folders = [app.FolderInfo(name="INBOX", flags=set())]
    selected_names: list[str] = []

    monkeypatch.setattr(
        app,
        "discover_folders",
        lambda _imap: (_ for _ in ()).throw(
            AssertionError("scan_new_messages should use preselected folders")
        ),
    )
    monkeypatch.setattr(
        app,
        "select_folder",
        lambda _imap, folder_name, readonly: selected_names.append(folder_name) or True,
    )
    monkeypatch.setattr(app, "get_uidvalidity", lambda _imap: "1")
    monkeypatch.setattr(app, "search_unseen_uids", lambda _imap: ["100"])
    monkeypatch.setattr(app, "fetch_message_summary", lambda *_args, **_kwargs: make_summary())
    monkeypatch.setattr(app, "fetch_message_body_text", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(app, "move_uid_to_mailbox", lambda *_args, **_kwargs: (True, "moved"))

    messages, folders_state, scanned_count = app.scan_new_messages(
        object(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=make_scanner_rules(always_delete_senders={"sender@example.test"}),
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
        folders_to_scan=selected_folders,
    )

    assert selected_names == ["INBOX"]
    assert scanned_count == 1
    assert len(messages) == 1
    assert folders_state["INBOX"]["processed_uids"] == ["100"]


def test_main_records_folder_selection_error_in_daily_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clear_account_env(monkeypatch)
    accounts_path = tmp_path / "accounts.json"
    accounts_path.write_text(
        json.dumps(
            {
                "gmail_accounts": {
                    "MAIN": {
                        "email": "main@example.test",
                        "app_password": "app-password",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "daily_summary": {
                    "enabled": True,
                    "summary_sender": "gmail:MAIN",
                    "summary_recipients": "owner@example.test",
                    "summary_time": "00:00",
                    "summary_interval_minutes": 15,
                },
                "account_scans": {
                    "gmail:MAIN": {
                        "folders": ["Spam"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    state_path = tmp_path / "state.json"
    monkeypatch.setattr(
        app.sys,
        "argv",
        [
            "email_cleaner.py",
            "--accounts-file",
            str(accounts_path),
            "--config-file",
            str(config_path),
            "--rules-file",
            str(tmp_path / "missing-rules.json"),
            "--state-file",
            str(state_path),
        ],
    )

    class FakeIMAPConnection:
        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _tb):
            return False

        def login(self, _email: str, _password: str):
            return "OK", [b""]

    monkeypatch.setattr(app.imaplib, "IMAP4_SSL", lambda *_args, **_kwargs: FakeIMAPConnection())
    monkeypatch.setattr(app, "ensure_mailbox_exists", lambda _imap, _folder: "Quarantine")
    monkeypatch.setattr(
        app,
        "discover_folders",
        lambda _imap: [
            app.FolderInfo(name="INBOX", flags=set()),
            app.FolderInfo(name="Spam", flags=set()),
        ],
    )
    monkeypatch.setattr(
        app,
        "scan_new_messages",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("scan_new_messages should not run when folder selection fails")
        ),
    )
    monkeypatch.setattr(app, "send_daily_summary_email", lambda *_args, **_kwargs: None)

    assert app.main() == 1

    state = json.loads(state_path.read_text(encoding="utf-8"))
    records = state["daily_summary"]["run_records"]
    assert records[0]["status"] == "error"
    assert records[0]["accounts"]["gmail:MAIN"]["messages_processed"] == 0
    assert records[0]["accounts"]["gmail:MAIN"]["errors"]
    assert "excluded folder" in records[0]["accounts"]["gmail:MAIN"]["errors"][0]
