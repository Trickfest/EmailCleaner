from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import email_cleaner as app
from tests.helpers import make_scanner_rules, make_summary


def clear_account_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_name in list(os.environ):
        if env_name.startswith("EMAIL_CLEANER_YAHOO_") or env_name.startswith("EMAIL_CLEANER_GMAIL_"):
            monkeypatch.delenv(env_name, raising=False)


def make_account() -> app.AccountCredentials:
    return app.AccountCredentials(
        provider="gmail",
        account_key="MAIN",
        email="main@example.test",
        app_password="app-password",
    )


def make_archive_account() -> app.AccountCredentials:
    return app.AccountCredentials(
        provider="yahoo",
        account_key="ARCHIVE",
        email="archive@example.test",
        app_password="app-password",
    )


def test_resolve_daily_summary_sender_account_requires_configured_account() -> None:
    account = make_account()
    config = app.DailySummaryConfig(
        enabled=True,
        summary_sender="gmail:MAIN",
        summary_recipients=("owner@example.test",),
        summary_time="06:00",
        summary_interval_minutes=1440,
    )

    assert app.resolve_daily_summary_sender_account(config, [account]) == account

    missing_config = app.DailySummaryConfig(
        enabled=True,
        summary_sender="yahoo:MAIN",
        summary_recipients=("owner@example.test",),
        summary_time="06:00",
        summary_interval_minutes=1440,
    )
    with pytest.raises(ValueError, match="summary_sender"):
        app.resolve_daily_summary_sender_account(missing_config, [account])


def test_daily_summary_due_on_first_run_after_configured_time() -> None:
    config = app.DailySummaryConfig(
        enabled=True,
        summary_sender="gmail:MAIN",
        summary_recipients=("owner@example.test",),
        summary_time="06:00",
        summary_interval_minutes=15,
    )
    state = app.empty_daily_summary_state()
    before_time = datetime(2026, 5, 17, 5, 59, tzinfo=timezone.utc)
    after_time = datetime(2026, 5, 17, 6, 1, tzinfo=timezone.utc)
    before_interval = datetime(2026, 5, 17, 6, 14, tzinfo=timezone.utc)
    after_interval = datetime(2026, 5, 17, 6, 16, tzinfo=timezone.utc)
    next_day_after_time = datetime(2026, 5, 18, 6, 0, tzinfo=timezone.utc)

    assert app.is_daily_summary_due(config, state, before_time) is False
    assert app.is_daily_summary_due(config, state, after_time) is True

    state["last_sent_at"] = after_time.isoformat()
    state["last_sent_local_date"] = after_time.date().isoformat()
    assert app.is_daily_summary_due(config, state, before_interval) is False
    assert app.is_daily_summary_due(config, state, after_interval) is False
    assert app.is_daily_summary_due(config, state, next_day_after_time) is True


def test_daily_summary_due_uses_local_day_not_rolling_interval() -> None:
    eastern = timezone(timedelta(hours=-4))
    config = app.DailySummaryConfig(
        enabled=True,
        summary_sender="gmail:MAIN",
        summary_recipients=("owner@example.test",),
        summary_time="06:00",
        summary_interval_minutes=1440,
    )
    state = app.empty_daily_summary_state()
    state["last_sent_at"] = datetime(2026, 5, 17, 19, 15, tzinfo=eastern).isoformat()
    state["last_sent_local_date"] = "2026-05-17"

    assert (
        app.is_daily_summary_due(
            config,
            state,
            datetime(2026, 5, 18, 6, 0, tzinfo=eastern),
        )
        is True
    )


def test_daily_summary_due_uses_last_sent_at_when_date_state_missing() -> None:
    config = app.DailySummaryConfig(
        enabled=True,
        summary_sender="gmail:MAIN",
        summary_recipients=("owner@example.test",),
        summary_time="06:00",
        summary_interval_minutes=15,
    )
    state = app.empty_daily_summary_state()
    state["last_sent_local_date"] = ""
    state["last_sent_at"] = datetime(2026, 5, 17, 6, 1, tzinfo=timezone.utc).isoformat()

    assert (
        app.is_daily_summary_due(
            config,
            state,
            datetime(2026, 5, 17, 6, 16, tzinfo=timezone.utc),
        )
        is False
    )


def test_daily_summary_due_honors_legacy_date_state() -> None:
    config = app.DailySummaryConfig(
        enabled=True,
        summary_sender="gmail:MAIN",
        summary_recipients=("owner@example.test",),
        summary_time="06:00",
        summary_interval_minutes=15,
    )
    state = app.empty_daily_summary_state()
    state["last_sent_local_date"] = "2026-05-17"

    assert (
        app.is_daily_summary_due(
            config,
            state,
            datetime(2026, 5, 17, 6, 30, tzinfo=timezone.utc),
        )
        is False
    )
    assert (
        app.is_daily_summary_due(
            config,
            state,
            datetime(2026, 5, 18, 6, 0, tzinfo=timezone.utc),
        )
        is True
    )


def test_build_daily_summary_account_stats_counts_aggregate_actions() -> None:
    quarantined = make_summary()
    quarantined.delete_candidate = True
    quarantined.delete_reason = "always_delete.sender"
    quarantined.action = "QUARANTINED"
    llm_delete = make_summary()
    llm_delete.delete_candidate = True
    llm_delete.llm_evaluated = True
    llm_delete.llm_decision = "delete_candidate"
    llm_delete.action = "QUARANTINED"
    llm_error = make_summary()
    llm_error.llm_evaluated = True
    llm_error.llm_decision = "error"
    cleanup_result = app.QuarantineCleanupResult(
        status="OK",
        configured_days=30,
        cutoff_date="17-Apr-2026",
        matched_count=2,
        deleted_count=2,
        would_delete_count=0,
        store_failed_count=0,
        detail="",
    )

    stats = app.build_daily_summary_account_stats(
        account=make_account(),
        messages=[quarantined, llm_delete, llm_error],
        scanned_folder_count=3,
        cleanup_result=cleanup_result,
        quarantine_folder_messages=5,
    )

    assert stats.messages_processed == 3
    assert stats.delete_candidates == 2
    assert stats.quarantined == 2
    assert stats.llm_evaluated == 2
    assert stats.llm_delete_candidates == 1
    assert stats.llm_failures == 1
    assert stats.cleanup_deleted == 2
    assert stats.quarantine_folder_messages == 5


def test_print_report_distinguishes_move_count_from_current_quarantine_count(
    capsys: pytest.CaptureFixture[str],
) -> None:
    message = make_summary()
    message.delete_candidate = True
    message.delete_reason = "always_delete.sender"
    message.action = "QUARANTINED"
    cleanup_result = app.QuarantineCleanupResult(
        status="OK",
        configured_days=7,
        cutoff_date="10-May-2026",
        matched_count=3,
        deleted_count=3,
        would_delete_count=0,
        store_failed_count=0,
        detail="",
    )

    app.print_report(
        account=make_account(),
        messages=[message],
        scanned_folder_count=1,
        scanner_rules=make_scanner_rules(quarantine_cleanup_days=7),
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
        cleanup_result=cleanup_result,
        openai_config=None,
        quarantine_folder_messages=2,
    )

    output = capsys.readouterr().out
    assert "Moved to Quarantine message(s): 1 (target folder: Quarantine)" in output
    assert "Quarantine cleanup deleted: 3 message(s)." in output
    assert "Quarantine folder now contains: 2 message(s)." in output
    assert "Quarantined message(s):" not in output


def test_format_daily_summary_body_includes_zero_report_for_all_accounts() -> None:
    now = datetime(2026, 5, 17, 6, 5, tzinfo=timezone.utc)

    body = app.format_daily_summary_body(
        daily_summary_state=app.empty_daily_summary_state(),
        accounts=[make_account()],
        window_start=now - timedelta(hours=24),
        window_end=now,
    )

    assert "Messages processed: 0" in body
    assert "Moved to Quarantine: 0" in body
    assert "Quarantine folder after latest cleanup: unknown" in body
    assert "gmail:MAIN (main@example.test)" in body
    assert "Errors:\n  None" in body


def test_format_daily_summary_body_uses_multiline_account_sections() -> None:
    main_account = make_account()
    archive_account = make_archive_account()
    state = app.empty_daily_summary_state()
    run_started = datetime(2026, 5, 17, 5, 30, tzinfo=timezone.utc)
    run_ended = datetime(2026, 5, 17, 5, 45, tzinfo=timezone.utc)
    app.append_daily_summary_run_record(
        state,
        app.DailySummaryRunRecord(
            started_at=run_started.isoformat(timespec="seconds"),
            ended_at=run_ended.isoformat(timespec="seconds"),
            status="success",
            exit_code=0,
            accounts={
                "gmail:MAIN": app.DailySummaryAccountStats(
                    provider="gmail",
                    account_key="MAIN",
                    email="main@example.test",
                    scanned_folders=3,
                    messages_processed=31,
                    delete_candidates=8,
                    quarantined=8,
                    quarantine_failures=0,
                    llm_evaluated=12,
                    llm_delete_candidates=3,
                    llm_failures=1,
                    cleanup_deleted=2,
                    cleanup_failures=0,
                    errors=(),
                    quarantine_folder_messages=7,
                ),
                "yahoo:ARCHIVE": app.DailySummaryAccountStats(
                    provider="yahoo",
                    account_key="ARCHIVE",
                    email="archive@example.test",
                    scanned_folders=2,
                    messages_processed=16,
                    delete_candidates=4,
                    quarantined=4,
                    quarantine_failures=0,
                    llm_evaluated=6,
                    llm_delete_candidates=2,
                    llm_failures=2,
                    cleanup_deleted=1,
                    cleanup_failures=0,
                    errors=("folder scan failed: SELECT_FAILED",),
                    quarantine_folder_messages=3,
                ),
            },
            errors=(),
        ),
        now=run_ended,
    )

    body = app.format_daily_summary_body(
        daily_summary_state=state,
        accounts=[main_account, archive_account],
        window_start=datetime(2026, 5, 16, 6, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 5, 17, 6, 0, tzinfo=timezone.utc),
    )

    assert body == (
        "EmailCleaner summary\n"
        "Window: 2026-05-16T06:00:00+00:00 to 2026-05-17T06:00:00+00:00\n"
        "Runs included: 1\n"
        "Status: errors detected\n"
        "\n"
        "Totals:\n"
        "  Messages processed: 47\n"
        "  Delete candidates: 12\n"
        "  Moved to Quarantine: 12\n"
        "  Quarantine failures: 0\n"
        "  OpenAI evaluated: 18\n"
        "  OpenAI delete candidates: 5\n"
        "  OpenAI failures: 3\n"
        "  Quarantine cleanup deleted: 3\n"
        "  Quarantine cleanup failures: 0\n"
        "  Quarantine folder after latest cleanup: 10\n"
        "\n"
        "Per account:\n"
        "  gmail:MAIN (main@example.test)\n"
        "    Messages processed: 31\n"
        "    Delete candidates: 8\n"
        "    Moved to Quarantine: 8\n"
        "    Quarantine failures: 0\n"
        "    OpenAI evaluated: 12\n"
        "    OpenAI delete candidates: 3\n"
        "    OpenAI failures: 1\n"
        "    Quarantine cleanup deleted: 2\n"
        "    Quarantine cleanup failures: 0\n"
        "    Quarantine folder after cleanup: 7\n"
        "  yahoo:ARCHIVE (archive@example.test)\n"
        "    Messages processed: 16\n"
        "    Delete candidates: 4\n"
        "    Moved to Quarantine: 4\n"
        "    Quarantine failures: 0\n"
        "    OpenAI evaluated: 6\n"
        "    OpenAI delete candidates: 2\n"
        "    OpenAI failures: 2\n"
        "    Quarantine cleanup deleted: 1\n"
        "    Quarantine cleanup failures: 0\n"
        "    Quarantine folder after cleanup: 3\n"
        "\n"
        "Errors:\n"
        "  - 2026-05-17T05:45:00+00:00: yahoo:ARCHIVE: folder scan failed: SELECT_FAILED\n"
    )


def test_daily_summary_uses_latest_quarantine_folder_count_not_sum() -> None:
    account = make_account()
    state = app.empty_daily_summary_state()
    first_run = datetime(2026, 5, 17, 5, 30, tzinfo=timezone.utc)
    second_run = datetime(2026, 5, 17, 5, 45, tzinfo=timezone.utc)

    for ended_at, moved_count, folder_count in (
        (first_run, 5, 10),
        (second_run, 1, 6),
    ):
        app.append_daily_summary_run_record(
            state,
            app.DailySummaryRunRecord(
                started_at=(ended_at - timedelta(minutes=5)).isoformat(timespec="seconds"),
                ended_at=ended_at.isoformat(timespec="seconds"),
                status="success",
                exit_code=0,
                accounts={
                    "gmail:MAIN": app.DailySummaryAccountStats(
                        provider="gmail",
                        account_key="MAIN",
                        email="main@example.test",
                        scanned_folders=1,
                        messages_processed=moved_count,
                        delete_candidates=moved_count,
                        quarantined=moved_count,
                        quarantine_failures=0,
                        llm_evaluated=0,
                        llm_delete_candidates=0,
                        llm_failures=0,
                        cleanup_deleted=0,
                        cleanup_failures=0,
                        errors=(),
                        quarantine_folder_messages=folder_count,
                    )
                },
                errors=(),
            ),
            now=ended_at,
        )

    body = app.format_daily_summary_body(
        daily_summary_state=state,
        accounts=[account],
        window_start=datetime(2026, 5, 17, 5, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 5, 17, 6, 0, tzinfo=timezone.utc),
    )

    assert "Moved to Quarantine: 6" in body
    assert "Quarantine folder after latest cleanup: 6" in body
    assert "Quarantine folder after latest cleanup: 16" not in body


def test_send_daily_summary_email_uses_configured_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    account = make_account()
    config = app.DailySummaryConfig(
        enabled=True,
        summary_sender="gmail:MAIN",
        summary_recipients=("owner@example.test", "backup@example.test"),
        summary_time="06:00",
        summary_interval_minutes=15,
    )
    sent_messages = []
    smtp_calls = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            smtp_calls.append((host, port, timeout))

        def __enter__(self) -> "FakeSMTP":
            return self

        def __exit__(self, *_args) -> None:
            return None

        def login(self, email: str, app_password: str) -> None:
            smtp_calls.append(("login", email, app_password))

        def send_message(self, message) -> None:
            sent_messages.append(message)

    monkeypatch.setattr(app.smtplib, "SMTP_SSL", FakeSMTP)

    app.send_daily_summary_email(
        daily_summary_config=config,
        sender_account=account,
        accounts=[account],
        daily_summary_state=app.empty_daily_summary_state(),
        now=datetime(2026, 5, 17, 6, 5, tzinfo=timezone.utc),
    )

    assert smtp_calls[0][0] == "smtp.gmail.com"
    assert smtp_calls[1] == ("login", "main@example.test", "app-password")
    assert sent_messages[0]["From"] == "main@example.test"
    assert sent_messages[0]["To"] == "owner@example.test, backup@example.test"
    body = sent_messages[0].get_content()
    assert "Window: 2026-05-17T05:50:00+00:00 to 2026-05-17T06:05:00+00:00" in body
    assert "Messages processed: 0" in body


def test_main_records_and_sends_daily_summary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
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
                }
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
        lambda _imap: [app.FolderInfo(name="INBOX", flags=set())],
    )

    message = make_summary()
    message.account_provider = "gmail"
    message.account_key = "MAIN"
    message.account_email = "main@example.test"
    message.delete_candidate = True
    message.delete_reason = "always_delete.sender"
    message.action = "QUARANTINED"
    monkeypatch.setattr(
        app,
        "scan_new_messages",
        lambda *_args, **_kwargs: (
            [message],
            {"INBOX": {"uidvalidity": "1", "processed_uids": ["100"]}},
            1,
        ),
    )
    monkeypatch.setattr(
        app,
        "cleanup_quarantine_messages",
        lambda *_args, **_kwargs: app.QuarantineCleanupResult(
            status="DISABLED",
            configured_days=None,
            cutoff_date=None,
            matched_count=0,
            deleted_count=0,
            would_delete_count=0,
            store_failed_count=0,
            detail="",
        ),
    )
    monkeypatch.setattr(app, "count_mailbox_messages", lambda *_args, **_kwargs: 2)

    sent_messages = []

    class FakeSMTP:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self) -> "FakeSMTP":
            return self

        def __exit__(self, *_args) -> None:
            return None

        def login(self, _email: str, _app_password: str) -> None:
            return None

        def send_message(self, message) -> None:
            sent_messages.append(message)

    monkeypatch.setattr(app.smtplib, "SMTP_SSL", FakeSMTP)

    assert app.main() == 0

    state = json.loads(state_path.read_text(encoding="utf-8"))
    records = state["daily_summary"]["run_records"]
    assert len(records) == 1
    assert records[0]["accounts"]["gmail:MAIN"]["messages_processed"] == 1
    assert records[0]["accounts"]["gmail:MAIN"]["quarantined"] == 1
    assert records[0]["accounts"]["gmail:MAIN"]["quarantine_folder_messages"] == 2
    assert state["daily_summary"]["last_sent_at"]
    assert state["daily_summary"]["last_sent_local_date"]
    assert len(sent_messages) == 1
    body = sent_messages[0].get_content()
    assert "Messages processed: 1" in body
    assert "Moved to Quarantine: 1" in body
    assert "Quarantine folder after latest cleanup: 2" in body
