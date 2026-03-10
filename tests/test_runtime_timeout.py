from __future__ import annotations

from pathlib import Path

import pytest

import email_cleaner as app
from tests.helpers import make_scanner_rules, make_summary


class DummyIMAP:
    pass


def test_runtime_budget_disabled_allows_unbounded_run() -> None:
    budget = app.RuntimeBudget(max_runtime_seconds=0, started_epoch_seconds=0.0)
    assert budget.enabled() is False
    assert budget.remaining_seconds() is None
    budget.ensure_within_limit("test")


def test_runtime_budget_raises_when_elapsed_exceeds_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app.time, "time", lambda: 12.0)
    budget = app.RuntimeBudget(max_runtime_seconds=5, started_epoch_seconds=0.0)
    with pytest.raises(app.RuntimeLimitExceeded):
        budget.ensure_within_limit("test_checkpoint")


def test_scan_new_messages_raises_when_runtime_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        app,
        "discover_folders",
        lambda _imap: [app.FolderInfo(name="INBOX", flags=set())],
    )
    monkeypatch.setattr(app, "select_folder", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(app, "get_uidvalidity", lambda _imap: "1")
    monkeypatch.setattr(app, "search_unseen_uids", lambda _imap: ["100"])
    monkeypatch.setattr(app, "fetch_message_summary", lambda *_args, **_kwargs: make_summary())
    monkeypatch.setattr(app.time, "time", lambda: 2.0)

    runtime_budget = app.RuntimeBudget(max_runtime_seconds=1, started_epoch_seconds=0.0)
    with pytest.raises(app.RuntimeLimitExceeded):
        app.scan_new_messages(
            DummyIMAP(),
            account=app.AccountCredentials(
                provider="gmail",
                account_key="MAIN",
                email="main@example.test",
                app_password="app-password",
            ),
            folders_state={},
            max_tracked_uids=5000,
            scanner_rules=make_scanner_rules(),
            hard_delete=False,
            dry_run=False,
            quarantine_folder="Quarantine",
            quarantine_will_be_created=False,
            runtime_budget=runtime_budget,
        )


def test_main_returns_timeout_exit_code_and_writes_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_path = tmp_path / "state.json"
    monkeypatch.setattr(
        app.sys,
        "argv",
        [
            "email_cleaner.py",
            "--state-file",
            str(state_path),
            "--max-runtime-seconds",
            "1",
        ],
    )

    account = app.AccountCredentials(
        provider="gmail",
        account_key="MAIN",
        email="main@example.test",
        app_password="app-password",
    )
    monkeypatch.setattr(app, "resolve_accounts", lambda _path: [account])
    monkeypatch.setattr(
        app,
        "filter_accounts",
        lambda accounts, provider_filter, account_key_filter: accounts,
    )
    monkeypatch.setattr(app, "load_state", lambda _path: {})

    class FakeIMAPConnection:
        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _tb):
            return False

        def login(self, _email: str, _password: str):
            return "OK", [b""]

    imap_calls: list[dict[str, object]] = []

    def fake_imap4_ssl(*_args, **kwargs):
        imap_calls.append(kwargs)
        return FakeIMAPConnection()

    monkeypatch.setattr(app.imaplib, "IMAP4_SSL", fake_imap4_ssl)
    monkeypatch.setattr(app, "ensure_mailbox_exists", lambda _imap, _folder: "Quarantine")
    monkeypatch.setattr(
        app,
        "scan_new_messages",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            app.RuntimeLimitExceeded("runtime limit reached during test")
        ),
    )

    save_calls: list[tuple[Path, dict[str, dict[str, dict[str, object]]], list[app.AccountCredentials]]] = []

    def fake_save_state(
        path: Path,
        accounts_state: dict[str, dict[str, dict[str, object]]],
        accounts: list[app.AccountCredentials],
    ) -> None:
        save_calls.append((path, accounts_state, accounts))

    monkeypatch.setattr(app, "save_state", fake_save_state)

    exit_code = app.main()
    assert exit_code == app.EXIT_TIMEOUT
    assert len(imap_calls) == 1
    assert 0 < imap_calls[0]["timeout"] <= app.DEFAULT_IMAP_TIMEOUT_SECONDS
    assert len(save_calls) == 1
    saved_path, _saved_state, saved_accounts = save_calls[0]
    assert saved_path == state_path
    assert [account.account_key for account in saved_accounts] == ["MAIN"]
