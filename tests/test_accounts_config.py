from __future__ import annotations

import json
import os

import pytest

import email_cleaner as app


def clear_account_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for env_name in list(os.environ):
        if env_name.startswith("EMAIL_CLEANER_YAHOO_") or env_name.startswith("EMAIL_CLEANER_GMAIL_"):
            monkeypatch.delenv(env_name, raising=False)


def test_resolve_accounts_reads_yahoo_and_gmail_sections(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    clear_account_env(monkeypatch)
    accounts_path = tmp_path / "accounts.json"
    accounts_path.write_text(
        json.dumps(
            {
                "yahoo_accounts": {
                    "MAIN": {
                        "email": "main@yahoo.com",
                        "app_password": "yahoo-app-password",
                    }
                },
                "gmail_accounts": {
                    "MAIN": {
                        "email": "main@gmail.com",
                        "app_password": "gmail-app-password",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    accounts = app.resolve_accounts(accounts_path)
    actual = {(account.provider, account.account_key, account.email) for account in accounts}

    assert actual == {
        ("yahoo", "MAIN", "main@yahoo.com"),
        ("gmail", "MAIN", "main@gmail.com"),
    }


def test_resolve_accounts_reads_gmail_from_env(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    clear_account_env(monkeypatch)
    monkeypatch.setenv("EMAIL_CLEANER_GMAIL_EMAIL_MAIN", "main@gmail.com")
    monkeypatch.setenv("EMAIL_CLEANER_GMAIL_APP_PASSWORD_MAIN", "gmail-app-password")

    accounts = app.resolve_accounts(tmp_path / "does-not-exist.json")

    assert len(accounts) == 1
    assert accounts[0].provider == "gmail"
    assert accounts[0].account_key == "MAIN"
    assert accounts[0].email == "main@gmail.com"


def test_resolve_accounts_reports_missing_field_with_provider(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    clear_account_env(monkeypatch)
    monkeypatch.setenv("EMAIL_CLEANER_GMAIL_EMAIL_MAIN", "main@gmail.com")

    with pytest.raises(ValueError, match=r"gmail\.MAIN"):
        app.resolve_accounts(tmp_path / "does-not-exist.json")


def test_resolve_imap_host_defaults_and_override() -> None:
    assert app.resolve_imap_host("yahoo", "") == "imap.mail.yahoo.com"
    assert app.resolve_imap_host("gmail", "") == "imap.gmail.com"
    assert app.resolve_imap_host("gmail", "imap.custom.example") == "imap.custom.example"
    with pytest.raises(ValueError, match="Unsupported provider"):
        app.resolve_imap_host("icloud", "")


def test_save_state_namespaces_by_provider_and_account(tmp_path) -> None:
    state_path = tmp_path / "state.json"
    accounts = [
        app.AccountCredentials(
            provider="yahoo",
            account_key="MAIN",
            email="main@yahoo.com",
            app_password="yahoo-app-password",
        ),
        app.AccountCredentials(
            provider="gmail",
            account_key="MAIN",
            email="main@gmail.com",
            app_password="gmail-app-password",
        ),
    ]
    accounts_state = {
        "yahoo:MAIN": {"INBOX": {"uidvalidity": "1", "processed_uids": ["101"]}},
        "gmail:MAIN": {"INBOX": {"uidvalidity": "2", "processed_uids": ["202"]}},
    }

    app.save_state(state_path, accounts_state, accounts)

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["accounts"]["yahoo:MAIN"]["provider"] == "yahoo"
    assert payload["accounts"]["yahoo:MAIN"]["account_key"] == "MAIN"
    assert payload["accounts"]["gmail:MAIN"]["provider"] == "gmail"
    assert payload["accounts"]["gmail:MAIN"]["account_key"] == "MAIN"

    loaded = app.load_state(state_path)
    assert loaded == accounts_state


def test_filter_accounts_by_provider_and_account_key() -> None:
    accounts = [
        app.AccountCredentials(
            provider="yahoo",
            account_key="MAIN",
            email="main@yahoo.com",
            app_password="yahoo-app-password",
        ),
        app.AccountCredentials(
            provider="gmail",
            account_key="MAIN",
            email="main@gmail.com",
            app_password="gmail-app-password",
        ),
        app.AccountCredentials(
            provider="gmail",
            account_key="ALT",
            email="alt@gmail.com",
            app_password="gmail-app-password-2",
        ),
    ]

    provider_only = app.filter_accounts(accounts, provider_filter="gmail", account_key_filter="")
    assert {(account.provider, account.account_key) for account in provider_only} == {
        ("gmail", "ALT"),
        ("gmail", "MAIN"),
    }

    provider_and_key = app.filter_accounts(
        accounts,
        provider_filter="gmail",
        account_key_filter="main",
    )
    assert len(provider_and_key) == 1
    assert provider_and_key[0].provider == "gmail"
    assert provider_and_key[0].account_key == "MAIN"


def test_filter_accounts_reports_no_match_with_filters() -> None:
    accounts = [
        app.AccountCredentials(
            provider="yahoo",
            account_key="MAIN",
            email="main@yahoo.com",
            app_password="yahoo-app-password",
        )
    ]

    with pytest.raises(ValueError, match="No accounts matched"):
        app.filter_accounts(accounts, provider_filter="gmail", account_key_filter="MAIN")
