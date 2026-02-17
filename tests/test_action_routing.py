from __future__ import annotations

import pytest

import email_cleaner as app
from tests.helpers import make_scanner_rules, make_summary


ACCOUNT = app.AccountCredentials(
    provider="yahoo",
    account_key="MAIN",
    email="main@example.test",
    app_password="app-password",
)


class DummyIMAP:
    pass


OPENAI_CONFIG = app.OpenAIConfig(
    enabled=True,
    model="gpt-5-mini",
    api_base_url="https://api.openai.com/v1",
    system_prompt="test prompt",
    confidence_threshold=0.85,
    timeout_seconds=20.0,
    max_body_chars=4000,
    max_subject_chars=300,
)


def patch_common_scan_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    *,
    summary_factory,
    folders: list[app.FolderInfo] | None = None,
    writable: bool = True,
    unseen_uids: list[str] | None = None,
    move_result: tuple[bool, str] = (True, "moved to Quarantine"),
) -> None:
    folder_list = folders or [app.FolderInfo(name="INBOX", flags=set())]
    unread = unseen_uids or ["100"]

    monkeypatch.setattr(app, "discover_folders", lambda _imap: folder_list)
    monkeypatch.setattr(
        app,
        "select_folder",
        lambda _imap, _name, readonly: True if readonly else writable,
    )
    monkeypatch.setattr(app, "get_uidvalidity", lambda _imap: "1")
    monkeypatch.setattr(app, "search_unseen_uids", lambda _imap: unread)
    monkeypatch.setattr(app, "fetch_message_summary", lambda *_args, **_kwargs: summary_factory())
    monkeypatch.setattr(app, "fetch_message_body_text", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(app, "move_uid_to_mailbox", lambda *_args, **_kwargs: move_result)


def test_scan_default_mode_moves_delete_candidate_to_quarantine(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = make_scanner_rules(always_delete_senders={"sender@example.test"})
    patch_common_scan_dependencies(monkeypatch, summary_factory=make_summary)

    messages, folders_state, scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
    )

    assert scanned_count == 1
    assert len(messages) == 1
    assert messages[0].delete_candidate is True
    assert messages[0].action == "QUARANTINED"
    assert messages[0].action_reason == "moved to Quarantine"
    assert folders_state["INBOX"]["processed_uids"] == ["100"]


def test_scan_dry_run_reports_would_quarantine(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = make_scanner_rules(always_delete_senders={"sender@example.test"})
    patch_common_scan_dependencies(monkeypatch, summary_factory=make_summary)

    messages, _folders_state, _scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=False,
        dry_run=True,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=True,
    )

    assert len(messages) == 1
    assert messages[0].action == "WOULD_QUARANTINE"
    assert "would create Quarantine and move message" in messages[0].action_reason


@pytest.mark.parametrize(
    "dry_run,expected_action",
    [
        (False, "HARD_DELETE_NOOP"),
        (True, "WOULD_HARD_DELETE_NOOP"),
    ],
)
def test_scan_hard_delete_uses_noop_actions(
    monkeypatch: pytest.MonkeyPatch,
    dry_run: bool,
    expected_action: str,
) -> None:
    rules = make_scanner_rules(always_delete_senders={"sender@example.test"})

    def fail_if_move_called(*_args, **_kwargs):
        raise AssertionError("move_uid_to_mailbox should not be called in hard-delete mode")

    patch_common_scan_dependencies(monkeypatch, summary_factory=make_summary)
    monkeypatch.setattr(app, "move_uid_to_mailbox", fail_if_move_called)

    messages, _folders_state, _scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=True,
        dry_run=dry_run,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
    )

    assert len(messages) == 1
    assert messages[0].action == expected_action
    assert "hard-delete path not implemented" in messages[0].action_reason


def test_scan_never_filter_overrides_delete_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = make_scanner_rules(
        never_filter_senders={"sender@example.test"},
        always_delete_senders={"sender@example.test"},
    )
    patch_common_scan_dependencies(monkeypatch, summary_factory=make_summary)

    messages, folders_state, _scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
    )

    assert len(messages) == 1
    assert messages[0].never_filter_match is True
    assert messages[0].delete_candidate is False
    assert messages[0].action == "SKIP_NEVER_FILTER"
    assert folders_state["INBOX"]["processed_uids"] == ["100"]


def test_scan_move_failure_keeps_uid_unprocessed(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = make_scanner_rules(always_delete_senders={"sender@example.test"})
    patch_common_scan_dependencies(
        monkeypatch,
        summary_factory=make_summary,
        move_result=(False, "copy failed"),
    )

    messages, folders_state, _scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
    )

    assert len(messages) == 1
    assert messages[0].action == "QUARANTINE_FAILED"
    assert messages[0].action_reason == "copy failed"
    assert folders_state["INBOX"]["processed_uids"] == []


def test_scan_read_only_folder_reports_quarantine_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = make_scanner_rules(always_delete_senders={"sender@example.test"})

    patch_common_scan_dependencies(monkeypatch, summary_factory=make_summary, writable=False)
    monkeypatch.setattr(
        app,
        "move_uid_to_mailbox",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("move_uid_to_mailbox should not be called for read-only folder")
        ),
    )

    messages, folders_state, _scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
    )

    assert len(messages) == 1
    assert messages[0].action == "QUARANTINE_FAILED"
    assert "read-only" in messages[0].action_reason
    assert folders_state["INBOX"]["processed_uids"] == []


def test_scan_skips_bulk_and_quarantine_folders(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = make_scanner_rules(always_delete_senders={"sender@example.test"})
    folders = [
        app.FolderInfo(name="INBOX", flags=set()),
        app.FolderInfo(name="Bulk", flags=set()),
        app.FolderInfo(name="Quarantine", flags=set()),
    ]
    patch_common_scan_dependencies(monkeypatch, summary_factory=make_summary, folders=folders)

    messages, _folders_state, scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
    )

    assert scanned_count == 1
    assert len(messages) == 1
    assert messages[0].folder == "INBOX"


def test_scan_openai_marks_delete_candidate_when_hard_rules_do_not_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rules = make_scanner_rules()
    patch_common_scan_dependencies(monkeypatch, summary_factory=make_summary)
    monkeypatch.setattr(
        app,
        "evaluate_openai_delete_candidate",
        lambda *_args, **_kwargs: app.OpenAIDecision(
            evaluated=True,
            decision="delete_candidate",
            confidence=0.94,
            reason="model=gpt-5-mini;confidence=0.94;codes=bulk_marketing",
            delete_candidate=True,
            reason_codes=("bulk_marketing",),
        ),
    )

    messages, _folders_state, _scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
        openai_config=OPENAI_CONFIG,
        openai_api_key="test-api-key",
    )

    assert len(messages) == 1
    assert messages[0].llm_evaluated is True
    assert messages[0].llm_decision == "delete_candidate"
    assert messages[0].delete_candidate is True
    assert messages[0].delete_reason.startswith("openai.delete_candidate:")
    assert messages[0].action == "QUARANTINED"


def test_scan_openai_not_called_when_hard_rule_already_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = make_scanner_rules(always_delete_senders={"sender@example.test"})
    patch_common_scan_dependencies(monkeypatch, summary_factory=make_summary)
    monkeypatch.setattr(
        app,
        "evaluate_openai_delete_candidate",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("OpenAI should not be called when deterministic rules match")
        ),
    )

    messages, _folders_state, _scanned_count = app.scan_new_messages(
        DummyIMAP(),
        account=ACCOUNT,
        folders_state={},
        max_tracked_uids=5000,
        scanner_rules=rules,
        hard_delete=False,
        dry_run=False,
        quarantine_folder="Quarantine",
        quarantine_will_be_created=False,
        openai_config=OPENAI_CONFIG,
        openai_api_key="test-api-key",
    )

    assert len(messages) == 1
    assert messages[0].delete_candidate is True
    assert messages[0].delete_reason == "always_delete.sender:sender@example.test"
    assert messages[0].llm_evaluated is False
