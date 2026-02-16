from __future__ import annotations

import yahoo_new_mail_poc as app


class CleanupIMAP:
    def __init__(
        self,
        *,
        search_status: str = "OK",
        search_uids: bytes = b"",
        store_fail_uids: set[str] | None = None,
        expunge_status: str = "OK",
    ) -> None:
        self.search_status = search_status
        self.search_uids = search_uids
        self.store_fail_uids = store_fail_uids or set()
        self.expunge_status = expunge_status
        self.store_calls: list[str] = []
        self.search_calls: list[tuple[object, ...]] = []
        self.expunge_calls = 0

    def uid(self, command: str, *args):
        if command == "SEARCH":
            self.search_calls.append(args)
            return self.search_status, [self.search_uids]
        if command == "STORE":
            uid = str(args[0])
            self.store_calls.append(uid)
            if uid in self.store_fail_uids:
                return "NO", [b"store failed"]
            return "OK", [b""]
        raise AssertionError(f"Unsupported UID command in test fake: {command}")

    def expunge(self):
        self.expunge_calls += 1
        return self.expunge_status, [b""]


def test_quarantine_cleanup_disabled(monkeypatch) -> None:
    imap = CleanupIMAP()
    monkeypatch.setattr(app, "find_mailbox_name", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("find_mailbox_name should not be called when cleanup is disabled")
    ))

    result = app.cleanup_quarantine_messages(
        imap,
        quarantine_folder="Quarantine",
        cleanup_days=None,
        dry_run=False,
    )

    assert result.status == "DISABLED"
    assert result.configured_days is None
    assert result.matched_count == 0


def test_quarantine_cleanup_skips_when_mailbox_missing(monkeypatch) -> None:
    imap = CleanupIMAP()
    monkeypatch.setattr(app, "find_mailbox_name", lambda *_args, **_kwargs: None)

    result = app.cleanup_quarantine_messages(
        imap,
        quarantine_folder="Quarantine",
        cleanup_days=7,
        dry_run=False,
    )

    assert result.status == "MAILBOX_MISSING"
    assert result.configured_days == 7
    assert result.matched_count == 0


def test_quarantine_cleanup_dry_run_reports_would_delete(monkeypatch) -> None:
    imap = CleanupIMAP(search_uids=b"10 11 12")
    monkeypatch.setattr(app, "find_mailbox_name", lambda *_args, **_kwargs: "Quarantine")
    monkeypatch.setattr(app, "select_folder", lambda *_args, **_kwargs: True)

    result = app.cleanup_quarantine_messages(
        imap,
        quarantine_folder="Quarantine",
        cleanup_days=7,
        dry_run=True,
    )

    assert result.status == "OK"
    assert result.matched_count == 3
    assert result.would_delete_count == 3
    assert result.deleted_count == 0
    assert imap.store_calls == []
    assert imap.expunge_calls == 0
    assert imap.search_calls


def test_quarantine_cleanup_deletes_messages_and_tracks_partial_failures(monkeypatch) -> None:
    imap = CleanupIMAP(search_uids=b"10 11 12", store_fail_uids={"11"})
    monkeypatch.setattr(app, "find_mailbox_name", lambda *_args, **_kwargs: "Quarantine")
    monkeypatch.setattr(app, "select_folder", lambda *_args, **_kwargs: True)

    result = app.cleanup_quarantine_messages(
        imap,
        quarantine_folder="Quarantine",
        cleanup_days=7,
        dry_run=False,
    )

    assert result.status == "OK"
    assert result.matched_count == 3
    assert result.deleted_count == 2
    assert result.store_failed_count == 1
    assert imap.expunge_calls == 1


def test_quarantine_cleanup_reports_expunge_failure(monkeypatch) -> None:
    imap = CleanupIMAP(search_uids=b"10", expunge_status="NO")
    monkeypatch.setattr(app, "find_mailbox_name", lambda *_args, **_kwargs: "Quarantine")
    monkeypatch.setattr(app, "select_folder", lambda *_args, **_kwargs: True)

    result = app.cleanup_quarantine_messages(
        imap,
        quarantine_folder="Quarantine",
        cleanup_days=7,
        dry_run=False,
    )

    assert result.status == "EXPUNGE_FAILED"
    assert result.matched_count == 1
