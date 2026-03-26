from __future__ import annotations

from pathlib import Path

import email_cleaner as app
from email_cleaner import (
    AccountCredentials,
    evaluate_malformed_from,
    fetch_message_summary,
)


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "eml"
ACCOUNT = AccountCredentials(
    provider="yahoo",
    account_key="MAIN",
    email="main@example.test",
    app_password="app-password",
)


class HeaderFetchIMAP:
    def __init__(self, headers_raw: bytes, status: str = "OK") -> None:
        self.headers_raw = headers_raw
        self.status = status

    def uid(self, command: str, uid: str, _query: str):
        if command != "FETCH":
            return "NO", []
        meta = f"{uid} (RFC822.SIZE {len(self.headers_raw)})".encode("ascii")
        return self.status, [(meta, self.headers_raw)]


def fixture_bytes(name: str) -> bytes:
    return (FIXTURE_DIR / name).read_bytes()


def test_fetch_message_summary_marks_missing_from_header() -> None:
    imap = HeaderFetchIMAP(fixture_bytes("malformed_from_missing.eml"))

    summary = fetch_message_summary(imap, ACCOUNT, "INBOX", "101")

    assert summary is not None
    assert summary.sender == ""
    assert summary.sender_email == ""
    assert summary.from_header_defects == ("MissingFromHeader",)

    malformed_match, malformed_reason = evaluate_malformed_from(summary)
    assert malformed_match is True
    assert malformed_reason == "delete_patterns.malformed_from:defects=MissingFromHeader"


def test_fetch_message_summary_captures_from_header_defects() -> None:
    imap = HeaderFetchIMAP(fixture_bytes("malformed_from_bad_quote.eml"))

    summary = fetch_message_summary(imap, ACCOUNT, "INBOX", "102")

    assert summary is not None
    assert summary.from_header_defects
    assert "InvalidHeaderDefect" in summary.from_header_defects

    malformed_match, malformed_reason = evaluate_malformed_from(summary)
    assert malformed_match is True
    assert malformed_reason.startswith("delete_patterns.malformed_from:defects=")


def test_fetch_message_summary_parses_normal_sender() -> None:
    imap = HeaderFetchIMAP(fixture_bytes("normal_sender.eml"))

    summary = fetch_message_summary(imap, ACCOUNT, "INBOX", "103")

    assert summary is not None
    assert summary.sender_name == "Jane Sender"
    assert summary.sender_email == "jane.sender@example.test"
    assert summary.sender_domain == "example.test"
    assert summary.from_header_defects == ()
    assert summary.size_bytes is not None


def test_fetch_message_summary_reads_authentication_results() -> None:
    imap = HeaderFetchIMAP(fixture_bytes("auth_triple_fail.eml"))

    summary = fetch_message_summary(imap, ACCOUNT, "INBOX", "104")

    assert summary is not None
    assert len(summary.authentication_results) == 3
    assert any("spf=fail" in header for header in summary.authentication_results)
    assert any("dkim=fail" in header for header in summary.authentication_results)
    assert any("dmarc=fail" in header for header in summary.authentication_results)


def test_fetch_message_summary_uses_raw_header_values_for_non_from_fields(
    monkeypatch,
) -> None:
    class FakeFromHeader:
        defects: tuple[object, ...] = ()

    class FakeMessage:
        def __getitem__(self, name: str):
            if name == "From":
                return FakeFromHeader()
            raise KeyError(name)

        def raw_items(self):
            return [
                ("From", "Test Sender <sender@example.test>"),
                ("To", "dest@example.test"),
                ("Subject", "Hello"),
                ("Date", "Thu, 26 Mar 2026 14:44:00 -0400"),
                (
                    "Message-ID",
                    "<[aunu_4].NNKKM.X8EVWC5CI9OCZMYGQE5TCP2AZC5OTDRYQWAMIN"
                    ".nkz1tsrz-8164-ykri-kwfj-xmhc2toiuymi@goodiesmail.com>",
                ),
                ("Authentication-Results", "mx.yahoo.com; spf=fail"),
            ]

        def get(self, _name: str, _default=None):
            raise AssertionError("fetch_message_summary should use raw header access")

        def get_all(self, _name: str, _default=None):
            raise AssertionError("fetch_message_summary should use raw header access")

    class FakeParser:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def parsebytes(self, _headers_raw: bytes) -> FakeMessage:
            return FakeMessage()

    monkeypatch.setattr(app, "BytesParser", FakeParser)
    imap = HeaderFetchIMAP(fixture_bytes("normal_sender.eml"))

    summary = fetch_message_summary(imap, ACCOUNT, "INBOX", "105")

    assert summary is not None
    assert summary.sender_email == "sender@example.test"
    assert summary.recipient == "dest@example.test"
    assert summary.subject == "Hello"
    assert summary.message_id.startswith("<[aunu_4].NNKKM.")
    assert summary.authentication_results == ("mx.yahoo.com; spf=fail",)
