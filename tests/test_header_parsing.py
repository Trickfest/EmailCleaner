from __future__ import annotations

from pathlib import Path

from email_cleaner import (
    AccountCredentials,
    evaluate_malformed_from,
    fetch_message_summary,
)


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "eml"
ACCOUNT = AccountCredentials(
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
