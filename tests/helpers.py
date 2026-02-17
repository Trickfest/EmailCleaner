from __future__ import annotations

from email_cleaner import (
    AlwaysDeleteRules,
    DeletePatternRules,
    MessageSummary,
    NeverFilterRules,
    ScannerRules,
    compile_regex_rules,
)


def make_scanner_rules(
    *,
    never_filter_senders: set[str] | None = None,
    never_filter_domains: set[str] | None = None,
    always_delete_senders: set[str] | None = None,
    always_delete_domains: set[str] | None = None,
    from_regex: list[str] | None = None,
    subject_regex: list[str] | None = None,
    body_regex: list[str] | None = None,
    auth_triple_fail: bool = False,
    malformed_from: bool = False,
    quarantine_cleanup_days: int | None = None,
) -> ScannerRules:
    return ScannerRules(
        never_filter=NeverFilterRules(
            senders=never_filter_senders or set(),
            domains=never_filter_domains or set(),
        ),
        always_delete=AlwaysDeleteRules(
            senders=always_delete_senders or set(),
            domains=always_delete_domains or set(),
        ),
        delete_patterns=DeletePatternRules(
            from_regex=compile_regex_rules(from_regex or [], "tests.from_regex"),
            subject_regex=compile_regex_rules(subject_regex or [], "tests.subject_regex"),
            body_regex=compile_regex_rules(body_regex or [], "tests.body_regex"),
            auth_triple_fail=auth_triple_fail,
            malformed_from=malformed_from,
        ),
        quarantine_cleanup_days=quarantine_cleanup_days,
    )


def make_summary(
    *,
    sender: str = "Sender <sender@example.test>",
    sender_name: str = "Sender",
    sender_email: str = "sender@example.test",
    sender_domain: str = "example.test",
    subject: str = "Test message",
    authentication_results: tuple[str, ...] = (),
    from_header_defects: tuple[str, ...] = (),
) -> MessageSummary:
    return MessageSummary(
        account_provider="yahoo",
        account_key="MAIN",
        account_email="main@example.test",
        folder="INBOX",
        uid="100",
        sender=sender,
        sender_name=sender_name,
        sender_email=sender_email,
        sender_domain=sender_domain,
        recipient="recipient@example.test",
        subject=subject,
        date="Mon, 16 Feb 2026 10:00:00 -0500",
        message_id="<msg-100@example.test>",
        authentication_results=authentication_results,
        from_header_defects=from_header_defects,
        size_bytes=1024,
        never_filter_match=False,
        never_filter_reason="",
        delete_candidate=False,
        delete_reason="",
        llm_evaluated=False,
        llm_decision="",
        llm_confidence=None,
        llm_reason="",
        action="NONE",
        action_reason="",
    )
