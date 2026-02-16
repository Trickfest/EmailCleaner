from __future__ import annotations

import json

import pytest

from tests.helpers import make_scanner_rules, make_summary
from yahoo_new_mail_poc import (
    evaluate_auth_triple_fail,
    evaluate_delete_candidate,
    evaluate_malformed_from,
    evaluate_never_filter,
    load_scanner_rules,
)


def test_never_filter_matches_sender_address() -> None:
    rules = make_scanner_rules(never_filter_senders={"sender@example.test"})
    summary = make_summary()

    matched, reason = evaluate_never_filter(
        summary.sender_email,
        summary.sender_domain,
        rules.never_filter,
    )

    assert matched is True
    assert reason == "never_filter.sender:sender@example.test"


def test_never_filter_matches_sender_domain() -> None:
    rules = make_scanner_rules(never_filter_domains={"example.test"})
    summary = make_summary()

    matched, reason = evaluate_never_filter(
        summary.sender_email,
        summary.sender_domain,
        rules.never_filter,
    )

    assert matched is True
    assert reason == "never_filter.domain:example.test"


def test_always_delete_precedence_wins_over_other_delete_rules() -> None:
    rules = make_scanner_rules(
        always_delete_senders={"sender@example.test"},
        from_regex=[r"(?i)sender"],
        subject_regex=[r"(?i)test"],
        body_regex=[r"(?i)gift"],
        auth_triple_fail=True,
        malformed_from=True,
    )
    summary = make_summary(
        authentication_results=(
            "mx.yahoo.com; spf=fail",
            "mx.yahoo.com; dkim=fail",
            "mx.yahoo.com; dmarc=fail",
        ),
        from_header_defects=("InvalidHeaderDefect",),
    )

    matched, reason = evaluate_delete_candidate(summary, "gift", rules)

    assert matched is True
    assert reason == "always_delete.sender:sender@example.test"


def test_auth_triple_fail_requires_exact_fail_values() -> None:
    passing = make_summary(
        authentication_results=(
            "mx.yahoo.com; spf=fail smtp.mailfrom=bad.example",
            "mx.yahoo.com; dkim=fail header.d=bad.example",
            "mx.yahoo.com; dmarc=fail header.from=bad.example",
        )
    )
    mixed = make_summary(
        authentication_results=(
            "mx.yahoo.com; spf=fail",
            "mx.yahoo.com; dkim=fail",
            "mx.yahoo.com; dkim=pass",
            "mx.yahoo.com; dmarc=fail",
        )
    )
    missing = make_summary(
        authentication_results=(
            "mx.yahoo.com; spf=fail",
            "mx.yahoo.com; dkim=fail",
        )
    )

    passing_match, _ = evaluate_auth_triple_fail(passing)
    mixed_match, _ = evaluate_auth_triple_fail(mixed)
    missing_match, _ = evaluate_auth_triple_fail(missing)

    assert passing_match is True
    assert mixed_match is False
    assert missing_match is False


def test_auth_triple_fail_precedence_over_malformed_from() -> None:
    rules = make_scanner_rules(auth_triple_fail=True, malformed_from=True)
    summary = make_summary(
        sender="",
        sender_name="",
        sender_email="",
        sender_domain="",
        authentication_results=(
            "mx.yahoo.com; spf=fail",
            "mx.yahoo.com; dkim=fail",
            "mx.yahoo.com; dmarc=fail",
        ),
        from_header_defects=("InvalidHeaderDefect",),
    )

    matched, reason = evaluate_delete_candidate(summary, "", rules)

    assert matched is True
    assert reason == "delete_patterns.auth_triple_fail:spf=fail,dkim=fail,dmarc=fail"


def test_malformed_from_precedence_over_regex() -> None:
    rules = make_scanner_rules(
        malformed_from=True,
        from_regex=[r"(?i)sender"],
        subject_regex=[r"(?i)test"],
        body_regex=[r"(?i)message"],
    )
    summary = make_summary(from_header_defects=("InvalidHeaderDefect",))

    matched, reason = evaluate_delete_candidate(summary, "message body", rules)

    assert matched is True
    assert reason.startswith("delete_patterns.malformed_from:defects=")


def test_evaluate_malformed_from_matches_when_sender_email_unparsed() -> None:
    summary = make_summary(
        sender="display-name-without-address",
        sender_name="",
        sender_email="",
        sender_domain="",
        from_header_defects=(),
    )

    matched, reason = evaluate_malformed_from(summary)

    assert matched is True
    assert reason == "delete_patterns.malformed_from:no_parsed_sender_email"


def test_from_regex_matches_display_name_and_email() -> None:
    rules = make_scanner_rules(from_regex=[r"(?i)sender", r"example\.test$"])

    by_name = make_summary(sender_name="Special Sender", sender_email="nomatch@other.test")
    by_email = make_summary(sender_name="No Match", sender_email="abc@example.test")

    name_match, name_reason = evaluate_delete_candidate(by_name, "", rules)
    email_match, email_reason = evaluate_delete_candidate(by_email, "", rules)

    assert name_match is True
    assert name_reason.endswith("[sender_name]")
    assert email_match is True
    assert email_reason.endswith("[sender_email]")


def test_subject_and_body_regex_are_applied_with_search_semantics() -> None:
    rules = make_scanner_rules(
        subject_regex=[r"(?i)limited\s+offer"],
        body_regex=[r"(?i)gift\s+card"],
    )

    subject_summary = make_summary(subject="A very LIMITED   OFFER just for you")
    body_summary = make_summary(subject="No subject hit")

    subject_match, subject_reason = evaluate_delete_candidate(subject_summary, "", rules)
    body_match, body_reason = evaluate_delete_candidate(body_summary, "claim your GIFT card now", rules)

    assert subject_match is True
    assert "tests.subject_regex" in subject_reason
    assert body_match is True
    assert "tests.body_regex" in body_reason


def test_load_scanner_rules_reads_malformed_from_boolean(tmp_path) -> None:
    rules_path = tmp_path / "rules.json"
    payload = {
        "delete_patterns": {
            "malformed_from": True,
            "from_regex": [r"(?i)promo"],
        }
    }
    rules_path.write_text(json.dumps(payload), encoding="utf-8")

    rules = load_scanner_rules(rules_path)

    assert rules.delete_patterns.malformed_from is True
    assert len(rules.delete_patterns.from_regex) == 1


def test_load_scanner_rules_reads_quarantine_cleanup_days(tmp_path) -> None:
    rules_path = tmp_path / "rules.json"
    payload = {"quarantine_cleanup_days": 7}
    rules_path.write_text(json.dumps(payload), encoding="utf-8")

    rules = load_scanner_rules(rules_path)

    assert rules.quarantine_cleanup_days == 7


def test_load_scanner_rules_rejects_non_boolean_malformed_from(tmp_path) -> None:
    rules_path = tmp_path / "rules.json"
    payload = {"delete_patterns": {"malformed_from": "yes"}}
    rules_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="delete_patterns.malformed_from"):
        load_scanner_rules(rules_path)


@pytest.mark.parametrize("value", [0, -3, "7", True])
def test_load_scanner_rules_rejects_invalid_quarantine_cleanup_days(tmp_path, value: object) -> None:
    rules_path = tmp_path / "rules.json"
    payload = {"quarantine_cleanup_days": value}
    rules_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="quarantine_cleanup_days"):
        load_scanner_rules(rules_path)
