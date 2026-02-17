from __future__ import annotations

import json

import pytest

import email_cleaner as app
from tests.helpers import make_summary


def make_openai_config(*, threshold: float = 0.85) -> app.OpenAIConfig:
    return app.OpenAIConfig(
        enabled=True,
        model="gpt-5-mini",
        api_base_url="https://api.openai.com/v1",
        system_prompt="test prompt",
        confidence_threshold=threshold,
        timeout_seconds=20.0,
        max_body_chars=4000,
        max_subject_chars=300,
    )


def make_app_config(*, max_tracked_uids: int = 5000) -> app.AppConfig:
    return app.AppConfig(
        openai=make_openai_config(),
        max_tracked_uids=max_tracked_uids,
    )


class FakeHTTPResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, *_args) -> None:
        return None


def test_load_app_config_defaults_when_file_missing(tmp_path) -> None:
    config = app.load_app_config(tmp_path / "does-not-exist.json")

    assert config.openai.enabled is False
    assert config.openai.model == "gpt-5-mini"
    assert config.openai.confidence_threshold == 0.85
    assert config.openai.system_prompt
    assert config.max_tracked_uids == 5000


def test_load_app_config_reads_openai_section(tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "max_tracked_uids": 1200,
                "openai": {
                    "enabled": True,
                    "model": "gpt-5-mini",
                    "api_base_url": "https://api.openai.com/v1",
                    "system_prompt": "custom spam classifier prompt",
                    "confidence_threshold": 0.92,
                    "timeout_seconds": 12,
                    "max_body_chars": 2500,
                    "max_subject_chars": 200,
                }
            }
        ),
        encoding="utf-8",
    )

    config = app.load_app_config(config_path)

    assert config.openai.enabled is True
    assert config.openai.system_prompt == "custom spam classifier prompt"
    assert config.openai.confidence_threshold == 0.92
    assert config.openai.timeout_seconds == 12
    assert config.openai.max_body_chars == 2500
    assert config.openai.max_subject_chars == 200
    assert config.max_tracked_uids == 1200


@pytest.mark.parametrize(
    "payload,match",
    [
        ({"openai": {"confidence_threshold": 1.1}}, "openai.confidence_threshold"),
        ({"openai": {"timeout_seconds": 0}}, "openai.timeout_seconds"),
        ({"openai": {"max_body_chars": 0}}, "openai.max_body_chars"),
        ({"openai": {"enabled": "yes"}}, "openai.enabled"),
        ({"openai": {"system_prompt": 42}}, "openai.system_prompt"),
        ({"max_tracked_uids": 0}, "max_tracked_uids"),
        ({"max_tracked_uids": "1000"}, "max_tracked_uids"),
    ],
)
def test_load_app_config_rejects_invalid_values(tmp_path, payload: dict[str, object], match: str) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=match):
        app.load_app_config(config_path)


def test_resolve_effective_max_tracked_uids_uses_config_when_cli_not_set() -> None:
    effective = app.resolve_effective_max_tracked_uids(
        cli_max_tracked_uids=None,
        app_config=make_app_config(max_tracked_uids=2345),
        argv=["--config-file", "config.json"],
    )

    assert effective == 2345


def test_resolve_effective_max_tracked_uids_prefers_cli_when_set() -> None:
    effective = app.resolve_effective_max_tracked_uids(
        cli_max_tracked_uids=999,
        app_config=make_app_config(max_tracked_uids=2345),
        argv=["--max-tracked-uids", "999"],
    )

    assert effective == 999


def test_resolve_effective_max_tracked_uids_clamps_cli_value() -> None:
    effective = app.resolve_effective_max_tracked_uids(
        cli_max_tracked_uids=0,
        app_config=make_app_config(max_tracked_uids=2345),
        argv=["--max-tracked-uids=0"],
    )

    assert effective == 1


def test_resolve_openai_api_key_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        app.resolve_openai_api_key(make_openai_config())


def test_evaluate_openai_delete_candidate_applies_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_api_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "decision": "delete_candidate",
                            "confidence": 0.91,
                            "reason_codes": ["bulk_marketing"],
                            "rationale": "bulk pattern",
                        }
                    )
                }
            }
        ]
    }
    monkeypatch.setattr(
        app.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: FakeHTTPResponse(fake_api_response),
    )

    decision = app.evaluate_openai_delete_candidate(
        make_summary(),
        "body text",
        make_openai_config(threshold=0.85),
        "test-api-key",
    )

    assert decision.evaluated is True
    assert decision.decision == "delete_candidate"
    assert decision.delete_candidate is True
    assert decision.reason_codes == ("bulk_marketing",)


def test_evaluate_openai_delete_candidate_does_not_send_temperature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_api_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "decision": "keep",
                            "confidence": 0.2,
                            "reason_codes": ["legit_sender"],
                            "rationale": "looks legitimate",
                        }
                    )
                }
            }
        ]
    }
    captured_request_payload: dict[str, object] = {}

    def fake_urlopen(request, **_kwargs):
        nonlocal captured_request_payload
        request_body = request.data.decode("utf-8")
        captured_request_payload = json.loads(request_body)
        return FakeHTTPResponse(fake_api_response)

    monkeypatch.setattr(app.urllib.request, "urlopen", fake_urlopen)

    _decision = app.evaluate_openai_delete_candidate(
        make_summary(),
        "body text",
        make_openai_config(threshold=0.85),
        "test-api-key",
    )

    assert "temperature" not in captured_request_payload
    messages = captured_request_payload.get("messages")
    assert isinstance(messages, list) and messages
    assert messages[0]["role"] == "system"
    assert messages[0]["content"] == "test prompt"


def test_evaluate_openai_delete_candidate_below_threshold_keeps(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_api_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "decision": "delete_candidate",
                            "confidence": 0.4,
                            "reason_codes": ["possible_marketing"],
                            "rationale": "uncertain",
                        }
                    )
                }
            }
        ]
    }
    monkeypatch.setattr(
        app.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: FakeHTTPResponse(fake_api_response),
    )

    decision = app.evaluate_openai_delete_candidate(
        make_summary(),
        "body text",
        make_openai_config(threshold=0.85),
        "test-api-key",
    )

    assert decision.evaluated is True
    assert decision.decision == "delete_candidate"
    assert decision.delete_candidate is False
    assert decision.reason.startswith("below_threshold:")
