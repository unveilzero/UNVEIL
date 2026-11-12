"""Effort levels offered and sent for Claude models."""

import pytest

from src.llm_core import _build_anthropic_payload
from src.reasoning_levels import claude_effort_metadata, model_reasoning_metadata, validate_reasoning_effort

FULL = ["low", "medium", "high", "xhigh", "max"]
MESSAGES = [{"role": "user", "content": "hi"}]


@pytest.mark.parametrize("model, levels, default", [
    ("claude-fable-5-2", FULL, "high"),
    ("claude-fable-5", FULL, "high"),
    ("claude-opus-5-5", FULL, "medium"),
    ("claude-sonnet-5-5", FULL, "high"),
    ("claude-haiku-5-5", FULL, "medium"),
    ("claude-opus-4-7", ["low", "medium", "high", "xhigh"], "high"),
    ("claude-opus-4-6", ["low", "medium", "high", "max"], "high"),
    ("claude-sonnet-4-6", ["low", "medium", "high", "max"], "high"),
    ("claude-opus-4-5-20251101", ["low", "medium", "high"], "high"),
])
def test_claude_models_with_effort_support(model, levels, default):
    meta = claude_effort_metadata(model)
    assert meta == {"default_reasoning_level": default, "supported_reasoning_levels": levels}


@pytest.mark.parametrize("model", [
    "claude-haiku-4-5-20251001", "claude-sonnet-4-5-20250929", "claude-sonnet-4-20250514",
    "anthropic/claude-fable-5.2", "gpt-4o", "kimi-k3.1-pro", "", None,
])
def test_models_without_effort_support_get_no_control(model):
    assert claude_effort_metadata(model) is None
    assert validate_reasoning_effort(model, "low") is None


def test_validation_accepts_only_levels_the_model_lists():
    assert validate_reasoning_effort("claude-haiku-5-5", " LOW ") == "low"
    assert validate_reasoning_effort("claude-opus-4-6", "xhigh") is None
    assert validate_reasoning_effort("claude-opus-4-7", "max") is None
    assert validate_reasoning_effort("claude-fable-5-2", "default") is None
    assert validate_reasoning_effort("claude-fable-5-2", "extreme") is None
    assert validate_reasoning_effort("claude-fable-5-2", None) is None


def test_chatgpt_subscription_levels_still_resolve():
    from src.chatgpt_subscription import get_chatgpt_model_metadata

    for model in ("gpt-5-codex", "gpt-5.1-codex", "gpt-5"):
        assert model_reasoning_metadata(model) == get_chatgpt_model_metadata(model)


def test_payload_carries_the_chosen_effort():
    payload = _build_anthropic_payload("claude-fable-5-2", MESSAGES, 0.5, 1024, reasoning_effort="low")
    assert payload["output_config"] == {"effort": "low"}
    streamed = _build_anthropic_payload("claude-haiku-5-5", MESSAGES, 0.5, 1024, stream=True, reasoning_effort="High")
    assert streamed["output_config"] == {"effort": "high"} and streamed["stream"] is True


@pytest.mark.parametrize("model, effort", [
    ("claude-fable-5-2", None), ("claude-fable-5-2", ""), ("claude-fable-5-2", "default"),
    ("claude-fable-5-2", "none"), ("claude-opus-4-6", "xhigh"), ("claude-haiku-4-5-20251001", "low"),
    ("some-proxy-model", "low"),
])
def test_payload_omits_effort_when_unset_or_unsupported(model, effort):
    payload = _build_anthropic_payload(model, MESSAGES, 0.5, 1024, reasoning_effort=effort)
    assert "output_config" not in payload


def test_payload_is_unchanged_for_callers_that_pass_no_effort():
    assert _build_anthropic_payload("claude-fable-5-2", MESSAGES, 0.5, 1024) == \
        _build_anthropic_payload("claude-fable-5-2", MESSAGES, 0.5, 1024, reasoning_effort=None)
