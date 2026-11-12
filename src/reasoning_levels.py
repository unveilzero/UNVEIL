"""Reasoning effort levels a model accepts, for the chat effort control.

ChatGPT subscription models advertise their own levels. Claude models take
``output_config.effort`` on the Messages API; the levels and defaults below
follow Anthropic's effort documentation as read on 2026-11-12. A model that
is not listed gets no effort control and no effort is sent for it.
"""

from __future__ import annotations

import re
from typing import Optional

_FULL = ("low", "medium", "high", "xhigh", "max")
_CLAUDE_NAME = re.compile(r"^claude-(fable|mythos|opus|sonnet|haiku)-(\d+)(?:-(\d{1,2}))?(?:-|$)")


def claude_effort_metadata(model: str) -> Optional[dict]:
    """Effort levels and API default for a native Claude model id, or None."""
    match = _CLAUDE_NAME.match(str(model or "").strip().lower())
    if not match:
        return None
    family = match.group(1)
    version = (int(match.group(2)), int(match.group(3) or 0))
    levels: tuple[str, ...] = ()
    default = "high"
    if family in {"fable", "mythos"}:
        if version >= (5, 0):
            levels = _FULL
    elif family == "opus":
        if version >= (5, 0) or version == (4, 8):
            levels = _FULL
            if version == (5, 5):
                default = "medium"
        elif version == (4, 7):
            levels = ("low", "medium", "high", "xhigh")
        elif version == (4, 6):
            levels = ("low", "medium", "high", "max")
        elif version == (4, 5):
            levels = ("low", "medium", "high")
    elif family == "sonnet":
        if version >= (5, 0):
            levels = _FULL
        elif version == (4, 6):
            levels = ("low", "medium", "high", "max")
    elif family == "haiku":
        if version >= (5, 5):
            levels = _FULL
            default = "medium"
    if not levels:
        return None
    return {"default_reasoning_level": default, "supported_reasoning_levels": list(levels)}


def model_reasoning_metadata(model: str) -> Optional[dict]:
    """Reasoning metadata for any model the chat effort control supports."""
    from src.chatgpt_subscription import get_chatgpt_model_metadata

    return get_chatgpt_model_metadata(model) or claude_effort_metadata(model)


def validate_reasoning_effort(model: str, effort: Optional[str]) -> Optional[str]:
    """Return the effort if the model accepts it, else None (send no override)."""
    cleaned = str(effort or "").strip().lower()
    if cleaned in {"", "default"}:
        return None
    meta = model_reasoning_metadata(model)
    if not meta:
        return None
    supported = [
        str(level if isinstance(level, str) else level.get("effort", "")).lower()
        for level in meta.get("supported_reasoning_levels", [])
    ]
    return cleaned if cleaned in supported else None
