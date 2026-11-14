"""UNVEIL guard: ARAD runtime monitoring for every tool call, and text checks.

Every tool call the agent runtime dispatches is described to ARAD's
``RuntimeEffectMonitor`` before it runs. The monitor decides ALLOW or BLOCK
from an allowlist, from blocked action sequences correlated per session and
per owner, and from its own timing and capacity rules. Each decision is
written to a hash-chained audit log.

A person's message is read by the text checks before a model sees it, and
so is outside content: the result of each tool call, the text of an
attachment, web search results and linked pages added in chat mode, video
transcripts and comments, the open document, email text, a research page,
and the result of a call to an outside tool server. A text whose wording
matches a rule is refused or withheld, and that decision is written to the
same audit log. The person sees the rule and the wording. An item that came
with a person's request is kept for a short time, and the person it belongs
to can release that one item.

This layer is additive. It runs after the application's own request
authority and approval checks and can only deny, never grant.

The guard always enforces: a BLOCK decision stops the call. There is no
setting that turns enforcement off.

Configuration (environment):

``UNVEIL_GUARD_PROFILE``  ``standard`` (default) or ``strict``.
``UNVEIL_GUARD_WINDOW``   Correlation window in seconds (default 300).
``UNVEIL_AUDIT_KEY``      Audit log key. If unset, a key file is created in
                          the data directory.
"""

from __future__ import annotations

import contextvars
import hashlib
import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Optional

from .arad.runtime_monitor import RuntimeEffectMonitor
from .text_checks import find_rule

logger = logging.getLogger("unveil.guard")

# Action names reported to the monitor.
OUTBOUND = "OUTBOUND"
SECRET_READ = "SECRET_READ"
PRIVATE_READ = "PRIVATE_READ"
EXECUTE = "EXECUTE"
ADMIN_CHANGE = "ADMIN_CHANGE"
WRITE = "WRITE"
READ = "READ"
OTHER = "TOOL"
# Source name of a person's message in the text checks.
MESSAGE = "message"
ALL_ACTIONS = (OUTBOUND, SECRET_READ, PRIVATE_READ, EXECUTE, ADMIN_CHANGE, WRITE, READ, OTHER)
# Second halves of a pair are evaluated first, so a blocked call records nothing.
_EVALUATION_ORDER = (OUTBOUND, EXECUTE, ADMIN_CHANGE, WRITE, OTHER, READ, PRIVATE_READ, SECRET_READ)

PROFILES = {
    # Reading credential material and then sending anything out.
    "standard": ((SECRET_READ, OUTBOUND),),
    # Also: reading any private user data and then sending anything out.
    "strict": ((SECRET_READ, OUTBOUND), (PRIVATE_READ, OUTBOUND)),
}

_SECRET_PATTERN = re.compile(
    r"(\.env\b|\.ssh\b|id_rsa|id_ed25519|\.pem\b|\.aws\b|\.gnupg|\.netrc|\.npmrc|\.pypirc|keychain|"
    r"credentials?\b|secrets?\b|api[_-]?keys?\b|access[_-]?tokens?\b|private[_-]?key|passwd\b|shadow\b|"
    r"wallet\.dat|auth\.json|audit\.key|\.kube/config)",
    re.IGNORECASE,
)
_NETWORK_PATTERN = re.compile(
    r"(\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bnetcat\b|\bssh\b|\bscp\b|\bsftp\b|\brsync\b|\bftp\b|\btelnet\b|"
    r"https?://|\brequests\.|\burllib\b|\bhttpx\b|\baiohttp\b|\bsocket\b|\bsmtplib\b|\bparamiko\b|"
    r"\bfetch\(|\bgit\s+push\b|\bdig\b|\bnslookup\b)",
    re.IGNORECASE,
)
_SECRET_TOOLS = frozenset({"manage_tokens"})
# Looking around. A command that sweeps the machine for credential material,
# dumps the whole environment, or probes the host and its network is refused
# on its own, before anything is read. Searches inside the workspace are not
# affected.
_WIDE_SEARCH_PATTERN = re.compile(
    r"\b(find|locate|grep\s+-\w*[rR]\w*|rg|ag|ack|ls\s+-\w*R\w*|tree|du|tar|zip)\b[^\n;|&]*?"
    r"(?<![\w./-])(/|~|\$HOME|/(?:home|root|etc|var|proc|sys|app|opt|mnt|srv|usr|run)(?:/[^\s;|&]*)?)(?=\s|$|[;|&])",
)
_ENV_DUMP_PATTERN = re.compile(
    r"((^|[;&|`(]\s*)(printenv|env|export\s+-p|declare\s+-x)\s*($|[;&|)>])"
    r"|/proc/(self|\d+|\*)/environ"
    r"|\b(print|dict|str|repr|list|sorted|json\.dumps|pprint)\(\s*os\.environ\s*[),]"
    r"|\bos\.environ\.(items|copy|values)\("
    r"|\b(console\.log|JSON\.stringify)\(\s*process\.env\s*[),])",
    re.IGNORECASE | re.MULTILINE,
)
_CREDENTIAL_WORD_PATTERN = re.compile(r"\b(passwords?|tokens?|bearer|cookies?)\b", re.IGNORECASE)
_HOST_PROBE_PATTERN = re.compile(
    r"(169\.254\.169\.254|metadata\.google\.internal|docker\.sock|"
    r"\b(nmap|masscan|zmap|arp-scan|netdiscover)\b)",
    re.IGNORECASE,
)
# Human authority. Agents may never change the application's own code, the
# login store, or this security layer; and a change to the application's
# settings needs a human's approval of that exact action, whatever approval
# mode is configured.
_PROTECTED_PATTERN = re.compile(
    r"(unveil_guard|unveil_security_routes|tool_execution\.py|mcp_manager\.py|auth\.json|audit\.key|"
    r"guard_audit\.jsonl|audit_anchor\.json|UNVEIL_GUARD_|UNVEIL_AUDIT_KEY|UNVEIL_WATCH_|UNVEIL_ROOM_|command_room|"
    r"unveil/security)",
    re.IGNORECASE,
)
_APP_ROOT = str(Path(__file__).resolve().parents[2])
_CHANGING_ACTIONS = frozenset({"WRITE", "EXECUTE", "ADMIN_CHANGE"})
# Tools that change how the application itself is configured or reached.
_HUMAN_APPROVAL_TOOLS = frozenset({
    "manage_settings", "manage_tokens", "manage_mcp", "manage_endpoints", "manage_webhooks",
})
# How long a withheld tool result is kept for the person to release, and how many are kept.
RELEASE_SECONDS = 900
MAX_HELD_RESULTS = 20
# How long the status stays "blocked" after the latest block.
RECENT_BLOCK_SECONDS = 600

_in_guarded_call: contextvars.ContextVar[bool] = contextvars.ContextVar("unveil_in_guarded_call", default=False)


def _data_dir() -> Path:
    from src.constants import DATA_DIR
    path = Path(DATA_DIR) / "unveil"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _digest(text: Any) -> str:
    return hashlib.sha256((text if isinstance(text, str) else "").encode("utf-8", "replace")).hexdigest()[:12]


def _strings(value: Any):
    """Yield each string inside a tool result."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _load_key(directory: Path) -> bytes:
    supplied = os.getenv("UNVEIL_AUDIT_KEY", "").strip()
    if supplied:
        return hashlib.sha256(supplied.encode("utf-8")).digest()
    key_file = directory / "audit.key"
    if not key_file.exists():
        key_file.touch(mode=0o600)
        key_file.write_bytes(secrets.token_bytes(32))
    key = key_file.read_bytes()
    if len(key) < 16:
        raise RuntimeError("UNVEIL audit key file is too short; remove it to regenerate")
    return key


def classify(tool: str, content: str) -> tuple[str, ...]:
    """Map one tool call onto the monitor's action names."""
    actions: set[str] = set()
    try:
        from src.tool_capabilities import ToolEffect, capabilities_for_action
        effects = capabilities_for_action(tool, content).effects
    except Exception:  # classification must never stop the guard from deciding
        effects, ToolEffect = frozenset(), None
    if ToolEffect is not None:
        if effects & {ToolEffect.NETWORK_EGRESS, ToolEffect.EXTERNAL_SIDE_EFFECT}:
            actions.add(OUTBOUND)
        if ToolEffect.READ_PRIVATE in effects:
            actions.add(PRIVATE_READ)
        if ToolEffect.EXECUTE_CODE in effects:
            actions.add(EXECUTE)
        if ToolEffect.ADMIN_CHANGE in effects:
            actions.add(ADMIN_CHANGE)
        if effects & {ToolEffect.WRITE_WORKSPACE, ToolEffect.WRITE_PRIVATE, ToolEffect.DESTRUCTIVE}:
            actions.add(WRITE)
        if effects & {ToolEffect.READ_PUBLIC, ToolEffect.READ_WORKSPACE, ToolEffect.BROKERED_NETWORK_READ}:
            actions.add(READ)
    text = content if isinstance(content, str) else ""
    if tool.startswith("mcp__"):
        actions.add(OUTBOUND)
    if tool in _SECRET_TOOLS or _SECRET_PATTERN.search(text):
        actions.add(SECRET_READ)
    if EXECUTE in actions and _NETWORK_PATTERN.search(text):
        actions.add(OUTBOUND)
    if not actions:
        actions.add(OTHER)
    return tuple(action for action in _EVALUATION_ORDER if action in actions)


class GuardDecision:
    __slots__ = ("allowed", "reason", "actions")

    def __init__(self, allowed: bool, reason: str, actions: tuple[str, ...]):
        self.allowed, self.reason, self.actions = allowed, reason, actions

    @property
    def blocked(self) -> bool:
        return not self.allowed


class UnveilGuard:
    def __init__(self, directory: Optional[Path] = None, *,
                 profile: Optional[str] = None, window: Optional[float] = None,
                 key: Optional[bytes] = None, clock=time.time):
        self.directory = Path(directory) if directory is not None else _data_dir()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.profile = (profile or os.getenv("UNVEIL_GUARD_PROFILE") or "standard").strip().lower()
        if self.profile not in PROFILES:
            raise ValueError(f"UNVEIL_GUARD_PROFILE must be one of {sorted(PROFILES)}")
        self.window = float(window if window is not None else (os.getenv("UNVEIL_GUARD_WINDOW") or "300"))
        self.sequences = PROFILES[self.profile]
        self._clock = clock
        self.audit_path = self.directory / "guard_audit.jsonl"
        self.monitor = RuntimeEffectMonitor(
            {action: {"*"} for action in ALL_ACTIONS},
            audit_log_path=self.audit_path,
            blocked_action_sequences=self.sequences,
            correlation_window_seconds=self.window,
            audit_key=key if key is not None else _load_key(self.directory),
            max_timestamp_skew_seconds=120,
        )
        self._lock = threading.Lock()
        self._eval_lock = threading.Lock()
        self._last_timestamp = 0.0
        self._recent: deque[dict] = deque(maxlen=200)
        self._counts = {"allowed": 0, "blocked": 0}
        self._held: dict[str, dict] = {}
        self._lockdown: Optional[str] = None
        self.started_at = clock()

    # -- lockdown ---------------------------------------------------------
    @property
    def lockdown(self) -> Optional[str]:
        return self._lockdown

    def enter_lockdown(self, reason: str) -> None:
        if self._lockdown is None:
            logger.critical("UNVEIL guard lockdown: %s", reason)
            self._lockdown = reason
            self._remember("LOCKDOWN", (), "BLOCK", reason, "system", "")

    def clear_lockdown(self) -> None:
        self._lockdown = None

    # -- decisions --------------------------------------------------------
    def _remember(self, tool, actions, decision, reason, agent, session_id, owner=None, **extra) -> None:
        with self._lock:
            self._recent.appendleft({
                "at": self._clock(), "tool": tool, "actions": list(actions), "decision": decision,
                "reason": reason, "agent": agent, "session": (session_id or "")[:12], "owner": owner or "", **extra,
            })

    def _audit_block(self, reason: str, event: dict) -> None:
        self.monitor.audit_log.append("runtime_effect_decision", {
            "decision": "BLOCK", "reason": reason, "event": event})

    @staticmethod
    def _human_authority_violation(tool: str, actions: tuple[str, ...], content: str,
                                   human_approved: bool) -> Optional[str]:
        if not _CHANGING_ACTIONS.intersection(actions):
            return None
        text = content if isinstance(content, str) else ""
        if _PROTECTED_PATTERN.search(text) or _APP_ROOT in text:
            return "protected_resource"
        if tool in _HUMAN_APPROVAL_TOOLS and ADMIN_CHANGE in actions and not human_approved:
            return "human_authorization_required"
        return None

    def check(self, tool: str, content: str, *, owner: Optional[str], session_id: Optional[str],
              system: bool = False, human_approved: bool = False) -> GuardDecision:
        """Decide one tool call. Raises nothing; an internal failure is a BLOCK."""
        actions: tuple[str, ...] = ()
        agent = f"system:{owner or 'server'}" if system else f"session:{session_id or 'none'}"
        try:
            if self._lockdown is not None:
                try:
                    with self._eval_lock:
                        self._audit_block("lockdown", {
                            "trace_id": session_id or agent, "agent_id": agent, "action": "LOCKDOWN",
                            "resource": tool})
                except Exception:
                    logger.exception("UNVEIL guard could not record a lockdown refusal")
                self._remember(tool, actions, "BLOCK", "lockdown", agent, session_id, owner)
                self._counts["blocked"] += 1
                return GuardDecision(False, f"lockdown:{self._lockdown}", actions)
            actions = classify(tool, content)
            verdict, reason = "ALLOW", "allowed_by_policy"
            present = set(actions)
            violation = (self._human_authority_violation(tool, actions, content, human_approved)
                         or self._looking_around(actions, content))
            if violation:
                verdict, reason = "BLOCK", violation
            for first, second in self.sequences:
                if verdict == "ALLOW" and first in present and second in present:
                    verdict, reason = "BLOCK", f"correlated_actions:{first}->{second}:same_call"
            # One decision at a time, with a clock that never runs backwards, so
            # concurrent calls cannot trip the monitor's ordering checks.
            with self._eval_lock:
                self._last_timestamp = max(self._clock(), self._last_timestamp)
                event = {
                    "trace_id": session_id or agent, "agent_id": agent,
                    "resource": f"{tool}#{_digest(content)}", "timestamp": self._last_timestamp,
                }
                if owner:
                    event["parent_agent_id"] = f"owner:{owner}"
                if verdict == "BLOCK":
                    self._audit_block(reason, dict(event, action="+".join(actions)))
                else:
                    for action in actions:
                        result = self.monitor.evaluate_event(dict(event, action=action))
                        if result["decision"] != "ALLOW":
                            verdict, reason = "BLOCK", result["reason"]
                            break
        except Exception as error:  # an internal failure is a BLOCK
            logger.exception("UNVEIL guard failure")
            verdict, reason = "BLOCK", f"guard_error:{type(error).__name__}"
        allowed = verdict == "ALLOW"
        self._counts["allowed" if allowed else "blocked"] += 1
        self._remember(tool, actions, verdict, reason, agent, session_id, owner)
        return GuardDecision(allowed, reason, actions)

    def check_text(self, source: str, text: str, *, owner: Optional[str], session_id: Optional[str],
                   held: Optional[tuple] = None) -> GuardDecision:
        """Decide one text before a model reads it. Raises nothing; an internal failure is a BLOCK.

        ``source`` is ``MESSAGE`` for a person's message, or the name of the tool or path the text came from.
        ``held`` is the key and the content of that item, kept so the person can release it.
        """
        agent = f"session:{session_id or 'none'}"
        shown: dict[str, str] = {}
        try:
            finding = find_rule(text if isinstance(text, str) else "", content=source != MESSAGE)
            if finding is None:
                return GuardDecision(True, "allowed_by_policy", ())
            reason = f"text_check:{finding.rule}"
            event = {"trace_id": session_id or agent, "agent_id": agent, "action": "TEXT",
                     "resource": f"{source}#{_digest(text)}"}
            if owner:
                event["parent_agent_id"] = f"owner:{owner}"
            self._audit_block(reason, event)
            shown["excerpt"] = finding.excerpt
            if held is not None:
                shown["release_id"] = self._hold(source, held, owner, session_id)
        except Exception as error:  # an internal failure is a BLOCK
            logger.exception("UNVEIL guard failure")
            reason = f"guard_error:{type(error).__name__}"
        self._counts["blocked"] += 1
        self._remember(source, (), "BLOCK", reason, agent, session_id, owner, **shown)
        return GuardDecision(False, reason, ())

    # -- release by a person ---------------------------------------------
    def _hold(self, tool: str, held: tuple, owner: Optional[str], session_id: Optional[str]) -> str:
        content, output = held
        now = self._clock()
        release_id = secrets.token_urlsafe(16)
        with self._lock:
            for expired in [key for key, entry in self._held.items() if entry["expires"] <= now]:
                del self._held[expired]
            while len(self._held) >= MAX_HELD_RESULTS:
                del self._held[next(iter(self._held))]
            self._held[release_id] = {
                "call": (owner or "", session_id or "", tool, _digest(content)), "output": output,
                "expires": now + RELEASE_SECONDS, "released": False,
            }
        return release_id

    def release(self, release_id: str, owner: str) -> bool:
        """A person releases one withheld result. Only the person it belongs to can do it, one time."""
        with self._lock:
            entry = self._held.get(release_id)
            if entry is None or entry["released"] or entry["expires"] <= self._clock() or entry["call"][0] != owner:
                return False
            self.monitor.audit_log.append("runtime_effect_decision", {
                "decision": "ALLOW", "reason": "released_by_person",
                "event": {"trace_id": entry["call"][1], "agent_id": f"owner:{owner}", "action": "RELEASE",
                          "resource": f"{entry['call'][2]}#{entry['call'][3]}"}})
            entry["released"] = True
            for row in self._recent:
                if row.get("release_id") == release_id:
                    row["released"] = True
        return True

    def take_released(self, tool: str, content: str, *, owner: Optional[str], session_id: Optional[str]):
        """Return the output a person released for this exact call, one time, or None."""
        call = (owner or "", session_id or "", tool, _digest(content))
        with self._lock:
            for release_id, entry in self._held.items():
                if entry["released"] and entry["call"] == call and entry["expires"] > self._clock():
                    del self._held[release_id]
                    return entry["output"]
        return None

    @staticmethod
    def _looking_around(actions: tuple[str, ...], content: str) -> Optional[str]:
        """A command whose purpose is to map the machine or collect credentials."""
        if EXECUTE not in actions:
            return None
        text = content if isinstance(content, str) else ""
        if _ENV_DUMP_PATTERN.search(text) or _HOST_PROBE_PATTERN.search(text):
            return "environment_scan"
        looks_for_credentials = _SECRET_PATTERN.search(text) or _CREDENTIAL_WORD_PATTERN.search(text)
        if looks_for_credentials and _WIDE_SEARCH_PATTERN.search(text):
            return "environment_scan"
        return None

    # -- reporting --------------------------------------------------------
    def status(self, *, limit: int = 25) -> dict[str, Any]:
        with self._lock:
            recent = list(self._recent)[:limit]
        last_block = next((row for row in recent if row["decision"] == "BLOCK"), None)
        return self.describe({
            "mode": "enforce", "profile": self.profile, "window_seconds": self.window,
            "lockdown": self._lockdown, "counts": dict(self._counts),
            "last_block": last_block, "recent": recent, "started_at": self.started_at,
        })

    def describe(self, report: dict[str, Any]) -> dict[str, Any]:
        """Set ``state`` from the lockdown flag and the most recent block in ``report``."""
        last_block = report.get("last_block")
        recent_block = last_block is not None and self._clock() - last_block["at"] < RECENT_BLOCK_SECONDS
        report["state"] = "blocked" if report.get("lockdown") or recent_block else "cleared"
        return report


_guard: Optional[UnveilGuard] = None
_guard_lock = threading.Lock()


def get_guard() -> UnveilGuard:
    global _guard
    if _guard is None:
        with _guard_lock:
            if _guard is None:
                _guard = UnveilGuard()
    return _guard


def reset_guard_for_tests(guard: Optional[UnveilGuard] = None) -> None:
    global _guard
    _guard = guard


_REASON_TEXT = {
    "protected_resource": "agents cannot change the application's code, logins or security layer",
    "human_authorization_required": "this settings change needs a person to approve this exact action",
}


def guard_tool_call(tool: str, content: str, *, owner: Optional[str], session_id: Optional[str],
                    human_approved: bool = False):
    """Gate used by the tool dispatcher. Returns None to proceed, or a blocked result tuple."""
    try:
        decision = get_guard().check(tool, content, owner=owner, session_id=session_id,
                                     human_approved=human_approved)
    except Exception as error:  # the guard could not even be built: fail closed
        logger.exception("UNVEIL guard unavailable")
        return f"{tool}: BLOCKED", {
            "error": f"UNVEIL guard is unavailable ({type(error).__name__}); the action was not run.",
            "exit_code": 1, "blocked": True, "failure_kind": "unveil_guard_denied", "policy": "unveil_guard",
        }
    if not decision.blocked:
        return None
    detail = _REASON_TEXT.get(decision.reason)
    return f"{tool}: BLOCKED", {
        "error": f"Blocked by the UNVEIL security layer (ARAD): {decision.reason}" + (f" ({detail})" if detail else ""),
        "exit_code": 1, "blocked": True, "failure_kind": "unveil_guard_denied",
        "policy": "unveil_guard", "unveil_reason": decision.reason,
    }


def guard_message(text: str, *, owner: Optional[str], session_id: Optional[str]) -> Optional[str]:
    """Gate used where a person's message enters. Returns None to proceed, or the refusal text."""
    try:
        decision = get_guard().check_text(MESSAGE, text, owner=owner, session_id=session_id)
    except Exception as error:  # the guard could not even be built: fail closed
        logger.exception("UNVEIL guard unavailable")
        return f"UNVEIL guard is unavailable ({type(error).__name__}); the message was not sent to the model."
    if not decision.blocked:
        return None
    return f"Blocked by the UNVEIL security layer ({decision.reason}). The message was not sent to the model."


def _read_content(source: str, output: Any, held: Optional[tuple], *, owner: Optional[str],
                  session_id: Optional[str], take_released: bool = False) -> Optional[str]:
    """Read outside content before a model gets it. Returns None to pass it on, or the reason it is withheld."""
    try:
        guard = get_guard()
        if take_released and guard.take_released(source, held[0], owner=owner, session_id=session_id):
            return None
        decision = guard.check_text(source, "\n".join(_strings(output)), owner=owner, session_id=session_id, held=held)
        return decision.reason if decision.blocked else None
    except Exception as error:  # the guard could not even be built: fail closed
        logger.exception("UNVEIL guard unavailable")
        return f"guard_unavailable:{type(error).__name__}"


def guard_content(source: str, output: Any, *, owner: Optional[str], session_id: Optional[str],
                  key: Optional[str] = None) -> Optional[str]:
    """Read outside content before a model gets it. Returns None to pass it on, or the reason it is withheld.

    ``source`` names where the content came from. With ``key``, the content is kept for a short time and the
    person can release it; ``released_tool_result(source, key)`` then returns it.
    """
    return _read_content(source, output, None if key is None else (key, output), owner=owner, session_id=session_id)


def guard_outside_text(source: str, text: str, *, owner: Optional[str], session_id: Optional[str]) -> Optional[str]:
    """Read outside text that came with a person's request. Returns None to pass it on, or the reason it is withheld.

    The text is kept for a short time. After the person releases it, the same text passes one time.
    """
    return _read_content(source, text, (text, text), owner=owner, session_id=session_id, take_released=True)


def withheld_notice(item: str, reason: str) -> str:
    """The words that tell a person or a model that the guard withheld an item the person can release."""
    return (f"{item}: withheld by the UNVEIL security layer ({reason}). It was not given to the model. The person "
            "can read the reason in the UNVEIL security panel and release it there, and then send the request again.")


def guard_tool_result(tool: str, content: str, output: tuple, *, owner: Optional[str], session_id: Optional[str]):
    """Gate used by the tool dispatcher after a tool ran. Returns None to pass the output on, or a withheld result tuple."""
    reason = guard_content(tool, output, owner=owner, session_id=session_id, key=content)
    if reason is None:
        return None
    return f"{tool}: BLOCKED", {
        "error": f"Withheld by the UNVEIL security layer ({reason}). The action ran, but its result was not given "
                 "to the model. The person can read the reason in the UNVEIL security panel and release this one "
                 "result there. After that, the same call returns the result.",
        "exit_code": 1, "blocked": True, "failure_kind": "unveil_guard_denied",
        "policy": "unveil_guard", "unveil_reason": reason,
    }


def released_tool_result(tool: str, content: str, *, owner: Optional[str], session_id: Optional[str]):
    """Returns the output a person released for this call or this content, one time, or None."""
    return get_guard().take_released(tool, content, owner=owner, session_id=session_id)


def guarded_call():
    """Context marker: tool calls made inside it were already decided by the dispatcher gate."""
    class _Marker:
        def __enter__(self_inner):
            self_inner.token = _in_guarded_call.set(True)

        def __exit__(self_inner, *exc):
            _in_guarded_call.reset(self_inner.token)
    return _Marker()


def guard_direct_mcp_call(qualified_name: str, arguments: Any) -> Optional[dict]:
    """Gate for calls to outside tool servers that do not come through the dispatcher."""
    if _in_guarded_call.get():
        return None
    try:
        content = repr(sorted(arguments.items())) if isinstance(arguments, dict) else repr(arguments)
        decision = get_guard().check(qualified_name, content, owner=None, session_id=None, system=True)
    except Exception as error:
        logger.exception("UNVEIL guard unavailable")
        return {"error": f"UNVEIL guard is unavailable ({type(error).__name__}); the call was not made.",
                "exit_code": 1, "blocked": True, "failure_kind": "unveil_guard_denied"}
    if not decision.blocked:
        return None
    return {"error": f"Blocked by the UNVEIL security layer (ARAD): {decision.reason}",
            "exit_code": 1, "blocked": True, "failure_kind": "unveil_guard_denied"}


def guard_direct_mcp_result(qualified_name: str, result: Any) -> Optional[dict]:
    """Gate for the result of a call to an outside tool server that did not come through the dispatcher."""
    if _in_guarded_call.get():
        return None
    reason = guard_content(qualified_name, result, owner=None, session_id=None)
    if reason is None:
        return None
    return {"error": f"Withheld by the UNVEIL security layer ({reason}). The call ran, but its result was not "
                     "given to the model.",
            "exit_code": 1, "blocked": True, "failure_kind": "unveil_guard_denied"}
