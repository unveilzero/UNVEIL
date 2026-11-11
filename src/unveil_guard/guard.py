"""UNVEIL guard: ARAD runtime monitoring for every tool call.

Every tool call the agent runtime dispatches is described to ARAD's
``RuntimeEffectMonitor`` before it runs. The monitor decides ALLOW or BLOCK
from an allowlist, from blocked action sequences correlated per session and
per owner, and from its own timing and capacity rules. Each decision is
written to a hash-chained audit log.

This layer is additive. It runs after the application's own request
authority and approval checks and can only deny, never grant.

Configuration (environment):

``UNVEIL_GUARD_MODE``     ``enforce`` (default) or ``observe``. In observe
                          mode decisions are logged and shown, never enforced.
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
# Human authority. Agents may never change the application's own code, the
# login store, or this security layer; and a change to the application's
# settings needs a human's approval of that exact action, whatever approval
# mode is configured.
_PROTECTED_PATTERN = re.compile(
    r"(unveil_guard|unveil_security_routes|tool_execution\.py|mcp_manager\.py|auth\.json|audit\.key|"
    r"guard_audit\.jsonl|audit_anchor\.json|UNVEIL_GUARD_|UNVEIL_AUDIT_KEY|UNVEIL_WATCH_)",
    re.IGNORECASE,
)
_APP_ROOT = str(Path(__file__).resolve().parents[2])
_CHANGING_ACTIONS = frozenset({"WRITE", "EXECUTE", "ADMIN_CHANGE"})
# Tools that change how the application itself is configured or reached.
_HUMAN_APPROVAL_TOOLS = frozenset({
    "manage_settings", "manage_tokens", "manage_mcp", "manage_endpoints", "manage_webhooks",
})
# How long the status stays "blocked" after the latest block.
RECENT_BLOCK_SECONDS = 600

_in_guarded_call: contextvars.ContextVar[bool] = contextvars.ContextVar("unveil_in_guarded_call", default=False)


def _data_dir() -> Path:
    from src.constants import DATA_DIR
    path = Path(DATA_DIR) / "unveil"
    path.mkdir(parents=True, exist_ok=True)
    return path


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
    __slots__ = ("allowed", "reason", "actions", "enforced")

    def __init__(self, allowed: bool, reason: str, actions: tuple[str, ...], enforced: bool):
        self.allowed, self.reason, self.actions, self.enforced = allowed, reason, actions, enforced

    @property
    def blocked(self) -> bool:
        return self.enforced and not self.allowed


class UnveilGuard:
    def __init__(self, directory: Optional[Path] = None, *, mode: Optional[str] = None,
                 profile: Optional[str] = None, window: Optional[float] = None,
                 key: Optional[bytes] = None, clock=time.time):
        self.directory = Path(directory) if directory is not None else _data_dir()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.mode = (mode or os.getenv("UNVEIL_GUARD_MODE", "enforce")).strip().lower()
        if self.mode not in {"enforce", "observe"}:
            raise ValueError("UNVEIL_GUARD_MODE must be 'enforce' or 'observe'")
        self.profile = (profile or os.getenv("UNVEIL_GUARD_PROFILE", "standard")).strip().lower()
        if self.profile not in PROFILES:
            raise ValueError(f"UNVEIL_GUARD_PROFILE must be one of {sorted(PROFILES)}")
        self.window = float(window if window is not None else os.getenv("UNVEIL_GUARD_WINDOW", "300"))
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
        self._counts = {"allowed": 0, "blocked": 0, "would_block": 0}
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
    def _remember(self, tool, actions, decision, reason, agent, session_id, owner=None) -> None:
        with self._lock:
            self._recent.appendleft({
                "at": self._clock(), "tool": tool, "actions": list(actions), "decision": decision,
                "reason": reason, "agent": agent, "session": (session_id or "")[:12], "owner": owner or "",
            })

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
        enforced = self.mode == "enforce"
        actions: tuple[str, ...] = ()
        agent = f"system:{owner or 'server'}" if system else f"session:{session_id or 'none'}"
        try:
            if self._lockdown is not None:
                try:
                    with self._eval_lock:
                        self.monitor.audit_log.append("runtime_effect_decision", {
                            "decision": "BLOCK" if enforced else "WOULD_BLOCK", "reason": "lockdown",
                            "event": {"trace_id": session_id or agent, "agent_id": agent, "action": "LOCKDOWN",
                                      "resource": tool}})
                except Exception:
                    logger.exception("UNVEIL guard could not record a lockdown refusal")
                self._remember(tool, actions, "BLOCK" if enforced else "WOULD_BLOCK", "lockdown", agent, session_id, owner)
                self._counts["blocked" if enforced else "would_block"] += 1
                return GuardDecision(False, f"lockdown:{self._lockdown}", actions, enforced)
            actions = classify(tool, content)
            verdict, reason = "ALLOW", "allowed_by_policy"
            present = set(actions)
            violation = self._human_authority_violation(tool, actions, content, human_approved)
            if violation:
                verdict, reason = "BLOCK", violation
            for first, second in self.sequences:
                if verdict == "ALLOW" and first in present and second in present:
                    verdict, reason = "BLOCK", f"correlated_actions:{first}->{second}:same_call"
            digest = hashlib.sha256((content or "").encode("utf-8", "replace")).hexdigest()[:12]
            # One decision at a time, with a clock that never runs backwards, so
            # concurrent calls cannot trip the monitor's ordering checks.
            with self._eval_lock:
                self._last_timestamp = max(self._clock(), self._last_timestamp)
                event = {
                    "trace_id": session_id or agent, "agent_id": agent,
                    "resource": f"{tool}#{digest}", "timestamp": self._last_timestamp,
                }
                if owner:
                    event["parent_agent_id"] = f"owner:{owner}"
                if verdict == "BLOCK":
                    self.monitor.audit_log.append("runtime_effect_decision", {
                        "decision": "BLOCK", "reason": reason, "event": dict(event, action="+".join(actions))})
                else:
                    for action in actions:
                        result = self.monitor.evaluate_event(dict(event, action=action))
                        if result["decision"] != "ALLOW":
                            verdict, reason = "BLOCK", result["reason"]
                            break
        except Exception as error:  # in enforce mode an internal failure is a BLOCK
            logger.exception("UNVEIL guard failure")
            verdict, reason = "BLOCK", f"guard_error:{type(error).__name__}"
        allowed = verdict == "ALLOW"
        if allowed:
            self._counts["allowed"] += 1
        elif enforced:
            self._counts["blocked"] += 1
        else:
            self._counts["would_block"] += 1
        self._remember(tool, actions, verdict if enforced or allowed else "WOULD_BLOCK", reason, agent, session_id, owner)
        return GuardDecision(allowed, reason, actions, enforced)

    # -- reporting --------------------------------------------------------
    def status(self, *, limit: int = 25) -> dict[str, Any]:
        with self._lock:
            recent = list(self._recent)[:limit]
        last_block = next((row for row in recent if row["decision"] == "BLOCK"), None)
        return self.describe({
            "mode": self.mode, "profile": self.profile, "window_seconds": self.window,
            "lockdown": self._lockdown, "counts": dict(self._counts),
            "last_block": last_block, "recent": recent, "started_at": self.started_at,
        })

    def describe(self, report: dict[str, Any]) -> dict[str, Any]:
        """Set ``state`` from the lockdown flag and the most recent block in ``report``."""
        last_block = report.get("last_block")
        recent_block = last_block is not None and self._clock() - last_block["at"] < RECENT_BLOCK_SECONDS
        if report.get("lockdown") or (recent_block and self.mode == "enforce"):
            report["state"] = "blocked"
        elif self.mode != "enforce":
            report["state"] = "observe"
        else:
            report["state"] = "cleared"
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
