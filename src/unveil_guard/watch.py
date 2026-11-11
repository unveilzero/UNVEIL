"""Background watch: re-verifies the guard's own integrity on a timer.

Runs for the life of the server, whether or not anyone is signed in. Each
cycle checks that

* the audit log still verifies and still contains everything it contained at
  the previous cycle (an anchor is kept between cycles),
* the security layer's files on disk are the ones that were loaded at start,
* the tool dispatcher is still the function that was installed at start.

Any failure puts the guard into lockdown: every tool call is refused until an
administrator clears it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

from .guard import UnveilGuard, get_guard

logger = logging.getLogger("unveil.watch")

_ROOT = Path(__file__).resolve().parent
_WATCHED_FILES = tuple(sorted(
    [path for path in _ROOT.rglob("*.py")] + [_ROOT.parent / "tool_execution.py", _ROOT.parent / "mcp_manager.py"]
))


def _fingerprint_files() -> str:
    digest = hashlib.sha256()
    for path in _WATCHED_FILES:
        digest.update(str(path.relative_to(_ROOT.parent)).encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


class GuardWatch:
    def __init__(self, guard: Optional[UnveilGuard] = None, *, interval: Optional[float] = None):
        self.guard = guard or get_guard()
        self.interval = float(interval if interval is not None else (os.getenv("UNVEIL_WATCH_INTERVAL") or "60"))
        if self.interval <= 0:
            raise ValueError("UNVEIL_WATCH_INTERVAL must be positive")
        self.anchor_path = self.guard.directory / "audit_anchor.json"
        self._files = _fingerprint_files()
        self._dispatcher = self._current_dispatcher()
        self.cycles = 0
        self.last_run: Optional[float] = None
        self.last_result: dict[str, Any] = {"ok": None, "checks": {}}
        self._last_counts = dict(self.guard.status(limit=0)["counts"])

    @staticmethod
    def _current_dispatcher():
        from src import tool_execution
        return tool_execution.execute_tool_block

    def _check_audit(self) -> Optional[str]:
        anchor = None
        if self.anchor_path.exists():
            try:
                anchor = json.loads(self.anchor_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return "anchor file unreadable"
        try:
            self.guard.monitor.verify_audit_log(expected_anchor=anchor)
        except ValueError as error:
            return str(error)
        self.anchor_path.write_text(json.dumps(self.guard.monitor.anchor_audit_log()), encoding="utf-8")
        return None

    def run_once(self) -> dict[str, Any]:
        checks: dict[str, Optional[str]] = {}
        try:
            checks["audit_log"] = self._check_audit()
        except Exception as error:
            checks["audit_log"] = f"check failed: {type(error).__name__}"
        try:
            checks["security_files"] = None if _fingerprint_files() == self._files else "files changed while running"
        except OSError as error:
            checks["security_files"] = f"files unreadable: {type(error).__name__}"
        checks["dispatcher"] = None if self._current_dispatcher() is self._dispatcher else "tool dispatcher was replaced"
        failures = {name: problem for name, problem in checks.items() if problem}
        counts = self.guard.status(limit=0)["counts"]
        activity = {name: counts[name] - self._last_counts.get(name, 0) for name in counts}
        self._last_counts = dict(counts)
        self.cycles += 1
        self.last_run = time.time()
        self.last_result = {"ok": not failures, "checks": {name: problem or "ok" for name, problem in checks.items()},
                            "activity_since_last_cycle": activity}
        if failures:
            self.guard.enter_lockdown("; ".join(f"{name}: {problem}" for name, problem in sorted(failures.items())))
        return self.last_result

    async def run_forever(self) -> None:
        logger.info("UNVEIL watch started (every %.0fs)", self.interval)
        while True:
            try:
                await asyncio.to_thread(self.run_once)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("UNVEIL watch cycle failed")
                self.guard.enter_lockdown("watch cycle failed")
            await asyncio.sleep(self.interval)

    def status(self) -> dict[str, Any]:
        return {"interval_seconds": self.interval, "cycles": self.cycles, "last_run": self.last_run, **self.last_result}


_watch: Optional[GuardWatch] = None


def start_watch() -> asyncio.Task:
    global _watch
    _watch = GuardWatch()
    return asyncio.create_task(_watch.run_forever(), name="unveil-guard-watch")


def get_watch() -> Optional[GuardWatch]:
    return _watch
