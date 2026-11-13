"""The room's side: accept a command, run it in a private namespace, stream it back.

Run as ``python -I server.py``. Settings come from the environment:

``UNVEIL_ROOM_TOKEN``       shared secret the app must present (required)
``UNVEIL_ROOM_WORKSPACES``  folders commands may use, separated by ``:``
``UNVEIL_ROOM_PORT``        listening port (default 7070)
``UNVEIL_ROOM_MAX_JOBS``    commands allowed at once (default 4)
"""

import asyncio
import hmac
import json
import os
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wire  # noqa: E402

TOKEN = os.environ.get("UNVEIL_ROOM_TOKEN", "")
PORT = int(os.environ.get("UNVEIL_ROOM_PORT", wire.DEFAULT_PORT))
MAX_JOBS = max(1, int(os.environ.get("UNVEIL_ROOM_MAX_JOBS", "4")))
ROOTS = tuple(
    os.path.realpath(path)
    for path in os.environ.get("UNVEIL_ROOM_WORKSPACES", "").split(":")
    if path and os.path.isabs(path)
)
MAX_SECONDS = 3600
WORKSPACE_MOUNT = "/workspace"
# Names a command may be given. The room's own environment is never passed on.
SAFE_ENV = frozenset({
    "PATH", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TERM", "COLUMNS", "LINES", "HOME", "TZ",
    "PYTHONIOENCODING", "PYTHONUNBUFFERED", "NO_COLOR", "FORCE_COLOR",
})
READONLY_PARENTS = ("/usr", "/opt")
_jobs = None  # asyncio.Semaphore, created with the loop
_proc_mode = None  # "private", "none" or "" (no working room)


def _base_args(proc_mode: str) -> list:
    args = [
        shutil.which("bwrap") or "bwrap", "--die-with-parent", "--new-session", "--unshare-pid",
        "--tmpfs", "/",
        "--dir", "/usr", "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--symlink", "usr/bin", "/sbin",
        "--dir", "/etc", "--ro-bind", "/etc", "/etc",
        "--dir", "/tmp", "--tmpfs", "/tmp",
        "--dev", "/dev",
    ]
    if proc_mode == "private":
        args += ["--proc", "/proc"]
    return args


def probe() -> str:
    """Which kind of room this container can build. Empty means none."""
    if not shutil.which("bwrap"):
        return ""
    for mode in ("private", "none"):
        try:
            done = subprocess.run(
                _base_args(mode) + ["/bin/true"], env={}, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if done.returncode == 0:
            return mode
    return ""


def _inside(path: str, parents) -> bool:
    return any(path == parent or path.startswith(parent + os.sep) for parent in parents)


def _dir_chain(path: str) -> list:
    args, current = [], ""
    for part in path.strip(os.sep).split(os.sep)[:-1]:
        current += os.sep + part
        args += ["--dir", current]
    return args


def build_command(request: dict) -> tuple:
    """Validate a request and return (argv, env, timeout). Raises ValueError."""
    workspace = request.get("workspace")
    if not isinstance(workspace, str) or not os.path.isabs(workspace):
        raise ValueError("workspace must be an absolute path")
    real = os.path.realpath(workspace)
    if not ROOTS or not _inside(real, ROOTS) or not os.path.isdir(real):
        raise ValueError("workspace is not one this room was given")
    argv = request.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(part, str) for part in argv):
        raise ValueError("argv must be a non-empty list of strings")
    timeout = request.get("timeout")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_SECONDS:
        raise ValueError("timeout out of range")
    env_in = request.get("env") or {}
    if not isinstance(env_in, dict):
        raise ValueError("env must be an object")
    env = {key: value for key, value in env_in.items()
           if key in SAFE_ENV and isinstance(value, str) and "\x00" not in value}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env["HOME"] = WORKSPACE_MOUNT

    args = _base_args(_proc_mode or "none")
    for extra in request.get("readonly") or []:
        if not isinstance(extra, str) or not os.path.isabs(extra):
            continue
        resolved = os.path.realpath(extra)
        # Anything under /usr is already visible; only other read-only program
        # folders that exist here are added. Nothing writable is ever added.
        if resolved.startswith("/usr") or not _inside(resolved, READONLY_PARENTS) or not os.path.isdir(resolved):
            continue
        args += _dir_chain(resolved) + ["--dir", resolved, "--ro-bind", resolved, resolved]
    args += ["--dir", WORKSPACE_MOUNT, "--bind", real, WORKSPACE_MOUNT]
    if real != WORKSPACE_MOUNT and not _inside(real, ("/usr", "/etc", "/tmp", "/dev", "/proc")):
        args += _dir_chain(real) + ["--dir", real, "--bind", real, real]
    if request.get("network") == "none":
        args.append("--unshare-net")
    args += ["--chdir", WORKSPACE_MOUNT]
    return args + argv, env, timeout


async def _read_exact(reader, count: int) -> bytes:
    return await reader.readexactly(count)


async def _pump(stream, writer, kind: bytes) -> None:
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return
        writer.write(wire.frame(kind, chunk))
        await writer.drain()


async def _feed(reader, proc) -> None:
    """Forward stdin from the app. Returns when the app closes its side."""
    try:
        while True:
            kind = await _read_exact(reader, 1)
            length = wire.parse_length(await _read_exact(reader, 4), wire.MAX_FRAME)
            payload = await _read_exact(reader, length) if length else b""
            if kind == wire.STDIN and proc.stdin is not None:
                proc.stdin.write(payload)
                await proc.stdin.drain()
            elif kind == wire.STDIN_END and proc.stdin is not None:
                proc.stdin.close()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError, OSError):
        return


def _kill(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


async def _finish(writer, code: int, message: str = "", timed_out: bool = False) -> None:
    try:
        if message:
            writer.write(wire.frame(wire.ERR, ("command room: " + message + "\n").encode()))
        writer.write(wire.frame(wire.EXIT, json.dumps({"exit": code, "timed_out": timed_out}).encode()))
        await writer.drain()
    except (ConnectionError, OSError):
        pass


async def handle(reader, writer) -> None:
    proc = None
    try:
        length = wire.parse_length(await asyncio.wait_for(_read_exact(reader, 4), 10), wire.MAX_HEADER)
        request = json.loads(await asyncio.wait_for(_read_exact(reader, length), 10))
        if not isinstance(request, dict) or not TOKEN or not hmac.compare_digest(
                str(request.get("token") or "").encode(), TOKEN.encode()):
            await _finish(writer, 126, "not authorised")
            return
        if request.get("ping"):
            writer.write(wire.frame(wire.PONG, json.dumps({"room": _proc_mode, "workspaces": list(ROOTS)}).encode()))
            await writer.drain()
            return
        if not _proc_mode:
            await _finish(writer, 125, "this container cannot build a room; command not executed")
            return
        try:
            argv, env, timeout = build_command(request)
        except ValueError as error:
            await _finish(writer, 125, f"{error}; command not executed")
            return
        if _jobs.locked():
            await _finish(writer, 125, "busy; command not executed")
            return
        async with _jobs:
            proc = await asyncio.create_subprocess_exec(
                *argv, env=env, cwd=os.path.realpath(request["workspace"]),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, start_new_session=True,
            )
            pumps = [asyncio.create_task(_pump(proc.stdout, writer, wire.OUT)),
                     asyncio.create_task(_pump(proc.stderr, writer, wire.ERR))]
            feeder = asyncio.create_task(_feed(reader, proc))
            waiter = asyncio.create_task(proc.wait())
            started = time.monotonic()
            timed_out = False
            while not waiter.done():
                await asyncio.wait({waiter, feeder}, timeout=1.0, return_when=asyncio.FIRST_COMPLETED)
                if feeder.done() and not waiter.done():
                    # The app went away. Nothing is left to report to, so stop.
                    _kill(proc)
                elif time.monotonic() - started > timeout + 5 and not waiter.done():
                    timed_out = True
                    _kill(proc)
            feeder.cancel()
            try:
                await asyncio.wait_for(asyncio.gather(*pumps, return_exceptions=True), 5)
            except asyncio.TimeoutError:
                for task in pumps:
                    task.cancel()
            await _finish(writer, proc.returncode if proc.returncode is not None else 125, timed_out=timed_out)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ValueError, OSError):
        pass
    finally:
        if proc is not None and proc.returncode is None:
            _kill(proc)
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def serve() -> None:
    global _jobs, _proc_mode
    _jobs = asyncio.Semaphore(MAX_JOBS)
    _proc_mode = probe()
    print(f"command room: listening on {PORT}; room={_proc_mode or 'unavailable'}; "
          f"workspaces={list(ROOTS)}", flush=True)
    server = await asyncio.start_server(handle, "0.0.0.0", PORT, limit=wire.MAX_FRAME + 16)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    if len(TOKEN) < 32:
        print("command room: UNVEIL_ROOM_TOKEN is missing or too short; not starting.", flush=True)
        time.sleep(30)
        sys.exit(1)
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
