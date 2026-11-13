"""The command room: commands run in a separate place that holds nothing."""

import asyncio
import importlib.util
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from src import containment
from src.command_room import client as room_client

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "src" / "command_room" / "server.py"
CLIENT = ROOT / "src" / "command_room" / "client.py"
TOKEN = "t" * 40


def _load_server(monkeypatch, roots):
    monkeypatch.setenv("UNVEIL_ROOM_TOKEN", TOKEN)
    monkeypatch.setenv("UNVEIL_ROOM_WORKSPACES", os.pathsep.join(map(str, roots)))
    spec = importlib.util.spec_from_file_location("room_server_under_test", SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._proc_mode = "none"
    return module


def test_requests_are_validated_before_anything_runs(tmp_path, monkeypatch):
    inside = tmp_path / "ws" / "chat"
    inside.mkdir(parents=True)
    server = _load_server(monkeypatch, [tmp_path / "ws"])
    good = {"workspace": str(inside), "argv": ["/bin/echo", "hi"], "timeout": 10,
            "env": {"PATH": "/usr/bin", "SECRET_KEY": "x", "LANG": "C.UTF-8"}}

    argv, env, timeout = server.build_command(good)
    assert argv[-2:] == ["/bin/echo", "hi"] and timeout == 10
    assert "SECRET_KEY" not in env and env["LANG"] == "C.UTF-8" and env["HOME"] == "/workspace"
    assert "--unshare-pid" in argv and "--tmpfs" in argv
    # Nothing but the workspace is writable inside.
    binds = [argv[i + 1] for i, part in enumerate(argv) if part == "--bind"]
    assert set(binds) == {str(inside.resolve())}

    for change in (
        {"workspace": "/etc"},
        {"workspace": str(tmp_path)},
        {"workspace": "relative/path"},
        {"workspace": str(inside / "missing")},
        {"argv": []},
        {"argv": "echo hi"},
        {"argv": ["echo", 5]},
        {"timeout": 0},
        {"timeout": 10 ** 6},
        {"timeout": True},
        {"env": "PATH=/usr/bin"},
    ):
        with pytest.raises(ValueError):
            server.build_command({**good, **change})


def test_a_link_out_of_the_workspaces_is_refused(tmp_path, monkeypatch):
    (tmp_path / "ws").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "ws" / "escape").symlink_to(tmp_path / "elsewhere")
    server = _load_server(monkeypatch, [tmp_path / "ws"])
    with pytest.raises(ValueError):
        server.build_command({"workspace": str(tmp_path / "ws" / "escape"), "argv": ["/bin/true"], "timeout": 5})


def test_extra_folders_are_read_only_and_limited(tmp_path, monkeypatch):
    inside = tmp_path / "ws"
    inside.mkdir()
    server = _load_server(monkeypatch, [inside])
    argv, _env, _t = server.build_command({
        "workspace": str(inside), "argv": ["/bin/true"], "timeout": 5,
        "readonly": ["/etc/ssl", "/home", str(tmp_path), "/app/data", "relative"],
    })
    assert not any(part in ("/home", str(tmp_path), "/app/data") for part in argv)


def test_address_forms():
    assert room_client.address("room:7070") == ("room", 7070)
    assert room_client.address("tcp://10.0.0.5:9000") == ("10.0.0.5", 9000)
    assert room_client.address("room") == ("room", 7070)
    assert room_client.address("") is None and room_client.address("room:abc") is None


def test_unconfigured_room_changes_nothing(monkeypatch, tmp_path):
    monkeypatch.delenv("UNVEIL_ROOM_URL", raising=False)
    monkeypatch.delenv("UNVEIL_ROOM_TOKEN", raising=False)
    assert containment._room_available() is False
    spec = containment.agent_spec(str(tmp_path), {}, 10)
    assert containment._room_provides(spec) == frozenset({containment.WALL_CLOCK})


def test_unreachable_room_is_not_available(monkeypatch):
    monkeypatch.setenv("UNVEIL_ROOM_URL", "127.0.0.1:1")
    monkeypatch.setenv("UNVEIL_ROOM_TOKEN", TOKEN)
    monkeypatch.setitem(containment._room_state, "checked", 0.0)
    assert containment._room_available() is False


# ── Against a real room ─────────────────────────────────────────────────────
def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def room(tmp_path, monkeypatch):
    if not containment._bwrap_available():
        pytest.skip("functional bubblewrap namespaces unavailable")
    roots = tmp_path / "workspaces"
    (roots / "mine").mkdir(parents=True)
    (roots / "other").mkdir()
    (roots / "other" / "private.txt").write_text("another chat")
    port = _free_port()
    env = {"PATH": os.environ.get("PATH", ""), "UNVEIL_ROOM_TOKEN": TOKEN,
           "UNVEIL_ROOM_WORKSPACES": str(roots), "UNVEIL_ROOM_PORT": str(port),
           "ROOM_HOST_SECRET": "must-not-reach-commands"}
    proc = subprocess.Popen([sys.executable, "-I", str(SERVER)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    url = f"127.0.0.1:{port}"
    for _ in range(50):
        if room_client.ping(url, TOKEN, timeout=0.5):
            break
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("room did not start: " + proc.stdout.read().decode(errors="replace"))
    monkeypatch.setenv("UNVEIL_ROOM_URL", url)
    monkeypatch.setenv("UNVEIL_ROOM_TOKEN", TOKEN)
    monkeypatch.setitem(containment._room_state, "checked", 0.0)
    monkeypatch.setattr(containment, "_store_path", lambda: tmp_path / "grants.json")
    yield roots
    proc.kill()
    proc.wait(timeout=5)


def _relay(room, command, *, token=TOKEN, workspace=None, timeout=20, stdin=b""):
    env = {"PATH": os.environ.get("PATH", ""), "UNVEIL_ROOM_URL": os.environ["UNVEIL_ROOM_URL"],
           "UNVEIL_ROOM_TOKEN": token, "APP_SECRET": "must-not-reach-commands"}
    return subprocess.run(
        [sys.executable, "-I", str(CLIENT), "--workspace", str(workspace or room / "mine"),
         "--timeout", str(timeout), "--", "/bin/bash", "-c", command],
        env=env, input=stdin, capture_output=True, timeout=60)


def test_a_command_sees_only_its_workspace(room):
    done = _relay(room, f"echo top=$(ls / | tr '\\n' ' '); env; cat {room}/other/private.txt; ls /root /home; id -u >/dev/null")
    out = done.stdout.decode()
    assert "workspace" in out.split("top=")[1].splitlines()[0]
    assert "must-not-reach-commands" not in out and "UNVEIL_ROOM" not in out and TOKEN not in out
    assert "another chat" not in out
    assert b"No such file or directory" in done.stderr


def test_output_exit_code_and_stdin_come_back(room):
    done = _relay(room, "cat; echo warn >&2; echo made > note.txt; exit 7", stdin=b"typed in\n")
    assert done.returncode == 7 and done.stdout == b"typed in\n" and done.stderr == b"warn\n"
    assert (room / "mine" / "note.txt").read_text() == "made\n"


def test_wrong_secret_and_foreign_workspace_run_nothing(room, tmp_path):
    refused = _relay(room, "echo ran > proof.txt", token="w" * 40)
    assert refused.returncode == 126 and not (room / "mine" / "proof.txt").exists()
    outside = tmp_path / "outside"
    outside.mkdir()
    foreign = _relay(room, "echo ran > proof.txt", workspace=outside)
    assert foreign.returncode == 125 and b"not executed" in foreign.stderr
    assert not (outside / "proof.txt").exists()


def test_stopping_the_relay_stops_the_command(room):
    marker = room / "mine" / "alive.txt"
    relay = subprocess.Popen(
        [sys.executable, "-I", str(CLIENT), "--workspace", str(room / "mine"), "--timeout", "60", "--",
         "/bin/bash", "-c", "while true; do date +%s%N > alive.txt; sleep 0.2; done"],
        env={"PATH": os.environ.get("PATH", ""), "UNVEIL_ROOM_URL": os.environ["UNVEIL_ROOM_URL"],
             "UNVEIL_ROOM_TOKEN": TOKEN})
    for _ in range(50):
        if marker.exists():
            break
        time.sleep(0.1)
    assert marker.exists()
    relay.terminate()
    relay.wait(timeout=10)
    time.sleep(2.5)
    before = marker.read_text()
    time.sleep(1.0)
    assert marker.read_text() == before


async def test_the_app_prefers_the_room_and_runs_through_it(room):
    spec = containment.agent_spec(str(room / "mine"), {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}, 20)
    grant = containment.acquire(spec, owner="room-test")
    assert grant.mechanism == containment.ROOM_MECHANISM
    assert {containment.FILESYSTEM, containment.PROCESS_TREE, containment.WALL_CLOCK} <= grant.enforced
    result = await containment.run(grant, "echo from-room; pwd; env | grep -c UNVEIL_ROOM; ls /app 2>&1 | head -1")
    lines = result.stdout.splitlines()
    assert lines[0] == "from-room" and lines[1] == "/workspace" and lines[2] == "0"
    assert result.exit_code == 0 and not result.timed_out
    containment.release(grant, grace_s=0)


async def test_the_room_is_not_claimed_for_a_workspace_it_was_not_given(room, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    spec = containment.agent_spec(str(elsewhere), {}, 10)
    assert containment._room_provides(spec) == frozenset({containment.WALL_CLOCK})
    monkeypatch.setattr(containment, "MECHANISMS", tuple(
        item for item in containment.MECHANISMS if item.name == containment.ROOM_MECHANISM))
    with pytest.raises(containment.ContainmentUnavailable):
        containment.acquire(spec, owner="room-test")


async def test_a_command_over_its_time_is_stopped(room):
    spec = containment.agent_spec(str(room / "mine"), {"PATH": os.environ.get("PATH", "")}, 2)
    grant = containment.acquire(spec, owner="room-test")
    started = time.monotonic()
    result = await containment.run(grant, "sleep 60")
    assert result.timed_out and time.monotonic() - started < 20
