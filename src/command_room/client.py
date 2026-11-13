"""The app's side: hand one command to the room and relay its output.

Used two ways. As a program (``python -I client.py --workspace … -- argv…``)
it stands in for the command itself: its output and exit code are the
command's, and stopping it stops the command. As a module it offers ``ping``.
It reads the room's address and secret from ``UNVEIL_ROOM_URL`` and
``UNVEIL_ROOM_TOKEN`` and passes neither on.
"""

import json
import os
import signal
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wire  # noqa: E402

UNREACHABLE = 125


def address(url: str):
    """('host', port) from 'host:port', or None."""
    text = (url or "").strip()
    for prefix in ("tcp://", "room://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    host, _, port = text.rpartition(":")
    if not host:
        host, port = text, str(wire.DEFAULT_PORT)
    if not host or not port.isdigit():
        return None
    return host, int(port)


def _recv_exact(sock, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def _read_frame(sock):
    kind = _recv_exact(sock, 1)
    length = wire.parse_length(_recv_exact(sock, 4), wire.MAX_FRAME)
    return kind, (_recv_exact(sock, length) if length else b"")


def ping(url: str, token: str, timeout: float = 2.0):
    """Ask the room what it can do. Returns its answer, or None if unreachable."""
    target = address(url)
    if not target or not token:
        return None
    try:
        with socket.create_connection(target, timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(wire.header({"token": token, "ping": True}))
            kind, payload = _read_frame(sock)
            if kind != wire.PONG:
                return None
            answer = json.loads(payload)
            return answer if isinstance(answer, dict) else None
    except (OSError, ValueError):
        return None


def _parse(argv):
    options = {"workspace": "", "timeout": 60, "network": "inherit", "readonly": []}
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--":
            return options, argv[index + 1:]
        if item in ("--workspace", "--timeout", "--network", "--readonly") and index + 1 < len(argv):
            value = argv[index + 1]
            if item == "--readonly":
                options["readonly"].append(value)
            elif item == "--timeout":
                options["timeout"] = int(value)
            else:
                options[item[2:]] = value
            index += 2
            continue
        raise SystemExit(f"command room: unexpected argument {item!r}")
    raise SystemExit("command room: missing '--' before the command")


def main(argv=None) -> int:
    options, command = _parse(list(sys.argv[1:] if argv is None else argv))
    target = address(os.environ.get("UNVEIL_ROOM_URL", ""))
    token = os.environ.get("UNVEIL_ROOM_TOKEN", "")
    if not target or not token or not command:
        sys.stderr.write("command room: not configured; command not executed\n")
        return UNREACHABLE
    env = {key: value for key, value in os.environ.items() if not key.startswith("UNVEIL_ROOM_")}
    try:
        sock = socket.create_connection(target, timeout=10)
    except OSError:
        sys.stderr.write("command room: unreachable; command not executed\n")
        return UNREACHABLE
    sock.settimeout(None)

    def _stop(*_):
        # Closing the connection is the stop signal: the room ends the command.
        try:
            sock.close()
        finally:
            os._exit(143)

    for name in ("SIGTERM", "SIGINT", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _stop)

    try:
        sock.sendall(wire.header({
            "token": token, "workspace": options["workspace"], "argv": command, "env": env,
            "timeout": options["timeout"], "network": options["network"], "readonly": options["readonly"],
        }))
    except (OSError, ValueError) as error:
        sys.stderr.write(f"command room: could not send the command ({error}); not executed\n")
        return UNREACHABLE

    lock = threading.Lock()

    def _send_stdin():
        try:
            source = sys.stdin.buffer
            while True:
                chunk = source.read1(65536) if hasattr(source, "read1") else source.read(65536)
                if not chunk:
                    break
                with lock:
                    sock.sendall(wire.frame(wire.STDIN, chunk))
            with lock:
                sock.sendall(wire.frame(wire.STDIN_END))
        except (OSError, ValueError):
            pass

    threading.Thread(target=_send_stdin, daemon=True).start()

    out, err = sys.stdout.buffer, sys.stderr.buffer
    try:
        while True:
            kind, payload = _read_frame(sock)
            if kind == wire.OUT:
                out.write(payload); out.flush()
            elif kind == wire.ERR:
                err.write(payload); err.flush()
            elif kind == wire.EXIT:
                code = json.loads(payload).get("exit")
                return code if isinstance(code, int) and code >= 0 else 128 + abs(code) if isinstance(code, int) else UNREACHABLE
    except (OSError, ValueError):
        sys.stderr.write("command room: connection lost; the command was stopped\n")
        return UNREACHABLE
    finally:
        try:
            sock.close()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
