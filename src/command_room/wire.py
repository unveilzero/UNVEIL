"""Framing shared by both ends of the command room connection."""

import json
import struct

OUT, ERR, EXIT, STDIN, STDIN_END, PONG = b"o", b"e", b"x", b"i", b"c", b"p"
MAX_HEADER = 256 * 1024
MAX_FRAME = 1024 * 1024
DEFAULT_PORT = 7070


def frame(kind: bytes, payload: bytes = b"") -> bytes:
    return kind + struct.pack(">I", len(payload)) + payload


def header(fields: dict) -> bytes:
    data = json.dumps(fields, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_HEADER:
        raise ValueError("command room: request too large")
    return struct.pack(">I", len(data)) + data


def parse_length(prefix: bytes, limit: int) -> int:
    (length,) = struct.unpack(">I", prefix)
    if length > limit:
        raise ValueError("command room: frame too large")
    return length
