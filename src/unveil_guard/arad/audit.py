"""Append-only hash-chained audit records with optional HMAC keying and external anchors."""

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path

GENESIS_HASH = "0" * 64


class AuditLog:
    """JSONL audit log with sequence, hash-chain and optional HMAC verification."""

    def __init__(self, path, key=None):
        if key is not None:
            if isinstance(key, str):
                key = key.encode("utf-8")
            if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
                raise ValueError("Audit key must be bytes or str of at least 16 bytes")
            key = bytes(key)
        self.path = Path(path)
        self._key = key
        self._lock = threading.Lock()
        self._sequence, self._head_hash, _ = self._read_and_validate()

    @property
    def keyed(self):
        return self._key is not None

    @staticmethod
    def _canonical(record):
        return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

    def _digest(self, record):
        data = self._canonical(record).encode("utf-8")
        if self._key is not None:
            return hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def _read_and_validate(self, anchor_sequence=None):
        """Validate the chain; return (records, head_hash, hash at ``anchor_sequence`` or None)."""
        anchored_hash = GENESIS_HASH if anchor_sequence == 0 else None
        if not self.path.exists():
            return 0, GENESIS_HASH, anchored_hash
        previous_hash, sequence = GENESIS_HASH, 0
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid audit record at line {line_number}") from exc
                if not isinstance(payload, dict):
                    raise ValueError(f"Invalid audit record at line {line_number}")
                chain_hash = payload.get("chain_hash")
                if not isinstance(chain_hash, str):
                    raise ValueError(f"Audit record has no valid hash at line {line_number}")
                record = dict(payload)
                record.pop("chain_hash", None)
                try:
                    expected = self._digest(record)
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"Invalid audit record at line {line_number}") from exc
                if not hmac.compare_digest(chain_hash, expected):
                    raise ValueError(f"Audit hash mismatch at line {line_number}")
                if record.get("previous_hash") != previous_hash:
                    raise ValueError(f"Broken audit chain at line {line_number}")
                if record.get("sequence") != sequence + 1:
                    raise ValueError(f"Sequence mismatch at line {line_number}")
                previous_hash, sequence = chain_hash, sequence + 1
                if sequence == anchor_sequence:
                    anchored_hash = chain_hash
        return sequence, previous_hash, anchored_hash

    def append(self, event, details):
        with self._lock:
            record = {
                "sequence": self._sequence + 1,
                "timestamp": time.time(),
                "event": str(event),
                "details": details,
                "previous_hash": self._head_hash,
            }
            chain_hash = self._digest(record)
            output = dict(record, chain_hash=chain_hash)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(self._canonical(output) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._sequence += 1
            self._head_hash = chain_hash
            return chain_hash

    def anchor(self):
        """Return the current head for storage outside the agent's reach."""
        with self._lock:
            return {"sequence": self._sequence, "head_hash": self._head_hash}

    def verify(self, expected_anchor=None):
        """Validate the chain and, given an anchor, that it was not cut or rewritten."""
        anchored_sequence = anchored_hash = None
        if expected_anchor is not None:
            try:
                anchored_sequence = expected_anchor["sequence"]
                anchored_hash = expected_anchor["head_hash"]
            except (KeyError, TypeError) as exc:
                raise ValueError("Anchor must contain 'sequence' and 'head_hash'") from exc
            if (not isinstance(anchored_sequence, int) or isinstance(anchored_sequence, bool)
                    or anchored_sequence < 0 or not isinstance(anchored_hash, str)):
                raise ValueError("Anchor must contain a non-negative integer 'sequence' and a string 'head_hash'")
        sequence, head_hash, actual = self._read_and_validate(anchored_sequence)
        if expected_anchor is not None:
            if anchored_sequence > sequence:
                raise ValueError(
                    f"Audit log truncated: anchor at record {anchored_sequence}, log has {sequence}"
                )
            if actual is None or not hmac.compare_digest(actual, anchored_hash):
                raise ValueError(f"Audit log rewritten: record {anchored_sequence} does not match anchor")
        return {"valid": True, "records": sequence, "head_hash": head_hash, "keyed": self.keyed}
