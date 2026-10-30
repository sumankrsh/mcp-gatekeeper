"""An append-only JSON Lines audit log where each entry carries the hash of the one before.

Every entry has `seq`, `prev` (the previous entry's hash) and `hash`, a
SHA-256 over the entry's canonical JSON. Changing, removing or reordering any
entry breaks the chain from that point on, and `verify` reports the first line
that no longer fits.

A plain hash chain can be rebuilt by anyone who can write the file. Set
MCP_GATEKEEPER_AUDIT_KEY and the hashes become HMAC-SHA256 with that key, so
the chain can only be rebuilt by someone who also holds the key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # POSIX only; on Windows a single process per log file is assumed.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

GENESIS = "0" * 64
KEY_ENV = "MCP_GATEKEEPER_AUDIT_KEY"


def canonical(entry: dict[str, Any]) -> bytes:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(entry: dict[str, Any], key: bytes | None) -> str:
    data = canonical(entry)
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def key_from_env() -> bytes | None:
    value = os.environ.get(KEY_ENV)
    return value.encode() if value else None


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    """Appends hash-chained entries. Safe to share between threads and, on POSIX, between processes."""

    def __init__(self, path: str | Path, key: bytes | None = None) -> None:
        self.path = Path(path)
        self.key = key
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock, open(self.path, "a+", encoding="utf-8") as fh:
            if fcntl is not None:
                fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                last = _last_entry(self.path)
                entry: dict[str, Any] = {
                    "seq": (last["seq"] + 1) if last else 1,
                    "ts": _now(),
                    "event": event,
                    **fields,
                    "mac": "hmac-sha256" if self.key else "sha256",
                    "prev": last["hash"] if last else GENESIS,
                }
                entry["hash"] = entry_hash(entry, self.key)
                fh.seek(0, os.SEEK_END)
                fh.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                if fcntl is not None:
                    fcntl.flock(fh, fcntl.LOCK_UN)
        return entry


def _last_entry(path: Path) -> dict[str, Any] | None:
    """Read the final line without loading the whole file."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            if size == 0:
                return None
            block = 4096
            data = b""
            pos = size
            while pos > 0:
                step = min(block, pos)
                pos -= step
                fh.seek(pos)
                data = fh.read(step) + data
                lines = data.rstrip(b"\n").split(b"\n")
                if len(lines) > 1 or pos == 0:
                    return json.loads(lines[-1])
    except FileNotFoundError:
        return None
    return None


def read_entries(path: str | Path) -> Iterator[tuple[int, dict[str, Any] | None, str]]:
    """Yield (line number, parsed entry or None if not JSON, raw line)."""
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, start=1):
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
            yield n, parsed if isinstance(parsed, dict) else None, raw


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    head: str
    problem: str = ""
    line: int = 0


def verify(path: str | Path, key: bytes | None = None, expect_head: str | None = None) -> VerifyResult:
    """Walk the chain from the first line and stop at the first entry that doesn't fit."""
    prev = GENESIS
    count = 0
    seen_head = expect_head is None
    for line, entry, _raw in read_entries(path):
        problem = _check_entry(entry, count, prev, key)
        if problem:
            return VerifyResult(False, count, prev, problem, line)
        assert entry is not None
        prev = entry["hash"]
        count += 1
        if not seen_head and prev == expect_head:
            seen_head = True
    if not seen_head:
        return VerifyResult(
            False,
            count,
            prev,
            f"the expected head {expect_head} is not in the log (entries were removed from the end)",
            0,
        )
    return VerifyResult(True, count, prev)


def _check_entry(entry: dict[str, Any] | None, count: int, prev: str, key: bytes | None) -> str:
    """Why this entry doesn't continue the chain, or "" if it does."""
    if entry is None:
        return "not a JSON object"
    if entry.get("seq") != count + 1:
        return f"expected seq {count + 1}, found {entry.get('seq')!r} (an entry was removed, added or reordered)"
    if entry.get("prev") != prev:
        return "'prev' does not match the hash of the entry before it"
    mac = entry.get("mac", "sha256")
    if mac == "hmac-sha256" and not key:
        return f"this log is signed with HMAC; set {KEY_ENV} to verify it"
    if key and mac != "hmac-sha256":
        return "entry is not HMAC-signed although a key was given (it may have been rewritten without the key)"
    expected = entry_hash(entry, key if mac == "hmac-sha256" else None)
    if not hmac.compare_digest(str(entry.get("hash", "")), expected):
        return "hash does not match the entry's contents (the entry was edited)"
    return ""
