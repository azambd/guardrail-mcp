"""Append-only, hash-chained JSONL audit log.

Each record stores the SHA-256 of the record before it (``prev``) and its own
hash over its canonical JSON. Editing, reordering or deleting any record in the
middle of the file breaks the chain, and ``verify`` reports exactly where.

The log is tamper-evident, not tamper-proof: someone with write access can
rewrite the whole chain or truncate the tail. Ship the file to storage the agent
host cannot modify (or anchor the latest hash elsewhere) if you need more.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # POSIX: lets the server and the CLI append safely at the same time.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def record_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class VerifyResult:
    ok: bool
    records: int
    error: str | None = None
    line: int | None = None


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._thread_lock = threading.Lock()

    # ---------------------------------------------------------------- write

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        """Append one event and return the stored record (with seq and hash)."""
        with self._thread_lock, open(self.path, "a+b") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                last = _read_last_record(fh)
                record: dict[str, Any] = {
                    "seq": (last["seq"] + 1) if last else 1,
                    "ts": now_iso(),
                    **event,
                    "prev": last["hash"] if last else GENESIS,
                }
                record["hash"] = record_hash(record)
                line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
                fh.seek(0, os.SEEK_END)
                fh.write(line.encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return record

    # ---------------------------------------------------------------- read

    def records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        return self.records()[-n:]

    def verify(self) -> VerifyResult:
        """Walk the chain from the start and check every link and hash."""
        if not self.path.exists():
            return VerifyResult(ok=True, records=0)
        prev = GENESIS
        expected_seq = 1
        count = 0
        with open(self.path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return VerifyResult(False, count, "line is not valid JSON", line_no)
                if record.get("prev") != prev:
                    return VerifyResult(False, count, "chain broken: prev hash does not match the previous record (a record was edited, removed or reordered)", line_no)
                if record.get("seq") != expected_seq:
                    return VerifyResult(False, count, f"sequence gap: expected seq {expected_seq}, found {record.get('seq')}", line_no)
                if record_hash(record) != record.get("hash"):
                    return VerifyResult(False, count, "hash mismatch: record content was modified", line_no)
                prev = record["hash"]
                expected_seq += 1
                count += 1
        return VerifyResult(ok=True, records=count)


class AuditLogCorrupted(RuntimeError):
    pass


def _read_last_record(fh: Any) -> dict[str, Any] | None:
    """Read the last JSON line of a binary file handle without loading all of it."""
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    if size == 0:
        return None
    window = 8192
    while True:
        start = max(0, size - window)
        fh.seek(start)
        lines = [ln for ln in fh.read().split(b"\n") if ln.strip()]
        # When we did not start at byte 0 the first line may be partial, so we
        # only trust the last line once a newline is known to precede it.
        if lines and (start == 0 or len(lines) > 1):
            try:
                return json.loads(lines[-1].decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuditLogCorrupted(
                    "the last line of the audit log is not valid JSON; run `guardrail-mcp audit verify`"
                ) from exc
        if start == 0:
            return None
        window *= 4
