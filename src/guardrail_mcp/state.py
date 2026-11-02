"""Durable state shared by the server and the CLI: approvals and write results.

SQLite keeps this dependency free and lets a human approve a request from a
second terminal (``guardrail-mcp approvals approve <id>``) while the server runs.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id          TEXT PRIMARY KEY,
    args_hash   TEXT NOT NULL,
    tool        TEXT NOT NULL,
    repo        TEXT,
    args_json   TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    decided_at  REAL,
    decided_by  TEXT,
    session     TEXT
);
CREATE INDEX IF NOT EXISTS approvals_hash ON approvals (args_hash, status);

CREATE TABLE IF NOT EXISTS write_results (
    args_hash   TEXT PRIMARY KEY,
    tool        TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at  REAL NOT NULL
);
"""


@dataclass
class Approval:
    id: str
    args_hash: str
    tool: str
    repo: str | None
    args: dict[str, Any]
    status: str
    created_at: float
    expires_at: float
    decided_at: float | None
    decided_by: str | None
    session: str | None

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Approval:
        data = dict(row)
        data["args"] = json.loads(data.pop("args_json"))
        return cls(**data)


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    # ---------------------------------------------------------------- idempotency

    def recent_result(self, args_hash: str, window_seconds: int) -> dict[str, Any] | None:
        if window_seconds <= 0:
            return None
        row = self._db.execute(
            "SELECT result_json, created_at FROM write_results WHERE args_hash = ?", (args_hash,)
        ).fetchone()
        if row is None or time.time() - row["created_at"] > window_seconds:
            return None
        return json.loads(row["result_json"])

    def save_result(self, args_hash: str, tool: str, result: dict[str, Any]) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO write_results (args_hash, tool, result_json, created_at) VALUES (?, ?, ?, ?)",
            (args_hash, tool, json.dumps(result, default=str), time.time()),
        )

    # ---------------------------------------------------------------- approvals

    def request_approval(
        self, *, args_hash: str, tool: str, repo: str | None, args: dict[str, Any], ttl: int, session: str
    ) -> Approval:
        """Return the open request for these exact arguments, or create one."""
        now = time.time()
        row = self._db.execute(
            "SELECT * FROM approvals WHERE args_hash = ? AND status = 'pending' AND expires_at > ? "
            "ORDER BY created_at DESC LIMIT 1",
            (args_hash, now),
        ).fetchone()
        if row is not None:
            return Approval.from_row(row)
        approval_id = "apr_" + secrets.token_hex(4)
        self._db.execute(
            "INSERT INTO approvals (id, args_hash, tool, repo, args_json, status, created_at, expires_at, session) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
            (approval_id, args_hash, tool, repo, json.dumps(args, default=str), now, now + ttl, session),
        )
        return self.get_approval(approval_id)  # type: ignore[return-value]

    def granted_approval(self, args_hash: str) -> Approval | None:
        row = self._db.execute(
            "SELECT * FROM approvals WHERE args_hash = ? AND status = 'approved' AND expires_at > ? "
            "ORDER BY decided_at DESC LIMIT 1",
            (args_hash, time.time()),
        ).fetchone()
        return Approval.from_row(row) if row else None

    def consume(self, approval_id: str) -> None:
        self._db.execute("UPDATE approvals SET status = 'consumed' WHERE id = ?", (approval_id,))

    def decide(self, approval_id: str, *, approve: bool, by: str) -> Approval:
        approval = self.get_approval(approval_id)
        if approval is None:
            raise KeyError(f"no approval request with id {approval_id!r}")
        if approval.status != "pending":
            raise ValueError(f"{approval_id} is already {approval.status}")
        if approval.expired:
            raise ValueError(f"{approval_id} expired; ask the agent to retry to open a new request")
        status = "approved" if approve else "denied"
        self._db.execute(
            "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status = 'pending'",
            (status, time.time(), by, approval_id),
        )
        return self.get_approval(approval_id)  # type: ignore[return-value]

    def get_approval(self, approval_id: str) -> Approval | None:
        row = self._db.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return Approval.from_row(row) if row else None

    def list_approvals(self, status: str | None = None, limit: int = 50) -> list[Approval]:
        if status:
            rows = self._db.execute(
                "SELECT * FROM approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?", (status, limit)
            ).fetchall()
        else:
            rows = self._db.execute("SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [Approval.from_row(r) for r in rows]
