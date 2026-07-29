"""Pluggable permit storage.

The kernel talks to a small protocol; two implementations ship:

- SqliteStore (default): durable, and the single-use burn is one atomic
  UPDATE ... WHERE status='approved', so two processes racing the same permit
  cannot both pass — no application-level lock required.
- MemoryStore: tests and ephemeral gates.

Any other backend (Postgres, Redis) only needs the same five methods; keep
`burn` compare-and-swap semantics or the one-shot guarantee is lost.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Dict, List, Optional, Protocol

from .permit import APPROVED, EXECUTED, Permit


class PermitStore(Protocol):
    def create(self, permit: Permit) -> None: ...
    def get(self, permit_id: str) -> Optional[Permit]: ...
    def update(self, permit: Permit) -> None: ...
    def burn(self, permit_id: str, executed_at: str) -> bool:
        """Atomically flip APPROVED -> EXECUTED. Returns True only for the one
        caller that won; a second attempt on the same permit returns False."""
        ...
    def list(self, status: Optional[str] = None) -> List[Permit]: ...


class MemoryStore:
    def __init__(self) -> None:
        self._rows: Dict[str, Permit] = {}
        self._lock = threading.Lock()

    def create(self, permit: Permit) -> None:
        with self._lock:
            self._rows[permit.id] = Permit.from_row(permit.to_row())

    def get(self, permit_id: str) -> Optional[Permit]:
        with self._lock:
            p = self._rows.get(permit_id)
            return Permit.from_row(p.to_row()) if p else None

    def update(self, permit: Permit) -> None:
        with self._lock:
            self._rows[permit.id] = Permit.from_row(permit.to_row())

    def burn(self, permit_id: str, executed_at: str) -> bool:
        with self._lock:
            p = self._rows.get(permit_id)
            if p is None or p.status != APPROVED:
                return False
            p.status = EXECUTED
            p.executed_at = executed_at
            return True

    def list(self, status: Optional[str] = None) -> List[Permit]:
        with self._lock:
            rows = [Permit.from_row(p.to_row()) for p in self._rows.values()]
        if status is not None:
            rows = [p for p in rows if p.status == status]
        return sorted(rows, key=lambda p: p.created_at)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS permits (
    id TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    args TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    approved_at TEXT,
    decided_at TEXT,
    executed_at TEXT,
    token TEXT,
    ttl_seconds INTEGER NOT NULL
)
"""

_COLS = ("id", "tool", "args", "binding_hash", "status", "created_at",
         "approved_at", "decided_at", "executed_at", "token", "ttl_seconds")


class SqliteStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as con:
            con.execute(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    @staticmethod
    def _to_permit(row: sqlite3.Row) -> Permit:
        d = dict(row)
        d["args"] = json.loads(d["args"] or "{}")
        return Permit.from_row(d)

    def create(self, permit: Permit) -> None:
        row = permit.to_row()
        row["args"] = json.dumps(row["args"], ensure_ascii=False)
        with self._conn() as con:
            con.execute(
                f"INSERT INTO permits ({','.join(_COLS)}) "
                f"VALUES ({','.join('?' for _ in _COLS)})",
                tuple(row[c] for c in _COLS),
            )

    def get(self, permit_id: str) -> Optional[Permit]:
        with self._conn() as con:
            row = con.execute("SELECT * FROM permits WHERE id = ?", (permit_id,)).fetchone()
        return self._to_permit(row) if row else None

    def update(self, permit: Permit) -> None:
        row = permit.to_row()
        row["args"] = json.dumps(row["args"], ensure_ascii=False)
        sets = ",".join(f"{c} = ?" for c in _COLS if c != "id")
        with self._conn() as con:
            con.execute(
                f"UPDATE permits SET {sets} WHERE id = ?",
                tuple(row[c] for c in _COLS if c != "id") + (permit.id,),
            )

    def burn(self, permit_id: str, executed_at: str) -> bool:
        with self._conn() as con:
            cur = con.execute(
                "UPDATE permits SET status = ?, executed_at = ? "
                "WHERE id = ? AND status = ?",
                (EXECUTED, executed_at, permit_id, APPROVED),
            )
            return cur.rowcount == 1

    def list(self, status: Optional[str] = None) -> List[Permit]:
        q = "SELECT * FROM permits"
        params: tuple = ()
        if status is not None:
            q += " WHERE status = ?"
            params = (status,)
        q += " ORDER BY created_at"
        with self._conn() as con:
            rows = con.execute(q, params).fetchall()
        return [self._to_permit(r) for r in rows]
