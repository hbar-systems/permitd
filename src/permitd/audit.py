"""Append-only audit trail: one JSON line per outcome.

Best-effort by contract: logging must never raise into the dispatch path. A
gate that can't write its audit line still answers; it just loses that line.
JSONL on purpose — the trail stays `tail -f`-able and trivially exportable.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def log(self, entry: Dict[str, Any]) -> None:
        """Append one record; `ts` is stamped here in UTC ISO-8601."""
        record = {"ts": datetime.now(timezone.utc).isoformat(), **entry}
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass  # never let an audit failure break the call

    def tail(self, n: int = 50) -> List[Dict[str, Any]]:
        """The most recent `n` records, oldest first."""
        try:
            if not self.path.exists():
                return []
            with self._lock:
                lines = self.path.read_text(encoding="utf-8").splitlines()
            out: List[Dict[str, Any]] = []
            for line in lines[-n:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
            return out
        except Exception:
            return []


def summarize_args(args: Dict[str, Any], max_len: int = 200) -> Dict[str, Any]:
    """Trim arg values for audit lines so the log never stores huge payloads.
    (The approval surface is the opposite: it always shows full args.)"""
    out: Dict[str, Any] = {}
    for k, v in (args or {}).items():
        if isinstance(v, str) and len(v) > max_len:
            out[k] = v[:max_len] + "…"
        else:
            out[k] = v
    return out
