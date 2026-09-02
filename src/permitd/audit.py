"""Append-only, hash-chained audit trail: one JSON line per outcome.

Every record carries `prev`: the SHA-256 of the previous line's exact bytes
(64 zeros for the first line). Editing, reordering, or deleting any line
except the very last one breaks the chain, and `verify()` reports the first
line where it breaks. Deleting the newest lines cannot be detected from the
file alone; anchor `tip()` somewhere the writer cannot reach if you need
that. The chain is unkeyed, so it is tamper-EVIDENT, not tamper-proof: an
attacker with write access could re-chain the whole file. That is the host
trust domain, which permitd does not defend against (THREAT_MODEL.md).

Best-effort by contract: logging must never raise into the dispatch path. A
gate that can't write its audit line still answers; it just loses that line,
and `dropped` counts how many it lost. JSONL on purpose — the trail stays
`tail -f`-able and trivially exportable.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64


def _line_hash(raw: bytes) -> str:
    """Hash of one line's exact bytes, newline excluded."""
    return hashlib.sha256(raw.rstrip(b"\n")).hexdigest()


def _last_line(path: Path) -> Optional[bytes]:
    """The last non-empty line of the file, read from the end so the cost
    does not grow with the log. None if the file is missing or empty."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0:
        return None
    with path.open("rb") as f:
        chunk = 4096
        buf = b""
        pos = size
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            stripped = buf.rstrip(b"\n")
            if b"\n" in stripped:
                return stripped.rsplit(b"\n", 1)[1]
            if pos == 0:
                return stripped or None
    return None


@dataclass
class VerifyResult:
    ok: bool
    lines: int                       # lines examined
    tip: str                         # hash of the last line (GENESIS if none)
    first_bad_line: Optional[int]    # 1-based, None when ok
    reason: str = ""


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.dropped = 0  # audit lines lost to write failures (best-effort contract)

    def log(self, entry: Dict[str, Any]) -> None:
        """Append one record; `ts` is stamped here in UTC ISO-8601 and `prev`
        chains it to the line before. `prev` is read from the file on every
        write so several processes (a Gate and the CLI) chain correctly."""
        record = {"ts": datetime.now(timezone.utc).isoformat(), **entry}
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                last = _last_line(self.path)
                record["prev"] = _line_hash(last) if last is not None else GENESIS
                line = json.dumps(record, ensure_ascii=False) + "\n"
                with self.path.open("ab") as f:
                    f.write(line.encode("utf-8"))
                    f.flush()
                    os.fsync(f.fileno())
        except Exception:
            self.dropped += 1  # never let an audit failure break the call

    def tip(self) -> str:
        """Hash of the newest line. Record it somewhere the writer cannot
        reach (another host, a ticket, a signed message) and later `verify()`
        can prove nothing after that point was removed."""
        try:
            with self._lock:
                last = _last_line(self.path)
        except Exception:
            return GENESIS
        return _line_hash(last) if last is not None else GENESIS

    def verify(self) -> VerifyResult:
        """Walk the file and check every `prev`. Lines written before the
        chain existed (no `prev` field) are tolerated only as a prefix; the
        chain must be unbroken from its first chained line to the end."""
        try:
            if not self.path.exists():
                return VerifyResult(True, 0, GENESIS, None)
            with self._lock:
                raw_lines = [ln for ln in self.path.read_bytes().split(b"\n") if ln.strip()]
        except Exception as e:
            return VerifyResult(False, 0, GENESIS, None, f"unreadable: {e}")
        expected = GENESIS
        chained = False
        for i, raw in enumerate(raw_lines, 1):
            try:
                rec = json.loads(raw)
            except Exception:
                return VerifyResult(False, i, _line_hash(raw), i, "not JSON")
            prev = rec.get("prev")
            if prev is None:
                if chained:
                    return VerifyResult(False, i, _line_hash(raw), i, "unchained line after chain started")
            else:
                if not chained:
                    chained = True
                    expected = _line_hash(raw_lines[i - 2]) if i > 1 else GENESIS
                if prev != expected:
                    return VerifyResult(False, i, _line_hash(raw), i, "prev hash mismatch")
            expected = _line_hash(raw)
        return VerifyResult(True, len(raw_lines), expected, None)

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
