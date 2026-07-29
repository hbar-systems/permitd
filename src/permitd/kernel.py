"""The permit kernel: propose -> approve -> execute (verify + burn) -> audit.

The contract (security lives here):

  PROPOSE   `propose()` records the exact (tool, canonicalized args) and
            returns a Permit. Nothing has run.
  APPROVE   `approve()` mints a single-use HMAC-signed token bound to
            sha256(tool + canonical args), with a short TTL.
  EXECUTE   `execute()` re-checks the SAME (tool, args) against the permit:
            signature recomputes, binding matches, unexpired, unused — the
            burn is atomic — and only then the tool runs. One audit line lands.
  DENY      `deny()` discards the proposal; any minted token dies with it.

Every non-execute outcome is fail-closed: a missing, expired, mismatched,
tampered, or reused permit is refused, and the refusal is audited. Approval
for "send X to Alice" can neither be replayed nor bent to "send Y to Eve" —
the args hash and the atomic burn see to that.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets as _secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .audit import AuditLog, summarize_args
from .binding import binding_hash
from .permit import APPROVED, DENIED, EXPIRED, PROPOSED, Permit
from .store import MemoryStore, PermitStore

DEFAULT_TTL_SECONDS = 300


class PermitError(Exception):
    """A permit operation was refused. `reason` is a short machine-readable
    label (also the audit label); str(e) is the human sentence."""

    def __init__(self, reason: str, message: Optional[str] = None) -> None:
        self.reason = reason
        super().__init__(message or reason)


def load_or_create_secret(path: str | Path) -> bytes:
    """Read the HMAC secret from `path`, creating it (0600) on first use so a
    library user and the `permitd` CLI sharing a store also share the secret."""
    p = Path(path)
    if p.exists():
        return p.read_bytes().strip()
    p.parent.mkdir(parents=True, exist_ok=True)
    secret = _secrets.token_hex(32).encode("ascii")
    p.write_bytes(secret + b"\n")
    try:
        p.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return secret


def _resolve_secret(secret: Optional[str | bytes], secret_path: Optional[str | Path]) -> bytes:
    if secret is not None:
        return secret.encode("utf-8") if isinstance(secret, str) else secret
    env = os.getenv("PERMITD_SECRET")
    if env:
        return env.encode("utf-8")
    if secret_path is not None:
        return load_or_create_secret(secret_path)
    # Ephemeral secret: fine for in-memory kernels; a persistent store shared
    # across processes should pass `secret` or `secret_path`.
    return _secrets.token_hex(32).encode("ascii")


class PermitKernel:
    def __init__(
        self,
        store: Optional[PermitStore] = None,
        *,
        secret: Optional[str | bytes] = None,
        secret_path: Optional[str | Path] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        audit: Optional[AuditLog] = None,
        clock: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self.store: PermitStore = store if store is not None else MemoryStore()
        self.ttl_seconds = ttl_seconds
        self.audit = audit
        self._secret = _resolve_secret(secret, secret_path)
        self._now = clock or (lambda: datetime.now(timezone.utc))

    # ── time ─────────────────────────────────────────────────────────────
    def _age_seconds(self, iso: Optional[str]) -> float:
        try:
            t = datetime.fromisoformat(iso or "")
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            return (self._now() - t).total_seconds()
        except Exception:
            return float("inf")  # unparseable timestamp → expired (fail closed)

    def _expire_if_stale(self, permit: Permit) -> Permit:
        """Both clocks are bounded: a proposal is approvable for ttl after
        propose; a minted approval is executable for ttl after approve."""
        stale = (
            (permit.status == PROPOSED and self._age_seconds(permit.created_at) > permit.ttl_seconds)
            or (permit.status == APPROVED and self._age_seconds(permit.approved_at) > permit.ttl_seconds)
        )
        if stale:
            permit.status = EXPIRED
            permit.token = None
            self.store.update(permit)
        return permit

    # ── signing ──────────────────────────────────────────────────────────
    def _sign(self, permit_id: str, bhash: str, approved_at: str) -> str:
        msg = f"{permit_id}.{bhash}.{approved_at}".encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def _log(self, event: str, permit: Optional[Permit] = None, **extra: Any) -> None:
        if self.audit is None:
            return
        entry: Dict[str, Any] = {"event": event}
        if permit is not None:
            entry.update({
                "permit_id": permit.id,
                "tool": permit.tool,
                "args": summarize_args(permit.args),
            })
        entry.update(extra)
        self.audit.log(entry)

    # ── PROPOSE ──────────────────────────────────────────────────────────
    def propose(self, tool: str, args: Optional[Dict[str, Any]] = None) -> Permit:
        """Record a pending call and return the Permit. Nothing executes here —
        an approval must be minted before the call can run at all."""
        permit = Permit(
            id="PRM-" + _secrets.token_hex(6),
            tool=tool,
            args=dict(args or {}),
            binding_hash=binding_hash(tool, args),
            status=PROPOSED,
            created_at=self._now().isoformat(),
            ttl_seconds=self.ttl_seconds,
        )
        self.store.create(permit)
        self._log("proposed", permit)
        return permit

    def get(self, permit_id: str) -> Optional[Permit]:
        permit = self.store.get(permit_id)
        return self._expire_if_stale(permit) if permit else None

    def pending(self) -> List[Permit]:
        """Proposals still awaiting a decision and not yet expired."""
        out = []
        for permit in self.store.list(status=PROPOSED):
            if self._expire_if_stale(permit).status == PROPOSED:
                out.append(permit)
        return out

    # ── APPROVE / DENY ───────────────────────────────────────────────────
    def approve(self, permit_id: str) -> Permit:
        """Operator approves. Mints the one-shot HMAC token scoped to the
        permit's (tool, args) hash. Raises PermitError on anything else."""
        permit = self.store.get(permit_id)
        if permit is None:
            raise PermitError("unknown_permit", f"no permit {permit_id}")
        permit = self._expire_if_stale(permit)
        if permit.status != PROPOSED:
            self._log("approve_refused", permit, reason=f"already_{permit.status}")
            raise PermitError(f"already_{permit.status}",
                              f"{permit_id} is {permit.status}, not approvable")
        permit.approved_at = self._now().isoformat()
        permit.token = self._sign(permit.id, permit.binding_hash, permit.approved_at)
        permit.status = APPROVED
        self.store.update(permit)
        self._log("approved", permit)
        return permit

    def deny(self, permit_id: str) -> Permit:
        permit = self.store.get(permit_id)
        if permit is None:
            raise PermitError("unknown_permit", f"no permit {permit_id}")
        if permit.status not in (PROPOSED, APPROVED):
            raise PermitError(f"already_{permit.status}",
                              f"{permit_id} is {permit.status}, not deniable")
        permit.status = DENIED
        permit.decided_at = self._now().isoformat()
        permit.token = None  # any minted token is dead on deny
        self.store.update(permit)
        self._log("denied", permit)
        return permit

    # ── VERIFY + BURN ────────────────────────────────────────────────────
    def verify_and_burn(self, tool: str, args: Optional[Dict[str, Any]],
                        permit_id: str) -> Tuple[bool, str]:
        """Fail-closed check run at execute time. Passes only if the permit
        was approved for THIS exact (tool, args), its signature recomputes
        (store-tamper check), it is unexpired, and this caller wins the atomic
        burn. Returns (ok, reason); reason is the audit/refusal label."""
        if not permit_id:
            return False, "missing_permit"
        permit = self.store.get(permit_id)
        if permit is None:
            return False, "unknown_permit"
        permit = self._expire_if_stale(permit)
        if permit.status != APPROVED:
            return False, {PROPOSED: "not_approved", DENIED: "denied",
                           EXPIRED: "expired"}.get(permit.status, "already_used")
        expected = self._sign(permit.id, permit.binding_hash, permit.approved_at or "")
        if not permit.token or not hmac.compare_digest(permit.token, expected):
            return False, "bad_signature"
        if permit.binding_hash != binding_hash(tool, args):
            return False, "args_mismatch"
        if not self.store.burn(permit.id, self._now().isoformat()):
            return False, "already_used"  # lost the race — one-shot holds
        return True, "ok"

    # ── EXECUTE ──────────────────────────────────────────────────────────
    def execute(self, tool: str, args: Optional[Dict[str, Any]],
                permit_id: str, runner: Callable[..., Any]) -> Any:
        """Verify + burn, then run `runner(**args)`. Refusals raise PermitError
        and are audited; the successful execution lands its audit line too."""
        args = dict(args or {})
        ok, reason = self.verify_and_burn(tool, args, permit_id)
        if not ok:
            if self.audit is not None:
                self.audit.log({"event": "refused", "permit_id": permit_id,
                                "tool": tool, "args": summarize_args(args),
                                "reason": reason})
            raise PermitError(reason, f"{tool}: permit {reason} — refused. "
                              "An approved action runs only against a fresh, "
                              "matching, operator-minted permit.")
        try:
            result = runner(**args)
        except Exception as e:
            if self.audit is not None:
                self.audit.log({"event": "failed", "permit_id": permit_id,
                                "tool": tool, "args": summarize_args(args),
                                "error": str(e)})
            raise
        if self.audit is not None:
            self.audit.log({"event": "executed", "permit_id": permit_id,
                            "tool": tool, "args": summarize_args(args), "ok": True})
        return result
