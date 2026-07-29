"""The Gate: a small tool registry with tiered governance over the kernel.

Tiers (the same semantics the kernel grew up with in production):

  GREEN   read-only over the caller's own state. Runs freely; audited.
  YELLOW  external read. Runs only under STANDING operator authorization
          (one toggle: `gate.standing_authorization = True`); audited.
  RED     write / exec / send. Per-call permit: propose -> approve -> execute.

The egress guard runs before any non-GREEN call — including at PROPOSE time,
so a secret-bearing proposal never reaches the approval surface. Failures are
returned as GateResult(ok=False), never raised, so a tool call can never crash
an agent turn.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import guard as _guard
from .audit import AuditLog, summarize_args
from .kernel import DEFAULT_TTL_SECONDS, PermitError, PermitKernel
from .permit import Permit
from .store import SqliteStore

GREEN = "green"
YELLOW = "yellow"
RED = "red"
TIERS = (GREEN, YELLOW, RED)


def default_paths(db: str | Path) -> Dict[str, Path]:
    """The convention that lets a library Gate and the `permitd` CLI meet on
    one database: permitd.db -> permitd.db.secret + permitd_audit.jsonl."""
    db = Path(db)
    return {
        "db": db,
        "secret": db.with_name(db.name + ".secret"),
        "audit": db.with_name(db.stem + "_audit.jsonl"),
    }


@dataclass
class RegisteredTool:
    name: str
    fn: Callable[..., Any]
    tier: str
    description: str = ""


@dataclass
class GateResult:
    """Uniform return shape for every call. `ok=False` + `reason` labels why
    nothing ran (or why the run failed); `permit` carries the public view of a
    freshly-proposed permit when the answer is 'go get approval'."""
    ok: bool
    result: Any = None
    error: str = ""
    reason: str = ""
    permit: Optional[Dict[str, Any]] = field(default=None)


class Gate:
    def __init__(
        self,
        kernel: Optional[PermitKernel] = None,
        *,
        db: Optional[str | Path] = None,
        secret: Optional[str | bytes] = None,
        audit_path: Optional[str | Path] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        use_guard: bool = True,
        standing_authorization: bool = False,
    ) -> None:
        if kernel is not None:
            self.kernel = kernel
            self.audit = kernel.audit
        else:
            if db is not None:
                paths = default_paths(db)
                self.audit = AuditLog(audit_path or paths["audit"])
                self.kernel = PermitKernel(
                    SqliteStore(paths["db"]),
                    secret=secret,
                    secret_path=None if secret else paths["secret"],
                    ttl_seconds=ttl_seconds,
                    audit=self.audit,
                )
            else:
                self.audit = AuditLog(audit_path) if audit_path else None
                self.kernel = PermitKernel(secret=secret, ttl_seconds=ttl_seconds,
                                           audit=self.audit)
        self.use_guard = use_guard
        self.standing_authorization = standing_authorization
        self.registry: Dict[str, RegisteredTool] = {}

    # ── registry ─────────────────────────────────────────────────────────
    def register(self, name: str, fn: Callable[..., Any], *, tier: str = GREEN,
                 description: str = "") -> None:
        if tier not in TIERS:
            raise ValueError(f"tool {name!r}: unknown tier {tier!r}")
        self.registry[name] = RegisteredTool(name, fn, tier, description)

    def tool(self, name: Optional[str] = None, *, tier: str = GREEN,
             description: str = "") -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator form: @gate.tool(tier=RED)."""
        def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register(name or fn.__name__, fn, tier=tier,
                          description=description or (fn.__doc__ or "").strip())
            return fn
        return deco

    def tools(self) -> List[Dict[str, str]]:
        return [{"name": t.name, "tier": t.tier, "description": t.description}
                for t in sorted(self.registry.values(), key=lambda t: t.name)]

    # ── operator surface (delegates) ─────────────────────────────────────
    def approve(self, permit_id: str) -> Permit:
        return self.kernel.approve(permit_id)

    def deny(self, permit_id: str) -> Permit:
        return self.kernel.deny(permit_id)

    def pending(self) -> List[Permit]:
        return self.kernel.pending()

    def get(self, permit_id: str) -> Optional[Permit]:
        return self.kernel.get(permit_id)

    # ── dispatch ─────────────────────────────────────────────────────────
    def call(self, name: str, args: Optional[Dict[str, Any]] = None, *,
             permit_id: Optional[str] = None) -> GateResult:
        args = dict(args or {})
        tool = self.registry.get(name)
        if tool is None:
            self._log({"event": "refused", "tool": name, "reason": "unknown_tool"})
            return GateResult(ok=False, reason="unknown_tool",
                              error=f"unknown tool: {name}")

        # Egress guard first — the earliest content check, ahead of the permit
        # flow on purpose: a poisoned RED call is refused at PROPOSE time, so no
        # approval card is ever shown for it and its secret-bearing args never
        # reach the audit trail. The same scan fires again on the execute
        # re-dispatch, so a secret buried in operator-approved args is refused
        # even post-approval. One chokepoint, both lanes.
        if self.use_guard and tool.tier != GREEN:
            allow, why = _guard.scan_outbound(name, args)
            if not allow:
                self._log({"event": "refused", "tool": name, "tier": tool.tier,
                           "reason": "egress_blocked", "guard": why})
                return GateResult(ok=False, reason="egress_blocked", error=(
                    f"{name} was blocked by the egress guard ({why}). The "
                    "arguments carry credential-shaped content that must not "
                    "leave; the call was refused before anything was sent. Do "
                    "not retry — remove the sensitive content."))

        if tool.tier == YELLOW and not self.standing_authorization:
            self._log({"event": "refused", "tool": name, "tier": YELLOW,
                       "reason": "not_authorized"})
            return GateResult(ok=False, reason="not_authorized", error=(
                f"{name} is a yellow-tier tool and requires standing operator "
                "authorization (gate.standing_authorization = True)."))

        if tool.tier == RED:
            if not permit_id:
                permit = self.kernel.propose(name, args)
                return GateResult(
                    ok=False, reason="approval_required", permit=permit.public(),
                    error=(f"{name} needs operator approval before it runs. "
                           f"Permit {permit.id} is proposed — ask the operator "
                           f"to run `permitd approve {permit.id}`, then retry "
                           "this exact call with that permit_id. Do not alter "
                           "the arguments; the permit is bound to them."))
            try:
                result = self.kernel.execute(name, args, permit_id,
                                             runner=tool.fn)
                return GateResult(ok=True, result=result)
            except PermitError as e:
                return GateResult(ok=False, reason=e.reason, error=str(e))
            except Exception as e:  # tool raised; kernel already audited it
                return GateResult(ok=False, reason="exception",
                                  error=f"{name} failed: {e}")

        # GREEN, or YELLOW under standing authorization.
        try:
            result = tool.fn(**args)
        except Exception as e:
            self._log({"event": "failed", "tool": name, "tier": tool.tier,
                       "args": summarize_args(args), "error": str(e)})
            return GateResult(ok=False, reason="exception",
                              error=f"{name} failed: {e}")
        self._log({"event": "executed", "tool": name, "tier": tool.tier,
                   "args": summarize_args(args), "ok": True})
        return GateResult(ok=True, result=result)

    def _log(self, entry: Dict[str, Any]) -> None:
        if self.audit is not None:
            self.audit.log(entry)
