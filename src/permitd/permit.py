"""The Permit record and its lifecycle states."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# Lifecycle: PROPOSED -> APPROVED -> EXECUTED
#                     -> DENIED
#            (PROPOSED or APPROVED past TTL) -> EXPIRED
PROPOSED = "proposed"
APPROVED = "approved"
DENIED = "denied"
EXECUTED = "executed"
EXPIRED = "expired"

STATUSES = {PROPOSED, APPROVED, DENIED, EXECUTED, EXPIRED}


@dataclass
class Permit:
    """One proposed tool call and the state of its authorization.

    `token` is the HMAC signature minted at approve time; it never appears in
    `public()` output — surfaces that render permits must not leak it."""
    id: str
    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    binding_hash: str = ""
    status: str = PROPOSED
    created_at: str = ""
    approved_at: Optional[str] = None
    decided_at: Optional[str] = None
    executed_at: Optional[str] = None
    token: Optional[str] = None
    ttl_seconds: int = 300

    def public(self) -> Dict[str, Any]:
        """The view handed to UIs and models. Full args on purpose: the
        approval surface is the operator's informed-consent surface, so it
        must show the exact thing being authorized — but never the token."""
        return {
            "id": self.id,
            "tool": self.tool,
            "args": dict(self.args),
            "status": self.status,
            "created_at": self.created_at,
            "ttl_seconds": self.ttl_seconds,
        }

    def to_row(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "args": dict(self.args),
            "binding_hash": self.binding_hash,
            "status": self.status,
            "created_at": self.created_at,
            "approved_at": self.approved_at,
            "decided_at": self.decided_at,
            "executed_at": self.executed_at,
            "token": self.token,
            "ttl_seconds": self.ttl_seconds,
        }

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "Permit":
        return cls(**{k: row.get(k) for k in (
            "id", "tool", "args", "binding_hash", "status", "created_at",
            "approved_at", "decided_at", "executed_at", "token", "ttl_seconds",
        )})
