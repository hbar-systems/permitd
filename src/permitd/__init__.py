"""permitd — governed tool execution for agent loops.

propose(tool, args) -> Permit (signed, TTL, single-use)
                    -> approve (out-of-band)
                    -> execute (verify + burn)
                    -> one audit line lands.

Core: `PermitKernel` (the flow above, storage-pluggable, stdlib-only).
Convenience: `Gate` (a tool registry with GREEN/YELLOW/RED tiers and an
egress guard over the kernel). Operator surface: the `permitd` CLI.
"""
from .audit import AuditLog, summarize_args
from .binding import binding_hash, canonical_args
from .gate import GREEN, RED, YELLOW, Gate, GateResult, default_paths
from .guard import scan_outbound
from .kernel import DEFAULT_TTL_SECONDS, PermitError, PermitKernel, load_or_create_secret
from .permit import APPROVED, DENIED, EXECUTED, EXPIRED, PROPOSED, Permit
from .store import MemoryStore, PermitStore, SqliteStore

__version__ = "0.1.0"

__all__ = [
    "AuditLog", "summarize_args",
    "binding_hash", "canonical_args",
    "GREEN", "YELLOW", "RED", "Gate", "GateResult", "default_paths",
    "scan_outbound",
    "DEFAULT_TTL_SECONDS", "PermitError", "PermitKernel", "load_or_create_secret",
    "PROPOSED", "APPROVED", "DENIED", "EXECUTED", "EXPIRED", "Permit",
    "MemoryStore", "PermitStore", "SqliteStore",
    "__version__",
]
