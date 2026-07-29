"""Argument canonicalization and the binding hash.

A permit is bound to one exact (tool, args) pair. The binding hash is the
scope of that bond: approval for "send X to Alice" can neither be replayed
nor bent to "send Y to Eve".
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional


def canonical_args(args: Optional[Dict[str, Any]]) -> str:
    """Stable JSON for args so the same call always hashes the same. Sorted
    keys + tight separators: argument ORDER and whitespace can't change the
    binding, but any value change does."""
    return json.dumps(args or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def binding_hash(tool: str, args: Optional[Dict[str, Any]]) -> str:
    """The scope a permit is bound to: this exact tool, these exact args. The
    tool name is folded in so a permit for one tool can never satisfy another."""
    return hashlib.sha256(f"{tool}\n{canonical_args(args)}".encode("utf-8")).hexdigest()
