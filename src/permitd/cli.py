"""The `permitd` CLI — the minimal approve surface.

Points at the same SQLite store (and derived secret + audit paths) as a
library `Gate(db=...)` or `PermitKernel(SqliteStore(...))`, so approval is
genuinely out-of-band: the agent proposes in one process, a human approves
here, the agent's retry executes.

    permitd pending            # what is waiting, with FULL args (informed consent)
    permitd show PRM-...
    permitd approve PRM-...
    permitd deny PRM-...
    permitd audit -n 20

Store selection: --db, else $PERMITD_DB, else ./permitd.db.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .audit import AuditLog
from .gate import default_paths
from .kernel import PermitError, PermitKernel
from .permit import Permit
from .store import SqliteStore


def _kernel(args: argparse.Namespace) -> tuple[PermitKernel, AuditLog]:
    db = args.db or os.getenv("PERMITD_DB") or "permitd.db"
    paths = default_paths(db)
    audit = AuditLog(args.audit or os.getenv("PERMITD_AUDIT") or paths["audit"])
    kernel = PermitKernel(
        SqliteStore(paths["db"]),
        secret_path=None if os.getenv("PERMITD_SECRET") else paths["secret"],
        audit=audit,
    )
    return kernel, audit


def _print_permit(p: Permit) -> None:
    # Full, untruncated args on purpose: this is the operator's
    # informed-consent surface — they must see the exact thing they authorize.
    print(f"  {p.id}  [{p.status}]  {p.tool}")
    print(f"      args: {json.dumps(p.args, ensure_ascii=False)}")
    print(f"      proposed: {p.created_at}  ttl: {p.ttl_seconds}s")


def cmd_pending(args: argparse.Namespace) -> int:
    kernel, _ = _kernel(args)
    pending = kernel.pending()
    if not pending:
        print("no pending permits")
        return 0
    print(f"{len(pending)} pending permit(s):")
    for p in pending:
        _print_permit(p)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    kernel, _ = _kernel(args)
    p = kernel.get(args.permit_id)
    if p is None:
        print(f"no permit {args.permit_id}", file=sys.stderr)
        return 1
    _print_permit(p)
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    kernel, _ = _kernel(args)
    p = kernel.get(args.permit_id)
    if p is not None:
        _print_permit(p)
    try:
        p = kernel.approve(args.permit_id)
    except PermitError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    print(f"approved — {p.id} is executable for {p.ttl_seconds}s, single use, "
          "bound to exactly these arguments")
    return 0


def cmd_deny(args: argparse.Namespace) -> int:
    kernel, _ = _kernel(args)
    try:
        p = kernel.deny(args.permit_id)
    except PermitError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    print(f"denied — {p.id} will never run")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    _, audit = _kernel(args)
    records = audit.tail(args.n)
    if not records:
        print("audit log is empty")
        return 0
    for r in records:
        print(json.dumps(r, ensure_ascii=False))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="permitd",
        description="Approve, deny, and audit permits for governed tool execution.")
    parser.add_argument("--db", help="permit store path (default: $PERMITD_DB or ./permitd.db)")
    parser.add_argument("--audit", help="audit log path (default: alongside the db)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("pending", help="list permits awaiting a decision").set_defaults(fn=cmd_pending)
    p = sub.add_parser("show", help="show one permit")
    p.add_argument("permit_id")
    p.set_defaults(fn=cmd_show)
    p = sub.add_parser("approve", help="approve a permit (mints the single-use token)")
    p.add_argument("permit_id")
    p.set_defaults(fn=cmd_approve)
    p = sub.add_parser("deny", help="deny a permit")
    p.add_argument("permit_id")
    p.set_defaults(fn=cmd_deny)
    p = sub.add_parser("audit", help="print recent audit lines")
    p.add_argument("-n", type=int, default=20, help="how many lines (default 20)")
    p.set_defaults(fn=cmd_audit)

    ns = parser.parse_args(argv)
    return ns.fn(ns)


if __name__ == "__main__":
    raise SystemExit(main())
