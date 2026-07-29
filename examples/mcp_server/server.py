"""An MCP server whose tools are gated by permitd.

Point any MCP-speaking agent (Claude Code included) at this server and it
gets propose -> approve -> execute + audit with zero agent-side changes:

  1. the agent calls write_note(...) -> "permit PRM-... proposed, waiting"
  2. you run `permitd --db <db> approve PRM-...` in another terminal
  3. the agent retries with that permit_id -> the note is written
  4. `permitd --db <db> audit` shows the whole story

Run: `python server.py` (stdio transport). Requires `pip install permitd[mcp]`.
State (permit db, secret, audit log, notes) lives next to this file so the
CLI and the server always meet on the same store regardless of cwd.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    from mcp.server.mcpserver import MCPServer as _Server  # mcp >= 2.0
except ImportError:
    from mcp.server.fastmcp import FastMCP as _Server      # mcp 1.x

from permitd import GREEN, RED, Gate

HERE = Path(__file__).resolve().parent
DB = os.getenv("PERMITD_DB", str(HERE / "permitd.db"))
NOTES = HERE / "notes"

gate = Gate(db=DB)
mcp = _Server("permitd-demo")


# ── gated implementations ────────────────────────────────────────────────────
@gate.tool(name="read_notes", tier=GREEN, description="list saved notes")
def _read_notes() -> str:
    NOTES.mkdir(exist_ok=True)
    files = sorted(p.name for p in NOTES.glob("*.txt"))
    return "notes: " + (", ".join(files) if files else "(none)")


@gate.tool(name="write_note", tier=RED, description="write a note file")
def _write_note(name: str, text: str) -> str:
    NOTES.mkdir(exist_ok=True)
    safe = Path(name).name or "note"
    path = NOTES / f"{safe}.txt"
    path.write_text(text, encoding="utf-8")
    return f"wrote {path.name} ({len(text)} chars)"


# ── MCP surface ──────────────────────────────────────────────────────────────
@mcp.tool()
def read_notes() -> str:
    """List the saved notes."""
    r = gate.call("read_notes")
    return str(r.result) if r.ok else r.error


@mcp.tool()
def write_note(name: str, text: str, permit_id: str = "") -> str:
    """Write a note. Governed: the first call (no permit_id) proposes a permit
    and returns its id; a human must approve it out-of-band (`permitd approve
    PRM-...`); then retry with the same name, text, and that permit_id."""
    r = gate.call("write_note", {"name": name, "text": text},
                  permit_id=permit_id or None)
    if r.ok:
        return str(r.result)
    if r.reason == "approval_required":
        return (f"{r.error}\n(approve with: permitd --db {DB} "
                f"approve {r.permit['id']})")
    return r.error


@mcp.tool()
def pending_permits() -> str:
    """Show permits waiting for human approval (read-only convenience)."""
    pending = gate.pending()
    if not pending:
        return "no pending permits"
    return "\n".join(f"{p.id}: {p.tool} {p.args}" for p in pending)


if __name__ == "__main__":
    mcp.run()
