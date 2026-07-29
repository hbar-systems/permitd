# permitd MCP example

Created: 2026-07-29

An MCP server whose tools go through the permitd gate. Any MCP-speaking agent
gets propose → approve → execute + audit for free — no agent-side changes.

## Setup

```
pip install "permitd[mcp]"
```

### With Claude Code

```
claude mcp add permitd-demo -- python /absolute/path/to/examples/mcp_server/server.py
```

### With any other MCP client

Run `python server.py` and connect over stdio.

## The demo

Ask the agent to *"write a note called hello saying hi"*. It calls
`write_note` and gets back:

```
write_note needs operator approval before it runs. Permit PRM-9a1b2c3d4e5f is
proposed — ask the operator to run `permitd approve PRM-9a1b2c3d4e5f`, then
retry this exact call with that permit_id. ...
```

In another terminal (the db lives next to server.py):

```
permitd --db examples/mcp_server/permitd.db pending
permitd --db examples/mcp_server/permitd.db approve PRM-9a1b2c3d4e5f
```

The agent retries `write_note(name, text, permit_id="PRM-9a1b2c3d4e5f")` — the
note is written. Deny instead, and the retry is refused (`denied`). Change the
text between propose and execute, and it is refused (`args_mismatch`). Every
outcome is one line in:

```
permitd --db examples/mcp_server/permitd.db audit
```

Tools: `read_notes` (GREEN — runs freely, audited), `write_note` (RED — the
flow above), `pending_permits` (convenience view).
