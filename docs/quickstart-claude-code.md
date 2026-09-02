# Five minutes: gate Claude Code with permitd

Created: 2026-09-02

By the end of this you will have Claude Code calling a tool that cannot run
until you type `approve` in another terminal, and an audit line for every
outcome. Nothing in Claude Code changes; it just gets told "waiting for
approval" and retries when you say so.

You need Python 3.10+ and Claude Code installed. Tested as pasted on
macOS with Python 3.14, mcp 2.1.1, permitd 0.2.0.

## 1. Install (one minute)

```
mkdir permitd-demo && cd permitd-demo
python3 -m venv venv && source venv/bin/activate
pip install "permitd[mcp]"
curl -sSLO https://raw.githubusercontent.com/hbar-systems/permitd/main/examples/mcp_server/server.py
```

`server.py` is an MCP server with three tools: `read_notes` (GREEN, runs
freely), `write_note` (RED, needs a permit), and `pending_permits`. The
permit store, secret, and audit log are created next to it on first use.

## 2. Register the server with Claude Code (thirty seconds)

```
claude mcp add permitd-demo -- "$PWD/venv/bin/python" "$PWD/server.py"
```

Absolute paths on purpose: Claude Code launches the server from its own
working directory, and the venv's Python is the one with `mcp` installed.

## 3. Ask Claude to do the RED thing (one minute)

```
claude
```

Then, inside Claude Code:

> Use the permitd-demo tools to write a note called hello saying hi.

Claude calls `write_note`. Claude Code may first show its own permission
prompt for the new MCP tool; allow it. That prompt is Claude Code's gate, not
yours. Then the tool answers:

```
write_note needs operator approval before it runs. Permit PRM-3f9c21ab44de is
proposed — ask the operator to run `permitd approve PRM-3f9c21ab44de`, then
retry this exact call with that permit_id. Do not alter the arguments; the
permit is bound to them.
```

Nothing has been written. Claude is now waiting on you.

## 4. Approve it from a second terminal (one minute)

```
cd permitd-demo && source venv/bin/activate
permitd --db permitd.db pending
```

```
1 pending permit(s):
  PRM-3f9c21ab44de  [proposed]  write_note
      args: {"name": "hello", "text": "hi"}
      proposed: 2026-09-02T09:04:23+00:00  ttl: 300s
```

You see the exact arguments, untruncated, because this is the moment you are
consenting to. Approve:

```
permitd --db permitd.db approve PRM-3f9c21ab44de
```

```
approved — PRM-3f9c21ab44de is executable for 300s, single use, bound to exactly these arguments
```

## 5. Let Claude retry (thirty seconds)

Back in Claude Code:

> Approved. Retry with that permit id.

Claude calls `write_note` again with `permit_id="PRM-3f9c21ab44de"` and gets
`wrote hello.txt (2 chars)`. The file is in `permitd-demo/notes/`.

## 6. Read the receipt

```
permitd --db permitd.db audit
```

```
{"ts": "...", "event": "proposed", "permit_id": "PRM-3f9c21ab44de", "tool": "write_note", "args": {"name": "hello", "text": "hi"}}
{"ts": "...", "event": "approved", "permit_id": "PRM-3f9c21ab44de", "tool": "write_note", "args": {"name": "hello", "text": "hi"}}
{"ts": "...", "event": "executed", "permit_id": "PRM-3f9c21ab44de", "tool": "write_note", "args": {"name": "hello", "text": "hi"}, "ok": true}
```

That is the whole loop: propose, approve, execute, audit line. Each line
carries the hash of the one before it:

```
permitd --db permitd.db audit --verify
```

```
ok — 3 line(s), chain intact, tip 9b1c…e4
```

## Three things worth trying next

**Ask Claude to reuse the permit.** "Write the same note again with the same
permit id." Refused with `already_used`; the burn is single-use and atomic.

**Deny one.** Ask for another note, then `permitd --db permitd.db deny
PRM-...`. Claude's retry is refused with `denied`, and the refusal is in the
audit log too.

**Change the arguments after approval.** Ask for a note, approve it, then tell
Claude "actually make the text say goodbye, same permit id". Refused with
`args_mismatch`: the permit is bound to the arguments you saw when you
approved.

## What you just built, and what you did not

Claude Code only ever speaks MCP to `server.py`. It cannot call `approve`,
cannot read the secret, cannot write the store. That is the deployment where
permitd's claims are strongest. If you also give Claude Code an unrestricted
shell on the same machine and keep the store in a directory it can write,
you are back to a guardrail. THREAT_MODEL.md at the repo root says exactly
where the line is.

## Clean up

```
claude mcp remove permitd-demo
```
