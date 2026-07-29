# permitd — design

Created: 2026-07-29

## Step 0 — operator decisions (settled 2026-07-29)

1. **Name:** `permitd`. The daemon-suffix reads as infrastructure, which is the
   positioning: not an agent, not a framework — the small thing that sits under
   an agent loop and holds the line.
2. **License:** MIT. This is an adoption/portfolio play; AGPL-by-reflex was
   explicitly rejected for this artifact. MIT over Apache-2.0 for brevity — no
   patent-grant machinery, one page a stranger actually reads.
3. **Repo:** `hbar-systems/permitd`, **public from day one**.

## What this is

A pip-installable governance kernel for agent tool execution, extracted from
`brainfoundry-nous` (where it runs in production as the tool-dispatch gate).
One artifact, two vocabularies, deliberately:

- **Governance vocabulary:** permits, per-call approval, fail-closed
  verification, append-only audit.
- **Loop-engineering vocabulary:** state that survives across agent loop turns.
  A permit proposed in turn N is approved out-of-band and executed in turn
  N+K — the kernel *is* durable loop state for the human-checkpoint layer.

## The flow (the whole library in one line)

```
propose(tool, args) → Permit(id, signed, TTL, single-use)
                    → approve(id)   [out-of-band: CLI, HTTP, any callable]
                    → execute(tool, args, permit_id) — verify + burn → run
                    → one audit line lands (JSONL, append-only)
```

Every non-execute outcome is fail-closed: missing, expired, denied, tampered,
args-mismatched, or already-burned permits are refused, and the refusal itself
is audited.

## Core mechanics (carried over from nous, hardened where noted)

- **Binding hash.** A permit is bound to `sha256(tool + "\n" + canonical_args)`
  where `canonical_args` is sorted-key, tight-separator JSON. Approval for
  "send X to Alice" can neither be replayed nor bent to "send Y to Eve" —
  argument order and whitespace can't change the binding; any value change does.
- **Signed permits (HMAC).** On approve, the kernel mints
  `HMAC-SHA256(secret, permit_id . binding_hash . approved_at)` and stores it on
  the record. At execute time the signature is *recomputed and compared* — a
  store row edited behind the kernel's back (status flipped to approved, hash
  swapped) fails verification. In nous this pattern is the intra-brain signed
  permit (`api/identity/permits.py`); here it degrades gracefully to
  store-tamper evidence since library and store usually share a machine.
- **Single-use burn, atomic.** nous documented a known limit: its JSON-file
  store + in-process lock is only atomic single-worker. permitd's default store
  is SQLite and the burn is one statement —
  `UPDATE permits SET status='executed' WHERE id=? AND status='approved'` —
  so two processes racing the same permit cannot both pass, without any
  application-level lock.
- **TTL.** Two clocks, both bounded: a proposal is approvable for
  `ttl_seconds` after propose; a minted approval is executable for
  `ttl_seconds` after approve (default 300s each). Unparseable timestamps
  count as expired (fail closed).
- **Tiers.** GREEN (run freely, audited), YELLOW (requires standing
  authorization — one operator toggle, audited), RED (per-call permit, the flow
  above). Same semantics as nous's `api/tools/` registry.
- **Egress guard.** Ported from nous `api/tools/egress.py`: before any
  non-GREEN call runs — including at propose time, so a poisoned proposal never
  even reaches the approval surface — arguments are scanned for
  credential-shaped content (private-key blocks, Bearer/Basic headers,
  AWS/GitHub/Slack/Stripe/OpenAI/Anthropic/Google key shapes, inline
  `secret=...` assignments), for the process's own sensitive env-var *values*,
  and by a conservative high-entropy backstop (URLs excised — signed CDN URLs
  false-positive on entropy; named patterns still scan full text). Refusal
  reasons name the matched *shape*, never the value.
- **Audit.** Append-only JSONL, one line per outcome (proposed, denied,
  expired, blocked, executed, failed), best-effort by contract: an audit write
  failure must never break the dispatch path. Arg values are trimmed in audit
  lines; the approval surface, by contrast, always shows full args — it is the
  operator's informed-consent surface and must not truncate.

## Storage

Pluggable via a small `PermitStore` protocol. Shipped:

- `SqliteStore` — default; atomic burn; safe across processes on one machine.
- `MemoryStore` — tests and ephemeral gates.

Audit is a separate append-only JSONL file (not in SQLite) so it stays
`tail -f`-able and trivially exportable.

## Deliberately OUT

Brains, RAG, memory, federation, budgets/metering, any UI beyond the approve
CLI. No framework dependencies in the core — stdlib only. The MCP server under
`examples/` is the only place a third-party package (`mcp`) appears, as an
optional extra (`pip install permitd[mcp]`).

The core is synchronous. Tool callables are plain functions; async frameworks
(the MCP example included) call the gate from their event loop — the gate's own
work is milliseconds of hashing and one SQLite statement.

## The MCP wedge

`examples/mcp_server/` is one example that is also the positioning: an MCP
server whose tools are gated by the kernel. Any MCP-speaking agent — Claude
Code included — gets propose/approve/execute + audit for free: the agent calls
a RED tool, receives "permit PRM-… proposed, waiting for approval", a human
runs `permitd approve PRM-…` in another terminal, the agent retries and the
call executes with the audit line landing. No agent-side changes at all.

## Ancestry

- `hbar-systems/hbar.brain.console` (2026-03) — the original
  PROPOSE/CONFIRM/EXECUTE + audit-trail prototype; the interaction grammar
  started there.
- `brainfoundry-nous` — the kernel as lived in production:
  `api/tools/__init__.py` (tiers + dispatch gate), `api/tools/approvals.py`
  (single-use args-bound tokens), `api/tools/egress.py` (outbound scan),
  `api/tools/audit.py` (JSONL trail), `api/identity/permits.py` (typed,
  time-bound signed permits). permitd is an extraction, not a fork: nous keeps
  its copy; divergence is expected and fine.

## Positioning inputs

`discussions/2026-07-12_brainfoundry-loop-state-layer-reframe.md` and
`discussions/2026-07-12_brainfoundry-competitive-landscape-memory-governance.md`
(hbar.world): the governance kernel and the MCP loop-state wedge are ONE
artifact; README speaks both languages; ride the loop-engineering vocabulary
while it is current.

## Acceptance test (the only definition of done)

Clean machine, `pip install`, a stranger follows the README:
propose → approve → execute → the audit line lands. Nothing else counts.
