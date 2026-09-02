# permitd — threat model

Created: 2026-09-02

Short and honest. Read this before you rely on permitd for anything that
matters. The one-sentence version: **permitd is a security boundary against
the model only when the model cannot reach the host process, the secret, or
the store. Everywhere else it is a guardrail against accidents.** Both are
useful. They are not the same thing, and the README's "an agent cannot fake"
holds only under the first.

## Three parties

| party | trust | what it holds |
|---|---|---|
| the **model** (the LLM producing tool calls) | untrusted; assume prompt injection | nothing but the tool-call channel |
| the **host** (the process that embeds `Gate` and runs the tool) | trusted | the HMAC secret, the SQLite store, the runner |
| the **approver** (a human, out-of-band) | trusted | `permitd approve` on the same store |

permitd's guarantees are statements about what the *model* can do. They say
nothing about a host that is itself malicious or compromised, and they weaken
to "convention" the moment the model and the host share a trust domain.

Two deployments, two very different claims:

- **MCP server** (`examples/mcp_server/`): the model speaks MCP; the host
  process holds the Gate. The model cannot call `approve()`, cannot read
  `permitd.db.secret`, cannot write the store. **This is a boundary.** An
  injected model can propose anything it likes; nothing RED runs until a human
  says so.
- **README two-terminal demo** (`agent.py` holds the `Gate`): the model's
  output and the Gate live in one Python process. If that process lets the
  model write and run code, the model can call `gate.approve(pid)` itself.
  **This is a guardrail:** it stops the loop from running a RED tool by
  accident, and it leaves a receipt. It does not stop a determined adversary
  inside the process.

If you want the boundary, deploy the MCP way, or otherwise keep `approve`,
the secret, and store write access in a process the model cannot drive.

## What permitd defends against

Against a model that can only issue tool calls:

- **Unreviewed RED execution.** A write / exec / send tool does not run
  without a permit that a human minted for it.
- **Replay.** A permit is single-use. The burn is one SQLite
  compare-and-swap; two callers racing the same permit cannot both pass.
- **Argument swap after approval.** The permit binds
  `sha256(tool + canonical_json(args))`. Approval for "send X to Alice" does
  not execute "send Y to Eve". Key order and whitespace do not matter; any
  value change does.
- **Stale approvals.** Two TTL clocks (default 300 s each): a proposal expires
  if not approved in time, an approval expires if not executed in time.
  Unparseable timestamps count as expired.
- **Store rows edited without the secret.** Approval mints an HMAC over
  `id.binding_hash.approved_at`, recomputed at execute time. Flipping a row to
  `approved` by hand, or swapping its hash, fails `bad_signature`.
- **Credential-shaped content in tool arguments.** The egress guard scans
  non-GREEN args at propose time and again at execute time for private-key
  blocks, bearer headers, well-known API-key shapes, inline `api_key=`
  assignments, the values of the host's own sensitive env vars, and a
  high-entropy backstop. A poisoned proposal is refused before an approval
  card is ever shown. The refusal names the matched shape, never the value.
- **Silent refusals.** Every non-execute outcome writes an audit line with
  its reason.
- **Quiet edits to the audit trail.** Each line carries the SHA-256 of the
  previous line's bytes. Editing, reordering, or deleting any line except the
  newest breaks the chain, and `permitd audit --verify` reports the first
  broken line. Deleting the newest lines is caught only if you anchored
  `permitd audit --tip` somewhere the writer cannot reach.

## What permitd does not defend against

Named so nobody discovers them in production:

- **A malicious or compromised host.** The host holds the secret and runs the
  tool. permitd cannot protect you from the process it lives in.
- **A model with filesystem or shell access on the host.** If the model can
  read `permitd.db.secret`, write `permitd.db`, or call `approve()`, it is in
  the host's trust domain and the boundary is gone. Claude Code with an
  unrestricted Bash tool on the same machine is exactly this case: use the
  MCP server *and* keep the store somewhere that shell cannot write.
- **Anyone who can run `permitd approve`.** The CLI is unauthenticated on
  purpose; the approver's identity is "whoever has this file". Protect the
  store with OS permissions, or put `approve` behind your own authenticated
  surface (it is one method call).
- **Time-of-check / time-of-use on referenced state.** The permit binds the
  arguments, not the world. "Write this file" approved at T can execute at
  T+200 s against a file whose contents, target, or symlink changed in
  between. If the world can change under you, bind a content hash into the
  args, or shorten the TTL.
- **Audit log rewriting by someone with write access and time.** The chain
  is unkeyed, so it is tamper-evident, not tamper-proof: whoever can write
  the file can re-chain it end to end. That is the host trust domain again.
  A tip anchored off-host is the defence. Audit writes are also best-effort
  by contract (a failed write never blocks the call); `AuditLog.dropped`
  counts them, and it is your job to look.
- **Egress guard bypass.** It is a shape scanner. A secret that is base64'd,
  split across arguments, or of a shape it does not know will pass. Treat it
  as a seatbelt, not as data-loss prevention.
- **Approval fatigue.** Humans approve raw JSON per RED call. That is right
  for one operator and a handful of tools; at ten agents it becomes
  rubber-stamping. permitd has no policy layer ("auto-approve X, hold Y") and
  does not pretend to.
- **Flooding.** A model can propose without limit. There is no rate limit on
  `propose`; the store just grows.
- **Bugs in your tools.** The runner executes with the host's privileges.
  An approved call to a buggy tool is an approved bug.
- **The model lying afterwards.** permitd records what ran and whether it
  raised. It does not verify the model's account of the result.

## Deployment guidance

1. Prefer the MCP server. It is the deployment where the claims are strongest.
2. Put `permitd.db`, `permitd.db.secret`, and `permitd_audit.jsonl` under an
   OS user the agent process cannot write to.
3. If the model has a shell on the same box, run the MCP server as a
   different user, or on a different box, and point the CLI at the store over
   a shared filesystem or your own approve endpoint.
4. Set `PERMITD_SECRET` in an environment the model cannot read, rather than
   letting the secret file sit next to the db.
5. Keep TTLs short for tools whose targets can change.
6. Record `permitd audit --tip` somewhere the host cannot write (a cron
   that posts it to another box is enough), and run `permitd audit --verify`
   before you trust the file in front of anyone.

## Known gaps, in priority order

These are the honest edges. None is promised; they are listed so you can
decide whether to wait for them.

1. Approver identity on the approval record, so "who approved" is a fact and
   not a filename.
2. A keyed chain (HMAC with the kernel secret) so re-chaining needs the secret
   and not just write access.
3. A rate limit on `propose`.

Shipped in 0.2.0: the hash chain, `--verify`, `--tip`, and the dropped-write
counter.

## Reporting

Open an issue at https://github.com/hbar-systems/permitd/issues. There is no
private disclosure channel yet; if you need one, say so in the issue and it
will be arranged.
