---
created: 2026-10-25
---
# permitd architecture

*Created 2026-10-25. Drawn from the code in this repository as it is today, nothing planned.*

Diagram: [architecture.mmd](architecture.mmd) (mermaid 11, `flowchart TD`) rendered to [architecture.png](architecture.png).

permitd is a stdlib-only Python library (plus a `permitd` console script) that holds the state of "may this tool call run?" across turns of an agent loop. A host process (the MCP example server, a brain runtime such as brainfoundry-nous, or any Python program) registers tools on a `Gate` with GREEN / YELLOW / RED tiers. Every non-GREEN call first passes the egress guard; a RED call without a `permit_id` makes `PermitKernel.propose` record a `Permit` bound to `sha256(tool + canonical args)` and returns `approval_required`. A human approves or denies from the `permitd` CLI in another process, which meets the library on the same SQLite store, secret file and audit log through `default_paths`; approval mints a single-use HMAC-SHA256 token with a TTL. The agent's retry carries the permit id, `verify_and_burn` recomputes the signature, checks the binding and expiry, wins the atomic compare-and-swap burn in the store, and only then runs the tool. Every outcome, including refusals, lands as one hash-chained JSONL line that `permitd audit --verify` can walk.

| subgraph | responsible for | key files |
|---|---|---|
| Permit model and signing | the `Permit` dataclass and its five states (`public()` never exposes the token), argument canonicalization and binding hash, HMAC secret loading (0600 file or `PERMITD_SECRET`), the `PermitStore` protocol with compare-and-swap `burn`, `SqliteStore` (default) and `MemoryStore` (tests) | `src/permitd/permit.py`, `src/permitd/binding.py`, `src/permitd/kernel.py`, `src/permitd/store.py` |
| Proposal and approval flow | `propose` / `pending` / `approve` / `deny`; token minted over `id.binding_hash.approved_at`; a proposal is approvable for one TTL and an approval executable for another | `src/permitd/kernel.py` |
| Execution gate | tier registry and `@gate.tool` decorator, `call()` dispatch returning a uniform `GateResult` (never raises), egress scan of outbound arguments before any non-GREEN call and again at execute, `verify_and_burn` + `execute` running the tool only after signature, binding, expiry and the atomic burn all pass | `src/permitd/gate.py`, `src/permitd/guard.py`, `src/permitd/kernel.py` |
| Audit log | append-only JSONL with `prev` = sha256 of the previous line, fsync per write, best-effort with a `dropped` counter, `verify()`, `tip()`, `tail()`, `summarize_args` | `src/permitd/audit.py` |
| CLI and integration surface | `permitd pending / show / approve / deny / audit [-n, --verify, --tip]`, store selection by `--db`, `$PERMITD_DB` or `./permitd.db`, `default_paths` convention, MCP example server (read_notes GREEN, write_note RED, pending_permits), hatchling package with `mcp` and `dev` extras, pytest matrix on Python 3.10 to 3.14, trusted-publishing release on `v*` tags, 64 tests across seven files | `src/permitd/cli.py`, `src/permitd/gate.py`, `examples/mcp_server/server.py`, `pyproject.toml`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `tests/` |

External things, drawn outside the subgraphs: the calling agent or MCP client (Claude Code in the quickstart), the human approver in a second terminal, the embedding host (a brain runtime such as brainfoundry-nous, or any Python process that constructs a `Gate`), and the files on disk (`permitd.db`, `permitd.db.secret`, `permitd_audit.jsonl`).

Related: [README](../README.md), [docs/quickstart-claude-code.md](quickstart-claude-code.md), [THREAT_MODEL.md](../THREAT_MODEL.md), [DESIGN.md](../DESIGN.md).
