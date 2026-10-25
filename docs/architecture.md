---
created: 2026-10-25
---
# permitd architecture

*Created 2026-10-25. Drawn from the code in this repository as it is today, nothing planned.*

Diagram: [architecture.mmd](architecture.mmd) (mermaid 11, `flowchart TD`) rendered to [architecture.png](architecture.png).

permitd is a stdlib-only Python library (plus a `permitd` console script) that holds the state of "may this tool call run?" across turns of an agent loop. An agent, usually through the MCP example server or by importing `Gate` directly, calls a tool; `Gate` runs the egress guard over the arguments, then for RED-tier tools asks `PermitKernel` to propose a permit bound to `sha256(tool + canonical args)`. A human approves or denies from the `permitd` CLI in another process, which shares the same SQLite store, secret file and audit log via `default_paths`; approval mints a single-use HMAC-SHA256 token with a TTL. The agent's retry carries the permit id, the kernel recomputes the signature, checks the binding and expiry, wins the atomic burn in the store, runs the tool, and every outcome (including refusals) lands as one hash-chained JSONL line that `permitd audit --verify` can walk.

| subgraph | responsible for | key files |
|---|---|---|
| Gate: registry and egress guard | GREEN/YELLOW/RED tier registry, `call()` dispatch, uniform `GateResult`, standing authorization for YELLOW, egress scan of outbound arguments before any non-GREEN call (including at propose time) | `src/permitd/gate.py`, `src/permitd/guard.py` |
| Permit kernel: model, binding, signing | propose / approve / deny / verify_and_burn / execute, HMAC-SHA256 token minting and recomputation, double TTL, the `Permit` dataclass and its five states, argument canonicalization and binding hash, secret loading (0600 file or `PERMITD_SECRET`) | `src/permitd/kernel.py`, `src/permitd/permit.py`, `src/permitd/binding.py` |
| Store | `PermitStore` protocol (five methods, compare-and-swap `burn`), durable `SqliteStore` with atomic burn, `MemoryStore` for tests | `src/permitd/store.py` |
| Audit trail | append-only JSONL with `prev` = sha256 of the previous line, `verify()`, `tip()`, `tail()`, best-effort writes with a `dropped` counter, `summarize_args` | `src/permitd/audit.py` |
| Operator CLI | `permitd pending / show / approve / deny / audit [-n, --verify, --tip]`, store selection by `--db`, `$PERMITD_DB` or `./permitd.db` | `src/permitd/cli.py` |
| Integration, packaging, CI | MCP example server (read_notes GREEN, write_note RED, pending_permits), hatchling package with `mcp` and `dev` extras and the console script, pytest on Python 3.10 to 3.14, trusted-publishing release on `v*` tags, 69 tests across seven files | `examples/mcp_server/server.py`, `pyproject.toml`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `tests/` |

External things: the agent loop or MCP client (Claude Code) that calls the tools, the human operator in a second terminal, the filesystem (`permitd.db`, `permitd.db.secret`, `permitd_audit.jsonl`, laid out by `default_paths`; `PERMITD_SECRET` in the environment overrides the secret file), and PyPI (permitd 0.2.0).

Related: [README](../README.md), [docs/quickstart-claude-code.md](quickstart-claude-code.md), [THREAT_MODEL.md](../THREAT_MODEL.md), [DESIGN.md](../DESIGN.md).
