# Changelog

## 0.2.0 — 2026-09-02

- Audit trail is hash-chained: every line carries `prev`, the SHA-256 of the
  previous line's bytes. `permitd audit --verify` walks the chain and names
  the first broken line; `permitd audit --tip` prints the newest hash for
  off-host anchoring. `AuditLog.verify()` / `.tip()` in the library.
- `AuditLog.dropped` counts audit lines lost to write failures.
- Audit writes are fsync'd.
- THREAT_MODEL.md: what is a boundary, what is a guardrail, and the list of
  things permitd does not defend against.
- docs/quickstart-claude-code.md: five-minute Claude Code walkthrough, tested
  end to end.
- README: "an agent cannot fake" → "the model cannot skip", with the threat
  model linked.

Logs written by 0.1.0 verify as an unchained prefix; the chain is enforced
from the first 0.2.0 line onward.

## 0.1.0 — 2026-07-30

Initial release: propose → permit → approve → execute → audit, HMAC-signed
single-use TTL permits bound to canonical args, atomic SQLite burn, egress
guard, GREEN/YELLOW/RED gate, `permitd` CLI, MCP server example.
