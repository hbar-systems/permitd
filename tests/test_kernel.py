import json
from datetime import datetime, timedelta, timezone

import pytest

from permitd import (APPROVED, DENIED, EXECUTED, EXPIRED, PROPOSED, AuditLog,
                     MemoryStore, PermitError, PermitKernel, SqliteStore)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def kernel(tmp_path):
    return PermitKernel(audit=AuditLog(tmp_path / "audit.jsonl"))


def test_happy_path_propose_approve_execute_audit(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kernel = PermitKernel(audit=AuditLog(audit_path))
    ran = []

    p = kernel.propose("send_message", {"to": "alice", "body": "hi"})
    assert p.status == PROPOSED
    assert kernel.get(p.id).token is None  # no token exists before approval

    kernel.approve(p.id)
    result = kernel.execute("send_message", {"to": "alice", "body": "hi"}, p.id,
                            runner=lambda to, body: ran.append((to, body)) or "sent")
    assert result == "sent"
    assert ran == [("alice", "hi")]
    assert kernel.get(p.id).status == EXECUTED

    events = [json.loads(l)["event"] for l in audit_path.read_text().splitlines()]
    assert events == ["proposed", "approved", "executed"]


def test_replay_is_refused(kernel):
    p = kernel.propose("t", {"x": 1})
    kernel.approve(p.id)
    kernel.execute("t", {"x": 1}, p.id, runner=lambda x: x)
    with pytest.raises(PermitError) as e:
        kernel.execute("t", {"x": 1}, p.id, runner=lambda x: x)
    assert e.value.reason == "already_used"


def test_args_mismatch_is_refused(kernel):
    p = kernel.propose("send", {"to": "alice"})
    kernel.approve(p.id)
    ok, reason = kernel.verify_and_burn("send", {"to": "eve"}, p.id)
    assert (ok, reason) == (False, "args_mismatch")
    # the permit survives a failed attempt and still works for the real args
    ok, reason = kernel.verify_and_burn("send", {"to": "alice"}, p.id)
    assert (ok, reason) == (True, "ok")


def test_wrong_tool_is_refused(kernel):
    p = kernel.propose("send", {"x": 1})
    kernel.approve(p.id)
    ok, reason = kernel.verify_and_burn("delete", {"x": 1}, p.id)
    assert (ok, reason) == (False, "args_mismatch")


def test_unapproved_and_unknown_and_missing(kernel):
    p = kernel.propose("t", {})
    assert kernel.verify_and_burn("t", {}, p.id) == (False, "not_approved")
    assert kernel.verify_and_burn("t", {}, "PRM-nope") == (False, "unknown_permit")
    assert kernel.verify_and_burn("t", {}, "") == (False, "missing_permit")


def test_deny_kills_permit(kernel):
    p = kernel.propose("t", {})
    kernel.deny(p.id)
    assert kernel.get(p.id).status == DENIED
    assert kernel.verify_and_burn("t", {}, p.id) == (False, "denied")
    with pytest.raises(PermitError):
        kernel.approve(p.id)


def test_deny_after_approve_kills_token(kernel):
    p = kernel.propose("t", {})
    kernel.approve(p.id)
    kernel.deny(p.id)
    assert kernel.verify_and_burn("t", {}, p.id) == (False, "denied")


def test_proposal_expires(tmp_path):
    clock = Clock()
    kernel = PermitKernel(ttl_seconds=300, clock=clock)
    p = kernel.propose("t", {})
    clock.advance(301)
    with pytest.raises(PermitError) as e:
        kernel.approve(p.id)
    assert e.value.reason == "already_expired"
    assert kernel.get(p.id).status == EXPIRED


def test_approval_expires(tmp_path):
    clock = Clock()
    kernel = PermitKernel(ttl_seconds=300, clock=clock)
    p = kernel.propose("t", {})
    kernel.approve(p.id)
    clock.advance(301)
    assert kernel.verify_and_burn("t", {}, p.id) == (False, "expired")


def test_store_tamper_fails_signature(tmp_path):
    kernel = PermitKernel()
    p = kernel.propose("send", {"to": "alice"})
    # attacker with store access flips the row to approved without the kernel
    raw = kernel.store.get(p.id)
    raw.status = APPROVED
    raw.approved_at = kernel._now().isoformat()
    raw.token = "f" * 64
    kernel.store.update(raw)
    assert kernel.verify_and_burn("send", {"to": "alice"}, p.id) == (False, "bad_signature")


def test_tampered_binding_hash_fails_signature(kernel):
    from permitd import binding_hash
    p = kernel.propose("send", {"to": "alice"})
    kernel.approve(p.id)
    # attacker swaps the stored args+binding to steer an approved permit
    raw = kernel.store.get(p.id)
    raw.args = {"to": "eve"}
    raw.binding_hash = binding_hash("send", {"to": "eve"})
    kernel.store.update(raw)
    assert kernel.verify_and_burn("send", {"to": "eve"}, p.id) == (False, "bad_signature")


def test_two_kernels_shared_store_and_secret(tmp_path):
    """Approval genuinely out-of-band: proposer and approver are different
    kernel instances (processes) meeting on one sqlite store + secret."""
    db = tmp_path / "p.db"
    agent = PermitKernel(SqliteStore(db), secret_path=tmp_path / "s")
    operator = PermitKernel(SqliteStore(db), secret_path=tmp_path / "s")
    p = agent.propose("send", {"to": "alice"})
    operator.approve(p.id)
    assert agent.verify_and_burn("send", {"to": "alice"}, p.id) == (True, "ok")


def test_different_secret_cannot_verify(tmp_path):
    db = tmp_path / "p.db"
    a = PermitKernel(SqliteStore(db), secret="secret-a")
    b = PermitKernel(SqliteStore(db), secret="secret-b")
    p = a.propose("send", {})
    a.approve(p.id)
    assert b.verify_and_burn("send", {}, p.id) == (False, "bad_signature")


def test_burn_is_single_use_across_kernels(tmp_path):
    db = tmp_path / "p.db"
    a = PermitKernel(SqliteStore(db), secret="s")
    b = PermitKernel(SqliteStore(db), secret="s")
    p = a.propose("t", {})
    a.approve(p.id)
    results = [a.verify_and_burn("t", {}, p.id), b.verify_and_burn("t", {}, p.id)]
    assert sorted(r[0] for r in results) == [False, True]


def test_pending_lists_only_live_proposals(tmp_path):
    clock = Clock()
    kernel = PermitKernel(clock=clock)
    p1 = kernel.propose("a", {})
    clock.advance(301)  # p1 expires
    p2 = kernel.propose("b", {})
    p3 = kernel.propose("c", {})
    kernel.deny(p3.id)
    assert [p.id for p in kernel.pending()] == [p2.id]


def test_refusal_and_failure_are_audited(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    kernel = PermitKernel(audit=AuditLog(audit_path))
    p = kernel.propose("t", {})
    with pytest.raises(PermitError):
        kernel.execute("t", {}, p.id, runner=lambda: "x")  # not approved
    kernel.approve(p.id)

    def boom():
        raise RuntimeError("tool blew up")

    with pytest.raises(RuntimeError):
        kernel.execute("t", {}, p.id, runner=boom)
    events = [json.loads(l)["event"] for l in audit_path.read_text().splitlines()]
    assert "refused" in events and "failed" in events
