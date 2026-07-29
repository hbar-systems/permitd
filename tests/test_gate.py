import json

import pytest

from permitd import GREEN, RED, YELLOW, Gate


@pytest.fixture
def gate(tmp_path):
    g = Gate(db=tmp_path / "permitd.db")
    g.register("read_notes", lambda: ["note1"], tier=GREEN)
    g.register("web_search", lambda query: f"results for {query}", tier=YELLOW)
    g.register("send_message", lambda to, body: f"sent to {to}", tier=RED,
               description="send a message")
    return g


def test_green_runs_freely_and_is_audited(gate, tmp_path):
    r = gate.call("read_notes")
    assert r.ok and r.result == ["note1"]
    lines = (tmp_path / "permitd_audit.jsonl").read_text().splitlines()
    assert json.loads(lines[-1])["event"] == "executed"


def test_unknown_tool_refused(gate):
    r = gate.call("nope")
    assert not r.ok and r.reason == "unknown_tool"


def test_yellow_requires_standing_authorization(gate):
    r = gate.call("web_search", {"query": "hello"})
    assert not r.ok and r.reason == "not_authorized"
    gate.standing_authorization = True
    r = gate.call("web_search", {"query": "hello"})
    assert r.ok and r.result == "results for hello"


def test_red_full_flow(gate, tmp_path):
    args = {"to": "alice", "body": "hi"}
    r = gate.call("send_message", args)
    assert not r.ok and r.reason == "approval_required"
    permit_id = r.permit["id"]
    assert r.permit["args"] == args  # approval surface shows full args

    gate.approve(permit_id)
    r = gate.call("send_message", args, permit_id=permit_id)
    assert r.ok and r.result == "sent to alice"

    # replay refused
    r = gate.call("send_message", args, permit_id=permit_id)
    assert not r.ok and r.reason == "already_used"

    events = [json.loads(l)["event"]
              for l in (tmp_path / "permitd_audit.jsonl").read_text().splitlines()]
    assert events[:3] == ["proposed", "approved", "executed"]


def test_red_approved_for_other_args_refused(gate):
    r = gate.call("send_message", {"to": "alice", "body": "hi"})
    pid = r.permit["id"]
    gate.approve(pid)
    r = gate.call("send_message", {"to": "eve", "body": "hi"}, permit_id=pid)
    assert not r.ok and r.reason == "args_mismatch"


def test_egress_guard_blocks_at_propose_time(gate):
    r = gate.call("send_message", {"to": "x", "body": "key sk-ant-" + "a1B2" * 8})
    assert not r.ok and r.reason == "egress_blocked"
    assert gate.pending() == []  # never reached the approval surface


def test_egress_guard_blocks_yellow(gate):
    gate.standing_authorization = True
    r = gate.call("web_search", {"query": "Bearer abcdefghij1234567890XYZQRS"})
    assert not r.ok and r.reason == "egress_blocked"


def test_green_exempt_from_guard(tmp_path):
    g = Gate(db=tmp_path / "g.db")
    g.register("summarize", lambda text: len(text), tier=GREEN)
    r = g.call("summarize", {"text": "sk-ant-" + "a1B2" * 8})
    assert r.ok  # green never leaves; not scanned


def test_tool_exception_never_raises(gate):
    def boom(to, body):
        raise RuntimeError("smtp down")
    gate.register("send_message", boom, tier=RED)
    r = gate.call("send_message", {"to": "a", "body": "b"})
    gate.approve(r.permit["id"])
    r = gate.call("send_message", {"to": "a", "body": "b"}, permit_id=r.permit["id"])
    assert not r.ok and r.reason == "exception" and "smtp down" in r.error


def test_decorator_registration(tmp_path):
    g = Gate(db=tmp_path / "g.db")

    @g.tool(tier=RED, description="delete a file")
    def delete_file(path):
        return f"deleted {path}"

    assert g.tools() == [{"name": "delete_file", "tier": "red",
                          "description": "delete a file"}]
    r = g.call("delete_file", {"path": "/tmp/x"})
    assert r.reason == "approval_required"
