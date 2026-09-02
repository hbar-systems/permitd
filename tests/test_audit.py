"""The audit trail: hash chain, tamper evidence, multi-process chaining,
best-effort contract."""
import hashlib
import json
import subprocess
import sys

from permitd import AuditLog, GENESIS, Gate, RED
from permitd.audit import _line_hash


def _lines(path):
    return [ln for ln in path.read_bytes().split(b"\n") if ln.strip()]


def test_first_line_chains_to_genesis(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.log({"event": "x"})
    rec = json.loads(_lines(log.path)[0])
    assert rec["prev"] == GENESIS
    assert "ts" in rec


def test_each_line_carries_hash_of_previous_bytes(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.log({"event": f"e{i}"})
    lines = _lines(log.path)
    for i in range(1, 5):
        assert json.loads(lines[i])["prev"] == hashlib.sha256(lines[i - 1]).hexdigest()
    v = log.verify()
    assert v.ok and v.lines == 5 and v.first_bad_line is None
    assert v.tip == _line_hash(lines[-1]) == log.tip()


def test_empty_or_missing_log_verifies_clean(tmp_path):
    log = AuditLog(tmp_path / "missing.jsonl")
    v = log.verify()
    assert v.ok and v.lines == 0 and v.tip == GENESIS
    assert log.tip() == GENESIS


def test_edit_in_the_middle_is_detected(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(4):
        log.log({"event": f"e{i}", "n": i})
    lines = _lines(log.path)
    rec = json.loads(lines[1]); rec["n"] = 99
    lines[1] = json.dumps(rec, ensure_ascii=False).encode()
    log.path.write_bytes(b"\n".join(lines) + b"\n")
    v = log.verify()
    assert not v.ok and v.first_bad_line == 3 and v.reason == "prev hash mismatch"


def test_deleting_a_middle_line_is_detected(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(4):
        log.log({"event": f"e{i}"})
    lines = _lines(log.path)
    del lines[1]
    log.path.write_bytes(b"\n".join(lines) + b"\n")
    v = log.verify()
    assert not v.ok and v.first_bad_line == 2


def test_reordering_is_detected(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(3):
        log.log({"event": f"e{i}"})
    lines = _lines(log.path)
    lines[1], lines[2] = lines[2], lines[1]
    log.path.write_bytes(b"\n".join(lines) + b"\n")
    assert not log.verify().ok


def test_tail_truncation_is_only_caught_by_an_anchored_tip(tmp_path):
    """Honest limit: dropping the newest lines leaves a valid chain. The
    anchored tip is what catches it."""
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(3):
        log.log({"event": f"e{i}"})
    anchored = log.tip()
    lines = _lines(log.path)
    log.path.write_bytes(b"\n".join(lines[:-1]) + b"\n")
    v = log.verify()
    assert v.ok               # the file alone cannot tell
    assert v.tip != anchored  # the anchor can


def test_garbage_line_breaks_the_chain(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.log({"event": "e0"})
    with log.path.open("ab") as f:
        f.write(b"not json\n")
    log.log({"event": "e2"})  # chains to the garbage line's bytes
    v = log.verify()
    assert not v.ok and v.first_bad_line == 2 and v.reason == "not JSON"


def test_legacy_unchained_prefix_is_tolerated_then_chain_enforced(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_text(json.dumps({"ts": "t", "event": "old"}) + "\n")
    log = AuditLog(path)
    log.log({"event": "new"})
    v = log.verify()
    assert v.ok and v.lines == 2
    # an unchained line AFTER the chain started is a break
    with path.open("a") as f:
        f.write(json.dumps({"ts": "t", "event": "sneaky"}) + "\n")
    v = log.verify()
    assert not v.ok and v.first_bad_line == 3


def test_two_writers_on_one_file_chain_correctly(tmp_path):
    """A Gate and the CLI are separate processes with separate AuditLog
    objects; prev must come from the file, not from memory."""
    path = tmp_path / "a.jsonl"
    a, b = AuditLog(path), AuditLog(path)
    a.log({"event": "from_a"})
    b.log({"event": "from_b"})
    a.log({"event": "from_a_again"})
    assert a.verify().ok and a.verify().lines == 3


def test_gate_and_kernel_lines_verify_end_to_end(tmp_path):
    gate = Gate(db=tmp_path / "permitd.db")

    @gate.tool(tier=RED)
    def send(to):
        return f"sent to {to}"

    r = gate.call("send", {"to": "alice"})
    pid = r.permit["id"]
    gate.approve(pid)
    assert gate.call("send", {"to": "alice"}, permit_id=pid).ok
    assert not gate.call("send", {"to": "alice"}, permit_id=pid).ok  # already_used
    v = gate.audit.verify()
    assert v.ok and v.lines == 4


def test_write_failure_is_counted_not_raised(tmp_path):
    log = AuditLog(tmp_path)  # a directory: open("ab") fails
    log.log({"event": "x"})
    assert log.dropped == 1


def test_cli_verify_and_tip(tmp_path):
    db = tmp_path / "permitd.db"
    gate = Gate(db=db)

    @gate.tool(tier=RED)
    def send(to):
        return "ok"

    gate.call("send", {"to": "bob"})
    env = {"PERMITD_DB": str(db), "PATH": "", "PYTHONPATH": ""}
    import os
    env["PATH"] = os.environ.get("PATH", "")
    env["PYTHONPATH"] = os.environ.get("PYTHONPATH", "")
    out = subprocess.run([sys.executable, "-m", "permitd.cli", "audit", "--verify"],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0 and out.stdout.startswith("ok — 1 line(s)")
    tip = subprocess.run([sys.executable, "-m", "permitd.cli", "audit", "--tip"],
                         capture_output=True, text=True, env=env).stdout.strip()
    assert tip == gate.audit.tip() and len(tip) == 64
    # break it
    lines = _lines(gate.audit.path)
    gate.audit.path.write_bytes(lines[0].replace(b"bob", b"eve") + b"\n")
    gate.audit.log({"event": "after"})
    out = subprocess.run([sys.executable, "-m", "permitd.cli", "audit", "--verify"],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 0  # a single edited first line re-chains cleanly...
    lines = _lines(gate.audit.path)
    lines[0] = lines[0].replace(b"eve", b"mallory")
    gate.audit.path.write_bytes(b"\n".join(lines) + b"\n")
    out = subprocess.run([sys.executable, "-m", "permitd.cli", "audit", "--verify"],
                         capture_output=True, text=True, env=env)
    assert out.returncode == 1 and "BROKEN at line 2" in out.stderr
