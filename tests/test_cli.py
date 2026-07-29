"""CLI as the out-of-band approval surface: agent-side kernel proposes,
`permitd approve` decides, agent-side execute lands the audit line."""
import json

from permitd import PermitKernel, SqliteStore, AuditLog, default_paths
from permitd.cli import main


def make_agent_side(tmp_path):
    paths = default_paths(tmp_path / "permitd.db")
    return PermitKernel(SqliteStore(paths["db"]), secret_path=paths["secret"],
                        audit=AuditLog(paths["audit"]))


def test_full_flow_through_cli(tmp_path, capsys):
    db = str(tmp_path / "permitd.db")
    agent = make_agent_side(tmp_path)
    p = agent.propose("send_message", {"to": "alice", "body": "hi"})

    assert main(["--db", db, "pending"]) == 0
    out = capsys.readouterr().out
    assert p.id in out and '"to": "alice"' in out  # full args shown

    assert main(["--db", db, "approve", p.id]) == 0
    assert "approved" in capsys.readouterr().out

    result = agent.execute("send_message", {"to": "alice", "body": "hi"}, p.id,
                           runner=lambda to, body: "sent")
    assert result == "sent"

    assert main(["--db", db, "audit", "-n", "10"]) == 0
    events = [json.loads(l)["event"] for l in capsys.readouterr().out.splitlines()]
    assert events == ["proposed", "approved", "executed"]


def test_deny_through_cli(tmp_path, capsys):
    db = str(tmp_path / "permitd.db")
    agent = make_agent_side(tmp_path)
    p = agent.propose("rm_rf", {"path": "/"})
    assert main(["--db", db, "deny", p.id]) == 0
    assert "denied" in capsys.readouterr().out
    assert agent.verify_and_burn("rm_rf", {"path": "/"}, p.id) == (False, "denied")


def test_unknown_permit_exits_nonzero(tmp_path, capsys):
    db = str(tmp_path / "permitd.db")
    assert main(["--db", db, "approve", "PRM-nope"]) == 1
    assert main(["--db", db, "show", "PRM-nope"]) == 1


def test_empty_states(tmp_path, capsys):
    db = str(tmp_path / "permitd.db")
    assert main(["--db", db, "pending"]) == 0
    assert "no pending" in capsys.readouterr().out
