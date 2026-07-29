import pytest

from permitd import APPROVED, MemoryStore, Permit, SqliteStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return MemoryStore()
    return SqliteStore(tmp_path / "permits.db")


def make_permit(pid="PRM-x", status="proposed"):
    return Permit(id=pid, tool="send", args={"to": "alice", "n": 1},
                  binding_hash="b" * 64, status=status,
                  created_at="2026-07-29T12:00:00+00:00", ttl_seconds=300)


def test_roundtrip(store):
    store.create(make_permit())
    p = store.get("PRM-x")
    assert p.tool == "send" and p.args == {"to": "alice", "n": 1}
    assert store.get("PRM-nope") is None


def test_update(store):
    store.create(make_permit())
    p = store.get("PRM-x")
    p.status = APPROVED
    p.token = "tok"
    store.update(p)
    assert store.get("PRM-x").status == APPROVED
    assert store.get("PRM-x").token == "tok"


def test_burn_only_once(store):
    store.create(make_permit(status=APPROVED))
    assert store.burn("PRM-x", "2026-07-29T12:01:00+00:00") is True
    assert store.burn("PRM-x", "2026-07-29T12:01:01+00:00") is False


def test_burn_requires_approved(store):
    store.create(make_permit(status="proposed"))
    assert store.burn("PRM-x", "t") is False


def test_list_filters_by_status(store):
    store.create(make_permit("PRM-1", "proposed"))
    store.create(make_permit("PRM-2", APPROVED))
    assert {p.id for p in store.list()} == {"PRM-1", "PRM-2"}
    assert [p.id for p in store.list(status=APPROVED)] == ["PRM-2"]
