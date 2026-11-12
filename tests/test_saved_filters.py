"""Saved filters live in the case file and hold only the examiner's filter choices."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from parsers import api_server, case_filters


@pytest.fixture
def conn(tmp_path):
    c = sqlite3.connect(str(tmp_path / "f.db"))
    c.executescript(case_filters.SCHEMA)
    yield c
    c.close()


def test_save_list_replace_remove(conn):
    assert case_filters.save_filter(conn, "calls", "  Missed   calls ", {"dir": "MISSED", "query": ""}) == {"name": "Missed calls", "replaced": False}
    assert case_filters.save_filter(conn, "calls", "Missed calls", {"dir": "MISSED", "query": "9876"})["replaced"] is True
    got = case_filters.list_filters(conn, "calls")
    assert [g["name"] for g in got] == ["Missed calls"] and got[0]["state"]["query"] == "9876"
    assert case_filters.list_filters(conn, "upi_ledger") == []                     # another screen is separate
    assert case_filters.remove_filter(conn, "calls", "Missed calls") == {"removed": 1}


@pytest.mark.parametrize("scope,name,state", [
    ("nope", "a", {"x": 1}), ("calls", "", {"x": 1}), ("calls", "x" * 61, {"x": 1}), ("calls", "a", {}), ("calls", "a", {"x": [1]}),
    ("calls", "a", {"x": {"y": 1}}), ("calls", "a", "text"),
])
def test_bad_filters_are_refused(conn, scope, name, state):
    with pytest.raises(case_filters.FilterError):
        case_filters.save_filter(conn, scope, name, state)


def test_limits(conn):
    for i in range(case_filters.MAX_PER_SCOPE):
        case_filters.save_filter(conn, "search", f"f{i}", {"a": i})
    with pytest.raises(case_filters.FilterError):
        case_filters.save_filter(conn, "search", "one too many", {"a": 1})
    assert case_filters.save_filter(conn, "search", "f0", {"a": 99})["replaced"]    # replacing is still allowed
    long = case_filters.save_filter(conn, "timeline", "long", {"q": "z" * 5000})
    assert len(case_filters.list_filters(conn, "timeline")[0]["state"]["q"]) == case_filters.MAX_VALUE_CHARS and long["replaced"] is False


def test_endpoints_need_a_case_and_stay_in_that_case(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", {**api_server._case_state, "loaded": False})
    client = TestClient(api_server.app)
    assert client.get("/api/case/filters", params={"scope": "calls"}).status_code == 412
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    ev = tmp_path / "ev"; ev.mkdir()
    c = sqlite3.connect(ev / "p.db")
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', ("t", 10.0, "a@ybl", "b@ybl", "100000000011", "2026-02-01 09:00:00")); c.commit(); c.close()
    assert client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "F-1"}).json()["success"]
    ok = client.post("/api/case/filters", json={"scope": "upi_ledger", "name": "Big", "state": {"amount": "OVER_1L"}})
    assert ok.status_code == 200
    assert client.get("/api/case/filters", params={"scope": "upi_ledger"}).json()["filters"][0]["state"] == {"amount": "OVER_1L"}
    assert client.post("/api/case/filters", json={"scope": "bad", "name": "x", "state": {"a": 1}}).status_code == 422
    assert client.post("/api/case/filters/remove", json={"scope": "upi_ledger", "name": "Big"}).json() == {"removed": 1}
    assert client.get("/api/case/filters", params={"scope": "upi_ledger"}).json()["filters"] == []


def test_non_finite_numbers_are_refused_and_remove_cleans_the_name(tmp_path):
    import sqlite3
    from parsers import case_filters
    c = sqlite3.connect(str(tmp_path / "f.db"))
    c.executescript(case_filters.SCHEMA)
    with pytest.raises(case_filters.FilterError):
        case_filters.save_filter(c, "calls", "x", {"a": float("nan")})
    with pytest.raises(case_filters.FilterError):
        case_filters.save_filter(c, "calls", "x", {"a": float("inf")})
    case_filters.save_filter(c, "calls", "two   words", {"a": 1})
    assert case_filters.remove_filter(c, "calls", "  two words ")["removed"] == 1
