"""Review step 3: replace-mode ingest keeps the examiner's decisions and never leaves a half-deleted case."""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from parsers import api_server
from tests.test_case_file import PHONE_A, PHONE_B, _phone, _tx_rows


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


def _first_tx_id(ws):
    return _tx_rows(ws)[0]["id"]


def test_replace_keeps_tags_filters_and_hash_lists(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    r = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "C-1"}).json()
    ws = r["workspace_dir"]
    rid = _first_tx_id(ws)
    assert client.post("/api/case/tags", json={"tag": "of_interest", "records": [{"table": "transactions", "id": rid}]}).json()["applied"] == 1
    assert client.post("/api/case/filters", json={"scope": "calls", "name": "mine", "state": {"a": 1}}).status_code == 200
    assert client.post("/api/case/hashsets", json={"name": "list", "kind": "known_notable", "text": "a" * 32}).status_code == 200
    # the same phone again, replace mode (the default)
    r2 = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "C-1"}).json()
    assert r2["success"]
    tags = client.get("/api/case/tags").json()["tags"]
    t = next(x for x in tags if x["tag"] == "of_interest")
    assert t["count"] == 1 and t["detached"] == 0           # placed again on the new record by provenance
    assert len(client.get("/api/case/filters", params={"scope": "calls"}).json()["filters"]) == 1
    assert [h["name"] for h in client.get("/api/case/hashsets").json()["hash_sets"]] == ["list"]
    assert len(_tx_rows(ws)) == 2                              # records not doubled


def test_replace_with_another_phone_does_not_place_tags_on_it(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    b = _phone(tmp_path, "phoneB", PHONE_B)
    ws = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "C-2"}).json()["workspace_dir"]
    client.post("/api/case/tags", json={"tag": "of_interest", "records": [{"table": "transactions", "id": _first_tx_id(ws)}]})
    client.post("/api/case/ingest", json={"evidence_path": str(b), "case_id": "C-2"})
    t = next(x for x in client.get("/api/case/tags").json()["tags"] if x["tag"] == "of_interest")
    assert t["count"] == 1 and t["detached"] == 1               # kept, but on no record of the other phone


def test_refused_container_leaves_the_case_readable(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    ws = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "C-3"}).json()["workspace_dir"]
    junk = tmp_path / "x.ufd"
    junk.write_bytes(b"not a container")
    r = client.post("/api/case/ingest", json={"evidence_path": str(junk), "case_id": "C-3"})
    assert r.status_code in (400, 422)
    assert os.path.isdir(os.path.join(ws, "items", "EV-001", "extracted_dbs")) or os.path.isdir(os.path.join(ws, "items", "EV-001"))
    assert not os.path.exists(os.path.join(ws, ".replaced"))
    assert len(_tx_rows(ws)) == 2
    assert client.get("/api/case/evidence-items").json()["items"][0]["item_id"] == "EV-001"


def test_early_refusal_is_reported_by_the_progress_record(client, tmp_path):
    r = client.post("/api/case/ingest", json={"evidence_path": str(tmp_path / "missing"), "case_id": "C-4"})
    assert r.status_code == 404
    p = client.get("/api/case/ingest/progress").json()
    assert p["state"] == "failed"


def test_second_ingest_is_refused_while_the_worker_runs(client, tmp_path):
    assert api_server._ingest_worker_lock.acquire(blocking=False)
    try:
        with pytest.raises(api_server.HTTPException) as e:
            api_server._execute_ingestion_pipeline(str(tmp_path), "C-5", "n", "", "", "replace", "", None)
        assert e.value.status_code == 409
    finally:
        api_server._ingest_worker_lock.release()
