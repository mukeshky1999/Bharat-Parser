"""5B.9 key broker: describe supplied keys without storing or returning them; list what needs a key; retry with a key."""
import json
import os

import pytest
from fastapi.testclient import TestClient

from parsers import api_server, key_broker
from tests.test_encrypted_db_ingest import _evidence


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    monkeypatch.setitem(api_server._case_state, "loaded", False)
    return TestClient(api_server.app)


def test_inspect_reports_readings_and_fingerprints_without_the_value():
    k = os.urandom(48).hex()
    rows = key_broker.inspect_keys({"hexkey": k, "pw": "correct horse", "bad": "xy", "empty": "  "})
    by = {r["name"]: r for r in rows}
    assert {x["how"] for x in by["hexkey"]["readings"]} >= {"hex", "passphrase"} and by["hexkey"]["usable"]
    assert all(len(x["fingerprint"]) == 8 for x in by["hexkey"]["readings"])
    assert [x["how"] for x in by["pw"]["readings"]] == ["passphrase"]
    assert not by["bad"]["usable"] and "No reading is possible" in by["bad"]["problems"][0]
    assert not by["empty"]["usable"] and by["empty"]["problems"] == ["The value is empty."]
    assert k not in json.dumps(rows) and "correct horse" not in json.dumps(rows)


def test_duplicate_material_under_two_names_is_flagged():
    k = os.urandom(32).hex() + os.urandom(16).hex()
    rows = key_broker.inspect_keys({"a": k, "b": k})
    assert any("same key material as 'a'" in p for p in rows[1]["problems"])


def test_refusals():
    with pytest.raises(key_broker.KeyBrokerError):
        key_broker.inspect_keys({})
    with pytest.raises(key_broker.KeyBrokerError):
        key_broker.inspect_keys({str(i): "abcdef" for i in range(51)})
    assert key_broker.inspect_keys({"x": "a" * 5000})[0]["problems"][0].startswith("The value is longer")


def test_check_endpoint_never_echoes_values_and_is_not_cached(client):
    secret = "my secret passphrase"
    r = client.post("/api/keys/check", json={"keys": {"k": secret}})
    assert r.status_code == 200 and secret not in r.text and r.headers["cache-control"] == "no-store"
    assert client.post("/api/keys/check", json={"keys": {}}).status_code == 422


def test_needed_then_retry_with_key_then_events(client, tmp_path):
    ev, key_hex = _evidence(tmp_path)
    assert client.get("/api/case/keys").status_code == 412
    first = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "KB-1"}).json()
    assert first["success"]
    need = client.get("/api/case/keys").json()
    assert len(need["needed"]) == 1 and need["needed"][0]["files"][0]["file"].endswith("signal.db")
    assert need["needed"][0]["source_path"] and need["needed"][0]["evidence_item"]
    # process the same device again with the key: the item is replaced, and nothing is left that needs a key
    again = client.post("/api/case/ingest", json={"evidence_path": need["needed"][0]["source_path"], "case_id": "KB-1", "mode": "add",
                                                  "keys": {"signal_key": key_hex}}).json()
    assert again["success"]
    after = client.get("/api/case/keys").json()
    assert after["needed"] == []
    used = [e for e in after["events"] if e["action"] == "key_used"]
    assert used and used[0]["details"]["key"].startswith("supplied:signal_key") and len(used[0]["details"]["fingerprint"]) == 8
    assert key_hex not in json.dumps(after) and key_hex not in json.dumps(client.get("/api/audit").json())
