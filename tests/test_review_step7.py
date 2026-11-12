"""Review step 7: paths, honest errors, limits, and the surface that needs no token."""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from parsers import api_server
from tests.test_case_file import PHONE_A, _phone


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


@pytest.fixture
def loaded(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "S7"})
    return client


def test_fusion_refuses_a_path_outside_the_case_and_unc_paths(loaded, tmp_path):
    secret = tmp_path / "secret.csv"
    secret.write_text("Date,Amount\n2026-01-01,5\n")
    r = loaded.post("/api/fusion/bank-statement", json={"statement_path": str(secret)})
    assert r.status_code in (403, 404)
    r = loaded.post("/api/fusion/cdr", json={"cdr_path": "//attacker/share/x.csv"})
    assert r.status_code == 403


def test_inspect_refusal_is_not_reported_as_a_result(loaded, tmp_path):
    other = tmp_path / "o.db"
    sqlite3.connect(str(other)).close()
    r = loaded.post("/api/sqlite/inspect", json={"db_path": str(other)})
    assert r.status_code in (403, 404)


def test_inspect_limit_is_bounded(loaded):
    assert loaded.post("/api/sqlite/inspect", json={"db_path": "x.db", "limit": 10_000_000}).status_code == 422


def test_unknown_artifact_category_is_a_client_error(loaded):
    assert loaded.get("/api/artifacts/query", params={"category": "no_such_table"}).status_code == 422


def test_docs_and_openapi_are_off_by_default(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_root_needs_the_token_when_one_is_set(client, monkeypatch):
    monkeypatch.setenv("BHARAT_API_TOKEN", "t" * 16)
    assert client.get("/").status_code == 401
    assert client.get("/", headers={"X-Bharat-Token": "t" * 16}).status_code == 200


def test_null_origin_is_allowed_only_with_a_token():
    import importlib
    import sys
    saved = dict(os.environ)
    try:
        os.environ.pop("BHARAT_API_TOKEN", None)
        fresh = importlib.reload(sys.modules["parsers.api_server"])
        assert "null" not in fresh._ALLOWED_ORIGINS
        os.environ["BHARAT_API_TOKEN"] = "x" * 16
        fresh = importlib.reload(sys.modules["parsers.api_server"])
        assert "null" in fresh._ALLOWED_ORIGINS
    finally:
        os.environ.clear()
        os.environ.update(saved)
        importlib.reload(sys.modules["parsers.api_server"])


def test_failed_analysis_step_is_in_the_processing_log(client, tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("synthetic failure")
    monkeypatch.setattr(api_server, "heal_counterparties_across_apps", boom)
    a = _phone(tmp_path, "phoneA", PHONE_A)
    r = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "S7B"}).json()
    failed = [e for e in r["processing_log"] if e["stage"] == "counterparty_healing"]
    assert failed and failed[0]["status"] == "FAILED" and "synthetic failure" in failed[0]["error"]


@pytest.mark.skipif(os.name != "nt", reason="junction test is Windows specific")
def test_junction_in_evidence_folder_is_not_followed(client, tmp_path):
    import subprocess
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("do not copy")
    a = _phone(tmp_path, "phoneA", PHONE_A)
    subprocess.run(["cmd", "/c", "mklink", "/J", str(a / "link"), str(outside)], check=True, capture_output=True)
    r = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "S7C"}).json()
    assert any("link" in (e.get("error", "") + e.get("file", "")).lower() for e in r["processing_log"] if e["status"] == "WARNING")
    wc = os.path.join(r["workspace_dir"], "items", "EV-001", "working_copy")
    assert not os.path.exists(os.path.join(wc, "link", "secret.txt"))


def test_direct_hex_window_does_not_reparse_offset_from_the_file_name(tmp_path):
    from parsers.ui_fts5_paginator import CaseUIPaginatorStore
    store = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")
    f = tmp_path / "Offset=0x10.bin"
    f.write_bytes(bytes(range(256)) * 4)
    res = store.read_provenance_hex_window(file_path=str(f), byte_offset=512, window_size=256)
    assert res["provenance_parsed"]["byte_offset"] == 512
