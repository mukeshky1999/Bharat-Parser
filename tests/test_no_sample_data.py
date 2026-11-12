"""Legal outputs must come from the case or be refused (REVIEW_FINDINGS C-03, H-12)."""
import pytest
from fastapi import HTTPException

from parsers import api_server as server



@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(server, "_case_state", {**server._case_state, "loaded": False})










def test_file_endpoints_reject_paths_outside_case(tmp_path, monkeypatch):
    from parsers.ui_fts5_paginator import CaseUIPaginatorStore

    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    monkeypatch.setattr(server, "_active_store", CaseUIPaginatorStore(str(ws), db_name="s.db"))
    with pytest.raises(HTTPException) as e:
        server.get_inspector_hex(file_path=str(outside), offset=0, window_size=128)
    assert e.value.status_code == 403


def test_mule_network_is_empty_without_case():
    res = server.get_graph_mule_network()
    assert res["empty"] is True and res["nodes"] == [] and res["edges"] == []
