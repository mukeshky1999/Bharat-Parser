"""Legal outputs must come from the case or be refused (REVIEW_FINDINGS C-03, H-12)."""
import pytest
from fastapi import HTTPException

from parsers import api_server as server
from parsers.api_server import NcrpFreezeRequest, Sec230BnssRequest


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(server, "_case_state", {**server._case_state, "loaded": False})


def test_ncrp_without_candidates_or_case_is_refused():
    with pytest.raises(HTTPException) as e:
        server.generate_ncrp_freeze_report(
            NcrpFreezeRequest(complainant_account="X1", acknowledgement_no="A1")
        )
    assert e.value.status_code == 422


def test_ncrp_requires_complainant_and_ack():
    with pytest.raises(HTTPException) as e:
        server.generate_ncrp_freeze_report(NcrpFreezeRequest(candidates=[{"account_no": "1"}]))
    assert e.value.status_code == 422


def test_sec230_without_items_is_refused():
    with pytest.raises(HTTPException) as e:
        server.generate_sec230_bnss_report(Sec230BnssRequest(case_id="C"))
    assert e.value.status_code == 422


def test_sec230_hashes_real_file_bytes(tmp_path, monkeypatch):
    import hashlib
    from parsers.api_server import Sec230MediaInput
    from parsers.ui_fts5_paginator import CaseUIPaginatorStore

    store = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")
    monkeypatch.setattr(server, "_active_store", store)
    f = tmp_path / "receipt.jpg"
    f.write_bytes(b"real bytes")
    res = server.generate_sec230_bnss_report(
        Sec230BnssRequest(case_id="C", output_dir=str(tmp_path / "out"),
                          items=[Sec230MediaInput(path=str(f))])
    )
    assert res["success"]
    html = open(res["html_viewer_path"], encoding="utf-8").read()
    assert hashlib.sha256(b"real bytes").hexdigest() in html


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
