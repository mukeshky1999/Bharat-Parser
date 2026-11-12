"""Phase 5B.2: a case holds several devices, is saved to disk, and reopens without processing anything again."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from parsers import api_server, examination_report
from parsers.case_file import CaseFile, case_dir_name, list_cases, resolve_case_dir, safe_case_dir_name


def _phone(root, name, rows, wallet_name="payments.db"):
    """An evidence folder with one payments database. Both phones use the same relative path on purpose."""
    ev = root / name
    ev.mkdir()
    db = ev / wallet_name
    c = sqlite3.connect(db)
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.executemany('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', rows)
    c.commit()
    c.close()
    return ev


PHONE_A = [("A", 1111.11, "me@ybl", "one@ybl", "100000000001", "2026-02-01 09:00:00"),
           ("B", 2222.22, "me@ybl", "two@ybl", "100000000002", "2026-02-02 09:00:00")]
PHONE_B = [("C", 3333.33, "me@ybl", "three@ybl", "100000000003", "2026-02-03 09:00:00"),
           ("D", 4444.44, "me@ybl", "four@ybl", "100000000004", "2026-02-04 09:00:00"),
           ("E", 5555.55, "me@ybl", "five@ybl", "100000000005", "2026-02-05 09:00:00")]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


def _tx_rows(workspace, item=None):
    c = sqlite3.connect(f"{workspace}/bharat_case_store.db")
    c.row_factory = sqlite3.Row
    q = "SELECT * FROM transactions" + (" WHERE Evidence_Item = ?" if item else "")
    rows = [dict(r) for r in c.execute(q, (item,) if item else ())]
    c.close()
    return rows


def _two_phone_case(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    b = _phone(tmp_path, "phoneB", PHONE_B)
    ra = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "CASE-2", "case_name": "two phones",
                                                "examiner_name": "E. Xaminer", "label": "Suspect phone"}).json()
    rb = client.post("/api/case/ingest", json={"evidence_path": str(b), "case_id": "CASE-2", "mode": "add",
                                                "label": "Second phone"}).json()
    return a, b, ra, rb


# ---------------------------------------------------------------- two devices in one case
def test_adding_a_device_keeps_the_first_device(client, tmp_path):
    a, b, ra, rb = _two_phone_case(client, tmp_path)
    assert ra["success"] and rb["success"]
    assert (ra["evidence_item"], rb["evidence_item"]) == ("EV-001", "EV-002")
    ws = rb["workspace_dir"]
    first, second = _tx_rows(ws, "EV-001"), _tx_rows(ws, "EV-002")
    assert len(first) == 2 and len(second) == 3
    assert {r["Transaction_ID"] for r in first}.isdisjoint({r["Transaction_ID"] for r in second})
    assert len(_tx_rows(ws)) == 5


def test_each_device_keeps_its_own_hashes_and_working_copy(client, tmp_path):
    _, _, ra, rb = _two_phone_case(client, tmp_path)
    items = client.get("/api/case/evidence-items").json()["items"]
    assert [i["item_id"] for i in items] == ["EV-001", "EV-002"]
    assert items[0]["label"] == "Suspect phone" and items[1]["label"] == "Second phone"
    assert items[0]["sha256"] and items[1]["sha256"] and items[0]["sha256"] != items[1]["sha256"]
    assert all(i["integrity_match"] is True for i in items)
    import os
    ws = rb["workspace_dir"]
    assert os.path.isfile(os.path.join(ws, "items", "EV-001", "working_copy", "payments.db"))
    assert os.path.isfile(os.path.join(ws, "items", "EV-002", "working_copy", "payments.db"))


def test_same_relative_path_in_two_devices_is_not_guessed(client, tmp_path):
    _two_phone_case(client, tmp_path)
    r = client.get("/api/case/hex-window", params={"file_path": "payments.db", "offset": 0})
    assert r.status_code == 409 and "more than one evidence item" in r.json()["detail"]
    a = client.get("/api/case/hex-window", params={"file_path": "payments.db", "offset": 4096, "evidence_item": "EV-001"})
    b = client.get("/api/case/hex-window", params={"file_path": "payments.db", "offset": 4096, "evidence_item": "EV-002"})
    assert a.status_code == 200 and b.status_code == 200
    assert a.json()["raw_hex"] != b.json()["raw_hex"]          # page 2 holds the rows, which differ


def test_adding_the_same_source_again_replaces_only_that_device(client, tmp_path):
    a, b, _, rb = _two_phone_case(client, tmp_path)
    again = client.post("/api/case/ingest", json={"evidence_path": str(b), "case_id": "CASE-2", "mode": "add"}).json()
    assert again["evidence_item"] == "EV-002"
    ws = again["workspace_dir"]
    assert len(_tx_rows(ws, "EV-001")) == 2 and len(_tx_rows(ws, "EV-002")) == 3      # not doubled
    assert len(client.get("/api/case/evidence-items").json()["items"]) == 2


def test_add_needs_an_existing_case(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    assert client.post("/api/case/ingest", json={"evidence_path": str(a), "mode": "add"}).status_code == 400
    r = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "NOPE", "mode": "add"})
    assert r.status_code == 404


def test_records_can_be_limited_to_one_device(client, tmp_path):
    _two_phone_case(client, tmp_path)
    both = client.get("/api/case/records", params={"category": "transactions"}).json()["total"]
    one = client.get("/api/case/records", params={"category": "transactions", "evidence_item": "EV-002"}).json()
    assert both == 5 and one["total"] == 3
    assert {r["Evidence_Item"] for r in one["rows"]} == {"EV-002"}


# ---------------------------------------------------------------- the report speaks per device
def test_report_states_hashes_per_device(client, tmp_path):
    _two_phone_case(client, tmp_path)
    items = api_server._case_state["items"]
    facts = examination_report.build_facts(api_server._case_state, {}, [], {"entries": [], "verified": True, "head_hash": ""},
                                           {}, {"Tool": "t"})
    assert facts["evidence"] is None and facts["device"] is None
    assert [u["item_id"] for u in facts["evidence_items"]] == ["EV-001", "EV-002"]
    html = examination_report.render_report_html(facts)
    for it in items:
        assert it["hashes"]["sha256"] in html
    csv_text = examination_report.render_facts_csv(facts)
    assert "evidence_items.EV-001.evidence.sha256_before" in csv_text and "evidence_items.EV-002.evidence.sha256_before" in csv_text


def test_one_failed_integrity_check_is_named_with_its_device():
    st = {"case_id": "C", "case_name": "n", "items": [
        {"item_id": "EV-001", "label": "a", "source_path": "a", "hashes": {"sha256": "1", "postIngestionSha256": "1", "integrityMatch": True},
         "device": {}, "processing_log": []},
        {"item_id": "EV-002", "label": "b", "source_path": "b", "hashes": {"sha256": "2", "postIngestionSha256": "3", "integrityMatch": False},
         "device": {}, "processing_log": [{"stage": "parse_database", "file": "x.db", "status": "FAILED", "error": "boom"}]},
    ]}
    facts = examination_report.build_facts(st, {}, [], {"entries": []}, {}, {})
    lim = facts["limitations"]
    assert any(x.startswith("[EV-002] Integrity comparison: MISMATCH") for x in lim)
    assert any(x.startswith("[EV-002] Failed:") for x in lim)
    assert not any(x.startswith("[EV-001]") for x in lim)


# ---------------------------------------------------------------- saved to disk, reopened without processing
def test_case_reopens_without_processing_again(client, tmp_path):
    _, _, _, rb = _two_phone_case(client, tmp_path)
    ws = rb["workspace_dir"]
    before = client.get("/api/case/state").json()
    # a different process state: nothing in memory
    api_server._case_state.clear()
    api_server._case_state.update({"loaded": False, "case_id": None})
    assert client.get("/api/case/state").json()["loaded"] is False

    opened = client.post("/api/case/open", json={"workspace_dir": ws, "db_name": "bharat_case_store.db"})
    assert opened.status_code == 200, opened.text
    after = client.get("/api/case/state").json()
    assert after["loaded"] and after["case_id"] == "CASE-2" and after["case_name"] == "two phones"
    assert [i["item_id"] for i in after["evidence_items"]] == ["EV-001", "EV-002"]
    assert after["hashes"] == before["hashes"]                       # the recorded hashes come back, nothing is re-hashed
    assert after["counts"] == before["counts"]
    assert client.get("/api/case/summary").json()["examiner_name"] == "E. Xaminer"
    # the evidence cannot have been read: the sources are gone and it still opens
    import shutil
    shutil.rmtree(tmp_path / "phoneA")
    shutil.rmtree(tmp_path / "phoneB")
    assert client.post("/api/case/open", json={"workspace_dir": ws, "db_name": "bharat_case_store.db"}).status_code == 200


def test_recent_cases_lists_saved_cases_newest_first(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    b = _phone(tmp_path, "phoneB", PHONE_B)
    client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "OLD-1", "case_name": "old"})
    client.post("/api/case/ingest", json={"evidence_path": str(b), "case_id": "NEW-1", "case_name": "new"})
    CaseFile(str(tmp_path / "cases" / case_dir_name("OLD-1"))).set_info(last_opened_utc="2020-01-01 00:00:00")
    cases = client.get("/api/cases/recent").json()["cases"]
    assert [c["case_id"] for c in cases] == ["NEW-1", "OLD-1"]
    assert cases[0]["evidence_items"][0]["item_id"] == "EV-001"
    # a folder that is not a case is not listed
    (tmp_path / "cases" / "stray").mkdir()
    assert len(client.get("/api/cases/recent").json()["cases"]) == 2
    # opening a case moves it to the top
    client.post("/api/case/open", json={"workspace_dir": str(tmp_path / "cases" / case_dir_name("OLD-1")), "db_name": "bharat_case_store.db"})
    assert client.get("/api/cases/recent").json()["cases"][0]["case_id"] == "OLD-1"


def test_active_item_switches_the_profile_not_the_records(client, tmp_path):
    _two_phone_case(client, tmp_path)
    assert api_server._case_state["active_item"] == "EV-002"
    assert client.post("/api/case/active-item", json={"item_id": "EV-001"}).status_code == 200
    assert api_server._case_state["active_item"] == "EV-001"
    assert api_server._case_state["hashes"]["sha256"] == api_server._case_state["items"][0]["hashes"]["sha256"]
    assert client.post("/api/case/active-item", json={"item_id": "EV-009"}).status_code == 404
    assert client.get("/api/case/records", params={"category": "transactions"}).json()["total"] == 5


def test_replace_mode_starts_the_case_again(client, tmp_path):
    a, b, _, _ = _two_phone_case(client, tmp_path)
    r = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "CASE-2"}).json()
    assert r["evidence_item"] == "EV-001"
    assert [i["item_id"] for i in client.get("/api/case/evidence-items").json()["items"]] == ["EV-001"]
    assert len(_tx_rows(r["workspace_dir"])) == 2


# ---------------------------------------------------------------- store and case file units
def test_case_id_cannot_leave_the_cases_folder(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    r = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "../../escape"}).json()
    import os
    assert os.path.commonpath([os.path.abspath(r["workspace_dir"]), str(tmp_path / "cases")]) == str(tmp_path / "cases")
    assert safe_case_dir_name("../../x") == "x" or ".." not in safe_case_dir_name("../../x")


def test_old_store_gains_the_evidence_item_column(tmp_path):
    from parsers.ui_fts5_paginator import CaseUIPaginatorStore
    s = CaseUIPaginatorStore(str(tmp_path))
    c = sqlite3.connect(s.db_path)
    c.execute("DROP INDEX IF EXISTS idx_transactions_evidence_item")
    c.execute("ALTER TABLE transactions DROP COLUMN Evidence_Item")
    c.commit()
    c.close()
    s2 = CaseUIPaginatorStore(str(tmp_path))
    c = sqlite3.connect(s2.db_path)
    assert "Evidence_Item" in {r[1] for r in c.execute("PRAGMA table_info(transactions)")}
    c.close()


def test_deleting_an_item_leaves_the_search_index_consistent(tmp_path):
    import pandas as pd
    from parsers.ui_fts5_paginator import CaseUIPaginatorStore
    s = CaseUIPaginatorStore(str(tmp_path))
    s.ingest_dataframe_chunked("contacts", pd.DataFrame([{"Contact_Name": "Asha Verma", "Identifier": "9876543210"}]), evidence_item="EV-001")
    s.ingest_dataframe_chunked("contacts", pd.DataFrame([{"Contact_Name": "Ravi Kumar", "Identifier": "9123456780"}]), evidence_item="EV-002")
    s.delete_evidence_item("EV-001")
    _, total = s.get_paginated_rows("contacts", search_query="Asha")
    assert total == 0
    _, total = s.get_paginated_rows("contacts", search_query="Ravi")
    assert total == 1


def test_case_file_round_trips_unknowns_as_none(tmp_path):
    cf = CaseFile(str(tmp_path))
    cf.upsert_item("EV-001", label="x", source_path="s", hashes={"sha256": "ab"})
    it = cf.get_item("EV-001")
    assert it["hashes"] == {"sha256": "ab"}
    assert it["integrity_match"] is None and it["device"] is None and it["processing_log"] is None
    with pytest.raises(ValueError):
        cf.upsert_item("EV-001", bogus=1)
    assert list_cases(str(tmp_path / "missing")) == []


# ---------------------------------------------------------------- review step 2: identity and location
def test_case_ids_that_sanitise_alike_get_separate_folders(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    b = _phone(tmp_path, "phoneB", PHONE_B)
    ra = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "FIR 12/2026"}).json()
    rb = client.post("/api/case/ingest", json={"evidence_path": str(b), "case_id": "FIR_12_2026"}).json()
    assert ra["workspace_dir"] != rb["workspace_dir"]
    ids = sorted(c["case_id"] for c in client.get("/api/cases/recent").json()["cases"])
    assert ids == ["FIR 12/2026", "FIR_12_2026"]


def test_old_layout_folder_is_found_only_for_its_own_id(tmp_path):
    root = tmp_path / "cases"
    old = root / safe_case_dir_name("FIR 12/2026")
    CaseFile(str(old)).set_info(case_id="FIR 12/2026")
    assert resolve_case_dir(str(root), "FIR 12/2026") == str(old)
    assert resolve_case_dir(str(root), "FIR_12_2026") == str(root / case_dir_name("FIR_12_2026"))


def test_ingest_refuses_a_folder_that_belongs_to_another_case(client, tmp_path):
    a = _phone(tmp_path, "phoneA", PHONE_A)
    forged = tmp_path / "cases" / case_dir_name("MINE")
    CaseFile(str(forged)).set_info(case_id="SOMEONE-ELSE")
    r = client.post("/api/case/ingest", json={"evidence_path": str(a), "case_id": "MINE"})
    assert r.status_code == 409


def test_open_refuses_folders_outside_the_cases_folder(client, tmp_path):
    ev = tmp_path / "evidence"
    ev.mkdir()
    db = ev / "bharat_case_store.db"
    import sqlite3
    sqlite3.connect(str(db)).close()
    before = db.read_bytes()
    r = client.post("/api/case/open", json={"workspace_dir": str(ev), "db_name": "bharat_case_store.db"})
    assert r.status_code == 403
    assert db.read_bytes() == before
    r2 = client.post("/api/case/open", json={"workspace_dir": str(tmp_path / "cases"), "db_name": "msgstore.db"})
    assert r2.status_code in (400, 403)


def test_workspace_root_follows_env_and_frozen_build(monkeypatch, tmp_path):
    monkeypatch.setenv("BHARAT_WORKSPACE_ROOT", str(tmp_path / "x"))
    assert api_server._default_workspace_root() == str(tmp_path / "x")
    monkeypatch.delenv("BHARAT_WORKSPACE_ROOT")
    monkeypatch.setattr(api_server.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))
    assert api_server._default_workspace_root() == str(tmp_path / "lad" / "BharatAnalyzer" / "cases")
