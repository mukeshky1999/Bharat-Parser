"""Tags in the report, the facts annexure, the accounts-of-interest sheet and the review package."""
import json
import sqlite3

import pandas as pd
import pytest

from parsers import case_tag_report, examination_report
from parsers.ui_fts5_paginator import CaseUIPaginatorStore


@pytest.fixture
def store(tmp_path):
    s = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")
    s.ingest_dataframe_chunked("transactions", pd.DataFrame({
        "Transaction_ID": ["T1", "T2", "T3", "T4", "T5"],
        "Amount": [1500.0, 20.0, 5.0, 70.0, 9.0],
        "Counterparty": ["Kumar", "Zed", "Complainant Co", "Zed Again", "NoAccount"],
        "VPA": ["k@ybl", "z@ybl", "c@ybl", "z@ybl", None],
        "Account": [None, None, None, None, None],
        "Application": ["PhonePe"] * 5,
        "Forensic_Provenance": ["pay.db :: t :: Row=1", "pay.db :: t :: Row=2", "pay.db :: t :: Row=3",
                                "pay.db :: t :: Row=4", "pay.db :: t :: Row=5"],
    }), evidence_item="EV-001")
    s.ingest_dataframe_chunked("chats", pd.DataFrame({
        "Application": ["WhatsApp", "WhatsApp"], "Message_Body": ["send money", "lawyer note"],
        "Forensic_Provenance": ["chat.db :: m :: Row=1", "chat.db :: m :: Row=2"],
    }), evidence_item="EV-001")
    return s


def _ids(store, table):
    c = sqlite3.connect(store.db_path)
    out = [r[0] for r in c.execute(f"SELECT id FROM {table} ORDER BY id")]
    c.close()
    return out


def _facts(store):
    conn = store._get_connection()
    try:
        tags = case_tag_report.tag_facts(conn)
    finally:
        conn.close()
    return examination_report.build_facts({"case_id": "C1", "case_name": "n"}, {}, [], {"entries": [], "verified": True, "head_hash": ""},
                                          {}, {}, tags)


def test_relied_upon_is_listed_and_privileged_is_counted_not_listed(store):
    c = _ids(store, "chats")
    store.tag_records("relied_upon", [("chats", c[0]), ("chats", c[1])], "note A")
    store.tag_records("privileged", [("chats", c[1])])
    f = _facts(store)["tags"]
    assert f["relied_upon_total"] == 1 and f["relied_upon_withheld_privileged"] == 1
    assert f["relied_upon"][0]["summary"] == "send money" and f["relied_upon"][0]["note"] == "note A"
    html = examination_report.render_report_html(_facts(store))
    assert "send money" in html and "lawyer note" not in html
    assert "1 relied-upon record(s) also carry the privileged tag" in html


def test_report_without_tags_says_so_and_csv_has_tag_rows(store):
    html = examination_report.render_report_html(_facts(store))
    assert "No records were tagged." in html and "9. Audit log" in html
    store.tag_records("of_interest", [("chats", _ids(store, "chats")[0])])
    csv_text = examination_report.render_facts_csv(_facts(store))
    assert "tags.of_interest,records=1 not_placed=0" in csv_text


def test_detached_relied_upon_is_counted_never_listed(store):
    c = _ids(store, "chats")
    store.tag_records("relied_upon", [("chats", c[0])])
    store.delete_evidence_item("EV-001")                      # tags are set aside, record is gone
    f = _facts(store)["tags"]
    assert f["relied_upon_total"] == 0 and f["relied_upon_detached"] == 1
    assert "could not be placed on a record" in examination_report.render_report_html(_facts(store))


def test_accounts_of_interest_leaves_out_shared_complainant_accounts(store):
    t = _ids(store, "transactions")
    store.tag_records("of_interest", [("transactions", t[0]), ("transactions", t[1]), ("transactions", t[2]), ("transactions", t[4])])
    store.tag_records("complainant", [("transactions", t[2])])
    store.tag_records("excluded", [("transactions", t[3])])      # same VPA as t[1]: z@ybl is left out
    conn = store._get_connection()
    try:
        d = case_tag_report.accounts_of_interest(conn)
    finally:
        conn.close()
    assert [a["vpa"] for a in d["accounts"]] == ["k@ybl"]
    left = {a["vpa"]: a["left_out_because"] for a in d["left_out"]}
    assert left == {"c@ybl": "complainant", "z@ybl": "excluded"}
    # a payment with no VPA or account is not an account: it is listed nowhere
    assert all("NoAccount" not in a["names_as_recorded"] for a in d["accounts"] + d["left_out"])
    csv_text = case_tag_report.accounts_csv(d)
    assert csv_text.splitlines()[0].startswith("section,vpa,account")
    assert "left out" in csv_text and "k@ybl" in csv_text


def test_accounts_csv_neutralises_formulas():
    d = {"accounts": [{"vpa": "=cmd|' /C calc'!A0", "account": "", "names_as_recorded": "", "tagged_records": 1,
                       "record_ids": "1", "evidence_items": "", "applications": "", "tags": "of_interest"}], "left_out": []}
    assert "'=cmd" in case_tag_report.accounts_csv(d)


def test_files_with_keep_out_records(store):
    c = _ids(store, "chats")
    store.tag_records("privileged", [("chats", c[1])])
    conn = store._get_connection()
    try:
        r = case_tag_report.files_with_keep_out_records(conn, ["/x/chat.db", "/x/pay.db"])
    finally:
        conn.close()
    assert r == {"/x/chat.db": {"privileged": 1}}


def test_endpoints_report_and_accounts(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from parsers import api_server
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    client = TestClient(api_server.app)
    assert client.get("/api/report/accounts-of-interest").status_code == 412
    ev = tmp_path / "phone"
    ev.mkdir()
    c = sqlite3.connect(ev / "a_payments.db")
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', ("A", 1500.0, "me@ybl", "x@ybl", "100000000001", "2026-02-01 09:00:00"))
    c.commit()
    c.close()
    assert client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "TO-1"}).json()["success"]
    rid = client.get("/api/case/search", params={"q": "100000000001", "mode": "contains"}).json()["hits"][0]["id"]
    assert client.post("/api/case/tags", json={"tag": "relied_upon", "records": [{"table": "transactions", "id": rid}]}).json()["applied"] == 1
    html = client.post("/api/report/examination", json={}).text
    assert "Records tagged by the examiner" in html and "Records relied upon" in html
    assert "tags.relied_upon" in client.get("/api/report/facts", params={"format": "csv"}).text
    j = client.get("/api/report/accounts-of-interest").json()
    assert set(j) == {"accounts", "left_out", "note"}
    assert client.get("/api/report/accounts-of-interest", params={"format": "csv"}).text.startswith("section,vpa")


def test_package_refuses_included_file_with_keep_out_records_unless_acknowledged(tmp_path):
    from parsers import review_package as rp
    f = tmp_path / "chat.db"
    f.write_bytes(b"abc")
    out1 = tmp_path / "p1"
    item = rp.PackageItem(source_path=str(f), disposition=rp.INCLUDE, tag_flags={"privileged": 2})
    with pytest.raises(rp.PackageRefused) as e:
        rp.build_package("C1", [item], str(out1))
    assert "privileged: 2" in str(e.value) and not out1.exists()           # nothing written
    # withholding is always allowed
    w = rp.PackageItem(source_path=str(f), disposition=rp.WITHHOLD_PRIVILEGED, tag_flags={"privileged": 2})
    assert rp.build_package("C1", [w], str(tmp_path / "p2")).withheld == 1
    # acknowledged: built, and the flag is in the manifest and the viewer
    res = rp.build_package("C1", [item], str(tmp_path / "p3"), acknowledge_tagged=True)
    meta = json.loads(open(res.manifest_path, encoding="utf-8").read())
    assert meta["tag_warning_acknowledged"] is True and meta["items"][0]["tagged_records"] == "privileged: 2"
    assert "records tagged: privileged: 2" in open(res.viewer_path, encoding="utf-8").read()
    # an untagged file is unaffected
    plain = rp.build_package("C1", [rp.PackageItem(source_path=str(f), disposition=rp.INCLUDE)], str(tmp_path / "p4"))
    assert json.loads(open(plain.manifest_path, encoding="utf-8").read())["tag_warning_acknowledged"] is False
