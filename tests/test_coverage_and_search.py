"""5B.4 parser transparency (Decoded_By + coverage) and 5B.5 search across the case store."""
import json
import os
import sqlite3

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from parsers import api_server, case_search
from parsers.ui_fts5_paginator import CaseUIPaginatorStore


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


def _mixed_folder(tmp_path):
    ev = tmp_path / "phone"
    ev.mkdir()
    c = sqlite3.connect(ev / "a_payments.db")
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', ("A", 1500.0, "me@ybl", "x@ybl", "100000000001", "2026-02-01 09:00:00"))
    c.commit()
    c.close()
    c = sqlite3.connect(ev / "unrelated.db")
    c.execute("CREATE TABLE weather (day TEXT, temp INTEGER)")
    c.execute("INSERT INTO weather VALUES ('mon', 31)")
    c.commit()
    c.close()
    c = sqlite3.connect(ev / "noextension")
    c.execute("CREATE TABLE t (a TEXT)")
    c.commit()
    c.close()
    (ev / "notes.txt").write_text("hello", encoding="utf-8")
    (ev / "locked.db").write_bytes(os.urandom(8192))
    return ev


def _ingest(client, ev, case="CV-1"):
    res = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": case}).json()
    assert res["success"], res
    return res


# ----------------------------------------------------------------------------------------------- 5B.4
def test_every_stored_record_names_its_decoder_and_version(client, tmp_path):
    res = _ingest(client, _mixed_folder(tmp_path))
    c = sqlite3.connect(res["workspace_dir"] + "/bharat_case_store.db")
    rows = c.execute("SELECT id, Decoded_By FROM transactions").fetchall()
    c.close()
    assert rows and all(by and f"parse_database_artifacts {api_server.TOOL_VERSION}" in by and "app profile:" in by for _, by in rows)
    rec = client.get("/api/case/record", params={"table": "transactions", "id": rows[0][0]}).json()["record"]
    assert rec["Decoded_By"] == rows[0][1] and rec["Evidence_Item"] == "EV-001"


def test_coverage_says_what_became_of_every_file(client, tmp_path):
    _ingest(client, _mixed_folder(tmp_path))
    cov = client.get("/api/case/coverage").json()
    by = {f["file"]: f for f in cov["files"]}
    assert set(by) == {"a_payments.db", "unrelated.db", "noextension", "notes.txt", "locked.db"}
    assert by["a_payments.db"]["outcome"] == "DECODED" and by["a_payments.db"]["records"].get("transactions") == 1
    assert by["a_payments.db"]["decoded_by"].startswith("parsers.heuristic_engine.parse_database_artifacts")
    assert by["unrelated.db"]["outcome"] == "NOT_DECODED" and "no table" in by["unrelated.db"]["reason"]
    assert by["unrelated.db"]["decoded_by"] is None and by["unrelated.db"]["records"] == {}
    assert by["noextension"]["outcome"] == "NOT_DECODED" and "extension" in by["noextension"]["reason"]
    assert by["notes.txt"]["outcome"] == "NOT_DECODED" and "no decoder" in by["notes.txt"]["reason"]
    assert by["locked.db"]["outcome"] == "ENCRYPTED_NO_KEY"
    assert cov["summary"]["files"] == 5 and cov["summary"]["by_outcome"]["DECODED"] == 1
    assert cov["decoders"][0]["records"] == {"transactions": 1} and "scope" in cov and "container" in cov["scope"]
    assert by["a_payments.db"]["size_bytes"] == os.path.getsize(tmp_path / "phone" / "a_payments.db")


def test_files_not_decoded_appear_under_limitations(client, tmp_path):
    from parsers import examination_report
    res = _ingest(client, _mixed_folder(tmp_path))
    lim = examination_report.limitations(res["processing_log"], {})
    assert any("unrelated.db" in x and "no table" in x for x in lim)
    assert any("1 file(s)" in x or "2 file(s)" in x for x in lim)       # notes.txt (and the file without extension, as a database)


def test_coverage_is_stored_with_the_case_and_removed_with_its_item(tmp_path):
    s = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")
    s.add_coverage("EV-001", [{"file": "a.db", "outcome": "DECODED", "records": {"chats": 2}, "decoded_by": "x 1"}])
    s.add_coverage("EV-002", [{"file": "b.db", "outcome": "NOT_DECODED", "reason": "r"}])
    again = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")                         # reopened
    assert [r["File"] for r in again.get_coverage()] == ["a.db", "b.db"]
    assert again.get_coverage("EV-001")[0]["Records"] == {"chats": 2}
    s.add_coverage("EV-001", [])                                                         # the same item processed again replaces its rows
    assert [r["File"] for r in s.get_coverage()] == ["b.db"]
    s.delete_evidence_item("EV-002")
    assert s.get_coverage() == []


def test_unknown_decoder_is_null_not_a_default(tmp_path):
    s = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")
    s.ingest_dataframe_chunked("contacts", pd.DataFrame({"Name": ["Asha"], "Phone": ["9"]}), evidence_item="EV-001")
    assert s.decoder_summary()[0]["decoded_by"] is None


# ----------------------------------------------------------------------------------------------- 5B.5
@pytest.fixture
def store(tmp_path):
    s = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")
    s.ingest_dataframe_chunked("chats", pd.DataFrame({
        "Application": ["WhatsApp", "WhatsApp", "Telegram"],
        "Message_Body": ["send the money today", "भुगतान १५०० रुपये हो गया", "meeting at noon"],
        "Sender_Name": ["Ravi", "Asha", "Ravi"],
        "Timestamp_IST": ["2026-02-01 10:00:00"] * 3,
        "Decoded_By": ["whatsapp decoder 1"] * 3,
    }), evidence_item="EV-001")
    s.ingest_dataframe_chunked("transactions", pd.DataFrame({
        "Transaction_ID": ["100000004567", "100000009999"], "Amount": [1500.0, 20.0],
        "Counterparty": ["Kumar Stores", "Zed"], "Application": ["PhonePe", "PhonePe"],
    }), evidence_item="EV-002")
    return s


def test_keyword_finds_words_and_prefixes_and_names_the_matching_field(store):
    r = store.search("money tod")
    assert r["total"] == 1 and r["total_is_exact"] and r["complete"]
    h = r["hits"][0]
    assert h["table"] == "chats" and h["matched_fields"] == ["Message_Body"] and "money" in h["snippet"]
    assert h["evidence_item"] == "EV-001" and h["decoded_by"] == "whatsapp decoder 1" and h["id"]
    assert store.get_record("chats", h["id"])["Message_Body"] == "send the money today"


def test_phrase_needs_the_words_in_order(store):
    assert store.search("the money", mode="phrase")["total"] == 1
    assert store.search("money the", mode="phrase")["total"] == 0


def test_query_text_cannot_break_the_index_syntax(store):
    for q in ['AND', 'a OR', '"', '*', 'near(', "x' --", 'col:val', '(((']:
        r = store.search(q)                       # no exception; a plain no-match is fine
        assert r["total"] >= 0


def test_contains_finds_part_of_an_identifier_which_keyword_cannot(store):
    assert store.search("4567")["total"] == 0
    r = store.search("4567", mode="contains", tables=["transactions"])
    assert r["total"] == 1 and r["hits"][0]["matched_fields"] == ["Transaction_ID"]


def test_contains_reads_indic_digits_and_ignores_zero_width_marks(store):
    r = store.search("1500", mode="contains")
    tables = {h["table"] for h in r["hits"]}
    assert tables == {"chats", "transactions"}                       # '१५००' in the Hindi message, 1500.0 in Amount
    assert store.search("भुग‍तान", mode="contains")["total"] == 1   # a zero-width joiner in the query
    assert store.search("भुगतान")["total"] == 1                       # the full-text index handles Devanagari words


def test_regex_and_its_limits(store):
    r = store.search(r"\b10{7}\d{4}\b", mode="regex", tables=["transactions"])
    assert r["total"] == 2
    for bad in ["(", "(a+)+$", "x" * 300]:
        with pytest.raises(case_search.SearchError):
            store.search(bad, mode="regex")


def test_filters_by_table_item_and_application(store):
    assert store.search("ravi", mode="contains", tables=["chats"])["total"] == 2
    assert store.search("ravi", mode="contains", application="Telegram")["total"] == 1
    assert store.search("1500", mode="contains", evidence_item="EV-002")["total"] == 1
    with pytest.raises(case_search.SearchError):
        store.search("x", tables=["sqlite_master"])


def test_a_scan_that_hits_the_time_limit_says_so(store):
    r = store.search("zzz", mode="contains", time_budget_s=0)
    assert r["complete"] is False and r["total_is_exact"] is False and "time limit" in r["stopped_reason"]


def test_paging(store):
    a = store.search("a", mode="contains", limit=2)
    b = store.search("a", mode="contains", limit=2, offset=2)
    assert a["total"] == b["total"] >= 4 and len(a["hits"]) == 2
    assert {(h["table"], h["id"]) for h in a["hits"]}.isdisjoint({(h["table"], h["id"]) for h in b["hits"]})


def test_search_does_not_change_the_store(store):
    def dump():
        c = sqlite3.connect(store.db_path)
        out = {t: c.execute(f"SELECT * FROM {t} ORDER BY id").fetchall() for t in ("chats", "transactions", "coverage")}
        c.close()
        return json.dumps(out, default=str)
    before = dump()
    store.search("money")
    store.search("1500", mode="contains")
    assert dump() == before


def test_search_endpoints(client, tmp_path):
    assert client.get("/api/case/search", params={"q": "x"}).status_code in (412, 200)   # no case yet or a leftover one
    _ingest(client, _mixed_folder(tmp_path), case="CV-2")
    r = client.get("/api/case/search", params={"q": "100000000001", "mode": "contains"}).json()
    assert r["total"] >= 1 and r["hits"][0]["table"] == "transactions"
    assert client.get("/api/case/search", params={"q": "(", "mode": "regex"}).status_code == 422
    assert client.get("/api/case/search", params={"q": "x", "mode": "fuzzy"}).status_code == 422
    assert client.get("/api/case/record", params={"table": "transactions", "id": 999999}).status_code == 404
    assert client.get("/api/case/record", params={"table": "sqlite_master", "id": 1}).status_code == 422


def test_record_endpoint_lists_the_records_tags(client, tmp_path):
    res = _ingest(client, _mixed_folder(tmp_path))
    c = sqlite3.connect(res["workspace_dir"] + "/bharat_case_store.db")
    rid = c.execute("SELECT id FROM transactions").fetchone()[0]
    c.close()
    assert client.get("/api/case/record", params={"table": "transactions", "id": rid}).json()["tags"] == []
    client.post("/api/case/tags", json={"tag": "of_interest", "records": [{"table": "transactions", "id": rid}]})
    assert client.get("/api/case/record", params={"table": "transactions", "id": rid}).json()["tags"] == ["of_interest"]
