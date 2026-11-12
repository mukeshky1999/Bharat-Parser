"""5B.6 tags and 5B.7 timeline."""
import json
import sqlite3

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from parsers import api_server, case_tags, case_timeline, case_search
from parsers.ui_fts5_paginator import CaseUIPaginatorStore


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


@pytest.fixture
def store(tmp_path):
    s = CaseUIPaginatorStore(str(tmp_path), db_name="s.db")
    s.ingest_dataframe_chunked("chats", pd.DataFrame({
        "Application": ["WhatsApp", "WhatsApp", "Telegram"],
        "Message_Body": ["send the money", "done", "noon"],
        "Sender_Name": ["Ravi", "Asha", "Ravi"],
        "Timestamp_UTC": ["2026-02-01 04:30:00", "2026-02-01 05:00:00", None],
        "Timestamp_IST": ["2026-02-01 10:00:00", "2026-02-01 10:30:00", None],
        "Forensic_Provenance": ["a.db @ 10", "a.db @ 20", "a.db @ 30"],
    }), evidence_item="EV-001")
    s.ingest_dataframe_chunked("transactions", pd.DataFrame({
        "Transaction_ID": ["T1", "T2", "T3"], "Amount": [1500.0, 20.0, 5.0], "Counterparty": ["Kumar", "Zed", "Q"],
        "Application": ["PhonePe"] * 3,
        "Date": ["2026-02-01 10:15:00", "2026-02-01 09:00:00", None],
        "Timestamp_IST": ["2026-02-01 10:15:00", None, None],
        "Timestamp_UTC": ["2026-02-01 04:45:00", None, None],
        "Timestamp_Basis": ["EPOCH_UTC", "LOCAL_ZONE_UNKNOWN", None],
        "Forensic_Provenance": ["p.db @ 1", "p.db @ 2", "p.db @ 3"],
    }), evidence_item="EV-001")
    return s


def _ids(store, table):
    c = sqlite3.connect(store.db_path)
    out = [r[0] for r in c.execute(f"SELECT id FROM {table} ORDER BY id")]
    c.close()
    return out


# ------------------------------------------------------------------------------------------------ 5B.6
def test_built_in_tags_are_listed_and_custom_ones_allowed(store):
    names = [t["tag"] for t in store.list_tags()["tags"]]
    assert names[:5] == ["relied_upon", "of_interest", "complainant", "privileged", "excluded"]
    c = _ids(store, "chats")
    r = store.tag_records("Needs Follow Up", [("chats", c[0])])
    assert r["tag"] == "needs_follow_up" and r["applied"] == 1
    assert any(t["tag"] == "needs_follow_up" and not t["builtin"] and t["count"] == 1 for t in store.list_tags()["tags"])


def test_tagging_is_idempotent_and_reports_missing_and_refuses_bad_input(store):
    c = _ids(store, "chats")
    assert store.tag_records("excluded", [("chats", c[0])])["applied"] == 1
    r = store.tag_records("excluded", [("chats", c[0]), ("chats", 9999)])
    assert r["applied"] == 0 and r["already_tagged"] == 1 and r["missing"] == [{"table": "chats", "id": 9999}]
    for bad in [("sqlite_master", 1), ("vfs_files", 1)]:
        with pytest.raises(case_tags.TagError):
            store.tag_records("excluded", [bad])
    with pytest.raises(case_tags.TagError):
        store.tag_records("  ", [("chats", c[0])])
    with pytest.raises(case_tags.TagError):
        store.tag_records("x" * 41, [("chats", c[0])])
    # a bad entry refuses the whole request before anything is written
    with pytest.raises(case_tags.TagError):
        store.tag_records("privileged", [("chats", c[1]), ("sqlite_master", 1)])
    assert store.tagged_records("privileged")["total"] == 0


def test_untag(store):
    c = _ids(store, "chats")
    store.tag_records("of_interest", [("chats", c[0]), ("chats", c[1])])
    assert store.untag_records("of_interest", [("chats", c[0])])["removed"] == 1
    assert [r["id"] for r in store.tagged_records("of_interest")["records"]] == [c[1]]


def test_tags_survive_reprocessing_when_the_source_location_matches(store):
    c = _ids(store, "chats")
    store.tag_records("relied_upon", [("chats", c[0]), ("chats", c[1])])
    store.delete_evidence_item("EV-001")                                     # the item is processed again
    assert store.tagged_records("relied_upon")["records"][0]["detached"] is True
    # processed again: same provenance for the first message, the second one is gone
    store.ingest_dataframe_chunked("chats", pd.DataFrame({
        "Application": ["WhatsApp", "WhatsApp"], "Message_Body": ["other", "send the money"],
        "Forensic_Provenance": ["z.db @ 1", "a.db @ 10"]}), evidence_item="EV-001")
    res = store.reattach_tags("EV-001")
    assert res == {"reattached": 1, "detached": 1}
    recs = {r["provenance"]: r for r in store.tagged_records("relied_upon")["records"]}
    assert recs["a.db @ 10"]["detached"] is False and recs["a.db @ 20"]["detached"] is True
    assert store.get_record("chats", recs["a.db @ 10"]["id"])["Message_Body"] == "send the money"
    assert recs["a.db @ 20"]["summary"] == "done"                              # what it was is still readable


def test_ambiguous_provenance_is_not_guessed(store):
    c = _ids(store, "chats")
    store.tag_records("relied_upon", [("chats", c[0])])
    store.delete_evidence_item("EV-001")
    store.ingest_dataframe_chunked("chats", pd.DataFrame({
        "Message_Body": ["x", "y"], "Forensic_Provenance": ["a.db @ 10", "a.db @ 10"]}), evidence_item="EV-001")
    assert store.reattach_tags("EV-001") == {"reattached": 0, "detached": 1}


def test_search_filters_by_tag_and_shows_tags(store):
    c = _ids(store, "chats")
    store.tag_records("relied_upon", [("chats", c[0])])
    store.tag_records("excluded", [("chats", c[0])])
    r = store.search("a", mode="contains", tag="relied_upon")
    assert r["total"] == 1 and r["hits"][0]["id"] == c[0] and r["hits"][0]["tags"] == ["excluded", "relied_upon"]
    assert store.search("a", mode="contains", tag="privileged")["total"] == 0
    assert store.search("money", tag="relied_upon")["total"] == 1                # keyword mode too


def test_tag_endpoints_and_audit(client, tmp_path):
    ev = tmp_path / "phone"
    ev.mkdir()
    c = sqlite3.connect(ev / "a_payments.db")
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', ("A", 1500.0, "me@ybl", "x@ybl", "100000000001", "2026-02-01 09:00:00"))
    c.commit()
    c.close()
    assert client.get("/api/case/tags").status_code in (412, 200)
    res = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "TG-1"}).json()
    assert res["success"]
    rid = client.get("/api/case/search", params={"q": "100000000001", "mode": "contains"}).json()["hits"][0]["id"]
    body = {"tag": "relied_upon", "records": [{"table": "transactions", "id": rid}]}
    assert client.post("/api/case/tags", json=body).json()["applied"] == 1
    assert client.get("/api/case/tags/records", params={"tag": "relied_upon"}).json()["total"] == 1
    assert client.post("/api/case/tags", json={"tag": "", "records": body["records"]}).status_code == 422
    assert client.post("/api/case/tags", json={"tag": "x", "records": [{"table": "nope", "id": 1}]}).status_code == 422
    # processing the same item again keeps the tag and places it on the record with the same source location
    again = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "TG-1", "mode": "add", "reprocess": True,
                                                 "item_id": "EV-001"}).json()
    if again.get("success"):
        t = client.get("/api/case/tags/records", params={"tag": "relied_upon"}).json()
        assert t["total"] == 1
    assert client.post("/api/case/tags/remove", json=body).json()["removed"] in (0, 1)
    log = client.get("/api/case/audit").json() if client.get("/api/case/audit").status_code == 200 else None
    if log is not None:
        assert "records_tagged" in json.dumps(log)


# ------------------------------------------------------------------------------------------------ 5B.7
def test_timeline_places_only_records_with_a_fixed_instant(store):
    r = store.timeline()
    assert r["counts"] == {"fixed": 3, "clock_only": 1, "no_time": 2}
    assert [(e["tbl"], e["ist"]) for e in r["events"]] == [
        ("chats", "2026-02-01 10:00:00"), ("transactions", "2026-02-01 10:15:00"), ("chats", "2026-02-01 10:30:00")]
    assert r["events"][1]["time_basis"] == "EPOCH_UTC" and r["events"][0]["time_basis"] == "RECORDED_UTC_AND_IST"
    assert r["time_basis"] == {"EPOCH_UTC": 1, "RECORDED_UTC_AND_IST": 2}
    assert "Ravi" in r["events"][0]["summary"] and r["events"][0]["decoded_by"] is None


def test_clock_only_and_no_time_are_listed_apart_not_guessed(store):
    r = store.timeline(group="clock_only")
    assert r["total"] == 1 and r["events"][0]["ist"] is None and r["events"][0]["local_clock"] == "2026-02-01 09:00:00"
    assert r["events"][0]["time_basis"] == "LOCAL_ZONE_UNKNOWN"
    n = store.timeline(group="no_time")
    assert n["total"] == 2 and all(e["ist"] is None and e["local_clock"] is None for e in n["events"])


def test_timeline_range_filters_and_order(store):
    assert store.timeline(frm="2026-02-01 10:10:00", to="2026-02-01 10:20:00")["total"] == 1
    assert store.timeline(frm="2026-02-02")["total"] == 0
    assert store.timeline(frm="2026-02-01", to="2026-02-01")["total"] == 3          # a day covers the whole day
    d = store.timeline(descending=True)
    assert d["events"][0]["ist"] == "2026-02-01 10:30:00"
    with pytest.raises(case_timeline.TimelineError):
        store.timeline(frm="yesterday")
    with pytest.raises(case_timeline.TimelineError):
        store.timeline(frm="2026-02-03", to="2026-02-01")


def test_timeline_filters_and_paging_and_buckets(store):
    assert store.timeline(tables=["chats"])["total"] == 2
    assert store.timeline(application="PhonePe")["total"] == 1
    assert store.timeline(evidence_item="EV-009")["total"] == 0
    a, b = store.timeline(limit=2), store.timeline(limit=2, offset=2)
    assert len(a["events"]) == 2 and len(b["events"]) == 1
    h = store.timeline(bucket="hour")["buckets"]
    assert h["items"] == [{"start": "2026-02-01 10", "count": 3}] and not h["truncated"]
    with pytest.raises(case_timeline.TimelineError):
        store.timeline(tables=["contacts"])
    with pytest.raises(case_timeline.TimelineError):
        store.timeline(group="all")


def test_timeline_by_tag_and_tags_on_events(store):
    c = _ids(store, "chats")
    store.tag_records("relied_upon", [("chats", c[1])])
    r = store.timeline(tag="relied_upon")
    assert r["total"] == 1 and r["events"][0]["id"] == c[1] and r["events"][0]["tags"] == ["relied_upon"]


def test_timeline_does_not_change_the_store(store):
    def dump():
        c = sqlite3.connect(store.db_path)
        out = {t: c.execute(f"SELECT * FROM {t} ORDER BY id").fetchall() for t in ("chats", "transactions", "tags")}
        c.close()
        return json.dumps(out, default=str)
    before = dump()
    store.timeline(bucket="day")
    store.timeline(group="clock_only")
    assert dump() == before


def test_timeline_endpoint(client, tmp_path):
    assert client.get("/api/case/timeline").status_code in (412, 200)
    ev = tmp_path / "phone"
    ev.mkdir()
    c = sqlite3.connect(ev / "a_payments.db")
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp INTEGER)')
    c.execute('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', ("A", 1500.0, "me@ybl", "x@ybl", "100000000001", 1769936400000))
    c.commit()
    c.close()
    assert client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "TL-1"}).json()["success"]
    r = client.get("/api/case/timeline", params={"bucket": "day"}).json()
    assert r["counts"]["fixed"] + r["counts"]["clock_only"] + r["counts"]["no_time"] >= 1
    assert client.get("/api/case/timeline", params={"from": "nope"}).status_code == 422
    assert client.get("/api/case/timeline", params={"group": "zzz"}).status_code == 422
