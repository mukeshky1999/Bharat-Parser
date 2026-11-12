"""Bank alerts (in testing): SMS notices read with the src/dlt rules, kept with provenance, never with an invented time."""
import sqlite3

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from parsers import api_server, bank_alerts

MS = 1_700_000_000_000     # 2023-11-14 22:13:20 UTC


def _android(path, with_sms_center=True, extra=()):
    c = sqlite3.connect(path)
    cols = "_id INTEGER PRIMARY KEY, address TEXT, body TEXT, date INTEGER, type INTEGER" + (", service_center TEXT, creator TEXT, sub_id INTEGER" if with_sms_center else "")
    c.execute(f"CREATE TABLE sms ({cols})")
    rows = [
        ("AD-HDFCBK-S", "Rs.5,000.00 debited from A/c XX1234 on 12-11-26 to VPA rakesh@ybl (UPI Ref 612345678901). Avl Bal Rs.10,000.00", MS, 1, "+919822000000", "com.google.android.apps.messaging", 1),
        ("VM-SBIINB-S", "Your OTP is 482913 for txn. Do not share", MS + 1000, 1, None, "com.evil.injector", 1),
        ("VK-CANBNK-S", "Lien marked on your A/c XX9988 as per Cyber Crime ack 31234", 0, 1, "+919822000000", "com.google.android.apps.messaging", 1),
        ("JD-OFFERS-P", "Win cash now! Click link", MS, 1, None, None, 1),
        ("+919876543210", "hi, call me when free", MS, 1, None, None, 1),
        ("AD-HDFCBK-S", "Rs.100 debited (sent by me)", MS, 2, None, None, 1),       # type 2 = sent: not read
        *extra,
    ]
    for i, (a, b, d, t, sc, cr, sub) in enumerate(rows, 1):
        if with_sms_center:
            c.execute("INSERT INTO sms VALUES (?,?,?,?,?,?,?,?)", (i, a, b, d, t, sc, cr, sub))
        else:
            c.execute("INSERT INTO sms VALUES (?,?,?,?,?)", (i, a, b, d, t))
    c.commit(); c.close()


def test_kind_is_found_by_content_not_name(tmp_path):
    _android(tmp_path / "whatever.bin")
    assert bank_alerts.sms_database_kind(str(tmp_path / "whatever.bin")) == "android"
    c = sqlite3.connect(tmp_path / "wa.db"); c.execute("CREATE TABLE message (_id INTEGER, from_me INTEGER)"); c.commit(); c.close()
    assert bank_alerts.sms_database_kind(str(tmp_path / "wa.db")) is None            # a chat database is not an SMS database
    assert bank_alerts.sms_database_kind(str(tmp_path / "missing.db")) is None


def test_android_alerts_categories_times_and_what_is_left_out(tmp_path):
    p = str(tmp_path / "mmssms.db"); _android(p)
    df, st = bank_alerts.read_alerts(p, "data/mmssms.db")
    assert st == {"read": 5, "kept": 3, "promotional_left_out": 1, "unclassified_left_out": 1}   # sent msg not read; friend's text left out
    by = {r["Category"]: r for _, r in df.iterrows()}
    d = by["TX_DEBIT_OUTFLOW"]
    assert d["Amount"] == 5000.0 and d["Balance"] == 10000.0 and d["Account_Masked"] == "A/c XX1234" and d["UTR"] == "612345678901"
    assert d["Counterparty"] == "rakesh@ybl" and d["Institution"] == "HDFC Bank" and d["Payment_Rail"] == "UPI"
    assert d["Received_UTC"].startswith("2023-11-14 22:13:20") and d["Received_Raw"] == str(MS)
    assert d["Forensic_Provenance"] == "data/mmssms.db :: sms :: RowID=1 :: State=Allocated B-Tree"
    otp = by["OTP_AUTHENTICATION_CODE"]
    assert otp["Code_Or_Location"] == "482913" and pd.isna(otp["Payment_Rail"])                    # no rail guessed for a code
    lien = by["LIEN_HOLD_OR_FREEZE_ALERT"]
    assert pd.isna(lien["Received_UTC"]) and pd.isna(lien["Received_IST"]) and pd.isna(lien["Received_Raw"])   # date 0: unknown, never 1970
    assert d["Spoof_Indicator"] == 0 and otp["Spoof_Indicator"] == 1                              # the indicator, not a verdict


def test_indicator_is_unknown_when_the_database_lacks_the_fields(tmp_path):
    p = str(tmp_path / "mmssms.db"); _android(p, with_sms_center=False)
    df, _ = bank_alerts.read_alerts(p, "f")
    assert len(df) == 3 and df["Spoof_Indicator"].isna().all()                                     # not "suspect": unknown


def test_ios_text_messages_and_cocoa_time(tmp_path):
    p = tmp_path / "sms.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
    c.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, text TEXT, attributedBody BLOB, date INTEGER, is_from_me INTEGER)")
    c.execute("INSERT INTO handle VALUES (1, 'AD-HDFCBK-S')")
    cocoa_ns = int((1_700_000_000 - 978_307_200) * 1e9)
    c.execute("INSERT INTO message VALUES (1, 1, 'Rs.250.00 credited to A/c XX4321 UPI Ref 612345678902', NULL, ?, 0)", (cocoa_ns,))
    c.execute("INSERT INTO message VALUES (2, 1, NULL, X'00', ?, 0)", (cocoa_ns,))                  # no readable body: skipped
    c.commit(); c.close()
    df, st = bank_alerts.read_alerts(str(p), "sms.db")
    assert st["read"] == 1 and len(df) == 1
    r = df.iloc[0]
    assert r["Category"] == "TX_CREDIT_INFLOW" and r["Amount"] == 250.0 and r["Received_UTC"].startswith("2023-11-14 22:13:20")
    assert pd.isna(r["Spoof_Indicator"])            # iOS stores no service centre: unknown


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    ev = tmp_path / "ev"; ev.mkdir()
    _android(ev / "mmssms.db")
    client = TestClient(api_server.app)
    r = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "BA-1"}).json()
    assert r["success"], r
    return client, r


def test_alerts_flow_through_ingest_coverage_search_timeline_and_tags(case):
    client, res = case
    rows = client.get("/api/artifacts/query", params={"category": "bank_alerts"}).json()["rows"]
    assert len(rows) == 3 and all(r["Decoded_By"].endswith("in testing") and r["Evidence_Item"] == "EV-001" for r in rows)
    log = [x for x in res["processing_log"] if x["stage"] == "bank_alerts"]
    assert log and "in testing" in log[0]["error"] and "3 of 5" in log[0]["error"]
    cov = client.get("/api/case/coverage").json()
    assert any(f["records"].get("bank_alerts") == 3 for f in cov["files"])
    hit = client.get("/api/case/search", params={"q": "482913", "mode": "contains"}).json()
    assert any(h["table"] == "bank_alerts" for h in hit["hits"])
    tl = client.get("/api/case/timeline", params={"group": "fixed", "tables": "bank_alerts"}).json()
    assert tl["total"] == 2 and tl["counts"]["no_time"] >= 1                                    # the date-0 alert has no time
    rid = rows[0]["id"]
    assert client.post("/api/case/tags", json={"tag": "of_interest", "records": [{"table": "bank_alerts", "id": rid}]}).json()["applied"] == 1
    assert client.get("/api/case/record", params={"table": "bank_alerts", "id": rid}).json()["tags"] == ["of_interest"]


def test_processing_the_device_again_does_not_duplicate_alerts(case, tmp_path):
    client, _ = case
    ev = str(tmp_path / "ev")
    again = client.post("/api/case/ingest", json={"evidence_path": ev, "case_id": "BA-1", "mode": "add"}).json()
    assert again["success"]
    n = client.get("/api/artifacts/query", params={"category": "bank_alerts"}).json()["total"]
    assert n == 3                                                                                  # the same device again replaces its records, none doubled
