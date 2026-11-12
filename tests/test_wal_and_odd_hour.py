"""5B.1 follow-ups: rows served from a WAL carry a -wal offset, and the odd-hour badge reads the right clock."""
import os
import sqlite3

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from parsers import api_server
from parsers.heuristic_engine import compute_transaction_risk_badges


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", dict(api_server._case_state))
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "cases"))
    return TestClient(api_server.app)


def test_ingested_rows_in_a_wal_name_the_wal_file_and_frame(client, tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    db = ev / "payments.db"
    c = sqlite3.connect(db)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA wal_autocheckpoint=0")
    c.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    c.execute("INSERT INTO \"Transaction\" VALUES ('A',1111.11,'me@ybl','one@ybl','100000000001','2026-02-01 09:00:00')")
    c.commit()
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.execute("INSERT INTO \"Transaction\" VALUES ('B',2222.22,'me@ybl','two@ybl','100000000002','2026-02-02 09:00:00')")
    c.commit()
    assert os.path.getsize(str(db) + "-wal") > 32
    res = client.post("/api/case/ingest", json={"evidence_path": str(ev), "case_id": "WAL-1"}).json()
    c.close()
    cs = sqlite3.connect(res["workspace_dir"] + "/bharat_case_store.db")
    prov = {r[0]: r[1] for r in cs.execute("SELECT Transaction_ID, Forensic_Provenance FROM transactions")}
    cs.close()
    line = prov["100000000002"]
    assert ":: Offset=0x" in line and "In=payments.db-wal frame" in line
    # the offset is a position inside the working copy's -wal file and the cell there is that row
    wal = open(os.path.join(res["workspace_dir"], "items", "EV-001", "working_copy", "payments.db-wal"), "rb").read()
    offset = int(line.split("Offset=0x")[1].split(" ")[0], 16)
    from src.sqlite.varint import decode_varint
    n, a = decode_varint(wal, offset)
    rowid, b = decode_varint(wal, offset + a)
    assert rowid == 2 and b"100000000002" in wal[offset:offset + a + b + n]


def _badges(rows):
    df = pd.DataFrame(rows, columns=["Date", "Amount", "Timestamp_Basis"])
    return compute_transaction_risk_badges(df).tolist()


def test_odd_hour_is_read_in_ist_when_the_source_fixes_the_instant():
    out = _badges([
        ("2026-02-01 20:00:00", 5000, "EPOCH_UTC"),                 # 01:30 IST: odd
        ("2026-02-01 02:00:00", 5000, "EPOCH_UTC"),                 # 07:30 IST: ordinary morning
        ("2026-02-01 23:00:00", 5000, "OFFSET_CONVERTED_UTC"),      # 04:30 IST: odd
    ])
    assert "Odd-Hour 12AM–5AM IST" in out[0]
    assert out[1].startswith("🟢")
    assert "Odd-Hour 12AM–5AM IST" in out[2]


def test_odd_hour_on_a_clock_with_no_zone_says_so():
    out = _badges([("2026-02-01 02:00:00", 5000, "LOCAL_ZONE_UNKNOWN")])
    assert "recorded clock" in out[0] and "zone not recorded" in out[0]
    assert "IST" not in out[0]


def test_small_amounts_are_never_odd_hour():
    assert _badges([("2026-02-01 20:00:00", 500, "EPOCH_UTC")])[0].startswith("🟢")
