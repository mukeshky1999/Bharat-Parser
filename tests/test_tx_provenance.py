"""X-13: a transaction keeps the source rows it came from and a time whose zone is stated honestly."""
import json
import sqlite3

import pandas as pd
import pytest

from parsers import api_server
from parsers.app_overrides import timestamp_record
from parsers.heuristic_engine import compose_tx_provenance, synthesize_and_deduplicate_records
from parsers.ui_fts5_paginator import CaseUIPaginatorStore


# ---------------------------------------------------------------- one time converter
def test_epoch_gives_utc_and_ist_five_thirty_apart():
    r = timestamp_record(1_700_000_000_000, 'unix_ms')          # 2023-11-14 22:13:20 UTC
    assert r['Timestamp_UTC'] == '2023-11-14 22:13:20'
    assert r['Timestamp_IST'] == '2023-11-15 03:43:20'
    assert r['Timestamp_Basis'] == 'EPOCH_UTC'
    assert r['Timestamp_Raw'] == '1700000000000'


def test_offset_string_is_converted_to_real_utc():
    r = timestamp_record('2024-01-05 10:00:00+05:30')
    assert r['Timestamp_UTC'] == '2024-01-05 04:30:00'
    assert r['Timestamp_IST'] == '2024-01-05 10:00:00'
    assert r['Timestamp_Basis'] == 'OFFSET_CONVERTED_UTC'


def test_bare_local_string_claims_no_utc_or_ist():
    r = timestamp_record('2026-11-01 22:43:19')
    assert r['Date'] == '2026-11-01 22:43:19'            # the clock string is kept as recorded
    assert r['Timestamp_UTC'] is None and r['Timestamp_IST'] is None
    assert r['Timestamp_Basis'] == 'LOCAL_ZONE_UNKNOWN'
    assert r['Timestamp_Raw'] == '2026-11-01 22:43:19'


def test_missing_time_stays_missing():
    r = timestamp_record(None)
    assert all(v is None for v in r.values())
    assert timestamp_record('0')['Timestamp_Basis'] is None


# ---------------------------------------------------------------- clustering keeps every contributing row
def _frame(rows):
    return pd.DataFrame(rows)


def test_merged_record_lists_every_contributing_row():
    df = _frame([
        {'Date': '2026-01-02 10:00:00', 'Transaction_ID': '123456789012', 'Amount': 500.0,
         'Counterparty': 'ravi@ybl', 'Status': 'SUCCESS', 'Type': 'DEBIT',
         'Source_Table': 'payments', 'Source_RowID': 7, 'Recovery_State': 'Allocated B-Tree'},
        {'Date': '2026-01-02 10:00:00', 'Transaction_ID': '123456789012', 'Amount': 500.0,
         'Counterparty': 'ravi@ybl', 'Status': 'SUCCESS', 'Type': 'DEBIT',
         'Source_Table': 'sms_inbox', 'Source_RowID': 41, 'Recovery_State': 'Allocated B-Tree'},
    ])
    out = synthesize_and_deduplicate_records(df)
    assert len(out) == 1
    sources = json.loads(out.iloc[0]['Source_Rows'])
    assert {(s['table'], s['rowid']) for s in sources} == {('payments', 7), ('sms_inbox', 41)}
    line = compose_tx_provenance('/data/app/pay.db', out.iloc[0]['Source_Rows'])
    assert line.count(' :: RowID=') == 2 and '/data/app/pay.db :: payments :: RowID=7' in line


def test_time_follows_the_row_that_supplied_the_date():
    df = _frame([
        {'Date': None, 'Transaction_ID': '123456789012', 'Amount': 90.0, 'Counterparty': 'a@ybl',
         'Status': 'SUCCESS', 'Type': 'DEBIT', 'Source_Table': 't1', 'Source_RowID': 1},
        {'Date': '2026-03-04 05:06:07', 'Timestamp_Raw': '1772600767', 'Timestamp_UTC': '2026-03-04 05:06:07',
         'Timestamp_IST': '2026-03-04 10:36:07', 'Timestamp_Basis': 'EPOCH_UTC',
         'Transaction_ID': '123456789012', 'Amount': 90.0, 'Counterparty': 'a@ybl',
         'Status': 'SUCCESS', 'Type': 'DEBIT', 'Source_Table': 't2', 'Source_RowID': 2},
    ])
    out = synthesize_and_deduplicate_records(df).iloc[0]
    assert out['Date'] == '2026-03-04 05:06:07'
    assert out['Timestamp_UTC'] == '2026-03-04 05:06:07' and out['Timestamp_Basis'] == 'EPOCH_UTC'


def test_row_without_source_info_says_not_recorded():
    df = _frame([{'Date': '2026-01-02 10:00:00', 'Transaction_ID': '123456789012', 'Amount': 5.0,
                  'Counterparty': 'q@ybl', 'Status': 'SUCCESS', 'Type': 'CREDIT'}])
    out = synthesize_and_deduplicate_records(df).iloc[0]
    assert out['Source_Rows'] is None
    assert compose_tx_provenance('f.db', out['Source_Rows']) is None


def test_time_taken_from_a_phonepe_id_is_labelled_derived_and_has_no_zone():
    df = _frame([{'Date': None, 'Transaction_ID': 'T2401051030450123456', 'Amount': 25.0,
                  'Counterparty': 'z@ybl', 'Status': 'SUCCESS', 'Type': 'DEBIT'}])
    out = synthesize_and_deduplicate_records(df).iloc[0]
    assert out['Timestamp_Basis'] == 'DERIVED_FROM_TRANSACTION_ID'
    assert out['Timestamp_UTC'] is None and out['Timestamp_IST'] is None


# ---------------------------------------------------------------- end to end through the real ingest
@pytest.fixture
def ingested(tmp_path, monkeypatch):
    monkeypatch.setattr(api_server, "_case_state", api_server._case_state)
    monkeypatch.setattr(api_server, "_active_store", api_server._active_store)
    ev = tmp_path / "evidence"
    ev.mkdir()
    db = ev / "payments.db"
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE "Transaction" (id TEXT, amount REAL, sender_vpa TEXT, receiver_vpa TEXT, utr TEXT, timestamp TEXT)')
    conn.executemany('INSERT INTO "Transaction" VALUES (?,?,?,?,?,?)', [
        ('A', 1111.11, 'me@ybl', 'one@ybl', '100000000001', '2026-02-01 09:00:00'),
        ('B', 2222.22, 'me@ybl', 'two@ybl', '100000000002', '2026-02-02 09:00:00'),
        ('C', 3333.33, 'me@ybl', 'three@ybl', '100000000003', '2026-02-03 09:00:00'),
    ])
    conn.commit()
    conn.close()
    epoch_db = ev / "wallet.db"
    conn = sqlite3.connect(epoch_db)
    conn.execute("CREATE TABLE payments (id INTEGER PRIMARY KEY, amount REAL, payee TEXT, txn_ref TEXT, created_at INTEGER)")
    conn.execute("INSERT INTO payments VALUES (1, 777.0, 'shop@okaxis', '200000000001', 1700000000000)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(api_server, "DEFAULT_WORKSPACE_ROOT", str(tmp_path / "ws"))
    api_server._execute_ingestion_pipeline(str(ev), "CASE-TX", "tx case", "Examiner", "Agency")
    store = api_server._active_store
    c = sqlite3.connect(store.db_path)
    c.row_factory = sqlite3.Row
    rows = [dict(r) for r in c.execute("SELECT * FROM transactions")]
    c.close()
    return db, rows


def test_every_stored_transaction_points_to_its_real_source_row(ingested):
    db, rows = ingested
    src = sqlite3.connect(db)
    checked = 0
    for r in rows:
        if 'payments.db' not in (r['Source_File'] or ''):
            continue
        prov = r['Forensic_Provenance']
        assert prov, f"transaction {r['Transaction_ID']} has no provenance"
        part = prov.split(' + ')[0]
        file_, table, rowid, state = [x.strip() for x in part.split(' :: ')][:4]
        assert table == 'Transaction' and state == 'State=Allocated B-Tree'
        rid = int(rowid.split('=')[1])
        amount, utr = src.execute('SELECT amount, utr FROM "Transaction" WHERE rowid = ?', (rid,)).fetchone()
        assert amount == pytest.approx(r['Amount']) and utr == r['Transaction_ID']
        checked += 1
    src.close()
    assert checked == 3


def test_local_clock_rows_do_not_claim_utc_or_ist(ingested):
    _, rows = ingested
    local = [r for r in rows if 'payments.db' in (r['Source_File'] or '')]
    assert local
    for r in local:
        assert r['Timestamp_Basis'] == 'LOCAL_ZONE_UNKNOWN'
        assert r['Timestamp_UTC'] is None and r['Timestamp_IST'] is None
        assert r['Timestamp_Raw'] == r['Date']


def test_epoch_rows_store_utc_and_ist_from_one_converter(ingested):
    _, rows = ingested
    epoch = [r for r in rows if 'wallet.db' in (r['Source_File'] or '')]
    assert epoch, "the epoch fixture produced no transaction"
    r = epoch[0]
    assert r['Timestamp_UTC'] == '2023-11-14 22:13:20'
    assert r['Timestamp_IST'] == '2023-11-15 03:43:20'
    assert r['Timestamp_Basis'] == 'EPOCH_UTC' and r['Timestamp_Raw'] == '1700000000000'
    assert ':: payments :: RowID=1 ::' in r['Forensic_Provenance']


def test_direction_follows_recorded_type_and_is_empty_when_unknown(ingested):
    _, rows = ingested
    for r in rows:
        if r['Type'] == 'DEBIT':
            assert r['Direction'] == 'OUTGOING'
        elif r['Type'] == 'CREDIT':
            assert r['Direction'] == 'INCOMING'
        else:
            assert r['Direction'] is None


# ---------------------------------------------------------------- case stores made before X-13
def test_old_case_store_gets_the_new_columns(tmp_path):
    first = CaseUIPaginatorStore(str(tmp_path), db_name="bharat_case_store.db")
    c = sqlite3.connect(first.db_path)             # make it look like a store written before X-13
    for col in ("Timestamp_Raw", "Timestamp_UTC", "Timestamp_Basis"):
        c.execute(f"ALTER TABLE transactions DROP COLUMN {col}")
    c.commit()
    assert "Timestamp_UTC" not in {r[1] for r in c.execute("PRAGMA table_info(transactions)")}
    c.close()
    store = CaseUIPaginatorStore(str(tmp_path), db_name="bharat_case_store.db")
    c = sqlite3.connect(store.db_path)
    cols = {r[1] for r in c.execute("PRAGMA table_info(transactions)")}
    c.close()
    assert {'Timestamp_Raw', 'Timestamp_UTC', 'Timestamp_Basis'} <= cols


# ---------------------------------------------------------------- page and byte offset (stage B)
def test_recorded_offset_is_the_real_cell_in_the_file(ingested):
    from src.sqlite.varint import decode_varint
    db, rows = ingested
    data = open(db, "rb").read()
    seen = 0
    for r in rows:
        if 'payments.db' not in (r['Source_File'] or ''):
            continue
        prov = r['Forensic_Provenance']
        assert ':: Offset=0x' in prov, prov
        rowid = int(prov.split('RowID=')[1].split(' ')[0])
        offset = int(prov.split('Offset=0x')[1].split(' ')[0], 16)
        page = int(prov.split('Page=')[1].split(' ')[0])
        payload_len, n1 = decode_varint(data, offset)
        cell_rowid, n2 = decode_varint(data, offset + n1)
        assert cell_rowid == rowid                                    # the cell at that offset is this row
        assert (offset // 4096) + 1 == page                            # and it lies on the stated page
        assert r['Transaction_ID'].encode() in data[offset:offset + n1 + n2 + payload_len]   # its bytes hold the UTR
        seen += 1
    assert seen == 3


def _wal_db(tmp_path):
    """A database whose table lives partly in the main file and partly (newer rows) in the -wal file."""
    db = tmp_path / "w.db"
    keep = sqlite3.connect(db)
    keep.execute("PRAGMA journal_mode=WAL")
    keep.execute("PRAGMA wal_autocheckpoint=0")
    keep.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    keep.execute("INSERT INTO t(v) VALUES ('in-main')")
    keep.commit()
    keep.execute("PRAGMA wal_checkpoint(TRUNCATE)")        # row 1 is now in the main file, the WAL is empty
    keep.execute("INSERT INTO t(v) VALUES ('in-wal')")
    keep.commit()                                          # row 2 is only in the WAL
    return db, keep


def test_locator_reads_rows_that_live_in_the_wal_at_their_wal_offset(tmp_path):
    from parsers.sqlite_locator import RowLocator
    from src.sqlite.varint import decode_varint
    db, keep = _wal_db(tmp_path)
    try:
        wal_bytes = open(str(db) + "-wal", "rb").read()
        assert len(wal_bytes) > 32, "the test needs frames in the WAL"
        loc = RowLocator(str(db))
        assert loc.exact is True
        got = loc.locate_ex("t", [1, 2])
        loc.close()
    finally:
        keep.close()
    page, offset, frame = got[2]
    assert frame is not None, "row 2 exists only in the WAL"
    payload_len, n1 = decode_varint(wal_bytes, offset)
    rowid, n2 = decode_varint(wal_bytes, offset + n1)
    assert rowid == 2 and b"in-wal" in wal_bytes[offset:offset + n1 + n2 + payload_len]
    assert offset >= 32 + 24                              # inside a frame, past the headers
    # the same table's page now has the WAL's version, so row 1 (same page) is located in the WAL as well
    assert got[1][2] == frame


def test_locator_uses_the_main_file_for_pages_without_a_committed_frame(tmp_path):
    from parsers.sqlite_locator import RowLocator
    db, keep = _wal_db(tmp_path)
    keep.execute("CREATE TABLE u (id INTEGER PRIMARY KEY, v TEXT)")
    keep.execute("INSERT INTO u(v) VALUES ('later')")
    keep.commit()
    keep.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    keep.execute("INSERT INTO t(v) VALUES ('newest')")
    keep.commit()
    try:
        data = open(db, "rb").read()
        loc = RowLocator(str(db))
        got = loc.locate_ex("u", [1])
        loc.close()
    finally:
        keep.close()
    page, offset, frame = got[1]
    assert frame is None and (offset // 4096) + 1 == page
    assert b"later" in data[offset:offset + 40]


def test_stale_wal_frames_are_ignored_like_sqlite_ignores_them(tmp_path):
    from parsers.sqlite_locator import RowLocator
    db, keep = _wal_db(tmp_path)
    try:
        wal = str(db) + "-wal"
        raw = bytearray(open(wal, "rb").read())
        raw[32 + 8] ^= 0x01                                # first frame's salt no longer matches the header
        open(wal, "wb").write(bytes(raw))
        loc = RowLocator(str(db))
        assert loc.exact is True
        assert all(w is None for _, _, w in loc.locate_ex("t", [1]).values())
        loc.close()
    finally:
        keep.close()


def test_provenance_line_names_the_wal_file_and_frame():
    line = compose_tx_provenance("f.db", json.dumps(
        [{"table": "t", "rowid": 3, "state": "Allocated B-Tree", "page": 2, "offset": 4152, "wal_frame": 1}]))
    assert line.endswith(":: Page=2 :: Offset=0x00001038 :: In=f.db-wal frame 1")


def test_rows_in_a_database_with_a_wal_say_offset_not_recorded():
    line = compose_tx_provenance("f.db", json.dumps([{"table": "t", "rowid": 3, "state": "Allocated B-Tree"}]))
    assert line.endswith(":: Offset=Not recorded")
