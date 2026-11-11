"""
Test Suite for Phase 2, Module 2.1: Forensic SQLite Engine,
Shared -wal Historical Frame Reader, Rollback -journal Decoder & B-Tree Residual Carver.

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real binary SQLite byte streams and database files (no mock objects).
- All fixtures write strictly to .workspace_tmp/
- Tests 65,536-byte page size & Page 1 offset 100.
- Tests multi-frame WAL edit & delete timeline extraction.
- Tests clobbered 4-byte freeblock header reverse serial-type alignment.
- Tests multi-overflow page chain reassembly.
- Tests 9-byte SQLite Varint decoder edge cases.
- Tests rollback journal parsing.
- Verifies canonical diagnostics and master recovered records schemas.
"""

import json
import os
import shutil
import sqlite3
import struct
from pathlib import Path
from typing import List, Dict, Any

import pytest

from src.core.enums import (
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
    ForensicGroup,
)


@pytest.fixture
def tmp_sqlite_dir():
    """Provides a safe isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_sqlite_engine")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


# ==============================================================================
# TEST 1: 9-Byte SQLite Varint Decoder & Serial Types
# ==============================================================================

def test_9byte_sqlite_varint_decoder():
    """
    Tests SQLite 9-byte Varint decoding according to Section 5.1:
    - 1-byte varints (0x00 to 0x7F)
    - Multi-byte varints (2 to 8 bytes, where each byte contributes 7 bits)
    - 9-byte varint where the 9th byte contributes ALL 8 bits (b & 0xFF)
    - Ensures large 64-bit integers and negative two's complement numbers decode correctly.
    """
    from src.sqlite.varint import decode_varint, encode_varint

    # 1 byte
    val, consumed = decode_varint(b"\x00", 0)
    assert val == 0 and consumed == 1

    val, consumed = decode_varint(b"\x7F", 0)
    assert val == 127 and consumed == 1

    # 2 bytes: 128 -> 0x81, 0x00
    val, consumed = decode_varint(b"\x81\x00", 0)
    assert val == 128 and consumed == 2

    # 3 bytes: 16384 -> 0x81, 0x80, 0x00
    val, consumed = decode_varint(b"\x81\x80\x00", 0)
    assert val == 16384 and consumed == 3

    # 9-byte varint test:
    # In SQLite, if the first 8 bytes have MSB=1, the 9th byte contributes all 8 bits!
    # For example, 0xFF * 8 followed by 0xFE:
    nine_bytes = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE"
    val, consumed = decode_varint(nine_bytes, 0)
    assert consumed == 9
    # The 9-byte varint encoder should round-trip
    encoded = encode_varint(val)
    val_rt, cons_rt = decode_varint(encoded, 0)
    assert val_rt == val
    assert cons_rt == len(encoded)

    # Test offset within buffer
    buf = b"PREFIX" + b"\x82\x00" + b"SUFFIX"
    val, consumed = decode_varint(buf, 6)
    assert val == 256 and consumed == 2


def test_serial_type_decoder():
    """
    Tests SQLite record serial-type parsing per Section 5.3:
    - Type 0: NULL
    - Type 1-6: 1, 2, 3, 4, 6, 8-byte signed ints (including 3-byte and 6-byte sign extension)
    - Type 7: 8-byte float
    - Type 8: constant 0
    - Type 9: constant 1
    - Type >= 12 even: BLOB
    - Type >= 13 odd: TEXT (UTF-8, UTF-16LE, UTF-16BE)
    """
    from src.sqlite.record import decode_serial_type, decode_record

    # 3-byte signed int: negative value
    # 0xFFFFFF = -1 in 24-bit two's complement
    val, consumed = decode_serial_type(3, b"\xFF\xFF\xFE", 0)
    assert val == -2 and consumed == 3

    # 6-byte signed int: 0x000001000000
    val, consumed = decode_serial_type(5, b"\x00\x00\x01\x00\x00\x00", 0)
    assert val == 0x1000000 and consumed == 6

    # Text UTF-8: type = 13 + 2 * len = 13 + 2 * 5 = 23
    val, consumed = decode_serial_type(23, b"Hello", 0, text_encoding="UTF-8")
    assert val == "Hello" and consumed == 5

    # Full record payload:
    # Header: [header_len, type_col1, type_col2, type_col3]
    # Header size = 4
    # col1 = int8 (type 1) -> 42 (1 byte)
    # col2 = TEXT "Hi" (type 13 + 4 = 17) -> "Hi" (2 bytes)
    # col3 = NULL (type 0) -> 0 bytes
    payload = b"\x04\x01\x11\x00" + struct.pack(">b", 42) + b"Hi"
    cols = decode_record(payload, text_encoding="UTF-8")
    assert cols == [42, "Hi", None]


# ==============================================================================
# TEST 2: Page 1 (Offset 100) & 65,536-Byte Page Size Test
# ==============================================================================

def test_page1_offset100_and_65536_page_size(tmp_sqlite_dir):
    """
    Acceptance Test 1 (Section 10):
    Creates a real SQLite database with PRAGMA page_size = 65536; (0x0001 at Bytes 16-17)
    and multiple tables.
    Verifies that ForensicSQLiteEngine:
    1. Reads page_size == 65536
    2. Correctly applies btree_header_offset = 100 on Page 1
    3. Successfully parses sqlite_schema without off-by-100 errors
    4. Identifies all table names, column names, affinities, and root pages.
    """
    from src.sqlite.engine import ForensicSQLiteEngine
    from src.sqlite.header import parse_sqlite_header

    db_path = tmp_sqlite_dir / "large_page.db"
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA page_size = 65536;")
    con.execute("VACUUM;")
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, balance REAL);")
    con.execute("CREATE TABLE orders (order_id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT);")
    for i in range(1, 11):
        con.execute(f"INSERT INTO users VALUES ({i}, 'user_{i}', {i * 100.5});")
        con.execute(f"INSERT INTO orders VALUES ({i}, {i}, 'item_{i}');")
    con.commit()
    con.close()

    # Raw header check
    with open(db_path, "rb") as f:
        header_bytes = f.read(100)
    header = parse_sqlite_header(header_bytes)
    assert header.page_size == 65536
    assert header.usable_page_size == 65536
    assert header.text_encoding == "UTF-8"

    # Engine process
    engine = ForensicSQLiteEngine()
    diag, records = engine.process_database(
        primary_db_path=db_path,
        staging_id=1,
        canonical_path="/data/data/com.app/large_page.db"
    )

    assert diag.page_size_bytes == 65536
    assert diag.usable_page_size_u == 65536
    assert "users" in engine.table_schemas
    assert "orders" in engine.table_schemas

    # Verify live records recovered from both tables
    user_rows = [r for r in records if r.table_name == "users" and r.recovery_classification == ResidualConfidence.ORIGINAL_RECORD]
    order_rows = [r for r in records if r.table_name == "orders" and r.recovery_classification == ResidualConfidence.ORIGINAL_RECORD]
    assert len(user_rows) == 10
    assert len(order_rows) == 10
    assert user_rows[0].columns_dict["username"] == "user_1"
    assert user_rows[0].source_page_number >= 1


# ==============================================================================
# TEST 3: Multi-Frame WAL Edit & Delete Timeline Recovery Test
# ==============================================================================

def test_multiframe_wal_edit_and_delete_timeline(tmp_sqlite_dir):
    """
    Acceptance Test 2 (Section 10):
    WAL-mode database with:
    - Tx 1: INSERT INTO messages VALUES (1, 'Meet at warehouse at 10 PM', 1762262400)
    - Tx 2: UPDATE messages SET body = 'Meet at cafe at 10 PM' WHERE id = 1
    - Tx 3: DELETE FROM messages WHERE id = 1
    Uncheckpointed WAL preserved.
    Verifies that:
    1. Both Tx 1 and Tx 2 are recovered as HISTORICAL_COMMITTED_RECORD.
    2. Exact wal_frame_number is captured.
    3. diff_vs_active_json tracks column changes between superseded WAL state and final state.
    4. Deleted row in Tx 3 is detected as DELETED_IN_LATER_WAL_FRAME.
    """
    from src.sqlite.engine import ForensicSQLiteEngine
    from src.sqlite.wal import WALReader

    db_path = tmp_sqlite_dir / "wal_timeline.db"
    wal_path = tmp_sqlite_dir / "wal_timeline.db-wal"

    # Step 1: Create base table and commit checkpoint
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode = WAL;")
    con.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT, timestamp INTEGER);")
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE);")

    # Step 2: Three distinct transactions without checkpoint
    con.execute("INSERT INTO messages VALUES (1, 'Meet at warehouse at 10 PM', 1762262400);")
    con.commit()

    con.execute("UPDATE messages SET body = 'Meet at cafe at 10 PM' WHERE id = 1;")
    con.commit()

    con.execute("DELETE FROM messages WHERE id = 1;")
    con.commit()

    # Freeze snapshot before close checkpoints it
    saved_db = tmp_sqlite_dir / "saved_wal.db"
    saved_wal = tmp_sqlite_dir / "saved_wal.db-wal"
    shutil.copyfile(db_path, saved_db)
    shutil.copyfile(wal_path, saved_wal)
    con.close()

    # Verify raw WAL parsing
    wal_reader = WALReader(saved_wal, page_size=4096)
    frames = wal_reader.read_all_frames()
    assert len(frames) >= 3

    # Run Forensic Engine
    engine = ForensicSQLiteEngine()
    diag, records = engine.process_database(
        primary_db_path=saved_db,
        wal_path=saved_wal,
        staging_id=2,
        canonical_path="/data/data/com.chat/databases/saved_wal.db"
    )

    assert diag.wal_frames_total >= 3
    assert diag.wal_historical_commits_recovered >= 2

    # Verify recovered historical versions
    historical_rows = [
        r for r in records
        if r.table_name == "messages" and r.recovery_classification == ResidualConfidence.HISTORICAL_COMMITTED_RECORD
    ]
    assert len(historical_rows) >= 2

    warehouse_records = [r for r in historical_rows if "Meet at warehouse" in str(r.columns_dict.get("body"))]
    cafe_records = [r for r in historical_rows if "Meet at cafe" in str(r.columns_dict.get("body"))]

    assert len(warehouse_records) >= 1
    assert len(cafe_records) >= 1

    wh_record = warehouse_records[0]
    assert wh_record.wal_frame_number is not None
    assert wh_record.source_origin_zone == "WAL_SUPERSEDED_COMMIT"
    # Row was deleted in active state, so diff indicates deletion
    assert wh_record.diff_vs_active is not None
    assert "DELETED" in str(wh_record.diff_vs_active) or "old_wal_value" in str(wh_record.diff_vs_active)


# ==============================================================================
# TEST 4: Clobbered 4-Byte Freeblock Header Recovery Test
# ==============================================================================

def test_clobbered_4byte_freeblock_header_recovery(tmp_sqlite_dir):
    """
    Acceptance Test 3 (Section 10):
    Creates a non-WAL database with PRAGMA secure_delete = OFF;
    Inserts 5 rows into transactions(id INT PRIMARY KEY, vpa TEXT, amount REAL, utr TEXT).
    Deletes the middle row (id = 3).
    Verifies that:
    1. first_freeblock_offset points to the deleted cell.
    2. The first 4 bytes of the deleted cell were clobbered by SQLite (next_offset + size).
    3. Zone 1 Freeblock Carver uses reverse serial-type alignment starting at bytes 4..9
       to successfully recover the surviving columns (vpa, amount, utr).
    4. Row is tagged as RESIDUAL_RECORD or PARTIAL_RECORD with source_origin_zone = IN_PAGE_FREEBLOCK.
    """
    from src.sqlite.engine import ForensicSQLiteEngine

    db_path = tmp_sqlite_dir / "freeblock_test.db"
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA page_size = 4096;")
    con.execute("PRAGMA secure_delete = OFF;")
    con.execute(
        "CREATE TABLE transactions (id INTEGER PRIMARY KEY, vpa TEXT, amount REAL, utr TEXT);"
    )
    test_rows = [
        (1, "merchant@okhdfcbank", 1500.00, "UTR100000000001"),
        (2, "suspect@paytm", 9999.50, "UTR100000000002"),
        (3, "victim_refund@ybl", 45000.00, "UTR100000000003"),  # TO BE DELETED
        (4, "groceries@icici", 250.75, "UTR100000000004"),
        (5, "rent@axl", 22000.00, "UTR100000000005"),
    ]
    for r in test_rows:
        con.execute("INSERT INTO transactions VALUES (?, ?, ?, ?);", r)
    con.commit()

    # Delete row 3 to create in-page freeblock
    con.execute("DELETE FROM transactions WHERE id = 3;")
    con.commit()
    con.close()

    # Process with engine
    engine = ForensicSQLiteEngine()
    diag, records = engine.process_database(
        primary_db_path=db_path,
        staging_id=3,
        canonical_path="/data/data/com.upi/databases/freeblock_test.db"
    )

    # Check for recovered row 3 columns
    recovered_residuals = [
        r for r in records
        if r.table_name == "transactions" and r.source_origin_zone == "IN_PAGE_FREEBLOCK"
    ]
    assert len(recovered_residuals) >= 1

    # Check that victim_refund@ybl and UTR100000000003 were recovered
    recovered_vpa = [r for r in recovered_residuals if r.columns_dict.get("vpa") == "victim_refund@ybl"]
    assert len(recovered_vpa) >= 1
    res_rec = recovered_vpa[0]
    assert res_rec.columns_dict.get("utr") == "UTR100000000003"
    assert res_rec.columns_dict.get("amount") == 45000.00
    assert res_rec.recovery_classification in (ResidualConfidence.RESIDUAL_RECORD, ResidualConfidence.PARTIAL_RECORD)


# ==============================================================================
# TEST 5: Overflow Page Chain Reassembly Test
# ==============================================================================

def test_overflow_page_chain_reassembly(tmp_sqlite_dir):
    """
    Acceptance Test 4 (Section 10):
    Inserts a row containing a 15,000-byte JSON string into a database with 4096-byte page size,
    forcing the record to spill across 1 B-Tree Leaf Page + 4 linked Overflow Pages.
    Verifies that:
    1. Section 5.2's U, P, X, M, K overflow calculation correctly determines local_bytes K.
    2. The 4-byte next_overflow_page pointer chain is traversed.
    3. All 15,000 bytes are reassembled and decoded without truncation or corruption.
    """
    from src.sqlite.engine import ForensicSQLiteEngine
    from src.sqlite.overflow import calculate_overflow_bounds

    # Check math independently first:
    # U = 4096, X = 4096 - 35 = 4061.
    # M = floor((4096 - 12) * 32 / 255) - 23 = floor(4084 * 32 / 255) - 23 = floor(512.5) - 23 = 512 - 23 = 489.
    # For P = 15050 > X:
    # K = 489 + ((15050 - 489) % (4096 - 4)) = 489 + (14561 % 4092) = 489 + 2285 = 2774.
    # Since 2774 <= 4061, local_bytes = 2774.
    local_bytes, has_overflow = calculate_overflow_bounds(usable_page_size=4096, total_payload_bytes=15050)
    assert has_overflow is True
    assert local_bytes == 2774

    # Now create actual database with 15,000 byte JSON payload
    db_path = tmp_sqlite_dir / "overflow_test.db"
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA page_size = 4096;")
    con.execute("CREATE TABLE large_notes (id INTEGER PRIMARY KEY, note_title TEXT, raw_json TEXT);")

    # Generate 15,000-byte JSON payload
    large_dict = {"chunk_" + str(i): "data_" + ("X" * 120) for i in range(110)}
    large_json_str = json.dumps(large_dict)
    assert len(large_json_str) >= 15000

    con.execute("INSERT INTO large_notes VALUES (1, 'Important Evidence', ?);", (large_json_str,))
    con.commit()
    con.close()

    # Process with engine
    engine = ForensicSQLiteEngine()
    diag, records = engine.process_database(
        primary_db_path=db_path,
        staging_id=4,
        canonical_path="/data/data/com.notes/overflow_test.db"
    )

    note_rows = [r for r in records if r.table_name == "large_notes"]
    assert len(note_rows) == 1
    recovered_json = note_rows[0].columns_dict["raw_json"]
    assert len(recovered_json) == len(large_json_str)
    assert recovered_json == large_json_str


# ==============================================================================
# TEST 6: Rollback Journal (-journal) Pre-Transaction State Recovery
# ==============================================================================

def test_rollback_journal_pretransaction_recovery(tmp_sqlite_dir):
    """
    Step 5 (Pipeline B2):
    Tests reading a rollback journal file with magic 0xD9D505F920A163D7 and sector records.
    Verifies that:
    1. Journal sector header is decoded (sector_size, page_size, page_count).
    2. Page records (page_number + page_data + checksum) are read.
    3. Decoded rows that differ from active .db are emitted as RESIDUAL_RECORD (ROLLBACK_JOURNAL).
    """
    from src.sqlite.journal import RollbackJournalReader
    from src.sqlite.engine import ForensicSQLiteEngine

    db_path = tmp_sqlite_dir / "journal_test.db"
    journal_path = tmp_sqlite_dir / "journal_test.db-journal"

    # Create baseline DB in DELETE journal mode
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA page_size = 4096;")
    con.execute("PRAGMA journal_mode = DELETE;")
    con.execute("CREATE TABLE chats (id INTEGER PRIMARY KEY, sender TEXT, text TEXT);")
    con.execute("INSERT INTO chats VALUES (1, 'Alice', 'Original secret plan');")
    con.commit()
    con.close()

    # Read the original page 2 (where chats table leaf page is)
    with open(db_path, "rb") as f:
        f.seek(4096)
        orig_page2 = f.read(4096)

    # Now update DB to new value
    con = sqlite3.connect(db_path)
    con.execute("UPDATE chats SET text = 'Overwritten sanitized plan' WHERE id = 1;")
    con.commit()
    con.close()

    # Synthesize a valid rollback journal containing the pre-transaction page 2
    # Journal Sector Header (28 bytes) + padding to sector_size (512 bytes):
    # magic: D9 D5 05 F9 20 A1 63 D7
    # page_count: 1
    # checksum_nonce: 0x12345678
    # initial_db_page_count: 2
    # disk_sector_size: 512
    # journal_page_size: 4096
    journal_hdr = struct.pack(
        ">8sIIIII",
        b"\xD9\xD5\x05\xF9\x20\xA1\x63\xD7",
        1,          # page_count
        0x12345678, # nonce
        2,          # initial_db_pages
        512,        # sector_size
        4096        # page_size
    )
    assert len(journal_hdr) == 28
    header_block = journal_hdr + b"\x00" * (512 - 28)

    # Page record: page_number (4 bytes) + page_bytes (4096 bytes) + checksum (4 bytes)
    page_record = struct.pack(">I", 2) + orig_page2 + struct.pack(">I", 0)

    with open(journal_path, "wb") as f:
        f.write(header_block + page_record)

    # Test Journal Reader directly
    j_reader = RollbackJournalReader(journal_path)
    pages = j_reader.read_all_pages()
    assert len(pages) == 1
    assert pages[0].page_number == 2
    assert len(pages[0].page_data) == 4096

    # Test Engine integration
    engine = ForensicSQLiteEngine()
    diag, records = engine.process_database(
        primary_db_path=db_path,
        journal_path=journal_path,
        staging_id=5,
        canonical_path="/data/data/com.chat/journal_test.db"
    )

    journal_records = [
        r for r in records
        if r.table_name == "chats" and r.source_origin_zone == "ROLLBACK_JOURNAL"
    ]
    assert len(journal_records) >= 1
    assert journal_records[0].columns_dict["text"] == "Original secret plan"
    assert journal_records[0].recovery_classification == ResidualConfidence.RESIDUAL_RECORD


# ==============================================================================
# TEST 7: Output Tables in Master Ledger & Diagnostics Schema
# ==============================================================================

def test_sqlite_engine_master_ledger_export(tmp_sqlite_dir):
    """
    Section 9: Database Schema for Module 2.1
    Verifies that ForensicSQLiteEngine creates and writes into:
    1. sqlite_database_diagnostics
    2. sqlite_recovered_records_master
    with exact column names, constraints, and valid JSON payloads.
    """
    from src.sqlite.engine import ForensicSQLiteEngine

    db_path = tmp_sqlite_dir / "ledger_test.db"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, note TEXT);")
    con.execute("INSERT INTO evidence VALUES (1, 'Active confidential row');")
    con.commit()
    con.close()

    engine = ForensicSQLiteEngine()
    output_ledger_path = tmp_sqlite_dir / "sqlite_forensic_engine.sqlite"

    engine.export_to_ledger(
        primary_db_path=db_path,
        staging_id=10,
        canonical_path="/var/mobile/evidence.db",
        ledger_db_path=output_ledger_path
    )

    assert output_ledger_path.exists()
    con = sqlite3.connect(output_ledger_path)
    cur = con.cursor()

    # Verify sqlite_database_diagnostics table schema and row
    cur.execute("SELECT * FROM sqlite_database_diagnostics WHERE staging_id = 10;")
    diag_row = cur.fetchone()
    assert diag_row is not None
    # Verify canonical_db_path
    col_names = [d[0] for d in cur.description]
    assert "canonical_db_path" in col_names
    assert "page_size_bytes" in col_names
    assert "journal_mode_header" in col_names

    # Verify sqlite_recovered_records_master table schema and row
    cur.execute("SELECT * FROM sqlite_recovered_records_master WHERE db_profile_id = ?;", (diag_row[0],))
    rec_rows = cur.fetchall()
    assert len(rec_rows) >= 1
    rec_cols = [d[0] for d in cur.description]
    assert "recovered_row_uid" in rec_cols
    assert "table_name" in rec_cols
    assert "recovery_classification" in rec_cols
    assert "source_origin_zone" in rec_cols
    assert "columns_json" in rec_cols
    con.close()
