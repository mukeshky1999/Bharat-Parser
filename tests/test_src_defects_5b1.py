"""Phase 5B.1: defects in src/ found in the first review (H-14, H-15, M-08, M-09, M-10, L-01, L-03).

Each test builds the case that failed before and checks the evidence is not changed, invented or mislabelled.
"""
from __future__ import annotations

import bz2
import hashlib
import io
import os
import sqlite3
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from src.sqlite.journal import JOURNAL_MAGIC, RollbackJournalReader, page_checksum


# ----------------------------------------------------------------------------------------------- H-14 journal
def _persist_journal(path: Path, page_size: int, pages: dict, nonce: int, zero_header: bool, good_sums=True):
    header = struct.pack(">8sIIIII", JOURNAL_MAGIC, len(pages), nonce, 2, 512, page_size)
    if zero_header:
        header = b"\x00" * 28  # PERSIST / TRUNCATE: the header is zeroed after commit
    body = header + b"\x00" * (512 - 28)
    for no, data in pages.items():
        assert len(data) == page_size
        ck = page_checksum(nonce, data) if good_sums else 0
        body += struct.pack(">I", no) + data + struct.pack(">I", ck)
    path.write_bytes(body)


def test_journal_uses_database_page_size_when_header_is_zeroed(tmp_path):
    page = bytes([7]) * 1024
    j = tmp_path / "a.db-journal"
    _persist_journal(j, 1024, {2: page, 3: page}, 0x1234, zero_header=True)
    # Without the database's page size the reader assumed 4096 and read nothing sensible (the review's case).
    rd = RollbackJournalReader(j, db_page_size=1024)
    pages = rd.read_all_pages()
    assert [p.page_number for p in pages] == [2, 3]
    assert rd.page_size_source == "DATABASE_HEADER"
    assert all(p.checksum_valid is None for p in pages), "a zeroed header has no nonce, so nothing can be checked"


def test_journal_checksum_is_verified_when_header_is_intact(tmp_path):
    page = bytes(range(256)) * 4
    j = tmp_path / "b.db-journal"
    _persist_journal(j, 1024, {2: page}, 0xABCD, zero_header=False, good_sums=True)
    assert RollbackJournalReader(j).read_all_pages()[0].checksum_valid is True
    _persist_journal(j, 1024, {2: page}, 0xABCD, zero_header=False, good_sums=False)
    rd = RollbackJournalReader(j)
    assert rd.read_all_pages()[0].checksum_valid is False, "a stale or torn record must not look current"
    assert rd.page_size_source == "JOURNAL_HEADER"


def test_journal_without_any_page_size_says_it_assumed(tmp_path):
    page = bytes([1]) * 4096
    j = tmp_path / "c.db-journal"
    _persist_journal(j, 4096, {2: page}, 1, zero_header=True)
    rd = RollbackJournalReader(j)
    rd.read_all_pages()
    assert rd.page_size_source == "ASSUMED_4096"


# ----------------------------------------------------------------------------------------------- H-15 vfs
from src.vfs.indexer import VFSIndexer  # noqa: E402
from src.vfs.reader import (  # noqa: E402
    EncryptedEntry, EntryIntegrityError, UnsupportedCompression, VFSReader,
)


def _catalog(tmp_path, archive: Path, cid=1):
    cat = tmp_path / "cat.sqlite"
    VFSIndexer(cat).index_archive(archive, cid)
    return cat, VFSReader(cat)


def _one(reader, path):
    rows = reader.vfs_query_paths(path)
    assert len(rows) == 1, rows
    return rows[0]


def test_uncompressed_android_backup_returns_the_right_bytes(tmp_path):
    payload = b"HELLO-EVIDENCE-0123456789"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo("apps/x/f.txt")
        ti.size = len(payload)
        tf.addfile(ti, io.BytesIO(payload))
    ab = tmp_path / "b.ab"
    ab.write_bytes(b"ANDROID BACKUP\n1\n0\nnone\n" + buf.getvalue())
    _, rd = _catalog(tmp_path, ab)
    row = _one(rd, "/apps/x/f.txt")
    assert rd.vfs_open_memory_stream(row["file_id"]).read() == payload, "the header offset was missing"


def _zip_with(tmp_path, name, data, method):
    zp = tmp_path / "z.zip"
    with zipfile.ZipFile(zp, "w", compression=method) as zf:
        zf.writestr(name, data)
    return zp


def test_zip_stored_deflate_and_bzip2_are_read_correctly(tmp_path):
    data = b"msg" * 500
    for i, method in enumerate((zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2), start=1):
        sub = tmp_path / f"m{i}"
        sub.mkdir()
        zp = _zip_with(sub, "fs/data/a.bin", data, method)
        _, rd = _catalog(sub, zp)
        row = _one(rd, "/fs/data/a.bin") if rd.vfs_query_paths("/fs/data/a.bin") else rd.vfs_query_paths("/data/a.bin")[0]
        assert rd.vfs_open_memory_stream(row["file_id"]).read() == data


def test_zip_unknown_method_is_refused_not_mislabelled(tmp_path):
    zp = _zip_with(tmp_path, "fs/data/a.bin", b"x" * 100, zipfile.ZIP_STORED)
    raw = bytearray(zp.read_bytes())
    # change the method to 14 (LZMA) in both the local header and the central directory
    for sig, off in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        i = raw.find(sig)
        raw[i + off:i + off + 2] = struct.pack("<H", 14)
    zp.write_bytes(bytes(raw))
    _, rd = _catalog(tmp_path, zp)
    row = rd.vfs_query_paths("%a.bin")[0]
    assert row["compression_method"] == "ZIP_UNSUPPORTED"
    with pytest.raises(UnsupportedCompression):
        rd.vfs_open_memory_stream(row["file_id"])


def test_zip_encrypted_flag_is_not_ignored(tmp_path):
    zp = _zip_with(tmp_path, "fs/data/a.bin", b"secret" * 10, zipfile.ZIP_STORED)
    raw = bytearray(zp.read_bytes())
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = raw.find(sig)
        raw[i + off] |= 0x01
    zp.write_bytes(bytes(raw))
    _, rd = _catalog(tmp_path, zp)
    row = rd.vfs_query_paths("%a.bin")[0]
    assert row["is_encrypted_entry"] == 1
    with pytest.raises(EncryptedEntry):
        rd.vfs_open_memory_stream(row["file_id"])


def test_zip_crc_mismatch_is_reported(tmp_path):
    zp = _zip_with(tmp_path, "fs/data/a.bin", b"A" * 64, zipfile.ZIP_STORED)
    raw = bytearray(zp.read_bytes())
    i = raw.find(b"A" * 64)
    raw[i] = ord("B")  # flip one stored byte; the recorded CRC no longer matches
    zp.write_bytes(bytes(raw))
    _, rd = _catalog(tmp_path, zp)
    row = rd.vfs_query_paths("%a.bin")[0]
    with pytest.raises(EntryIntegrityError):
        rd.vfs_open_memory_stream(row["file_id"])


def test_underscore_in_a_path_is_not_a_wildcard(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in ("d/msg_store.db", "d/msgXstore.db"):
            ti = tarfile.TarInfo(name)
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
    tar = tmp_path / "t.tar"
    tar.write_bytes(buf.getvalue())
    _, rd = _catalog(tmp_path, tar)
    got = [r["filename"] for r in rd.vfs_query_paths("/d/msg_store.db")]
    assert got == ["msg_store.db"]
    got = sorted(r["filename"] for r in rd.vfs_query_paths("/d/msg%"))
    assert got == ["msgXstore.db", "msg_store.db"]
    assert [r["filename"] for r in rd.vfs_query_paths("/d/msg_%")] == ["msg_store.db"]


def _ios_backup(tmp_path):
    bdir = tmp_path / "backup"
    bdir.mkdir()
    (bdir / "Info.plist").write_bytes(b"<plist/>")
    (bdir / "Status.plist").write_bytes(b"<plist/>")
    (bdir / "Manifest.plist").write_bytes(b"<plist/>")
    man = bdir / "Manifest.db"
    c = sqlite3.connect(man)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    c.execute("INSERT INTO Files VALUES ('aabbcc', 'HomeDomain', 'Library/SMS/sms.db', 1, NULL)")
    c.commit()
    # keep the WAL on disk: copy the three files so the test has a Manifest.db with a live WAL beside it
    snap = tmp_path / "snap"
    snap.mkdir()
    for suf in ("", "-wal", "-shm"):
        if (bdir / ("Manifest.db" + suf)).exists():
            (snap / ("Manifest.db" + suf)).write_bytes((bdir / ("Manifest.db" + suf)).read_bytes())
    c.close()
    for suf in ("", "-wal", "-shm"):
        p = bdir / ("Manifest.db" + suf)
        if p.exists():
            p.unlink()
    for suf in ("", "-wal", "-shm"):
        if (snap / ("Manifest.db" + suf)).exists():
            (bdir / ("Manifest.db" + suf)).write_bytes((snap / ("Manifest.db" + suf)).read_bytes())
    (bdir / "aa").mkdir()
    (bdir / "aa" / "aabbcc").write_bytes(b"sms")
    return bdir


def test_ios_manifest_is_not_modified_by_indexing(tmp_path):
    bdir = _ios_backup(tmp_path)
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in bdir.glob("Manifest.db*")}
    assert any(n.endswith("-wal") for n in before), "the test needs a Manifest.db with a WAL"
    VFSIndexer(tmp_path / "cat.sqlite").index_archive(bdir, 1)
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in bdir.glob("Manifest.db*")}
    assert before == after, "the evidence's Manifest.db or its WAL changed"
    rd = VFSReader(tmp_path / "cat.sqlite")
    assert rd.vfs_query_paths("%sms.db"), "rows still in the WAL must be indexed"


def test_wal_companion_comes_from_the_same_container(tmp_path):
    cat = tmp_path / "cat.sqlite"
    ix = VFSIndexer(cat)
    for cid, wal_bytes in ((1, b"WAL-OF-DEVICE-ONE"), (2, b"WAL-OF-DEVICE-TWO")):
        tar = tmp_path / f"c{cid}.tar"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for nm, data in (("d/x.db", b"SQLite format 3\x00" + b"\x00" * 100), ("d/x.db-wal", wal_bytes)):
                ti = tarfile.TarInfo(nm)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        tar.write_bytes(buf.getvalue())
        ix.index_archive(tar, cid)
    rd = VFSReader(cat)
    rows = rd.vfs_query_paths("/d/x.db")
    assert len(rows) == 2
    for r in rows:
        fam = rd.vfs_stage_sqlite_family(r["file_id"], tmp_path / f"stg{r['container_id']}")
        want = b"WAL-OF-DEVICE-ONE" if r["container_id"] == 1 else b"WAL-OF-DEVICE-TWO"
        assert fam.wal_path.read_bytes() == want


# ----------------------------------------------------------------------------------------------- M-08 sqlcipher
def _cipher_fixture(tmp_path):
    from tests.test_phase2_module2_2_crypto import create_synthetic_sqlcipher_v4_db_and_wal
    k_enc, salt = os.urandom(32), os.urandom(16)
    db, wal = tmp_path / "s.sqlite", tmp_path / "s.sqlite-wal"
    create_synthetic_sqlcipher_v4_db_and_wal(db, wal, k_enc, salt)
    return db, wal, k_enc + salt


def test_sqlcipher_clean_input_reports_everything_authenticated(tmp_path):
    from src.crypto.sqlcipher import SQLCipherDecryptor
    db, wal, key = _cipher_fixture(tmp_path)
    d = SQLCipherDecryptor()
    ok, frames = d.decrypt_database_and_wal(db, wal, tmp_path / "o.db", tmp_path / "o.wal", key)
    r = d.last_report
    assert ok and frames == 1
    assert r.mac_checked and r.db_pages == 2 and r.db_pages_failed_mac == []
    assert r.wal_frames_total == 1 and r.wal_frames_rejected == 0


def test_sqlcipher_altered_database_page_is_named(tmp_path):
    from src.crypto.sqlcipher import SQLCipherDecryptor
    db, wal, key = _cipher_fixture(tmp_path)
    raw = bytearray(db.read_bytes())
    raw[4096 + 100] ^= 0xFF  # inside page 2's ciphertext
    db.write_bytes(bytes(raw))
    d = SQLCipherDecryptor()
    ok, _ = d.decrypt_database_and_wal(db, wal, tmp_path / "o.db", tmp_path / "o.wal", key)
    assert ok
    assert d.last_report.db_pages_failed_mac == [2]


def test_sqlcipher_torn_wal_frame_is_rejected_not_re_signed(tmp_path):
    from src.crypto.sqlcipher import SQLCipherDecryptor
    db, wal, key = _cipher_fixture(tmp_path)
    raw = bytearray(wal.read_bytes())
    raw[32 + 24 + 200] ^= 0xFF  # inside the only frame's ciphertext
    wal.write_bytes(bytes(raw))
    d = SQLCipherDecryptor()
    ok, frames = d.decrypt_database_and_wal(db, wal, tmp_path / "o.db", tmp_path / "o.wal", key)
    assert ok and frames == 0, "a frame that fails its HMAC used to be given a fresh valid checksum"
    assert d.last_report.wal_frames_rejected == 1 and "HMAC" in d.last_report.wal_stop_reason


def test_sqlcipher_stale_wal_frame_salts_stop_the_read(tmp_path):
    from src.crypto.sqlcipher import SQLCipherDecryptor
    db, wal, key = _cipher_fixture(tmp_path)
    raw = bytearray(wal.read_bytes())
    raw[32 + 8] ^= 0x01  # frame salt-1 no longer matches the WAL header
    wal.write_bytes(bytes(raw))
    d = SQLCipherDecryptor()
    _, frames = d.decrypt_database_and_wal(db, wal, tmp_path / "o.db", tmp_path / "o.wal", key)
    assert frames == 0 and "salts" in d.last_report.wal_stop_reason


def test_sqlcipher_forced_profile_with_wrong_key_fails(tmp_path):
    from src.crypto.sqlcipher import SQLCipherDecryptor, STANDARD_PROFILES
    db, wal, key = _cipher_fixture(tmp_path)
    d = SQLCipherDecryptor()
    ok, _ = d.decrypt_database_and_wal(db, wal, tmp_path / "o.db", tmp_path / "o.wal", os.urandom(48),
                                       forced_profile=STANDARD_PROFILES[0])
    assert ok is False, "a forced profile must still authenticate page 1"
    assert "page 1" in d.last_report.failure


# ----------------------------------------------------------------------------------------------- M-09 record
def test_truncated_record_columns_are_unknown_not_zero():
    from src.sqlite.record import decode_record
    # header: size 3, types 4 (4-byte int) and 13+2*6=25 (text of 6 bytes); body cut after 2 bytes of the integer
    payload = bytes([3, 4, 25]) + b"\x00\x01"
    vals = decode_record(payload)
    assert list(vals) == [None, None]
    assert vals.truncated == [0, 1]
    full = bytes([3, 4, 25]) + struct.pack(">i", 42) + b"abcdef"
    ok = decode_record(full)
    assert list(ok) == [42, "abcdef"] and ok.truncated == []


def test_text_cut_short_is_not_shown_as_a_shorter_message():
    from src.sqlite.record import decode_record
    payload = bytes([2, 13 + 2 * 10]) + b"hello"  # claims 10 bytes, only 5 present
    vals = decode_record(payload)
    assert list(vals) == [None] and vals.truncated == [0]


def test_corroboration_rank_depends_on_where_the_record_came_from(tmp_path):
    from src.sqlite.engine import ForensicSQLiteEngine
    p = tmp_path / "t.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE m (id INTEGER PRIMARY KEY, body TEXT)")
    for i in range(1, 6):
        c.execute("INSERT INTO m VALUES (?, ?)", (i, f"message number {i}"))
    c.commit()
    c.execute("DELETE FROM m WHERE id = 3")
    c.commit()
    c.close()
    _, recs = ForensicSQLiteEngine().process_database(primary_db_path=p, wal_path=None, staging_id=1, canonical_path="/t.db")
    scores = {r.recovery_classification.value: r.evidentiary_state.corroboration_score for r in recs}
    assert scores["ORIGINAL_RECORD"] == 1.0
    others = [v for k, v in scores.items() if k != "ORIGINAL_RECORD"]
    assert all(v < 1.0 for v in others), scores


# ----------------------------------------------------------------------------------------------- M-10 sms
@pytest.mark.parametrize("body,category", [
    ("Rs.500 debited from A/c XX1234. If not you, call 1930 to report cyber fraud. Ref 123456789012", "TX_DEBIT_OUTFLOW"),
    ("Dear Account holder, your statement for Rs.1,200.00 is ready", "UNCLASSIFIED"),
    ("Rs.800 credited to A/c XX1234 as per your consent. Ref 998877665544", "TX_CREDIT_INFLOW"),
    ("Your electricity bill of Rs.1,450.00 is due on 20 Jan", "UNCLASSIFIED"),
    ("Hold of INR 45,000.00 marked on A/c XX4821 for Cyber Crime Ack No 33111260048291", "LIEN_HOLD_OR_FREEZE_ALERT"),
    ("Your A/c XX1234 has been frozen as per order", "LIEN_HOLD_OR_FREEZE_ALERT"),
    ("Rs.300 debited from A/c XX1234 and credited to beneficiary", "TX_DEBIT_OUTFLOW"),
])
def test_sms_categories_do_not_use_substrings(body, category):
    from src.dlt.sms_grammar import FinancialSMSGrammarParser
    assert FinancialSMSGrammarParser().parse_sms(body).sms_event_category == category


def test_mobile_number_with_country_code_is_not_a_utr():
    from src.dlt.sms_grammar import FinancialSMSGrammarParser
    res = FinancialSMSGrammarParser().parse_sms("Rs.500 debited from A/c XX1234. For queries call 919223008333")
    assert res.utr_or_rrn_reference is None
    res2 = FinancialSMSGrammarParser().parse_sms("Rs.500 debited from A/c XX1234 UTR 630914829104")
    assert res2.utr_or_rrn_reference == "630914829104"


# ----------------------------------------------------------------------------------------------- L-01 timestamps
def test_unix_nanoseconds_are_not_read_as_filetime():
    from src.core.timestamps import format_timestamp_triplet as f
    raw, utc, _ = f(1700000000000000000)
    assert utc.startswith("2023-11-14 22:13:20")
    assert f(133500000000000000)[1].startswith("2024-01-17")  # FILETIME still works
    assert f(13350000000000000)[1].startswith("2024-01-17")   # WebKit microseconds still works


def test_ambiguous_seconds_are_left_unknown_in_auto_mode():
    from src.core.timestamps import format_timestamp_triplet as f
    raw, utc, ist = f(730000000)
    assert (raw, utc, ist) == (730000000, "", "")
    assert f(730000000, "cocoa")[1].startswith("2024-02-19")  # when the caller knows the epoch, it is converted
    assert f(1700000000)[1].startswith("2023-11-14")           # a plain modern Unix value is unaffected


def test_unconvertible_value_gives_no_time_instead_of_the_raw_number():
    from src.core.timestamps import format_timestamp_triplet as f
    assert f("not a time") == ("not a time", "", "")


# ----------------------------------------------------------------------------------------------- L-03 ledger
def _ledger(tmp_path):
    from src.provenance.ledger import ProvenanceLedger
    lg = ProvenanceLedger(tmp_path / "l.sqlite")
    for i in range(3):
        lg.record_chain_of_custody_event(f"2026-01-0{i + 1}T00:00:00Z", "1.0", "WS1", "HASH", f"item {i}", "aa", "bb")
    return lg


def test_custody_chain_verifies_and_head_changes_with_each_event(tmp_path):
    lg = _ledger(tmp_path)
    v = lg.verify_custody_chain()
    assert v["ok"] and v["events"] == 3 and v["unchained"] == 0
    h = lg.custody_head_hash()
    lg.record_chain_of_custody_event("2026-01-09T00:00:00Z", "1.0", "WS1", "HASH", "item 9")
    assert lg.custody_head_hash() != h


def test_custody_log_refuses_update_and_delete(tmp_path):
    lg = _ledger(tmp_path)
    c = sqlite3.connect(lg.db_path)
    with pytest.raises(sqlite3.DatabaseError):
        c.execute("UPDATE chain_of_custody_audit_log SET target_description='x'")
    with pytest.raises(sqlite3.DatabaseError):
        c.execute("DELETE FROM chain_of_custody_audit_log")
    c.close()


def test_custody_chain_detects_an_edited_row(tmp_path):
    lg = _ledger(tmp_path)
    c = sqlite3.connect(lg.db_path)
    c.execute("DROP TRIGGER custody_no_update")  # an attacker with file access
    c.execute("UPDATE chain_of_custody_audit_log SET target_description='changed' WHERE event_id=2")
    c.commit()
    c.close()
    v = lg.verify_custody_chain()
    assert v["ok"] is False and v["first_bad_event_id"] == 2


def test_old_ledger_rows_are_reported_as_unchained(tmp_path):
    from src.provenance.ledger import ProvenanceLedger
    p = tmp_path / "old.sqlite"
    c = sqlite3.connect(p)
    c.execute("""CREATE TABLE chain_of_custody_audit_log (event_id INTEGER PRIMARY KEY AUTOINCREMENT, event_utc_iso TEXT NOT NULL,
        software_version TEXT NOT NULL, workstation_hostname TEXT NOT NULL, action_type TEXT NOT NULL,
        target_description TEXT NOT NULL, input_sha256 TEXT, output_sha256 TEXT)""")
    c.execute("INSERT INTO chain_of_custody_audit_log VALUES (1,'2025-01-01','1','H','A','old',NULL,NULL)")
    c.commit()
    c.close()
    lg = ProvenanceLedger(p)
    lg.record_chain_of_custody_event("2026-01-01", "1", "H", "A", "new")
    v = lg.verify_custody_chain()
    assert v["ok"] and v["unchained"] == 1 and v["events"] == 2
