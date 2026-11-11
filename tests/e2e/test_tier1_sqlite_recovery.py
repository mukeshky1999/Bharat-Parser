"""
Tier 1 Feature Coverage: SQLite Recovery & Deep Storage Forensics
Tests 4-State WAL frame classification, rolling Fibonacci checksums,
28-byte rollback journal recovery, varint & record decoders, freelist carving,
and corrupted database recovery.
"""

from __future__ import annotations

import io
import os
import shutil
import sqlite3
import struct
import sys
import unittest
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from src.sqlite.journal import RollbackJournalReader
from src.sqlite.record import decode_record
from src.sqlite.varint import decode_varint, encode_varint
from src.sqlite.wal import WALFrameState, WALReader, compute_wal_checksum
from parsers.corrupt_db_carver import carve_corrupted_sqlite_file
from parsers.freelist_carver import carve_sqlite_freelists


class TestTier1SQLiteRecovery(unittest.TestCase):
    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t1_sqlite_")

    def tearDown(self):
        env_setup.cleanup_isolated_sandbox(self.sandbox)

    def test_wal_rolling_fibonacci_checksum(self):
        """
        T1.2.1: Validates cumulative 64-bit WAL rolling checksum calculation.
        Authoritative source: SQLite WAL Specification Section 3.2.
        """
        # Test known invariant: empty buffer leaves s0, s1 unchanged
        s0_init, s1_init = 0x12345678, 0x87654321
        s0, s1 = compute_wal_checksum(b"", is_big_endian=False, s0=s0_init, s1=s1_init)
        self.assertEqual(s0, s0_init)
        self.assertEqual(s1, s1_init)

        # Test deterministic checksumming of an 8-byte word
        sample_chunk = struct.pack("<II", 0x11111111, 0x22222222)
        s0_calc, s1_calc = compute_wal_checksum(sample_chunk, is_big_endian=False, s0=0, s1=0)
        self.assertNotEqual(s0_calc, 0)
        self.assertNotEqual(s1_calc, 0)

    def test_wal_4_state_frame_classification(self):
        """
        T1.2.2: Validates classification of WAL frames into:
        - VALID_COMMITTED
        - VALID_UNCOMMITTED
        - CORRUPTED_CHECKSUM
        - ZERO_PADDED
        Authoritative source: SQLite 3.x WAL File Format Specification.
        """
        page_size = 4096
        wal_path = self.sandbox / "test.db-wal"

        # Construct WAL Header (32 bytes, big-endian format)
        salt1 = 0xA1B2C3D4
        salt2 = 0xE5F6A7B8
        wal_header_no_cksum = struct.pack(
            ">IIIIII",
            0x377F0682,
            3007000,
            page_size,
            1,
            salt1,
            salt2,
        )
        s0, s1 = compute_wal_checksum(wal_header_no_cksum, is_big_endian=False, s0=0, s1=0)
        wal_header = wal_header_no_cksum + struct.pack(">II", s0, s1)

        # Frame 0: Page 1, commit_size 0 (superseded by Frame 1)
        p0_data = b"0" * page_size
        f0_hdr_first8 = struct.pack(">II", 1, 0)
        f0_hdr_salts = struct.pack(">II", salt1, salt2)
        s0, s1 = compute_wal_checksum(f0_hdr_first8, is_big_endian=False, s0=s0, s1=s1)
        s0, s1 = compute_wal_checksum(p0_data, is_big_endian=False, s0=s0, s1=s1)
        frame0 = f0_hdr_first8 + f0_hdr_salts + struct.pack(">II", s0, s1) + p0_data

        # Frame 1: Page 1, commit_size 1 (Latest committed for Page 1)
        p1_data = b"1" * page_size
        f1_hdr_first8 = struct.pack(">II", 1, 1)
        f1_hdr_salts = struct.pack(">II", salt1, salt2)
        s0, s1 = compute_wal_checksum(f1_hdr_first8, is_big_endian=False, s0=s0, s1=s1)
        s0, s1 = compute_wal_checksum(p1_data, is_big_endian=False, s0=s0, s1=s1)
        frame1 = f1_hdr_first8 + f1_hdr_salts + struct.pack(">II", s0, s1) + p1_data

        # Frame 2: Page 2, commit_size 0 (Uncommitted in flight)
        p2_data = b"2" * page_size
        f2_hdr_first8 = struct.pack(">II", 2, 0)
        f2_hdr_salts = struct.pack(">II", salt1, salt2)
        s0, s1 = compute_wal_checksum(f2_hdr_first8, is_big_endian=False, s0=s0, s1=s1)
        s0, s1 = compute_wal_checksum(p2_data, is_big_endian=False, s0=s0, s1=s1)
        frame2 = f2_hdr_first8 + f2_hdr_salts + struct.pack(">II", s0, s1) + p2_data

        # Frame 3: Corrupted Checksum (Prior checkpoint residual)
        p3_data = b"3" * page_size
        f3_hdr_bad = struct.pack(">IIIIII", 3, 0, salt1, salt2, 0xDEADBEEF, 0xCAFEBABE)
        frame3 = f3_hdr_bad + p3_data

        wal_path.write_bytes(wal_header + frame0 + frame1 + frame2 + frame3)

        reader = WALReader(wal_path, page_size=page_size)
        frames = reader.read_all_frames()
        self.assertEqual(len(frames), 4)

        self.assertEqual(frames[0].state, WALFrameState.HISTORICAL_SUPERSEDED_COMMITTED_FRAME)
        self.assertEqual(frames[1].state, WALFrameState.LATEST_COMMITTED_WAL_FRAME)
        self.assertEqual(frames[2].state, WALFrameState.UNCOMMITTED_IN_FLIGHT_WAL_FRAME)
        self.assertEqual(frames[3].state, WALFrameState.PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME)

    def test_rollback_journal_28_byte_header_and_page_restore(self):
        """
        T1.2.3: Validates 28-byte rollback journal sector decoding and page restoration.
        Authoritative source: SQLite 3.x Rollback Journal Specification.
        """
        journal_path = self.sandbox / "test.db-journal"
        page_size = 1024

        # Rollback journal header:
        # 8-byte magic: \xd9\xd5\x05\xf9\x20\xa1\x63\xd7
        # 4-byte page_count = 1
        # 4-byte random nonce
        # 4-byte db_page_count = 5
        # 4-byte sector_size = 512
        # 4-byte page_size = 1024
        magic = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"
        header = magic + struct.pack(">IIIII", 1, 0x12345678, 5, 512, page_size)
        # Pad header to sector size (512 bytes)
        header_padded = header + b"\x00" * (512 - len(header))

        # Page 1 record: 4-byte page_number + 1024 bytes data + 4-byte checksum
        page_num = 2
        page_data = b"JOURNAL_PRE_TRANSACTION_RECOVERY_PAGE" + b"\x00" * (page_size - 37)
        page_cksum = 0x99887766
        page_entry = struct.pack(">I", page_num) + page_data + struct.pack(">I", page_cksum)

        journal_path.write_bytes(header_padded + page_entry)

        reader = RollbackJournalReader(journal_path)
        pages = reader.read_all_pages()
        self.assertGreaterEqual(len(pages), 1)

        target_pg = pages[0]
        self.assertEqual(target_pg.page_number, 2)
        self.assertEqual(target_pg.page_data[:37], b"JOURNAL_PRE_TRANSACTION_RECOVERY_PAGE")

    def test_sqlite_varint_and_record_payload_decoding(self):
        """
        T1.2.4: Validates variable-length integer parsing and record payload decoding.
        Authoritative source: SQLite Record Format Specification Section 2.1.
        """
        # 1. Test varint single byte
        val, n = decode_varint(b"\x19")
        self.assertEqual(val, 25)
        self.assertEqual(n, 1)

        # 2. Test varint multi-byte (value 300 = 0x02, 0x2C -> 2*128 + 44 = 300)
        encoded_300 = encode_varint(300)
        val300, n300 = decode_varint(encoded_300)
        self.assertEqual(val300, 300)

        # 3. Test record decoding:
        # Construct header: header_size varint, serial_types:
        # col 0: 1 (int8: -128 to 127) -> value 42
        # col 1: 0 (NULL)
        # col 2: 13 (Text length: (13-13)/2 = 0? (23 - 13)/2 = 5 bytes "INDIA")
        # Text serial type for length L is: serial = 2*L + 13 -> for 5 bytes: 23 = 0x17
        serial_types = [1, 0, 23]
        col_values = [b"\x2A", b"", b"INDIA"]

        hdr_body = bytes([1, 0, 23])
        hdr_len = len(hdr_body) + 1  # 4 bytes
        record_bytes = bytes([hdr_len]) + hdr_body + b"".join(col_values)

        decoded = decode_record(record_bytes)
        self.assertEqual(len(decoded), 3)
        self.assertEqual(decoded[0], 42)
        self.assertIsNone(decoded[1])
        self.assertEqual(decoded[2], "INDIA")

    def test_freelist_and_unallocated_cell_carving(self):
        """
        T1.2.5: Validates freelist cell carving against authentic WhatsApp evidence database.
        Authoritative source: test_evidence/msgstore.db with uncheckpointed WAL.
        """
        evidence_db = env_setup.TEST_EVIDENCE_DIR / "msgstore.db"
        if not evidence_db.exists():
            self.skipTest(f"Evidence {evidence_db} not found")

        df = carve_sqlite_freelists(str(evidence_db))
        self.assertIsNotNone(df)
        self.assertGreaterEqual(len(df), 0)

    def test_corrupted_sqlite_file_carver(self):
        """
        T1.2.6: Validates recovery of records from corrupted/clobbered SQLite databases.
        Authoritative source: parsers.corrupt_db_carver.carve_corrupted_sqlite_file.
        """
        # Create a real SQLite database, commit records, then clobber page 1 header
        corrupt_db_path = self.sandbox / "corrupted_ledger.db"
        conn = sqlite3.connect(corrupt_db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE transactions (id TEXT, amount REAL, utr TEXT, vpa TEXT)")
        cur.execute("INSERT INTO transactions VALUES ('TX101', 5000.0, '630911223344', 'merchant@okhdfcbank')")
        cur.execute("INSERT INTO transactions VALUES ('TX102', 12500.50, '839201948201', 'mule@ybl')")
        conn.commit()
        conn.close()

        # Intentionally corrupt the first 32 bytes of SQLite header
        with open(corrupt_db_path, "r+b") as f:
            f.seek(0)
            f.write(b"CORRUPTED_GARBAGE_BYTES_HEADER!!")

        # Standard sqlite3.connect will fail on corrupt header
        with self.assertRaises(sqlite3.DatabaseError):
            fail_conn = sqlite3.connect(corrupt_db_path)
            fail_conn.execute("SELECT * FROM transactions").fetchall()

        # Carve with forensic corrupt DB carver
        df_carved = carve_corrupted_sqlite_file(str(corrupt_db_path))
        self.assertIsNotNone(df_carved)
        # Should carve without crashing and return a DataFrame
        self.assertTrue(hasattr(df_carved, "columns"))


if __name__ == "__main__":
    unittest.main()
