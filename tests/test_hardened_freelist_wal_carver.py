"""
Hostile QA Automation Test Suite: SQLite Freelist Carver & WAL Recovery Engine
Validates:
1. Two's complement sign inversion fix when encountering corrupted 9-byte varints.
2. WAL frame multi-revision rollback extraction from mock .db-wal files.
"""

import os
import shutil
import sqlite3
import struct
import tempfile
import unittest
import pandas as pd

from parsers.freelist_carver import (
    read_varint,
    decode_record_payload,
    parse_page_unallocated_cells,
    carve_sqlite_freelists,
    STANDARD_TX_COLUMNS,
)
from parsers.wal_rollback_analyzer import (
    parse_wal_file,
    analyze_wal_revisions,
)


class TestHardenedFreelistWalCarver(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="hostile_qa_freelist_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. CORRUPTED 9-BYTE VARINT & TWO'S COMPLEMENT SIGN INVERSION FIX
    # --------------------------------------------------------------------------
    def test_corrupted_nine_byte_varint_two_complement_sign_handling(self):
        """
        Injects corrupted 9-byte varints with the 64th bit (MSB) set.
        Under flawed two's complement handling, 0xFFFFFFFFFFFFFFFF or 0x8000000000000000
        inverts to a negative value (-1), which would bypass unsigned bounds checks
        (e.g., p_size <= 2048) and cause buffer bounds underflow or crash.
        Asserts that:
        - read_varint accurately decodes the 9-byte sequence without bounds violation.
        - decode_record_payload safely rejects corrupted header length without underflow.
        - parse_page_unallocated_cells does not crash or underflow when slack contains 9-byte varints.
        """
        # Test Case A: 9 bytes with all bits set (0xFF * 9 -> 64-bit unsigned 0xFFFFFFFFFFFFFFFF)
        varint_all_ff = b"\xff" * 9
        val_ff, off_ff = read_varint(varint_all_ff, 0)
        self.assertEqual(off_ff, 9, "9-byte varint must consume exactly 9 bytes")
        self.assertEqual(
            val_ff,
            0xFFFFFFFFFFFFFFFF,
            "Decoded varint must match unsigned 64-bit 0xFFFFFFFFFFFFFFFF",
        )
        # Verify it is positive in Python (arbitrary precision) and not converted to -1
        self.assertGreater(val_ff, 0, "Varint must not undergo negative sign inversion")

        # Test Case B: 9 bytes with 8 continuation bytes and 0x01 in final byte
        varint_high_bit = b"\x80" * 8 + b"\x01"
        val_high, off_high = read_varint(varint_high_bit, 0)
        self.assertEqual(off_high, 9)
        self.assertEqual(val_high, 1)

        # Test Case C: Decode record payload starting with corrupted 9-byte varint header length
        corrupt_payload = varint_all_ff + b"random_corrupted_payload_data_here"
        decoded_records = decode_record_payload(corrupt_payload)
        self.assertEqual(
            decoded_records,
            [],
            "decode_record_payload must gracefully return empty list for corrupted varint header",
        )

        # Test Case D: Inject corrupted 9-byte varint into B-Tree leaf page slack area
        page_bytes = bytearray(4096)
        page_bytes[0] = 0x0D  # SQLite Leaf Table B-Tree page marker
        # Put 9-byte varint in slack offset 20
        page_bytes[20:29] = varint_all_ff
        # Followed by a VPA string to ensure scanner inspects this page
        page_bytes[30:50] = b"target@oksbi 9999.00"
        
        # parse_page_unallocated_cells must not throw IndexError or MemoryError
        carved_cells = parse_page_unallocated_cells(bytes(page_bytes), page_num=1)
        self.assertIsInstance(carved_cells, list)

    def test_freelist_database_with_corrupted_varints(self):
        """
        Creates an SQLite database whose freelist trunk and unallocated slack
        contain hostile 9-byte varints, ensuring carve_sqlite_freelists finishes cleanly.
        """
        db_path = os.path.join(self.test_dir, "corrupt_varint_freelist.db")
        db_bytes = bytearray(4096 * 2)

        # Header: 100 bytes minimum
        db_bytes[:16] = b"SQLite format 3\x00"
        struct.pack_into(">H", db_bytes, 16, 4096)  # page size = 4096
        # Freelist trunk on page 2
        struct.pack_into(">I", db_bytes, 32, 2)  # first freelist trunk page
        struct.pack_into(">I", db_bytes, 36, 1)  # total freelist pages

        # Page 2: Freelist trunk page pointing to 0 next trunks, 0 leaves
        p2_off = 4096
        struct.pack_into(">I", db_bytes, p2_off, 0)      # next trunk page = 0
        struct.pack_into(">I", db_bytes, p2_off + 4, 0)  # leaf count = 0
        # Inject corrupted 9-byte varint in page 2 body
        db_bytes[p2_off + 10 : p2_off + 19] = b"\xff" * 9

        with open(db_path, "wb") as f:
            f.write(db_bytes)

        df = carve_sqlite_freelists(db_path)
        self.assertIsInstance(df, pd.DataFrame)
        for col in STANDARD_TX_COLUMNS:
            self.assertIn(col, df.columns)

    # --------------------------------------------------------------------------
    # 2. MOCK .db-wal FILE & WAL FRAME EXTRACTION TEST
    # --------------------------------------------------------------------------
    def test_mock_wal_file_frame_extraction(self):
        """
        Creates a mock .db file and a paired .db-wal file containing multiple revisions
        of a B-Tree page (recovering an overwritten transaction).
        Asserts that carve_sqlite_freelists parses the WAL frames and extracts the transaction.
        """
        db_path = os.path.join(self.test_dir, "evidence_vault.db")
        wal_path = f"{db_path}-wal"

        # 1. Construct valid base SQLite database (page 1)
        base_db = bytearray(4096)
        base_db[:16] = b"SQLite format 3\x00"
        struct.pack_into(">H", base_db, 16, 4096)  # page size = 4096
        with open(db_path, "wb") as f:
            f.write(base_db)

        # 2. Construct transaction record payload
        # Transaction ID: "987654321098" (12 digits, valid Indian UPI TxID format)
        # Counterparty: "merchant@okhdfcbank" (valid VPA)
        # Amount: 4500.0 (valid float)
        txid_bytes = b"987654321098"
        vpa_bytes = b"merchant@okhdfcbank"
        amount_val = 4500.0

        st_txid = len(txid_bytes) * 2 + 13
        st_vpa = len(vpa_bytes) * 2 + 13
        st_amt = 7  # 8-byte float

        hdr_body = bytes([st_txid, st_vpa, st_amt])
        hdr_len = len(hdr_body) + 1
        record_payload = bytes([hdr_len]) + hdr_body + txid_bytes + vpa_bytes + struct.pack(">d", amount_val)

        # SQLite Leaf Table B-Tree cell: varint payload_size, varint rowid, payload
        cell_bytes = bytes([len(record_payload), 1]) + record_payload

        # 3. Construct Page 2 with this active cell
        pg2_rev1 = bytearray(4096)
        pg2_rev1[0] = 0x0D  # Leaf Table B-Tree page
        cell_start = 4096 - len(cell_bytes)
        struct.pack_into(">H", pg2_rev1, 3, 1)           # num_cells = 1
        struct.pack_into(">H", pg2_rev1, 5, cell_start)  # cell content offset
        struct.pack_into(">H", pg2_rev1, 8, cell_start)  # cell pointer 0
        pg2_rev1[cell_start : cell_start + len(cell_bytes)] = cell_bytes

        # 4. Construct Page 2 Revision 2: an empty page (simulating overwrite/deletion in subsequent commit)
        pg2_rev2 = bytearray(4096)
        pg2_rev2[0] = 0x0D
        struct.pack_into(">H", pg2_rev2, 3, 0)
        struct.pack_into(">H", pg2_rev2, 5, 4096)

        # 5. Assemble .db-wal file
        # 32-byte WAL Header: Magic (0x377F0682), File Format (3007000), Page Size (4096), Seq (1)
        wal_header = struct.pack(">IIIIIIII", 0x377F0682, 3007000, 4096, 1, 0x1234, 0x5678, 0, 0)

        # 24-byte Frame 1 Header: pgno=2, commit_count=0 (uncommitted/historical frame)
        f1_header = struct.pack(">IIIIII", 2, 0, 0x1234, 0x5678, 0, 0)

        # 24-byte Frame 2 Header: pgno=2, commit_count=1 (committed newer revision where tx is wiped)
        f2_header = struct.pack(">IIIIII", 2, 1, 0x1234, 0x5678, 0, 0)

        with open(wal_path, "wb") as f:
            f.write(wal_header)
            f.write(f1_header + pg2_rev1)
            f.write(f2_header + pg2_rev2)

        # 6. Carve freelists and WAL
        carved_df = carve_sqlite_freelists(db_path)

        # Assertions
        self.assertFalse(carved_df.empty, "carve_sqlite_freelists must extract records from .db-wal")
        
        matches = carved_df[
            (carved_df["Counterparty"] == "merchant@okhdfcbank") &
            (carved_df["Amount"] == 4500.0)
        ]
        self.assertEqual(len(matches), 1, "Expected exactly 1 extracted historical WAL transaction")
        
        extracted_row = matches.iloc[0]
        self.assertEqual(extracted_row["Transaction_ID"], "WAL_REV_P2_F1")
        # This hand-built WAL has all-zero checksums, so it is not a valid log (REVIEW M-01): the
        # frame is still recovered but labelled residual, never as a committed pre-commit version.
        self.assertIn("RESIDUAL WAL FRAME #1", extracted_row["Status"])
        self.assertIn("checksum", extracted_row["Status"])
        self.assertEqual(extracted_row["Type"], "TRANSFER")

    # --------------------------------------------------------------------------
    # 3. REAL SQLITE DATABASE WITH DELETED ROWS IN WAL MODE (EVIDENCE GENERATION PARITY)
    # --------------------------------------------------------------------------
    def test_real_sqlite_wal_deleted_rows_recovery(self):
        """
        Creates a genuine SQLite database in Write-Ahead Log (WAL) mode using sqlite3.
        Inserts active and secret rows, then executes a DELETE query to push rows
        into the WAL uncheckpointed historical frames/slack.
        Verifies:
        - 32-byte WAL header and 24-byte frame headers adhere to SQLite specifications
          (4096-byte page size, big-endian salts, and cumulative rolling checksums).
        - analyze_wal_revisions and carve_sqlite_freelists recover all deleted rows
          without crashing or silently swallowing exceptions.
        """
        db_path = os.path.join(self.test_dir, "real_whatsapp_evidence.db")
        wal_path = f"{db_path}-wal"
        shm_path = f"{db_path}-shm"

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA wal_autocheckpoint=0;")
        cur.execute("""
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_remote_jid TEXT,
                key_from_me INTEGER,
                data TEXT,
                timestamp INTEGER,
                status INTEGER
            )
        """)

        # 1. Insert 25 active messages
        for i in range(25):
            cur.execute(
                "INSERT INTO message (key_remote_jid, key_from_me, data, timestamp, status) VALUES (?, ?, ?, ?, ?)",
                (f"+919876543{i:03d}", 1, f"Active message {i} normal conversation", 1700000000000 + i * 1000, 1),
            )
        conn.commit()

        # 2. Insert 10 secret messages with distinct VPAs to be deleted
        deleted_vpas = [f"secret_target_{i}@okhdfcbank" for i in range(10)]
        for i, vpa in enumerate(deleted_vpas):
            cur.execute(
                "INSERT INTO message (key_remote_jid, key_from_me, data, timestamp, status) VALUES (?, ?, ?, ?, ?)",
                (f"+919876543{i:03d}", 1, f"SECRET DELETED MSG {i} - Transfer to {vpa} Amount: Rs. 5000", 1700000000000 + i * 1000, 1),
            )
        conn.commit()

        # 3. Delete the secret messages (moves them into historical WAL frames / freelists)
        cur.execute("DELETE FROM message WHERE data LIKE 'SECRET DELETED MSG%'")
        conn.commit()

        # 4. Preserve live WAL & SHM files before closing connection
        wal_bak = f"{wal_path}.bak"
        shm_bak = f"{shm_path}.bak"
        if os.path.exists(wal_path):
            shutil.copyfile(wal_path, wal_bak)
        if os.path.exists(shm_path):
            shutil.copyfile(shm_path, shm_bak)

        conn.close()

        if os.path.exists(wal_bak):
            shutil.move(wal_bak, wal_path)
        if os.path.exists(shm_bak):
            shutil.move(shm_bak, shm_path)

        self.assertTrue(os.path.exists(wal_path), "Real SQLite WAL file must exist on disk")
        self.assertGreater(os.path.getsize(wal_path), 32, "WAL file must contain frames")

        # 5. Audit parse_wal_file on real SQLite WAL binary
        revisions, detected_pg_size = parse_wal_file(wal_path)
        self.assertEqual(detected_pg_size, 4096, "SQLite default page size must be 4096")
        self.assertGreater(len(revisions), 0, "WAL frames must be parsed into revisions")

        for pgno, frames in revisions.items():
            for f in frames:
                self.assertEqual(len(f.data), 4096, "Frame data length must match page size 4096")
                self.assertTrue(f.is_valid_salt, "Frame salt must match WAL header salt")
                self.assertTrue(f.is_valid_checksum, "Frame rolling checksum must be valid")

        # 6. Carve via carve_sqlite_freelists and verify recovery
        carved_df = carve_sqlite_freelists(db_path)
        self.assertFalse(carved_df.empty, "carve_sqlite_freelists must recover deleted rows from real WAL")

        recovered_vpas = set(carved_df["Counterparty"].dropna())
        for vpa in deleted_vpas:
            self.assertIn(vpa, recovered_vpas, f"Deleted VPA {vpa} must be recovered from real WAL")

        # Check status and amounts
        matched_rows = carved_df[carved_df["Counterparty"].isin(deleted_vpas)]
        # Every deleted VPA is recovered. A record may legitimately be found in more than one place
        # (WAL frame and the database file's unallocated gap); those are reported as separate sources.
        self.assertEqual(set(matched_rows["Counterparty"]), set(deleted_vpas), "Must recover all 10 distinct deleted rows")
        self.assertGreaterEqual(len(matched_rows), 10)
        for _, row in matched_rows.iterrows():
            self.assertTrue(
                "OLDER VERSION OF PAGE" in str(row["Status"]) or "DELETED" in str(row["Status"]),
                f"Unexpected status: {row['Status']}",
            )
            self.assertEqual(row["Amount"], 5000.0)


if __name__ == "__main__":
    unittest.main()
