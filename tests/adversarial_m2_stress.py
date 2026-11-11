"""
Adversarial Stress Test Suite for Milestone 2: Core Forensic Ingestion & Storage Recovery Engine.
Conducted independently by Challenger 1.
"""

from __future__ import annotations

import io
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from src.core.enums import CompressionMethod, ContainerType, ResidualConfidence
from src.vfs.indexer import AbHeaderInfo, AbUnpacker, VFSIndexer, VFSIndexEntry
from src.vfs.reader import VFSReader
from src.sqlite.wal import WALFrameState, WALReader, compute_wal_checksum, parse_wal_header
from src.sqlite.journal import RollbackJournalReader, JournalSectorHeader, JOURNAL_MAGIC
from src.sqlite.carver import ResidualCarver, is_valid_upi_vpa, is_valid_utr, extract_indian_currency_amount
from src.sqlite.models import ColumnSchema, TableSchema
from src.sqlite.overflow import reassemble_overflow_chain, MAX_SAFE_OVERFLOW_PAYLOAD
from src.nonsqlite.snappy import snappy_decompress
from src.nonsqlite.leveldb import LevelDBDecoder, infer_leveldb_value_type, LEVELDB_MAGIC

import importlib.util
# Load vpa_harvester into sys.modules to satisfy freelist_carver runtime dependency
_vh_path = _root / "bharat-pa-forensics" / "parsers" / "vpa_harvester.py"
if _vh_path.exists():
    _vh_spec = importlib.util.spec_from_file_location("parsers.vpa_harvester", str(_vh_path))
    _vh_mod = importlib.util.module_from_spec(_vh_spec)
    _vh_spec.loader.exec_module(_vh_mod)
    sys.modules["parsers.vpa_harvester"] = _vh_mod

_fl_spec = importlib.util.spec_from_file_location("freelist_carver", str(_root / "parsers" / "freelist_carver.py"))
_fl_mod = importlib.util.module_from_spec(_fl_spec)
_fl_spec.loader.exec_module(_fl_mod)
sys.modules["parsers.freelist_carver"] = _fl_mod
_record_to_transaction = _fl_mod._record_to_transaction


class TestAdversarialArchiveStress(unittest.TestCase):
    """Stress tests for ZIP64, PAX headers, and Android Backup offset decoding."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="adv_archive_"))
        self.vfs_db = self.tmp_dir / "test_vfs.db"
        self.indexer = VFSIndexer(self.vfs_db)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_zip64_large_offsets_and_sizes(self):
        """Verify ZIP64 extra field 0x0001 parsing with 64-bit offsets and sizes."""
        zip_path = self.tmp_dir / "large_zip64.zip"

        fname = b"huge_forensic_image.dd"
        local_hdr = (
            b"PK\x03\x04"
            + struct.pack("<HHHHHIIIHH", 45, 0, 0, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, len(fname), 0)
            + fname
        )

        comp_size_64 = 0x100000000  # 4GB
        uncomp_size_64 = 0x200000000  # 8GB
        local_off_64 = 0x0

        # Extra field 0x0001
        extra_field_zip64 = (
            struct.pack("<HH", 0x0001, 24)
            + struct.pack("<QQQ", uncomp_size_64, comp_size_64, local_off_64)
        )

        cd_entry = (
            b"PK\x01\x02"
            + struct.pack(
                "<HHHHHHIIIHHHHHII",
                45, 45, 0, 0, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF,
                len(fname), len(extra_field_zip64), 0, 0, 0, 0, 0xFFFFFFFF
            )
            + fname
            + extra_field_zip64
        )

        cd_start_offset = len(local_hdr)
        cd_size = len(cd_entry)

        zip64_eocd_record = (
            b"PK\x06\x06"
            + struct.pack("<QHHIIQQQQ", 44, 45, 45, 0, 0, 1, 1, cd_size, cd_start_offset)
        )
        zip64_eocd_offset = cd_start_offset + cd_size

        # ZIP64 End of Central Directory Locator (PK\x06\x07): 20 bytes
        # 4 bytes magic, 4 bytes disk number, 8 bytes zip64 eocd offset, 4 bytes total disks
        zip64_locator = (
            b"PK\x06\x07"
            + struct.pack("<IQI", 0, zip64_eocd_offset, 1)
        )

        # Standard EOCD (PK\x05\x06) with 0xFFFF and 0xFFFFFFFF
        eocd = (
            b"PK\x05\x06"
            + struct.pack("<HHHHIIH", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        )

        with open(zip_path, "wb") as f:
            f.write(local_hdr)
            f.write(cd_entry)
            f.write(zip64_eocd_record)
            f.write(zip64_locator)
            f.write(eocd)

        count = self.indexer._index_zip_archive(zip_path, container_id=1)
        self.assertEqual(count, 1)

        conn = sqlite3.connect(self.vfs_db)
        cur = conn.cursor()
        cur.execute("SELECT filename, uncompressed_size, compressed_size, archive_data_offset FROM vfs_index")
        row = cur.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "huge_forensic_image.dd")
        self.assertEqual(row[1], uncomp_size_64, "ZIP64 uncompressed size must match 8GB")
        self.assertEqual(row[2], comp_size_64, "ZIP64 compressed size must match 4GB")
        self.assertEqual(row[3], local_off_64, "ZIP64 local header offset must match 0")

    def test_zip64_corrupt_locator_graceful_handling(self):
        """Ensure corrupted ZIP64 locator pointing to EOF+1000 degrades gracefully without crash."""
        zip_path = self.tmp_dir / "corrupt_zip64.zip"
        eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 0, 0, 0, 0, 0)
        corrupt_locator = b"PK\x06\x07" + struct.pack("<IQI", 0, 999999999, 1)

        with open(zip_path, "wb") as f:
            f.write(corrupt_locator)
            f.write(eocd)

        # Should not raise exception; fallback gracefully
        count = self.indexer._index_zip_archive(zip_path, container_id=2)
        self.assertEqual(count, 0)

    def test_pax_header_extraction_adversarial(self):
        """Stress-test PAX extended header block parsing with multi-byte Unicode, long paths, and malformed records."""
        # Build individual records with strictly calculated byte lengths
        def make_pax_record(key: str, val: str) -> bytes:
            kv_bytes = f"{key}={val}\n".encode("utf-8")
            # Calculate total length including length prefix and space
            length = len(kv_bytes) + 3  # Start guess with 2 digits + 1 space
            while True:
                prefix = f"{length} ".encode("ascii")
                total = len(prefix) + len(kv_bytes)
                if total == length:
                    return prefix + kv_bytes
                length = total

        r1 = make_pax_record("path", "data/user/0/com.phonepe.app/खाता.db")
        r2 = make_pax_record("size", "10737418240")
        r3 = make_pax_record("SCHILY.xattr.user.pin", "123456")
        r4 = make_pax_record("empty_val", "")
        r5 = make_pax_record("complex", "val=with=equals")
        r6 = make_pax_record("spaced", "val with space")

        pax_data = r1 + r2 + r3 + r4 + r5 + r6

        attrs = self.indexer._parse_pax_payload(pax_data)
        self.assertEqual(attrs.get("path"), "data/user/0/com.phonepe.app/खाता.db")
        self.assertEqual(attrs.get("size"), "10737418240")
        self.assertEqual(attrs.get("SCHILY.xattr.user.pin"), "123456")
        self.assertEqual(attrs.get("empty_val"), "")
        self.assertEqual(attrs.get("complex"), "val=with=equals")
        self.assertEqual(attrs.get("spaced"), "val with space")

        # Malformed record lengths (non-numeric, truncated)
        malformed = b"NaN path=invalid\n99999 truncated"
        attrs2 = self.indexer._parse_pax_payload(malformed)
        self.assertIsInstance(attrs2, dict)

    def test_adb_backup_offset_decoding_adversarial(self):
        """Test ADB backup offset calculation for 4-line unencrypted vs 9-line encrypted backups."""
        # Unencrypted ADB Backup (4 lines)
        ab_unenc = self.tmp_dir / "backup_plain.ab"
        tar_payload = b"FAKE_TAR_PAYLOAD_UNENCRYPTED_12345"
        compressed_tar = zlib.compress(tar_payload)
        header_plain = b"ANDROID BACKUP\n1\n1\nnone\n"
        ab_unenc.write_bytes(header_plain + compressed_tar)

        info = AbUnpacker.parse_header(ab_unenc)
        self.assertEqual(info.magic, "ANDROID BACKUP")
        self.assertEqual(info.backup_version, 1)
        self.assertTrue(info.compressed)
        self.assertFalse(info.is_encrypted)
        self.assertEqual(info.encryption_algorithm, "none")
        self.assertEqual(info.data_offset, len(header_plain))

        # Encrypted ADB Backup (9 lines)
        ab_enc = self.tmp_dir / "backup_encrypted.ab"
        header_enc = (
            b"ANDROID BACKUP\n"
            b"5\n"
            b"1\n"
            b"AES-256\n"
            b"user_salt_hex_string\n"
            b"cksum_salt_hex_string\n"
            b"10000\n"
            b"user_iv_hex_string\n"
            b"master_key_blob\n"
        )
        ab_enc.write_bytes(header_enc + b"ENCRYPTED_PAYLOAD_BYTES")

        info_enc = AbUnpacker.parse_header(ab_enc)
        self.assertEqual(info_enc.magic, "ANDROID BACKUP")
        self.assertEqual(info_enc.backup_version, 5)
        self.assertTrue(info_enc.is_encrypted)
        self.assertEqual(info_enc.encryption_algorithm, "AES-256")
        self.assertEqual(info_enc.data_offset, len(header_enc))

        # Malformed ADB Backup (wrong magic)
        ab_bad = self.tmp_dir / "bad.ab"
        ab_bad.write_bytes(b"NOT AN ANDROID BACKUP\n1\n1\nnone\n")
        with self.assertRaises(ValueError):
            AbUnpacker.parse_header(ab_bad)


class TestAdversarialDatabaseRecovery(unittest.TestCase):
    """Stress tests for SQLite WAL frames, salts, checksums, and rollback journal probing."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="adv_db_"))

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_wal_dual_endianness_checksums(self):
        """Test WAL checksum calculation across LE (0x377F0682) and BE (0x377F0683)."""
        sample_buf = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 32  # 256 bytes

        s0_le, s1_le = compute_wal_checksum(sample_buf, is_big_endian=False)
        s0_be, s1_be = compute_wal_checksum(sample_buf, is_big_endian=True)

        self.assertIsInstance(s0_le, int)
        self.assertIsInstance(s1_le, int)
        self.assertIsInstance(s0_be, int)
        self.assertIsInstance(s1_be, int)
        self.assertNotEqual((s0_le, s1_le), (s0_be, s1_be))

    def test_wal_mismatched_salts_and_corrupt_checksums(self):
        """
        Verify that mismatched salt or corrupted checksum stops the active chain
        and marks subsequent frames as PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME.
        """
        wal_file = self.tmp_dir / "test_chain.wal"
        page_size = 4096
        salt1 = 0x11111111
        salt2 = 0x22222222

        # 1. Build Header: exactly 24 bytes prefix + 8 bytes checksum = 32 bytes
        hdr_prefix = struct.pack(">IIIIII", 0x377F0682, 3007000, page_size, 1, salt1, salt2)
        h_s0, h_s1 = compute_wal_checksum(hdr_prefix, is_big_endian=False)
        wal_header = hdr_prefix + struct.pack(">II", h_s0, h_s1)

        s0, s1 = h_s0, h_s1

        # Frame 1: Valid active frame (page 1, commit_size=0)
        p1_data = b"PAGE_1_CONTENT_V1" + b"\x00" * (page_size - 17)
        f1_hdr_head = struct.pack(">IIII", 1, 0, salt1, salt2)
        s0, s1 = compute_wal_checksum(f1_hdr_head[:8], is_big_endian=False, s0=s0, s1=s1)
        s0, s1 = compute_wal_checksum(p1_data, is_big_endian=False, s0=s0, s1=s1)
        frame1 = f1_hdr_head + struct.pack(">II", s0, s1) + p1_data

        # Frame 2: Valid commit frame updating page 1 (page 1, commit_size=2) -> supersedes Frame 1!
        p1_v2_data = b"PAGE_1_CONTENT_V2" + b"\x00" * (page_size - 17)
        f2_hdr_head = struct.pack(">IIII", 1, 2, salt1, salt2)
        s0, s1 = compute_wal_checksum(f2_hdr_head[:8], is_big_endian=False, s0=s0, s1=s1)
        s0, s1 = compute_wal_checksum(p1_v2_data, is_big_endian=False, s0=s0, s1=s1)
        frame2 = f2_hdr_head + struct.pack(">II", s0, s1) + p1_v2_data

        # Frame 3: Mismatched salt (salt1 = 0x99999999) -> Breaks active chain!
        p3_data = b"PAGE_3_CONTENT" + b"\x00" * (page_size - 14)
        f3_hdr = struct.pack(">IIIIII", 3, 0, 0x99999999, salt2, 0x12345678, 0x87654321)
        frame3 = f3_hdr + p3_data

        # Frame 4: Residual frame after broken chain
        p4_data = b"PAGE_4_CONTENT" + b"\x00" * (page_size - 14)
        f4_hdr = struct.pack(">IIIIII", 4, 0, salt1, salt2, 0xAAAA5555, 0x5555AAAA)
        frame4 = f4_hdr + p4_data

        wal_file.write_bytes(wal_header + frame1 + frame2 + frame3 + frame4)

        reader = WALReader(wal_file, page_size=page_size)
        frames = reader.read_all_frames()

        self.assertEqual(len(frames), 4)
        self.assertTrue(frames[0].is_valid_active_checksum)
        self.assertTrue(frames[1].is_valid_active_checksum)
        self.assertFalse(frames[2].is_valid_active_checksum)
        self.assertFalse(frames[3].is_valid_active_checksum)

        # State classification verification
        self.assertEqual(frames[0].state, WALFrameState.HISTORICAL_SUPERSEDED_COMMITTED_FRAME)
        self.assertEqual(frames[1].state, WALFrameState.LATEST_COMMITTED_WAL_FRAME)
        self.assertEqual(frames[2].state, WALFrameState.PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME)
        self.assertEqual(frames[3].state, WALFrameState.PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME)

    def test_wal_truncated_frame_mid_page(self):
        """Verify that mid-page truncated WAL files read valid leading frames without failing."""
        wal_file = self.tmp_dir / "truncated.wal"
        page_size = 4096
        salt1, salt2 = 0x11, 0x22

        hdr_prefix = struct.pack(">IIIIII", 0x377F0682, 3007000, page_size, 1, salt1, salt2)
        h_s0, h_s1 = compute_wal_checksum(hdr_prefix, is_big_endian=False)
        wal_header = hdr_prefix + struct.pack(">II", h_s0, h_s1)

        p1_data = b"VALID_PAGE" + b"\x00" * (page_size - 10)
        f1_head = struct.pack(">IIII", 1, 1, salt1, salt2)
        s0, s1 = compute_wal_checksum(f1_head[:8], is_big_endian=False, s0=h_s0, s1=h_s1)
        s0, s1 = compute_wal_checksum(p1_data, is_big_endian=False, s0=s0, s1=s1)
        frame1 = f1_head + struct.pack(">II", s0, s1) + p1_data

        # Frame 2 is cut off after 12 bytes of header (truncated mid-frame)
        truncated_frame2 = struct.pack(">III", 2, 0, salt1)

        wal_file.write_bytes(wal_header + frame1 + truncated_frame2)

        reader = WALReader(wal_file, page_size=page_size)
        frames = reader.read_all_frames()

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].page_number, 1)
        self.assertEqual(frames[0].state, WALFrameState.LATEST_COMMITTED_WAL_FRAME)

    def test_rollback_journal_sector_probing(self):
        """Test rollback journal probing at offset 0, offset 512, and offset 4096 (PERSIST/TRUNCATE)."""
        page_size = 4096
        sector_size = 512

        # Journal with header at offset 512 (PERSIST zeroed sector 0)
        j_file = self.tmp_dir / "test.db-journal"
        sector_0 = b"\x00" * 512

        hdr = (
            JOURNAL_MAGIC
            + struct.pack(">iIIII", 1, 0x1234, 10, sector_size, page_size)
        )
        pad_hdr = hdr + b"\x00" * (sector_size - len(hdr))

        page_rec = struct.pack(">I", 5) + (b"PAGE_5_DATA" * 400)[:page_size] + struct.pack(">I", 0xABCD)

        j_file.write_bytes(sector_0 + pad_hdr + page_rec)

        reader = RollbackJournalReader(j_file)
        pages = reader.read_all_pages()

        self.assertIsNotNone(reader.header)
        self.assertEqual(reader.header.header_offset, 512)
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0].page_number, 5)


class TestAdversarialCarving(unittest.TestCase):
    """Stress tests for 4-zone B-Tree carving and Indian VPA/Amount filter strictness."""

    def setUp(self):
        self.schema = TableSchema(
            name="upi_transactions",
            rootpage=2,
            sql="CREATE TABLE upi_transactions (id INTEGER PRIMARY KEY, vpa TEXT, amount TEXT, utr TEXT)",
            columns=[
                ColumnSchema("id", "INTEGER", "INTEGER", is_primary_key=True),
                ColumnSchema("vpa", "TEXT", "TEXT"),
                ColumnSchema("amount", "TEXT", "TEXT"),
                ColumnSchema("utr", "TEXT", "TEXT"),
            ],
            ipk_column_name="id",
        )
        self.carver = ResidualCarver(
            table_schemas={"upi_transactions": self.schema},
            page_size=4096
        )

    def test_rejection_of_cells_without_valid_indian_vpa_and_amounts(self):
        """Verify that records lacking valid Indian VPA, UTR, or Amount are rejected."""
        # Test 1: Valid Indian VPA, valid Amount, valid UTR -> MUST PASS
        valid_tx = _record_to_transaction(
            values=["vikram.sharma@okicici", "Rs. 4,500.00", "123456789012"],
            origin_tag="test_valid",
        )
        self.assertIsNotNone(valid_tx)
        self.assertEqual(valid_tx["Counterparty"], "vikram.sharma@okicici")
        self.assertEqual(valid_tx["Amount"], 4500.0)
        self.assertEqual(valid_tx["Transaction_ID"], "123456789012")

        # Test 2: Generic email (user@example.com) -> NOT a valid Indian UPI VPA -> MUST BE REJECTED
        invalid_email_tx = _record_to_transaction(
            values=["john.doe@example.com", "Rs. 1,000.00", "123456789012"],
            origin_tag="test_email",
        )
        self.assertIsNone(invalid_email_tx, "Generic non-UPI email must be rejected")

        # Test 3: Valid VPA but missing / absurd amount -> MUST BE REJECTED
        missing_amount_tx = _record_to_transaction(
            values=["vikram@okhdfcbank", "No Amount Here", "123456789012"],
            origin_tag="test_no_amount",
        )
        self.assertIsNone(missing_amount_tx, "Transaction without valid amount must be rejected")

        # Test 4: Valid amount but no VPA and no crypto address -> MUST BE REJECTED
        no_vpa_tx = _record_to_transaction(
            values=["Random Person", "₹2,500.00", "123456789012"],
            origin_tag="test_no_vpa",
        )
        self.assertIsNone(no_vpa_tx, "Transaction without VPA or crypto address must be rejected")

        # Test 5: High-entropy random noise buffers fed to _carve_intact_cells_in_slice
        for i in range(500):
            noise = os.urandom(256)
            recs = self.carver._carve_intact_cells_in_slice(
                slice_bytes=noise,
                page_num=10,
                base_byte_offset=0,
                zone="UNALLOCATED_GAP",
                candidate_tables=list(self.carver.table_schemas.values()),
            )
            self.assertEqual(len(recs), 0, f"Random noise slice {i} produced unexpected record!")

    def test_hostile_overflow_bounds_and_cycle_prevention(self):
        """Verify cycle detection and memory bounds protection on corrupt overflow chains."""
        # 1. Cyclic overflow chain: Page 2 -> Page 3 -> Page 2 -> ...
        page_store = {
            2: struct.pack(">I", 3) + b"PAGE_2_OVERFLOW_CHUNK" * 50,
            3: struct.pack(">I", 2) + b"PAGE_3_OVERFLOW_CHUNK" * 50,
        }

        def fetcher(p_num: int) -> bytes:
            return page_store.get(p_num, b"")

        reassembled = reassemble_overflow_chain(
            first_chunk=b"FIRST_CHUNK",
            first_overflow_page_num=2,
            total_payload_bytes=100000,
            usable_page_size=4096,
            page_fetcher=fetcher,
        )
        self.assertTrue(len(reassembled) > len(b"FIRST_CHUNK"))

        # 2. Huge overflow size bounds protection (e.g. 10 GB payload claimed)
        self.assertEqual(MAX_SAFE_OVERFLOW_PAYLOAD, 100 * 1024 * 1024)


class TestAdversarialLevelDB(unittest.TestCase):
    """Stress tests for Snappy decompression, WriteBatch parsing, and tombstone tracking."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="adv_ldb_"))

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_snappy_decompression_valid_and_malformed(self):
        """Verify pure-Python Snappy decompressor handles literals, copies, and corrupted streams."""
        raw_literal = b"Hello, Bharat Forensic Unified Suite!"
        snappy_lit = bytes([len(raw_literal), (len(raw_literal) - 1) << 2]) + raw_literal
        decomp = snappy_decompress(snappy_lit)
        self.assertEqual(decomp, raw_literal)

        corrupt_snappy = b"\x10\x01\x00"
        decomp_corrupt = snappy_decompress(corrupt_snappy)
        self.assertIsInstance(decomp_corrupt, bytes)

        corrupt_snappy2 = b"\x20\x02\xFF\xFF"
        decomp_corrupt2 = snappy_decompress(corrupt_snappy2)
        self.assertIsInstance(decomp_corrupt2, bytes)

    def test_leveldb_writebatch_parsing_and_tombstones(self):
        """Verify LevelDB WriteBatch decoding, sequence numbers, and tombstone tracking."""
        ldb_dir = self.tmp_dir / "test_leveldb"
        ldb_dir.mkdir(parents=True, exist_ok=True)
        log_file = ldb_dir / "000003.log"

        k1 = b"user:101"
        v1 = b"Active User"
        k2 = b"user:102"
        v2 = b"To Be Deleted"

        batch = bytearray()
        batch.extend(struct.pack("<Q", 100))  # base_seq = 100
        batch.extend(struct.pack("<I", 3))    # count = 3

        # Entry 1 (seq 100): Put user:101
        batch.append(0x01)
        batch.append(len(k1))
        batch.extend(k1)
        batch.append(len(v1))
        batch.extend(v1)

        # Entry 2 (seq 101): Put user:102
        batch.append(0x01)
        batch.append(len(k2))
        batch.extend(k2)
        batch.append(len(v2))
        batch.extend(v2)

        # Entry 3 (seq 102): Delete Tombstone user:102
        batch.append(0x00)
        batch.append(len(k2))
        batch.extend(k2)

        chunk_header = struct.pack("<IHB", 0, len(batch), 1)
        block = chunk_header + bytes(batch)
        log_file.write_bytes(block)

        decoder = LevelDBDecoder()
        recovered = decoder.decode_leveldb_directory(ldb_dir)

        self.assertTrue(len(recovered) >= 2)
        user_101 = next((r for r in recovered if r.key_name_text == "user:101"), None)
        user_102 = next((r for r in recovered if r.key_name_text == "user:102"), None)

        self.assertIsNotNone(user_101)
        self.assertEqual(user_101.value_operation_type, "LIVE_VALUE")
        self.assertEqual(user_101.decoded_value_text_or_json, "Active User")

        self.assertIsNotNone(user_102)
        self.assertEqual(user_102.value_operation_type, "EXPLICIT_DELETION_TOMBSTONE")


if __name__ == "__main__":
    unittest.main()
