"""
Tier 2 Boundary & Corner Case Test Suite.
Verifies system resilience against corrupt headers, truncated WAL frames,
zero-byte archives, extreme financial amounts, unallocated noise rejection,
missing salts, and varint stream boundary conditions.
"""

from __future__ import annotations

import io
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from src.core.enums import ContainerType
from src.vfs.fingerprint import ContainerFingerprinter
from src.vfs.indexer import VFSIndexer
from src.sqlite.wal import WALFrameState, WALReader, compute_wal_checksum, parse_wal_header
from src.sqlite.varint import decode_varint, encode_varint
from src.banking.narration_parser import CoreBankingNarrationParser
from src.legal_and_bsa.models import IntegrityAuditDisclosure
from src.legal_and_bsa.bsa_certificate_generator import Section63BsaCertificateGenerator
from parsers.corrupt_db_carver import carve_corrupted_sqlite_file


class TestTier2BoundaryCorner(unittest.TestCase):
    """Tier 2: Boundary conditions, corrupt inputs, and edge stress cases."""

    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t2_boundary_")

    def tearDown(self):
        if self.sandbox.exists():
            shutil.rmtree(self.sandbox, ignore_errors=True)

    def test_zero_byte_archive_boundary_handling(self):
        """Zero-byte tar, zip, and adb files must not cause crashes or index corruption."""
        zero_tar = self.sandbox / "empty.tar"
        zero_tar.write_bytes(b"")

        zero_zip = self.sandbox / "empty.zip"
        zero_zip.write_bytes(b"")

        zero_ab = self.sandbox / "empty.ab"
        zero_ab.write_bytes(b"")

        fingerprinter = ContainerFingerprinter()

        # Fingerprinting 0-byte files should safely yield UNKNOWN
        fp_tar = fingerprinter.fingerprint(zero_tar)
        self.assertEqual(fp_tar.container_type, ContainerType.UNKNOWN)

        fp_zip = fingerprinter.fingerprint(zero_zip)
        self.assertEqual(fp_zip.container_type, ContainerType.UNKNOWN)

        fp_ab = fingerprinter.fingerprint(zero_ab)
        self.assertEqual(fp_ab.container_type, ContainerType.UNKNOWN)

        # Indexing 0-byte archive in VFS must complete gracefully with 0 indexed records
        catalog_db = self.sandbox / "vfs_zero.sqlite"
        indexer = VFSIndexer(catalog_db)
        count = indexer.index_archive(zero_tar, container_id=1)
        self.assertEqual(count, 0)

        count_zip = indexer.index_archive(zero_zip, container_id=2)
        self.assertEqual(count_zip, 0)

    def test_truncated_wal_mid_frame_power_loss(self):
        """A WAL file interrupted mid-write (valid frame followed by truncated frame) must recover valid frame."""
        page_size = 4096
        salt1 = 0x11223344
        salt2 = 0x55667788

        # 1. Construct 32-byte WAL Header
        hdr_magic = 0x377F0683  # Big-endian checksum format
        hdr_prefix = struct.pack(">IIIIII", hdr_magic, 3007000, page_size, 1, salt1, salt2)
        s0, s1 = compute_wal_checksum(hdr_prefix, is_big_endian=True, s0=0, s1=0)
        wal_header = hdr_prefix + struct.pack(">II", s0, s1)

        # 2. Frame 1: Valid committed frame
        frame1_data = b"VALID_PAGE_ONE_DATA" + b"\x00" * (page_size - 19)
        f1_hdr_bytes = struct.pack(">IIII", 1, 1, salt1, salt2)
        s0_1, s1_1 = compute_wal_checksum(f1_hdr_bytes[:8] + frame1_data, is_big_endian=True, s0=s0, s1=s1)
        frame1_bytes = f1_hdr_bytes + struct.pack(">II", s0_1, s1_1) + frame1_data

        # 3. Frame 2: Truncated frame (only header + 256 bytes instead of 4096 bytes)
        partial_page_data = b"TRUNCATED_MID_WRITE_POWER_LOSS" * 8  # 240 bytes
        f2_hdr_bytes = struct.pack(">IIII", 2, 2, salt1, salt2)
        frame2_bytes = f2_hdr_bytes + struct.pack(">II", 0, 0) + partial_page_data

        wal_file = self.sandbox / "interrupted.db-wal"
        wal_file.write_bytes(wal_header + frame1_bytes + frame2_bytes)

        reader = WALReader(wal_file, page_size=page_size)
        frames = reader.read_all_frames()

        # The reader must recover Frame 1 and safely halt before the truncated Frame 2
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].frame_index, 1)
        self.assertEqual(frames[0].page_number, 1)
        self.assertEqual(frames[0].page_data[:19], b"VALID_PAGE_ONE_DATA")

    def test_wal_missing_salt_checkpoint_residual(self):
        """Frames from prior checkpoint whose salts do not match the current WAL header must be residual."""
        page_size = 4096
        salt1 = 0xAAAA1111
        salt2 = 0xBBBB2222

        # 1. Header with salt1, salt2
        hdr_magic = 0x377F0683
        hdr_prefix = struct.pack(">IIIIII", hdr_magic, 3007000, page_size, 1, salt1, salt2)
        s0, s1 = compute_wal_checksum(hdr_prefix, is_big_endian=True, s0=0, s1=0)
        wal_header = hdr_prefix + struct.pack(">II", s0, s1)

        # 2. Frame 1 with matching salt
        p1_data = b"PAGE_ONE" + b"\x00" * (page_size - 8)
        f1_hdr = struct.pack(">IIII", 1, 1, salt1, salt2)
        s0_1, s1_1 = compute_wal_checksum(f1_hdr[:8] + p1_data, is_big_endian=True, s0=s0, s1=s1)
        frame1 = f1_hdr + struct.pack(">II", s0_1, s1_1) + p1_data

        # 3. Frame 2 with mismatched / stale salt (from prior run before checkpoint reset)
        stale_salt1 = 0xDEADBEEF
        stale_salt2 = 0xCAFEBABE
        p2_data = b"PAGE_TWO_STALE" + b"\x00" * (page_size - 14)
        f2_hdr = struct.pack(">IIII", 2, 0, stale_salt1, stale_salt2)
        frame2 = f2_hdr + struct.pack(">II", 0, 0) + p2_data

        wal_file = self.sandbox / "residual.db-wal"
        wal_file.write_bytes(wal_header + frame1 + frame2)

        reader = WALReader(wal_file, page_size=page_size)
        frames = reader.read_all_frames()

        self.assertEqual(len(frames), 2)
        # Frame 1 should be committed
        self.assertEqual(frames[0].state, WALFrameState.LATEST_COMMITTED_WAL_FRAME)
        # Frame 2 with mismatched salt must be classified as PRIOR_CHECKPOINT_RESIDUAL
        self.assertEqual(frames[1].state, WALFrameState.PRIOR_CHECKPOINT_RESIDUAL_WAL_FRAME)

    def test_unallocated_pseudo_noise_rejection(self):
        """Random pseudo-noise bytes must yield zero carved transaction false positives."""
        # Create 200 KB file consisting of pseudo-random bytes without currency indicators
        noise_data = bytes((i * 37 + 101) % 256 for i in range(200 * 1024))
        noise_file = self.sandbox / "noise.bin"
        noise_file.write_bytes(noise_data)

        carved_df = carve_corrupted_sqlite_file(str(noise_file))
        # Pure random noise without explicit currency prefix must yield 0 carved transactions
        self.assertEqual(len(carved_df), 0)

    def test_real_evidence_raw_disk_carving(self):
        """Verifies raw carving against test_evidence/test_disk.dd produces genuine records."""
        test_dd = Path("test_evidence/test_disk.dd")
        if not test_dd.exists():
            self.skipTest("test_evidence/test_disk.dd not present")

        df = carve_corrupted_sqlite_file(str(test_dd))
        self.assertGreater(len(df), 0)
        # All carved transactions must have valid amounts and counterparty VPAs
        for _, row in df.iterrows():
            self.assertGreater(row["Amount"], 0.0)
            self.assertIn("@", row["Counterparty"])

    def test_varint_boundary_conditions(self):
        """Tests SQLite 9-byte varint boundaries: 0, 1-byte, 9-byte max 64-bit int, and negative values."""
        # 1. Zero
        self.assertEqual(decode_varint(encode_varint(0)), (0, 1))

        # 2. Maximum single-byte (127)
        self.assertEqual(decode_varint(encode_varint(127)), (127, 1))

        # 3. Multi-byte values
        for val in [128, 16383, 16384, 2097151, 2097152, 268435455, 268435456]:
            enc = encode_varint(val)
            dec, n_bytes = decode_varint(enc)
            self.assertEqual(dec, val)
            self.assertEqual(len(enc), n_bytes)

        # 4. Maximum positive 63-bit integer
        max_int63 = (1 << 63) - 1
        enc_max = encode_varint(max_int63)
        dec_max, n_max = decode_varint(enc_max)
        self.assertEqual(dec_max, max_int63)
        self.assertEqual(n_max, 9)

        # 5. Negative values (-1, -100, -9223372036854775808)
        for neg_val in [-1, -100, -4294967296, -(1 << 63)]:
            enc_neg = encode_varint(neg_val)
            dec_neg, n_neg = decode_varint(enc_neg)
            self.assertEqual(dec_neg, neg_val)

        # 6. Truncated varint at end of buffer (8 bytes of 0x80)
        truncated_buf = b"\x80" * 4
        dec_trunc, n_trunc = decode_varint(truncated_buf)
        self.assertEqual(n_trunc, 4)

        # 7. Offset exceeding buffer length raises ValueError
        with self.assertRaises(ValueError):
            decode_varint(b"\x01", pos=5)

    def test_extreme_financial_values_and_malformed_narrations(self):
        """Verifies narration parser handling of extreme values: zero, small, large, malformed delimiters."""
        parser = CoreBankingNarrationParser()

        # 1. Extreme Large Transaction: ₹999,99,99,999.00
        large_upi = "UPI/CR/999999999999/TREASURY/SBI/corp@sbi/9999999999"
        res_large = parser.parse_narration(large_upi)
        self.assertEqual(res_large.utr_or_rrn, "999999999999")
        self.assertEqual(res_large.direction, "CREDIT")
        self.assertEqual(res_large.counterparty_vpa, "corp@sbi")

        # 2. Micro Transaction: ₹0.01 / penny drop verification
        micro_upi = "UPI/DR/123456789012/PENNY VERIFY/HDFC/verify@hdfc/Penny test"
        res_micro = parser.parse_narration(micro_upi)
        self.assertEqual(res_micro.utr_or_rrn, "123456789012")
        self.assertEqual(res_micro.direction, "DEBIT")

        # 3. None / Empty String input resilience
        res_none = parser.parse_narration(None)
        self.assertIsNone(res_none.utr_or_rrn)

        res_empty = parser.parse_narration("")
        self.assertIsNone(res_empty.utr_or_rrn)

        # 4. Malformed narration with special characters and missing tokens
        malformed = "UPI///////$$$///"
        res_malformed = parser.parse_narration(malformed)
        self.assertEqual(res_malformed.payment_rail, "UPI")

    def test_anti_forensics_clock_rollback_boundary(self):
        """Verifies Section 63(2)(c) clause generation handles extreme clock rollback."""
        generator = Section63BsaCertificateGenerator()

        # Extreme clock rollback of 720 hours (30 days in the past)
        audit_extreme_rollback = IntegrityAuditDisclosure(
            clock_tampering_detected=True,
            clock_tampering_details="Manual system clock rollback of -720.0 hours detected via GPS monotonic delta",
            monotonic_counter_bounds="hardware monotonic timer and SQLite ROWID checkpoint ordering",
            root_or_jailbreak_detected=False,
            malware_or_overlay_detected=False,
        )

        clause = generator.synthesize_sec63_2_c_clause(audit_extreme_rollback)
        self.assertIn("Section 63(2)(c)", clause)
        self.assertIn("-720.0 hours", clause)
        self.assertIn("mathematically isolated", clause)


if __name__ == "__main__":
    unittest.main()
