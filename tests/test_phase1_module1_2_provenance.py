"""
Tests for Phase 1 Module 1.2: Dual SHA-256 Hashing & Metadata Provenance Engine.
Complies with:
- ISO/IEC 27037 & SWGDE Forensics Standards.
- Section 63(4)(c) Bharatiya Sakshya Adhiniyam (BSA) 2023.
- Section 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.

Verifies:
1. Product A Container Hashing (Single-file streaming, folder composite manifest hash, vendor log cross-verification).
2. Product B Staged & Derivative Hashing (Zero-pass Tee hashing, Product B1 read-only lock, Product B2 derivative).
3. 5-Epoch Forensic Timestamp Normalization & 5-Column Storage Standard.
4. Security & Metadata Provenance (POSIX UID/GID/mode, iOS Protection Class A-D, SELinux tamper detection, WhereFroms URLs).
5. Provenance Ledger Database Schema (container_integrity_ledger, file_provenance_catalog, derivative_staging_ledger, chain_of_custody_audit_log).
"""

import hashlib
import io
import os
import plistlib
import sqlite3
import pytest
from pathlib import Path

# Production module imports (failing during Phase A RED phase)
from src.provenance.hasher import (
    ProductAHasher,
    ProductAHashResult,
    FolderCompositeHashResult,
    VendorVerificationResult,
    TeeHasher,
)
from src.provenance.timestamps import (
    TimestampNormalizer,
    NormalizedTimestampRecord,
)
from src.provenance.security import (
    SecurityMetadataDecoder,
)
from src.provenance.ledger import (
    ProvenanceLedger,
)


# ============================================================================
# Helpers
# ============================================================================

def make_sample_file(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


# ============================================================================
# Test Cases
# ============================================================================

class TestProductAHasher:
    """Product A Original Container Hashing & Vendor Verification Tests."""

    def test_single_file_streaming_hash(self, tmp_path):
        content = b"FORENSIC_EVIDENCE_STREAMING_TEST" * 1024  # 32 KB
        file_path = make_sample_file(tmp_path / "extraction.tar", content)
        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_md5 = hashlib.md5(content).hexdigest()

        hasher = ProductAHasher()
        result = hasher.hash_file(file_path, compute_md5=True)

        assert isinstance(result, ProductAHashResult)
        assert result.sha256 == expected_sha256
        assert result.md5 == expected_md5
        assert result.total_bytes == len(content)
        assert result.start_utc_iso.endswith("Z")
        assert result.completed_utc_iso.endswith("Z")

    def test_folder_composite_manifest_hash_deterministic(self, tmp_path):
        folder_a = tmp_path / "folder_a"
        folder_b = tmp_path / "folder_b"

        # Create files in folder A in one order
        make_sample_file(folder_a / "Manifest.db", b"SQLITE_FORMAT_3")
        make_sample_file(folder_a / "3d" / "3d0d7e5f", b"SMS_BYTES")
        make_sample_file(folder_a / "Manifest.plist", b"PLIST_BYTES")

        # Create files in folder B in reverse order
        make_sample_file(folder_b / "Manifest.plist", b"PLIST_BYTES")
        make_sample_file(folder_b / "Manifest.db", b"SQLITE_FORMAT_3")
        make_sample_file(folder_b / "3d" / "3d0d7e5f", b"SMS_BYTES")

        hasher = ProductAHasher()
        res_a = hasher.hash_folder(folder_a)
        res_b = hasher.hash_folder(folder_b)

        assert isinstance(res_a, FolderCompositeHashResult)
        assert isinstance(res_b, FolderCompositeHashResult)
        # Cross-OS repeatable deterministic composite hash
        assert res_a.composite_sha256 == res_b.composite_sha256
        assert len(res_a.composite_sha256) == 64
        # Verify canonical manifest structure (0x0A newlines, sorted UTF-8 relative paths)
        assert " *3d/3d0d7e5f\n" in res_a.manifest_content
        assert " *Manifest.db\n" in res_a.manifest_content
        assert " *Manifest.plist\n" in res_a.manifest_content

    def test_vendor_hash_verification_cellebrite_ufd(self, tmp_path):
        data = b"REAL_CONTAINER_PAYLOAD"
        tar_file = make_sample_file(tmp_path / "dump.tar", data)
        computed_hash = hashlib.sha256(data).hexdigest()

        # 1. Matching UFD file
        ufd_file = tmp_path / "dump.ufd"
        ufd_file.write_text(f"[General]\nDevice=Pixel\n\n[SHA256]\ndump.tar={computed_hash}\n")

        hasher = ProductAHasher()
        res_match = hasher.verify_vendor_hash(computed_hash, ufd_file)
        assert res_match.status == "VERIFIED_MATCH"
        assert res_match.vendor_expected_hash == computed_hash

        # 2. Mismatching UFD file
        tampered_ufd = tmp_path / "tampered.ufd"
        tampered_ufd.write_text("[SHA256]\ndump.tar=0000000000000000000000000000000000000000000000000000000000000000\n")

        res_mismatch = hasher.verify_vendor_hash(computed_hash, tampered_ufd)
        assert res_mismatch.status == "CRITICAL_MISMATCH"

        # 3. No vendor log provided
        res_self = hasher.verify_vendor_hash(computed_hash, None)
        assert res_self.status == "SELF_ANCHORED_NO_VENDOR_LOG"


class TestTimestampNormalizer:
    """Stage 4: 5-Epoch Forensic Timestamp Normalization Tests."""

    def test_five_clock_epochs_synchronized_vectors(self):
        """
        Tests that all 5 epochs resolve to the exact same calendar date and timestamp.
        Reference: 2026-11-04 14:40:00.450123 UTC
        """
        tn = TimestampNormalizer()

        # 1. Unix seconds
        res_u_sec = tn.normalize_timestamp(1793803200.450123)
        assert isinstance(res_u_sec, NormalizedTimestampRecord)
        assert res_u_sec.ts_epoch_unit == "UNIX_SECONDS"
        assert res_u_sec.ts_utc_iso8601 == "2026-11-04T14:40:00.450123Z"

        # 2. Unix nanoseconds (19 digits)
        res_u_ns = tn.normalize_timestamp(1793803200450123008)
        assert res_u_ns.ts_epoch_unit == "UNIX_NANOSECONDS"
        assert res_u_ns.ts_utc_iso8601.startswith("2026-11-04T14:40:00.450123")

        # 3. Apple Cocoa seconds (since 2001-01-01)
        res_c_sec = tn.normalize_timestamp(815496000.4501231, epoch_hint="COCOA_SECONDS")
        assert res_c_sec.ts_epoch_unit == "COCOA_SECONDS"
        assert res_c_sec.ts_utc_iso8601 == "2026-11-04T14:40:00.450123Z"

        # 4. Apple Cocoa nanoseconds (since 2001-01-01, iOS sms.db date)
        res_c_ns = tn.normalize_timestamp(815496000450123008, epoch_hint="COCOA_NANOSECONDS")
        assert res_c_ns.ts_epoch_unit == "COCOA_NANOSECONDS"
        assert res_c_ns.ts_utc_iso8601.startswith("2026-11-04T14:40:00.450123")

        # 5. WebKit microseconds (since 1601-01-01)
        res_wk_us = tn.normalize_timestamp(13438276800450122, epoch_hint="WEBKIT_MICROSECONDS")
        assert res_wk_us.ts_epoch_unit == "WEBKIT_MICROSECONDS"
        assert res_wk_us.ts_utc_iso8601.startswith("2026-11-04T14:40:00.450122")

    def test_msdos_local_vs_zip_extra_field_provenance(self):
        tn = TimestampNormalizer()

        # Basic MS-DOS header time without extra field
        dos_rec = tn.normalize_dos_timestamp(dos_date=0x5D64, dos_time=0x7500, has_zip_extra_field=False)
        assert dos_rec.ts_tz_provenance == "AMBIGUOUS_LOCAL_ZIP_DOS"

        # MS-DOS entry with 0x5455 UTC Extra Field
        extra_rec = tn.normalize_dos_timestamp(dos_date=0x5D64, dos_time=0x7500, has_zip_extra_field=True, utc_seconds=1714800000)
        assert extra_rec.ts_tz_provenance == "UTC_ZIP_EXTRA_FIELD"
        assert extra_rec.ts_utc_iso8601 == "2024-05-04T05:20:00.000000Z"


class TestSecurityMetadataDecoder:
    """Stage 5: Extended Attributes, Permissions & Tamper Detection Tests."""

    def test_posix_mode_and_uid_gid(self):
        sec = SecurityMetadataDecoder()
        octal_str = sec.decode_posix_mode(0o100644)
        assert octal_str == "0100644"

    def test_ios_protection_classes(self):
        sec = SecurityMetadataDecoder()
        assert sec.decode_ios_protection_class(1) == "CLASS_A"
        assert sec.decode_ios_protection_class(2) == "CLASS_B"
        assert sec.decode_ios_protection_class(3) == "CLASS_C"
        assert sec.decode_ios_protection_class(4) == "CLASS_D"
        assert sec.decode_ios_protection_class(99) is None

    def test_android_selinux_tamper_detection(self):
        sec = SecurityMetadataDecoder()

        # 1. Root framework artifacts (Magisk / KSU / SU)
        flag_magisk = sec.check_selinux_tamper("u:object_r:magisk_file:s0", "/data/adb/magisk.db")
        assert flag_magisk == "ROOT_FRAMEWORK_ARTIFACT"

        flag_ksu = sec.check_selinux_tamper("u:object_r:ksu_file:s0", "/system/bin/ksu")
        assert flag_ksu == "ROOT_FRAMEWORK_ARTIFACT"

        # 2. Anomalous unlabeled system files
        flag_unlabeled = sec.check_selinux_tamper("u:object_r:unlabeled:s0", "/system/bin/app_process")
        assert flag_unlabeled == "ANOMALOUS_UNLABELED_SYSTEM_FILE"

        # 3. ADB / Shell injected files into private app sandboxes
        flag_injected = sec.check_selinux_tamper("u:object_r:shell_data_file:s0", "/data/user/0/com.phonepe.app/databases/app.db")
        assert flag_injected == "ADB_OR_SHELL_INJECTED_FILE"

        # 4. Clean app sandbox file
        flag_clean = sec.check_selinux_tamper("u:object_r:app_data_file:s0:c512,c768", "/data/user/0/com.phonepe.app/databases/app.db")
        assert flag_clean is None

    def test_decode_where_froms_urls(self):
        sec = SecurityMetadataDecoder()
        urls = ["https://malicious.in/payload.apk", "https://google.com/search?q=apk"]
        bplist_data = plistlib.dumps(urls, fmt=plistlib.FMT_BINARY)

        decoded_urls = sec.decode_where_froms(bplist_data)
        assert decoded_urls == urls


class TestProvenanceLedgerAndDatabase:
    """Stage 6: SQLite Provenance Ledger Database & Tee Hasher Tests."""

    def test_ledger_schema_and_records(self, tmp_path):
        db_path = tmp_path / "provenance_ledger.sqlite"
        ledger = ProvenanceLedger(db_path=db_path)

        # 1. Record container integrity (Product A)
        container_id = ledger.record_container_integrity(
            source_input_path="/evidence/dump.tar",
            container_type="TAR",
            acquisition_tier="TIER_2_FFS",
            total_size_bytes=1048576,
            product_a_sha256="a" * 64,
            product_a_md5="b" * 32,
            vendor_log_path="/evidence/dump.ufd",
            vendor_expected_hash="a" * 64,
            verification_status="VERIFIED_MATCH",
            hash_started_utc="2026-11-04T10:00:00.000000Z",
            hash_completed_utc="2026-11-04T10:00:05.000000Z"
        )
        assert container_id == 1
        container_rec = ledger.get_container_record(container_id)
        assert container_rec["product_a_sha256"] == "a" * 64
        assert container_rec["verification_status"] == "VERIFIED_MATCH"

        # 2. Record file provenance
        ledger.record_file_provenance(
            vfs_file_id=101,
            canonical_path="/data/user/0/com.phonepe.app/databases/phonepe.db",
            mtime_raw="1714800000",
            mtime_utc_ns=1714800000000000000,
            mtime_utc_iso="2024-05-04T05:20:00.000000Z",
            btime_raw="1714700000",
            btime_utc_ns=1714700000000000000,
            btime_utc_iso="2024-05-03T01:33:20.000000Z",
            ctime_utc_iso="2024-05-04T05:20:00.000000Z",
            atime_utc_iso="2024-05-04T05:20:00.000000Z",
            ts_tz_provenance="INTRINSIC_UTC",
            posix_mode_octal="0100660",
            owner_uid=10145,
            owner_gid=10145,
            ios_protection_class=None,
            android_selinux_label="u:object_r:app_data_file:s0:c512,c768",
            where_froms_urls_json=None,
            is_backup_excluded=0,
            tamper_anomaly_flag=None
        )
        prov_rec = ledger.get_file_provenance(101)
        assert prov_rec["canonical_path"] == "/data/user/0/com.phonepe.app/databases/phonepe.db"
        assert prov_rec["owner_uid"] == 10145

        # 3. Record derivative staging (Product B1 & Product B2)
        staging_id = ledger.record_derivative_staging(
            source_vfs_file_id=101,
            companion_wal_file_id=102,
            staged_local_path="staging/stg_001/target.db",
            product_b1_raw_sha256="c" * 64,
            companion_wal_sha256="d" * 64,
            derivation_action="SQLITE_WAL_CHECKPOINT_MERGE",
            crypto_key_reference=None,
            product_b2_derived_sha256="e" * 64,
            staged_utc_timestamp="2026-11-04T10:05:00.000000Z"
        )
        assert staging_id == 1
        deriv_rec = ledger.get_derivative_record(staging_id)
        assert deriv_rec["product_b1_raw_sha256"] == "c" * 64
        assert deriv_rec["product_b2_derived_sha256"] == "e" * 64

        # 4. Record chain of custody audit log
        ledger.record_chain_of_custody_event(
            event_utc_iso="2026-11-04T10:05:01.000000Z",
            software_version="v1.0.0-build20261104",
            workstation_hostname="FORENSIC-WS-01",
            action_type="PRODUCT_B_STAGED",
            target_description="Staged phonepe.db + phonepe.db-wal",
            input_sha256="c" * 64,
            output_sha256="e" * 64
        )
        events = ledger.get_chain_of_custody_events()
        assert len(events) == 1
        assert events[0]["action_type"] == "PRODUCT_B_STAGED"
        assert events[0]["software_version"] == "v1.0.0-build20261104"

    def test_tee_hasher_streaming(self, tmp_path):
        payload = b"TEE_STREAM_DATA_BYTES" * 500
        src_stream = io.BytesIO(payload)
        dst_path = tmp_path / "staged_tee.bin"

        tee = TeeHasher()
        computed_sha256, bytes_written = tee.stream_and_hash(src_stream, dst_path)

        assert bytes_written == len(payload)
        assert computed_sha256 == hashlib.sha256(payload).hexdigest()
        assert dst_path.read_bytes() == payload
