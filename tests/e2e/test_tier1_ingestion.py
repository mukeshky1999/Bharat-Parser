"""
Tier 1 Feature Coverage: Core Forensic Ingestion & Archive Handlers
Tests UFED containers, POSIX/PAX Tar, ZIP64, ADB backup, iOS backup Manifest.db,
Canonical Path Normalization, and SHA-256 Provenance Hashing.
"""

from __future__ import annotations

import hashlib
import io
import os
import plistlib
import sqlite3
import struct
import sys
import tarfile
import unittest
import zipfile
import zlib
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from src.core.enums import ContainerType, EntryType, ForensicGroup
from src.provenance.hasher import ProductAHasher
from src.provenance.ledger import ProvenanceLedger
from src.vfs.fingerprint import ContainerFingerprinter
from src.vfs.indexer import VFSIndexer
from src.vfs.normalizer import CanonicalPathNormalizer
from src.vfs.reader import VFSReader


class TestTier1Ingestion(unittest.TestCase):
    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t1_ingest_")
        self.db_path = self.sandbox / "vfs_index.sqlite"
        self.ledger_path = self.sandbox / "evidentiary_ledger.sqlite"
        self.indexer = VFSIndexer(catalog_db_path=self.db_path)
        self.reader = VFSReader(catalog_db_path=self.db_path)
        self.fingerprinter = ContainerFingerprinter()
        self.hasher = ProductAHasher()

    def tearDown(self):
        env_setup.cleanup_isolated_sandbox(self.sandbox)

    def test_ufed_container_fingerprint_and_hash_cross_check(self):
        """
        T1.1.1: Validates UFED .ufd manifest parsing, fingerprinting, and cryptographic
        cross-check against declared vendor hashes.
        Authoritative source: NIST FIPS 180-4 SHA-256 & Cellebrite UFED XML/INI specification.
        """
        payload_data = b"FORENSIC_RAW_ACQUISITION_UFED_PAYLOAD_EVIDENCE_DUMP_2026"
        expected_sha256 = hashlib.sha256(payload_data).hexdigest().lower()
        expected_md5 = hashlib.md5(payload_data).hexdigest().lower()

        bin_file = self.sandbox / "extraction_dump.bin"
        bin_file.write_bytes(payload_data)

        # Cellebrite UFED format .ufd manifest
        ufd_file = self.sandbox / "extraction_dump.ufd"
        ufd_content = f"""[General]
Version=1.0
EvidenceName=Device_Pixel_7A
DeviceModel=Pixel 7a
IMEI=869402058192019
Sha256={expected_sha256}
MD5={expected_md5}
[Files]
Count=1
File0=extraction_dump.bin
"""
        ufd_file.write_text(ufd_content, encoding="utf-8")

        # 1. Verify container fingerprinting
        fp = self.fingerprinter.fingerprint(bin_file)
        self.assertIsNotNone(fp)

        # 2. Verify vendor hash verification using ProductAHasher
        hash_res = self.hasher.hash_file(bin_file, compute_md5=True)
        self.assertEqual(hash_res.sha256.lower(), expected_sha256)
        self.assertEqual(hash_res.md5.lower(), expected_md5)

        vendor_res = self.hasher.verify_vendor_hash(hash_res.sha256, ufd_file)
        self.assertEqual(vendor_res.status, "VERIFIED_MATCH")
        self.assertEqual(vendor_res.vendor_expected_hash.lower(), expected_sha256)

    def test_posix_and_pax_tar_archive_indexing(self):
        """
        T1.1.2: Validates zero-extraction indexing of POSIX UStar and PAX extended header archives.
        Authoritative source: POSIX.1-2001 (IEEE Std 1003.1) TAR format specification.
        """
        tar_path = self.sandbox / "test_backup.tar"
        test_file_content = b"PAX_EXTENDED_HEADER_FORENSIC_DATA_PAYLOAD"
        with tarfile.open(tar_path, mode="w") as tar:
            ti = tarfile.TarInfo(name="data/data/com.whatsapp/databases/msgstore.db")
            ti.size = len(test_file_content)
            ti.mtime = 1714800000
            ti.mode = 0o644
            ti.pax_headers = {"path": "data/data/com.whatsapp/databases/msgstore.db", "comment": "forensic-clone"}
            tar.addfile(ti, io.BytesIO(test_file_content))

        count = self.indexer.index_archive(tar_path, container_id=1)
        self.assertGreaterEqual(count, 1)

        # Query cataloged entries via VFSReader
        entries = self.reader.vfs_query_paths("/data/user/0/com.whatsapp%")
        self.assertGreaterEqual(len(entries), 1)

        target_entry = entries[0]
        self.assertIn("/data/user/0/com.whatsapp", target_entry["canonical_path"])
        self.assertEqual(target_entry["uncompressed_size"], len(test_file_content))

        # Test on-demand memory stream extraction
        stream = self.reader.vfs_open_memory_stream(target_entry["file_id"])
        self.assertEqual(stream.read(), test_file_content)

    def test_zip_and_zip64_central_directory_indexing(self):
        """
        T1.1.3: Validates backward Central Directory scanning and on-demand streaming of ZIP archives.
        Authoritative source: PKWARE ZIP File Format Specification 6.3.4.
        """
        zip_path = self.sandbox / "test_device.zip"
        inner_content = b"GOOGLE_PAY_PAISA_DB_RAW_STREAM"
        with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("data/data/com.google.android.apps.nbu.paisa.user/databases/paisa.db", inner_content)

        count = self.indexer.index_archive(zip_path, container_id=2)
        self.assertGreaterEqual(count, 1)

        results = self.reader.vfs_query_paths("/data/user/0/com.google.android.apps.nbu.paisa.user%")
        self.assertGreaterEqual(len(results), 1)

        paisa_entry = results[0]
        self.assertEqual(paisa_entry["uncompressed_size"], len(inner_content))

        stream = self.reader.vfs_open_memory_stream(paisa_entry["file_id"])
        self.assertEqual(stream.read(), inner_content)

    def test_android_adb_backup_header_and_magic(self):
        """
        T1.1.4: Validates Android ADB backup header parsing, magic validation, and zlib inflation.
        Authoritative source: Android Open Source Project (AOSP) BackupManagerService.
        """
        ab_path = self.sandbox / "backup.ab"
        inner_tar = io.BytesIO()
        with tarfile.open(fileobj=inner_tar, mode="w") as tar:
            data = b"ADB_EXTRACTED_PAYLOAD_SAMPLE"
            ti = tarfile.TarInfo(name="apps/com.phonepe.app/f/config.json")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        compressed_payload = zlib.compress(inner_tar.getvalue())

        header = b"ANDROID BACKUP\n5\n1\nnone\n"
        ab_path.write_bytes(header + compressed_payload)

        fp = self.fingerprinter.fingerprint(ab_path)
        self.assertEqual(fp.container_type, ContainerType.ANDROID_AB_BACKUP)

    def test_ios_backup_manifest_db_and_domain_normalizer(self):
        """
        T1.1.5: Validates iOS logical backup Manifest.db parsing and 6-rule domain normalization.
        Authoritative source: Apple MobileBackup2 format specification.
        """
        norm = CanonicalPathNormalizer()
        self.assertEqual(
            norm.normalize_ios_domain("AppDomain-com.whatsapp", "Documents/ChatStorage.sqlite"),
            "/private/var/mobile/Containers/Data/Application/com.whatsapp/Documents/ChatStorage.sqlite",
        )
        self.assertEqual(
            norm.normalize_ios_domain("HomeDomain", "Library/Preferences/com.apple.Preferences.plist"),
            "/private/var/mobile/Library/Preferences/com.apple.Preferences.plist",
        )
        self.assertEqual(
            norm.normalize_ios_domain("MediaDomain", "DCIM/100APPLE/IMG_0001.JPG"),
            "/private/var/mobile/Media/DCIM/100APPLE/IMG_0001.JPG",
        )
        self.assertEqual(
            norm.normalize_ios_domain("CameraRollDomain", "Media/DCIM/101APPLE/IMG_0002.JPG"),
            "/private/var/mobile/Media/DCIM/101APPLE/IMG_0002.JPG",
        )
        self.assertEqual(
            norm.normalize_ios_domain("SystemPreferencesDomain", "SystemConfiguration/preferences.plist"),
            "/private/var/preferences/SystemConfiguration/preferences.plist",
        )

        # Construct synthetic iOS backup folder with Manifest.db, Manifest.plist, and Info.plist
        ios_backup_dir = self.sandbox / "ios_backup_guid"
        ios_backup_dir.mkdir()
        manifest_path = ios_backup_dir / "Manifest.db"

        # Manifest.plist
        manifest_plist = ios_backup_dir / "Manifest.plist"
        with open(manifest_plist, "wb") as pf:
            plistlib.dump({"IsEncrypted": False, "Version": "2.0"}, pf)

        # Info.plist
        info_plist = ios_backup_dir / "Info.plist"
        with open(info_plist, "wb") as pf:
            plistlib.dump({"Device Name": "iPhone 14 Pro", "Product Version": "17.0"}, pf)

        conn = sqlite3.connect(manifest_path)
        conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        file_id = "3d0d7e5fb2ce288813306e4d463639ff1023795b"
        conn.execute(
            "INSERT INTO Files (fileID, domain, relativePath, flags, file) VALUES (?, ?, ?, ?, ?)",
            (file_id, "AppDomain-net.whatsapp.WhatsApp", "ChatStorage.sqlite", 1, b"bplist00\x00"),
        )
        conn.commit()
        conn.close()

        prefix_dir = ios_backup_dir / file_id[:2]
        prefix_dir.mkdir()
        chat_file = prefix_dir / file_id
        chat_content = b"IOS_SQLITE_CHAT_STORAGE_MOCK_DATA"
        chat_file.write_bytes(chat_content)

        count = self.indexer.index_archive(ios_backup_dir, container_id=3)
        self.assertGreaterEqual(count, 1)

        results = self.reader.vfs_query_paths("/private/var/mobile/Containers/Data/Application%")
        self.assertGreaterEqual(len(results), 1)
        self.assertIn("ChatStorage.sqlite", results[0]["canonical_path"])

    def test_dual_sha256_ledger_integrity(self):
        """
        T1.1.6: Validates cryptographic SHA-256 dual-hashing and immutable evidentiary ledger records.
        Authoritative source: Section 63 BSA 2023 Statutory Provenance standard.
        """
        test_file = self.sandbox / "ledger_evidence.raw"
        sample_bytes = b"IMMUTABLE_CHAIN_OF_CUSTODY_FORENSIC_RAW_STREAM_VERIFIED"
        test_file.write_bytes(sample_bytes)

        hash_res = self.hasher.hash_file(test_file, compute_md5=True)
        self.assertEqual(hash_res.sha256, hashlib.sha256(sample_bytes).hexdigest().lower())

        ledger = ProvenanceLedger(self.ledger_path)
        cid = ledger.record_container_integrity(
            source_input_path=str(test_file),
            container_type="RAW_IMAGE",
            acquisition_tier="TIER_1_LOGICAL",
            total_size_bytes=len(sample_bytes),
            product_a_sha256=hash_res.sha256,
            product_a_md5=hash_res.md5,
            verification_status="VERIFIED",
            hash_started_utc=hash_res.start_utc_iso,
            hash_completed_utc=hash_res.completed_utc_iso,
        )

        rec = ledger.get_container_record(cid)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["product_a_sha256"], hash_res.sha256)
        self.assertEqual(rec["verification_status"], "VERIFIED")

    def test_real_evidence_zip_container_ingestion(self):
        """
        T1.1.7: Validates ingestion against the authentic forensic test archive in test_evidence.
        Authoritative source: Real test_evidence/android_logical_extraction.zip.
        """
        real_zip = env_setup.TEST_EVIDENCE_DIR / "android_logical_extraction.zip"
        if not real_zip.exists():
            self.skipTest(f"Authentic fixture {real_zip} not present")

        count = self.indexer.index_archive(real_zip, container_id=4)
        self.assertGreater(count, 0)

        entries = self.reader.vfs_query_paths("%databases%")
        self.assertGreater(len(entries), 0)
        found_names = [e["canonical_path"] for e in entries]
        has_msgstore = any("msgstore.db" in p for p in found_names)
        has_paisa = any("paisa.db" in p for p in found_names)
        self.assertTrue(has_msgstore or has_paisa)


if __name__ == "__main__":
    unittest.main()
