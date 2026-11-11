"""
Tests for Phase 1 Module 1.1: Virtual Filesystem (VFS) & Streaming Archive Indexer.
Enforces:
1. Container Magic-Byte Fingerprinting (directory & single-file magic bytes).
2. Canonical Path Normalization (6 rules).
3. Zero-Extraction Header Indexing for TAR (USTAR, PAX, GNU LongLink, symlinks).
4. Zero-Extraction Header Indexing for ZIP & ZIP64 (EOCD, ZIP64 EOCD, extra field 0x0001).
5. iOS Logical Backup Indexing (Manifest.db + bplist00 metadata decoding).
6. SQLite Database Catalog & Batch Commit (vfs_index.sqlite schema & indexes).
7. On-Demand Stream API (vfs_query_paths, vfs_open_memory_stream, Windows illegal character survival).
8. SQLite Co-File Family Auto-Discovery & Staging (UUID folder, target.db + target.db-wal, read-only Product B1, writable work copy).
9. Non-negotiable forensic invariants & canonical enums (5D State, Residual Confidence, Dual Timestamps, Forensic Groups).
"""

import io
import os
import stat
import struct
import tarfile
import zipfile
import plistlib
import sqlite3
import pytest
from pathlib import Path

# Production module imports (failing during Phase A RED phase)
from src.core.enums import (
    ContainerType,
    EntryType,
    CompressionMethod,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
    ResidualConfidence,
    ForensicGroup,
)
from src.core.timestamps import ForensicTimestamp
from src.vfs.fingerprint import ContainerFingerprinter, FingerprintResult
from src.vfs.normalizer import CanonicalPathNormalizer
from src.vfs.indexer import VFSIndexer, VFSIndexEntry
from src.vfs.reader import VFSReader, StagedSQLiteFamily


# ============================================================================
# Helpers to construct realistic binary fixtures
# ============================================================================

def make_tar_bytes(files_dict: dict[str, bytes], pax_attrs: dict[str, dict[str, str]] | None = None) -> bytes:
    """Builds a real binary TAR stream with optional PAX extended attributes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in files_dict.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = 1714800000  # 2024-05-04 05:20:00 UTC
            ti.mode = 0o644
            if pax_attrs and name in pax_attrs:
                ti.pax_headers = pax_attrs[name]
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def make_zip_bytes(files_dict: dict[str, bytes]) -> bytes:
    """Builds a standard real binary ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in files_dict.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_zip64_bytes(files_dict: dict[str, bytes]) -> bytes:
    """Builds a real ZIP64 archive with ZIP64 EOCD and 64-bit records."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED, force_zip64=True) as zf:
        for name, data in files_dict.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_ios_backup_manifest_db(db_path: Path, files_rows: list[tuple[str, str, str, int, bytes]]):
    """Creates a real iOS Manifest.db SQLite database with Files table."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE Files (
            fileID TEXT PRIMARY KEY,
            domain TEXT,
            relativePath TEXT,
            flags INTEGER,
            file BLOB
        )
    """)
    cur.executemany("INSERT INTO Files VALUES (?, ?, ?, ?, ?)", files_rows)
    conn.commit()
    conn.close()


# ============================================================================
# Test Cases
# ============================================================================

class TestContainerFingerprinting:
    """Stage 1: Container Magic-Byte Fingerprinting Engine Tests."""

    def test_fingerprint_tar_uncompressed_magic(self, tmp_path):
        # Create a 512-byte block with 'ustar\0' at offset 257
        block = bytearray(512)
        block[257:263] = b"ustar\x00"
        tar_file = tmp_path / "test.tar"
        tar_file.write_bytes(block)

        fp = ContainerFingerprinter()
        res = fp.fingerprint(tar_file)
        assert res.container_type == ContainerType.TAR_UNCOMPRESSED
        assert res.magic_description.startswith("POSIX USTAR")

    def test_fingerprint_tar_gz_magic(self, tmp_path):
        # GZIP magic 1F 8B 08 containing compressed tar block
        tar_data = make_tar_bytes({"test.txt": b"forensic data"})
        import gzip
        gz_data = gzip.compress(tar_data)
        gz_file = tmp_path / "test.tar.gz"
        gz_file.write_bytes(gz_data)

        fp = ContainerFingerprinter()
        res = fp.fingerprint(gz_file)
        assert res.container_type == ContainerType.TAR_GZ_COMPRESSED

    def test_fingerprint_zip_and_ufdr(self, tmp_path):
        # Standard ZIP
        zip_data = make_zip_bytes({"test.txt": b"content"})
        zip_file = tmp_path / "test.zip"
        zip_file.write_bytes(zip_data)

        fp = ContainerFingerprinter()
        res_zip = fp.fingerprint(zip_file)
        assert res_zip.container_type == ContainerType.STANDARD_ZIP

        # UFDR with report.xml at root
        ufdr_data = make_zip_bytes({"report.xml": b"<report/>", "data.db": b"sqlite"})
        ufdr_file = tmp_path / "extraction.ufdr"
        ufdr_file.write_bytes(ufdr_data)

        res_ufdr = fp.fingerprint(ufdr_file)
        assert res_ufdr.container_type == ContainerType.CELLEBRITE_UFDR

    def test_fingerprint_android_ab_and_e01(self, tmp_path):
        # Android Backup header
        ab_data = b"ANDROID BACKUP\n1\n0\nnone\n" + b"\x00" * 100
        ab_file = tmp_path / "backup.ab"
        ab_file.write_bytes(ab_data)

        fp = ContainerFingerprinter()
        res_ab = fp.fingerprint(ab_file)
        assert res_ab.container_type == ContainerType.ANDROID_AB_BACKUP

        # EnCase E01 header
        e01_data = b"EVF\t\r\n\xff\x00" + b"\x00" * 100
        e01_file = tmp_path / "evidence.E01"
        e01_file.write_bytes(e01_data)

        res_e01 = fp.fingerprint(e01_file)
        assert res_e01.container_type == ContainerType.ENCASE_E01_IMAGE

    def test_fingerprint_directories(self, tmp_path):
        # iOS Backup Directory
        ios_dir = tmp_path / "ios_backup"
        ios_dir.mkdir()
        (ios_dir / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
        (ios_dir / "Info.plist").write_bytes(plistlib.dumps({"Device Name": "iPhone"}))
        conn = sqlite3.connect(ios_dir / "Manifest.db")
        conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY)")
        conn.close()

        fp = ContainerFingerprinter()
        res_ios = fp.fingerprint(ios_dir)
        assert res_ios.container_type == ContainerType.IOS_BACKUP_DIR

        # UFED Package Directory
        ufed_dir = tmp_path / "ufed_pkg"
        ufed_dir.mkdir()
        (ufed_dir / "extraction.ufd").write_text("[General]\nDevice=Android\n")
        (ufed_dir / "dump.tar").write_bytes(b"ustar\x00")

        res_ufed = fp.fingerprint(ufed_dir)
        assert res_ufed.container_type == ContainerType.UFED_PACKAGE_DIR


class TestCanonicalPathNormalizer:
    """Stage 3: 6-Step Canonical Path Normalization Rules Tests."""

    def test_windows_backslashes_and_double_slashes(self):
        norm = CanonicalPathNormalizer()
        assert norm.normalize_path("data\\system\\packages.xml") == "/data/system/packages.xml"
        assert norm.normalize_path("//data///user//0//com.phonepe.app") == "/data/user/0/com.phonepe.app"

    def test_strip_vendor_prefixes(self):
        norm = CanonicalPathNormalizer()
        assert norm.normalize_path("/fs/data/system/packages.xml") == "/data/system/packages.xml"
        assert norm.normalize_path("/root/private/var/mobile/Library/SMS/sms.db") == "/private/var/mobile/Library/SMS/sms.db"
        assert norm.normalize_path("/Dump/data/data/com.whatsapp/databases/msgstore.db") == "/data/user/0/com.whatsapp/databases/msgstore.db"
        assert norm.normalize_path("/files/sdcard/DCIM/photo.jpg") == "/data/media/0/DCIM/photo.jpg"

    def test_ios_var_to_private_var(self):
        norm = CanonicalPathNormalizer()
        assert norm.normalize_path("/var/mobile/Library/SMS/sms.db") == "/private/var/mobile/Library/SMS/sms.db"
        assert norm.normalize_path("/var/wireless/Library/CallHistoryDB/CallHistory.storedata") == "/private/var/wireless/Library/CallHistoryDB/CallHistory.storedata"

    def test_android_data_data_to_data_user_0(self):
        norm = CanonicalPathNormalizer()
        assert norm.normalize_path("/data/data/com.whatsapp/databases/msgstore.db") == "/data/user/0/com.whatsapp/databases/msgstore.db"

    def test_android_shared_storage_canonicalization(self):
        norm = CanonicalPathNormalizer()
        assert norm.normalize_path("/sdcard/Pictures/Screenshots/receipt.png") == "/data/media/0/Pictures/Screenshots/receipt.png"
        assert norm.normalize_path("/mnt/sdcard/Download/file.pdf") == "/data/media/0/Download/file.pdf"
        assert norm.normalize_path("/storage/emulated/10/WhatsApp/media.jpg") == "/data/media/10/WhatsApp/media.jpg"

    def test_ios_backup_domain_mapping(self):
        norm = CanonicalPathNormalizer()
        assert norm.normalize_ios_domain("HomeDomain", "Library/SMS/sms.db") == "/private/var/mobile/Library/SMS/sms.db"
        assert norm.normalize_ios_domain("WirelessDomain", "Library/CallHistoryDB/CallHistory.storedata") == "/private/var/wireless/Library/CallHistoryDB/CallHistory.storedata"
        assert norm.normalize_ios_domain("CameraRollDomain", "Media/PhotoData/Photos.sqlite") == "/private/var/mobile/Media/PhotoData/Photos.sqlite"
        assert norm.normalize_ios_domain("SystemPreferencesDomain", "SystemConfiguration/com.apple.wifi.known-networks.plist") == "/private/var/preferences/SystemConfiguration/com.apple.wifi.known-networks.plist"
        assert norm.normalize_ios_domain("KeychainDomain", "keychain-backup.plist") == "/private/var/Keychains/keychain-backup.plist"
        assert norm.normalize_ios_domain("AppDomain-com.phonepe.app", "Documents/wallet.db") == "/private/var/mobile/Containers/Data/Application/com.phonepe.app/Documents/wallet.db"
        assert norm.normalize_ios_domain("AppDomainGroup-group.net.one97.paytm", "shared.plist") == "/private/var/mobile/Containers/Shared/AppGroup/group.net.one97.paytm/shared.plist"


class TestVFSIndexerAndCatalog:
    """Stage 2 & Stage 4: Zero-Extraction Header Indexing and SQLite Catalog Tests."""

    def test_index_uncompressed_tar_with_pax_and_xattrs(self, tmp_path):
        catalog_db = tmp_path / "vfs_index.sqlite"
        pax_data = {
            "root/data/system/packages.xml": {
                "path": "/data/system/packages.xml",
                "mtime": "1714800000.123456",
                "LIBARCHIVE.creationtime": "1714700000.654321",
                "SCHILY.xattr.security.selinux": "u:object_r:system_data_file:s0",
            }
        }
        tar_bytes = make_tar_bytes(
            {"root/data/system/packages.xml": b"<packages><package name='com.phonepe'/></packages>"},
            pax_attrs=pax_data
        )
        archive_path = tmp_path / "test_extract.tar"
        archive_path.write_bytes(tar_bytes)

        indexer = VFSIndexer(catalog_db_path=catalog_db)
        container_id = 1
        count = indexer.index_archive(archive_path, container_id=container_id)
        assert count == 1

        # Check vfs_index schema & records
        conn = sqlite3.connect(catalog_db)
        cur = conn.cursor()
        cur.execute("SELECT canonical_path, parent_dir_path, filename, uncompressed_size, archive_data_offset, compression_method FROM vfs_index")
        row = cur.fetchone()
        conn.close()

        assert row is not None
        canonical_path, parent_dir, filename, size, offset, comp_method = row
        assert canonical_path == "/data/system/packages.xml"
        assert parent_dir == "/data/system"
        assert filename == "packages.xml"
        assert size == len(b"<packages><package name='com.phonepe'/></packages>")
        assert offset > 0
        assert comp_method == CompressionMethod.RAW_STORED.value

    def test_index_zip_and_zip64(self, tmp_path):
        catalog_db = tmp_path / "vfs_index.sqlite"
        zip_bytes = make_zip64_bytes({
            "fs/data/user/0/com.whatsapp/databases/msgstore.db": b"SQLITE_DATA_MSGSTORE",
            "fs/data/user/0/com.whatsapp/databases/wa.db": b"SQLITE_DATA_WA"
        })
        archive_path = tmp_path / "whatsapp_ffs.zip"
        archive_path.write_bytes(zip_bytes)

        indexer = VFSIndexer(catalog_db_path=catalog_db)
        count = indexer.index_archive(archive_path, container_id=2)
        assert count == 2

        conn = sqlite3.connect(catalog_db)
        cur = conn.cursor()
        cur.execute("SELECT canonical_path, filename, uncompressed_size, compression_method FROM vfs_index ORDER BY filename")
        rows = cur.fetchall()
        conn.close()

        assert len(rows) == 2
        assert rows[0][0] == "/data/user/0/com.whatsapp/databases/msgstore.db"
        assert rows[0][1] == "msgstore.db"
        assert rows[1][0] == "/data/user/0/com.whatsapp/databases/wa.db"

    def test_index_ios_backup_manifest_db(self, tmp_path):
        catalog_db = tmp_path / "vfs_index.sqlite"
        backup_dir = tmp_path / "ios_backup"
        backup_dir.mkdir()
        (backup_dir / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
        (backup_dir / "Info.plist").write_bytes(plistlib.dumps({"Product Type": "iPhone14,2"}))

        file_id = "3d0d7e5fb2ce288813306e4d4636395e047a3d28"
        file_folder = backup_dir / file_id[:2]
        file_folder.mkdir(parents=True, exist_ok=True)
        disk_file = file_folder / file_id
        disk_file.write_bytes(b"SMS_DATABASE_BYTES")

        # Encode realistic bplist00 metadata in file column
        meta_dict = {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {"root": plistlib.UID(1)},
            "$objects": [
                "$null",
                {
                    "$class": plistlib.UID(2),
                    "Size": len(b"SMS_DATABASE_BYTES"),
                    "Birth": 736500000.0,
                    "LastModified": 736510000.0,
                    "LastStatusChange": 736510000.0,
                    "Mode": 33188,
                    "ProtectionClass": 3,
                },
                {"$classes": ["NSDictionary", "NSObject"], "$classname": "NSDictionary"}
            ]
        }
        bplist_blob = plistlib.dumps(meta_dict, fmt=plistlib.FMT_BINARY)

        manifest_db = backup_dir / "Manifest.db"
        make_ios_backup_manifest_db(manifest_db, [
            (file_id, "HomeDomain", "Library/SMS/sms.db", 1, bplist_blob)
        ])

        indexer = VFSIndexer(catalog_db_path=catalog_db)
        count = indexer.index_archive(backup_dir, container_id=3)
        assert count == 1

        conn = sqlite3.connect(catalog_db)
        cur = conn.cursor()
        cur.execute("SELECT canonical_path, filename, backup_file_id_sha1, uncompressed_size FROM vfs_index")
        row = cur.fetchone()
        conn.close()

        assert row is not None
        assert row[0] == "/private/var/mobile/Library/SMS/sms.db"
        assert row[1] == "sms.db"
        assert row[2] == file_id
        assert row[3] == len(b"SMS_DATABASE_BYTES")


class TestVFSReaderAndStreaming:
    """Stage 5: On-Demand Stream & SQLite Co-File Materialization API Tests."""

    def test_windows_illegal_characters_and_case_survival(self, tmp_path):
        catalog_db = tmp_path / "vfs_index.sqlite"
        tar_payloads = {
            "root/data/user/0/com.phonepe.app/Cache_A.txt": b"CACHE_UPPERCASE",
            "root/data/user/0/com.phonepe.app/cache_a.txt": b"cache_lowercase",
            "root/data/user/0/com.phonepe.app/tx?id=100&ref=upi:vpa*": b"URL_WITH_SPECIAL_CHARS"
        }
        tar_bytes = make_tar_bytes(tar_payloads)
        archive_path = tmp_path / "phonepe.tar"
        archive_path.write_bytes(tar_bytes)

        indexer = VFSIndexer(catalog_db_path=catalog_db)
        indexer.index_archive(archive_path, container_id=10)

        reader = VFSReader(catalog_db_path=catalog_db)
        files = reader.vfs_query_paths("/data/user/0/com.phonepe.app/%")
        assert len(files) == 3

        # Stream all three files via memory stream without touching host Windows filesystem
        for f in files:
            stream = reader.vfs_open_memory_stream(f["file_id"])
            content = stream.read()
            if f["filename"] == "Cache_A.txt":
                assert content == b"CACHE_UPPERCASE"
            elif f["filename"] == "cache_a.txt":
                assert content == b"cache_lowercase"
            elif "tx?id=100" in f["filename"]:
                assert content == b"URL_WITH_SPECIAL_CHARS"

    def test_sqlite_co_file_family_materialization(self, tmp_path):
        catalog_db = tmp_path / "vfs_index.sqlite"
        staging_dir = tmp_path / "staging_workspace"
        staging_dir.mkdir()

        tar_payloads = {
            "root/private/var/mobile/Library/SMS/sms.db": b"SQLITE_SMS_DB_HEADER_AND_PAGES",
            "root/private/var/mobile/Library/SMS/sms.db-wal": b"WAL_FRAMES_CONTAINING_NEW_MESSAGES",
            "root/private/var/mobile/Library/SMS/sms.db-shm": b"SHM_INDEX_BYTES",
            "root/private/var/mobile/Library/SMS/sms.db-journal": b"JOURNAL_ROLLBACK_BYTES"
        }
        tar_bytes = make_tar_bytes(tar_payloads)
        archive_path = tmp_path / "ios_sms_dump.tar"
        archive_path.write_bytes(tar_bytes)

        indexer = VFSIndexer(catalog_db_path=catalog_db)
        indexer.index_archive(archive_path, container_id=20)

        reader = VFSReader(catalog_db_path=catalog_db)
        sms_rows = reader.vfs_query_paths("/private/var/mobile/Library/SMS/sms.db")
        assert len(sms_rows) == 1
        sms_file_id = sms_rows[0]["file_id"]

        # Materialize SQLite Family
        family = reader.vfs_stage_sqlite_family(sms_file_id, staging_dir=staging_dir)

        assert isinstance(family, StagedSQLiteFamily)
        assert family.primary_db_path.exists()
        assert family.primary_db_path.name == "target.db"
        assert family.wal_path is not None and family.wal_path.exists()
        assert family.wal_path.name == "target.db-wal"
        assert family.journal_path is not None and family.journal_path.exists()
        assert family.journal_path.name == "target.db-journal"

        # Check Product B1 SHA-256 hashes are populated
        import hashlib
        expected_db_sha256 = hashlib.sha256(b"SQLITE_SMS_DB_HEADER_AND_PAGES").hexdigest()
        expected_wal_sha256 = hashlib.sha256(b"WAL_FRAMES_CONTAINING_NEW_MESSAGES").hexdigest()
        assert family.product_b1_db_sha256 == expected_db_sha256
        assert family.companion_wal_sha256 == expected_wal_sha256

        # Check Product B1 files are marked Read-Only
        mode_db = os.stat(family.primary_db_path).st_mode
        assert not (mode_db & stat.S_IWUSR), "Product B1 target.db must be read-only"

        # Check writable working copy exists in work/ folder (Product B2)
        assert family.working_copy_db_path.exists()
        assert family.working_copy_wal_path is not None and family.working_copy_wal_path.exists()
        mode_work_db = os.stat(family.working_copy_db_path).st_mode
        assert bool(mode_work_db & stat.S_IWUSR), "Working copy must be writable"

        # Check 5D Evidentiary State registration
        assert family.evidentiary_state.existence == EvidentiaryExistence.OBSERVED
        assert family.evidentiary_state.storage_layer == EvidentiaryStorage.LIVE_RECORD
        assert family.evidentiary_state.forensic_group == ForensicGroup.G01_INGESTION_AND_OWNERSHIP
