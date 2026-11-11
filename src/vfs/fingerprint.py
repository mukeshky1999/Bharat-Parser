"""
Container Magic-Byte Fingerprinting Engine.
Phase 1, Module 1.1, Section 3: Inspects raw headers and structures without trusting extensions alone.
"""

import gzip
import io
import logging
import os
import plistlib
import sqlite3
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from src.core.enums import ContainerType

logger = logging.getLogger(__name__)


SQLITE3_MAGIC = b"SQLite format 3\x00"
ZIP_LOCAL_MAGIC = b"PK\x03\x04"
ZIP_EOCD_MAGIC = b"PK\x05\x06"
TAR_USTAR_POSIX = b"ustar\x00"
TAR_USTAR_GNU = b"ustar  \x00"
GZIP_MAGIC = b"\x1f\x8b\x08"
ANDROID_AB_MAGIC = b"ANDROID BACKUP\n"
E01_MAGIC = b"EVF\t\r\n\xff\x00"
APFS_NXSB_MAGIC = b"NXSB"
GPT_EFI_MAGIC = b"EFI PART"


@dataclass(slots=True)
class FingerprintResult:
    """Result of container fingerprinting analysis."""
    container_type: ContainerType
    magic_description: str
    is_directory: bool
    is_encrypted: bool = False
    payload_paths: list[Path] = field(default_factory=list)


class ContainerFingerprinter:
    """Detects forensic extraction container formats using byte-level verification."""

    def fingerprint(self, target_path: Union[str, Path]) -> FingerprintResult:
        """Inspects target directory or file and returns exact ContainerType."""
        path = Path(target_path)
        if not path.exists():
            return FingerprintResult(
                container_type=ContainerType.UNKNOWN,
                magic_description="Path does not exist",
                is_directory=False
            )

        if path.is_dir():
            return self._fingerprint_directory(path)
        else:
            return self._fingerprint_file(path)

    def _fingerprint_directory(self, dir_path: Path) -> FingerprintResult:
        # Check for iOS Logical Backup: Manifest.db, Manifest.plist, Info.plist
        manifest_db = dir_path / "Manifest.db"
        manifest_plist = dir_path / "Manifest.plist"
        info_plist = dir_path / "Info.plist"

        if manifest_db.exists() and manifest_plist.exists() and info_plist.exists():
            # Check SQLite header on Manifest.db
            is_encrypted = False
            try:
                with open(manifest_db, "rb") as f:
                    header = f.read(16)
                if header == SQLITE3_MAGIC:
                    # Check Manifest.plist for encryption flag
                    try:
                        with open(manifest_plist, "rb") as pf:
                            plist_data = plistlib.load(pf)
                            if isinstance(plist_data, dict):
                                is_encrypted = bool(plist_data.get("IsEncrypted", False))
                    except Exception:
                        is_encrypted = False

                    return FingerprintResult(
                        container_type=ContainerType.IOS_BACKUP_DIR,
                        magic_description="iOS Logical Backup Directory with SQLite Manifest.db",
                        is_directory=True,
                        is_encrypted=is_encrypted,
                        payload_paths=[manifest_db]
                    )
            except OSError as err:
                logger.debug("Failed reading SQLite header on Manifest.db: %s", err)

        # Check for Cellebrite UFED package directory
        ufd_files = list(dir_path.glob("*.ufd")) + list(dir_path.glob("*.ufdx"))
        if ufd_files:
            payloads = [
                p for p in dir_path.iterdir()
                if p.suffix.lower() in {".tar", ".zip", ".bin", ".dd", ".img", ".ufdr"}
            ]
            return FingerprintResult(
                container_type=ContainerType.UFED_PACKAGE_DIR,
                magic_description=f"Cellebrite UFED Package Directory with descriptor {ufd_files[0].name}",
                is_directory=True,
                is_encrypted=False,
                payload_paths=payloads
            )

        # Check for generic Unpacked File-System directory
        indicators = ["data", "system", "private", "var"]
        subdirs = {p.name.lower() for p in dir_path.iterdir() if p.is_dir()}
        if any(ind in subdirs for ind in indicators):
            return FingerprintResult(
                container_type=ContainerType.UNPACKED_FS_DIR,
                magic_description="Unpacked Mobile File-System Directory Tree",
                is_directory=True,
                is_encrypted=False,
                payload_paths=[dir_path]
            )

        return FingerprintResult(
            container_type=ContainerType.UNPACKED_FS_DIR,
            magic_description="Generic Directory Container",
            is_directory=True,
            is_encrypted=False,
            payload_paths=[dir_path]
        )

    def _fingerprint_file(self, file_path: Path) -> FingerprintResult:
        file_size = file_path.stat().st_size
        with open(file_path, "rb") as f:
            header = f.read(1024)

        # 1. Android Backup Header
        if header.startswith(ANDROID_AB_MAGIC):
            lines = header.split(b"\n")
            is_enc = False
            if len(lines) >= 4 and lines[3].strip() != b"none":
                is_enc = True
            return FingerprintResult(
                container_type=ContainerType.ANDROID_AB_BACKUP,
                magic_description="Android ADB Backup Archive",
                is_directory=False,
                is_encrypted=is_enc,
                payload_paths=[file_path]
            )

        # 2. EnCase E01 Image Header
        if header.startswith(E01_MAGIC):
            return FingerprintResult(
                container_type=ContainerType.ENCASE_E01_IMAGE,
                magic_description="EnCase EWF Expert Witness Compression Image (E01)",
                is_directory=False,
                is_encrypted=False,
                payload_paths=[file_path]
            )

        # 3. APFS or GPT Raw Disk Image
        if len(header) >= 36 and header[32:36] == APFS_NXSB_MAGIC:
            return FingerprintResult(
                container_type=ContainerType.RAW_DISK_OR_APFS,
                magic_description="Raw APFS Container Block Dump (NXSB Magic)",
                is_directory=False,
                is_encrypted=False,
                payload_paths=[file_path]
            )
        if len(header) >= 520 and header[512:520] == GPT_EFI_MAGIC:
            return FingerprintResult(
                container_type=ContainerType.RAW_DISK_OR_APFS,
                magic_description="Raw Physical Disk Image with GUID Partition Table (GPT)",
                is_directory=False,
                is_encrypted=False,
                payload_paths=[file_path]
            )

        # 4. GZIP Stream (.tar.gz)
        if header.startswith(GZIP_MAGIC):
            try:
                with gzip.open(file_path, "rb") as gz:
                    decompressed_head = gz.read(512)
                if len(decompressed_head) >= 263 and (
                    decompressed_head[257:263] == TAR_USTAR_POSIX or
                    decompressed_head[257:265] == TAR_USTAR_GNU
                ):
                    return FingerprintResult(
                        container_type=ContainerType.TAR_GZ_COMPRESSED,
                        magic_description="GZIP Compressed TAR Archive (TAR.GZ / TGZ)",
                        is_directory=False,
                        is_encrypted=False,
                        payload_paths=[file_path]
                    )
            except Exception as err:
                logger.debug("Failed decompressing header as GZIP TAR: %s", err)

        # 5. Uncompressed TAR
        if len(header) >= 263 and (
            header[257:263] == TAR_USTAR_POSIX or
            header[257:265] == TAR_USTAR_GNU
        ):
            return FingerprintResult(
                container_type=ContainerType.TAR_UNCOMPRESSED,
                magic_description="POSIX USTAR / GNU Standard Tape Archive (TAR)",
                is_directory=False,
                is_encrypted=False,
                payload_paths=[file_path]
            )

        # 6. ZIP / UFDR
        if header.startswith(ZIP_LOCAL_MAGIC):
            # Check if UFDR or Standard ZIP
            is_ufdr = file_path.suffix.lower() == ".ufdr"
            if not is_ufdr:
                try:
                    with zipfile.ZipFile(file_path, "r") as zf:
                        names = set(zf.namelist())
                        if "report.xml" in names or any("report.xml" in n for n in names):
                            is_ufdr = True
                except Exception as err:
                    logger.debug("Non-standard ZIP structure during UFDR check: %s", err)

            target_type = ContainerType.CELLEBRITE_UFDR if is_ufdr else ContainerType.STANDARD_ZIP
            desc = "Cellebrite UFDR Extraction Package" if is_ufdr else "Standard ZIP / ZIP64 Archive"
            return FingerprintResult(
                container_type=target_type,
                magic_description=desc,
                is_directory=False,
                is_encrypted=False,
                payload_paths=[file_path]
            )

        return FingerprintResult(
            container_type=ContainerType.UNKNOWN,
            magic_description="Unknown Binary or Container Signature",
            is_directory=False,
            is_encrypted=False,
            payload_paths=[file_path]
        )
