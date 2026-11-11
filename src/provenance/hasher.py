"""
Dual SHA-256 Hashing Engine (Product A & Product B) and Vendor Log Verifier.
Phase 1, Module 1.2, Section 3.
"""

import configparser
import hashlib
import io
import json
import logging
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional, Union, Dict, Tuple

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ProductAHashResult:
    """Cryptographic hash result for an original evidence container file."""
    sha256: str
    md5: Optional[str]
    total_bytes: int
    start_utc_iso: str
    completed_utc_iso: str


@dataclass(slots=True)
class FolderCompositeHashResult:
    """Cryptographic composite hash and canonical manifest for a folder extraction."""
    composite_sha256: str
    manifest_content: str
    file_hashes: Dict[str, str]
    total_bytes: int
    start_utc_iso: str
    completed_utc_iso: str


@dataclass(slots=True)
class VendorVerificationResult:
    """Acquisition tool log comparison status."""
    status: str
    vendor_expected_hash: Optional[str]
    vendor_log_path: Optional[str]


class ProductAHasher:
    """Computes courtroom-defensible baseline hashes for evidence containers."""

    CHUNK_SIZE = 8 * 1024 * 1024  # 8 MB streaming buffer for flat RAM consumption

    def hash_file(
        self,
        file_path: Union[str, Path],
        compute_md5: bool = False,
        chunk_size: Optional[int] = None
    ) -> ProductAHashResult:
        """
        Streams a single container file and computes SHA-256 (and optional MD5) in constant RAM.
        """
        path = Path(file_path)
        buffer_size = chunk_size or self.CHUNK_SIZE
        start_dt = datetime.now(timezone.utc)

        sha256_obj = hashlib.sha256()
        md5_obj = hashlib.md5() if compute_md5 else None
        total_bytes = 0

        with open(path, "rb") as f:
            while True:
                chunk = f.read(buffer_size)
                if not chunk:
                    break
                sha256_obj.update(chunk)
                if md5_obj:
                    md5_obj.update(chunk)
                total_bytes += len(chunk)

        end_dt = datetime.now(timezone.utc)

        return ProductAHashResult(
            sha256=sha256_obj.hexdigest().lower(),
            md5=md5_obj.hexdigest().lower() if md5_obj else None,
            total_bytes=total_bytes,
            start_utc_iso=start_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            completed_utc_iso=end_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )

    def hash_folder(
        self,
        folder_path: Union[str, Path],
        chunk_size: Optional[int] = None
    ) -> FolderCompositeHashResult:
        """
        Constructs a cross-OS deterministic Canonical Hash Manifest for directory extractions.
        Files are sorted strictly by lexicographical UTF-8 byte order of their NFC relative paths.
        """
        root = Path(folder_path).resolve()
        buffer_size = chunk_size or self.CHUNK_SIZE
        start_dt = datetime.now(timezone.utc)

        # 1. Enumerate all regular files recursively
        all_files: list[tuple[bytes, str, Path]] = []
        for p in root.rglob("*"):
            if p.is_file():
                rel_path = str(p.relative_to(root)).replace("\\", "/")
                rel_path_nfc = unicodedata.normalize("NFC", rel_path)
                sort_key = rel_path_nfc.encode("utf-8")
                all_files.append((sort_key, rel_path_nfc, p))

        # 2. Sort strictly by UTF-8 bytes
        all_files.sort(key=lambda x: x[0])

        file_hashes: Dict[str, str] = {}
        manifest_lines: list[str] = []
        total_bytes = 0

        for _, rel_nfc, p in all_files:
            file_sha256_obj = hashlib.sha256()
            with open(p, "rb") as f:
                while True:
                    chunk = f.read(buffer_size)
                    if not chunk:
                        break
                    file_sha256_obj.update(chunk)
                    total_bytes += len(chunk)

            f_hash = file_sha256_obj.hexdigest().lower()
            file_hashes[rel_nfc] = f_hash
            manifest_lines.append(f"{f_hash} *{rel_nfc}\n")

        manifest_content = "".join(manifest_lines)
        composite_sha256 = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest().lower()
        end_dt = datetime.now(timezone.utc)

        return FolderCompositeHashResult(
            composite_sha256=composite_sha256,
            manifest_content=manifest_content,
            file_hashes=file_hashes,
            total_bytes=total_bytes,
            start_utc_iso=start_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            completed_utc_iso=end_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )

    def verify_vendor_hash(
        self,
        computed_hash: str,
        vendor_log_path: Optional[Union[str, Path]]
    ) -> VendorVerificationResult:
        """
        Cross-verifies the newly calculated Product A hash against vendor logs (UFD, UFDX, GrayKey).
        """
        if vendor_log_path is None:
            return VendorVerificationResult(
                status="SELF_ANCHORED_NO_VENDOR_LOG",
                vendor_expected_hash=None,
                vendor_log_path=None
            )

        log_path = Path(vendor_log_path)
        if not log_path.exists():
            return VendorVerificationResult(
                status="SELF_ANCHORED_NO_VENDOR_LOG",
                vendor_expected_hash=None,
                vendor_log_path=str(log_path)
            )

        content = log_path.read_text(encoding="utf-8", errors="replace")
        extracted_hash: Optional[str] = None

        # 1. Cellebrite UFD/UFDX INI parsing
        if log_path.suffix.lower() in {".ufd", ".ufdx"} or "[General]" in content or "[SHA256]" in content:
            cp = configparser.ConfigParser(interpolation=None)
            try:
                cp.read_string(content)
                for section in ("SHA256", "Hashes", "General"):
                    if cp.has_section(section):
                        for _, val in cp.items(section):
                            val_clean = val.strip().lower()
                            if len(val_clean) == 64 and re.fullmatch(r"[a-f0-9]{64}", val_clean):
                                extracted_hash = val_clean
                                break
                    if extracted_hash:
                        break
            except Exception as err:
                logger.debug("ConfigParser failed for vendor log, using regex: %s", err)

        # 2. Fallback regex for 64-hex SHA-256 in text/JSON
        if not extracted_hash:
            matches = re.findall(r"\b([a-fA-F0-9]{64})\b", content)
            if matches:
                # Find matching one or default to first
                for m in matches:
                    if m.lower() == computed_hash.lower():
                        extracted_hash = m.lower()
                        break
                if not extracted_hash:
                    extracted_hash = matches[0].lower()

        if extracted_hash:
            if extracted_hash.lower() == computed_hash.lower():
                return VendorVerificationResult(
                    status="VERIFIED_MATCH",
                    vendor_expected_hash=extracted_hash,
                    vendor_log_path=str(log_path)
                )
            else:
                return VendorVerificationResult(
                    status="CRITICAL_MISMATCH",
                    vendor_expected_hash=extracted_hash,
                    vendor_log_path=str(log_path)
                )

        return VendorVerificationResult(
            status="SELF_ANCHORED_NO_VENDOR_LOG",
            vendor_expected_hash=None,
            vendor_log_path=str(log_path)
        )


class TeeHasher:
    """Zero-pass streaming writer and hasher for Product B1 pre-open staging."""

    def stream_and_hash(
        self,
        source_stream: BinaryIO,
        destination_path: Union[str, Path],
        chunk_size: int = 64 * 1024
    ) -> Tuple[str, int]:
        """
        Simultaneously writes chunks to destination and updates SHA-256 state machine.
        Returns (sha256_hexdigest, total_bytes_written).
        """
        dest = Path(destination_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        sha256_obj = hashlib.sha256()
        total_written = 0

        with open(dest, "wb") as f_out:
            while True:
                chunk = source_stream.read(chunk_size)
                if not chunk:
                    break
                f_out.write(chunk)
                sha256_obj.update(chunk)
                total_written += len(chunk)

        return sha256_obj.hexdigest().lower(), total_written
