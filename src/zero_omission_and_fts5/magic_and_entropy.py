"""
Magic-Byte Discrepancy Detector & Shannon Entropy + Chi-Square Classifier (Sub-Engine 8.2B).
Unmasks disguised file extensions and disambiguates compressed media from true cryptographic ciphertext.
"""

import math
import os
from typing import Optional

from src.zero_omission_and_fts5.models import (
    DetectedMagicSignature,
    EntropyCryptoClassification,
    EntropyAnalysisResult,
    MagicInspectionResult,
)


class MagicByteDiscrepancyDetector:
    """Inspects header and footer bytes of files to detect disguised file formats."""

    # Map signature to list of legitimate extensions
    SIGNATURE_EXTENSIONS = {
        DetectedMagicSignature.SQLITE_3_DATABASE: [
            ".db",
            ".sqlite",
            ".sqlite3",
            ".sqlitedb",
            ".storedata",
            ".db3",
            "rkstorage",
        ],
        DetectedMagicSignature.SQLITE_WAL_JOURNAL: [
            "-wal",
            ".wal",
            "-journal",
            ".journal",
        ],
        DetectedMagicSignature.APPLE_BINARY_PLIST: [
            ".plist",
            ".icloud",
            ".flashed",
        ],
        DetectedMagicSignature.ANDROID_BINARY_XML_ABX: [
            ".xml",
            ".abx",
        ],
        DetectedMagicSignature.APPLE_BIOME_SEGB: [
            ".segb",
            ".stream",
        ],
        DetectedMagicSignature.LEVELDB_SSTABLE_LDB: [
            ".ldb",
            ".sst",
        ],
        DetectedMagicSignature.JAVA_DALVIK_DEX: [
            ".dex",
        ],
        DetectedMagicSignature.ELF_EXECUTABLE_OR_SO: [
            ".so",
            ".bin",
            ".elf",
            "",
        ],
        DetectedMagicSignature.ZIP_APK_JAR_DOCX_XLSX: [
            ".zip",
            ".apk",
            ".jar",
            ".docx",
            ".xlsx",
            ".pptx",
        ],
        DetectedMagicSignature.RAR_OR_7ZIP_ARCHIVE: [
            ".rar",
            ".7z",
        ],
        DetectedMagicSignature.GZIP_ZSTD_LZ4_BZIP2: [
            ".gz",
            ".zst",
            ".lz4",
            ".bz2",
        ],
        DetectedMagicSignature.PDF_DOCUMENT: [
            ".pdf",
        ],
        DetectedMagicSignature.JPEG_PNG_WEBP_HEIC_GIF: [
            ".jpg",
            ".jpeg",
            ".png",
            ".webp",
            ".heic",
            ".mp4",
            ".mov",
            ".gif",
        ],
        DetectedMagicSignature.KTX_GPU_TEXTURE: [
            ".ktx",
        ],
        DetectedMagicSignature.WHATSAPP_CRYPT_BACKUP: [
            ".crypt12",
            ".crypt14",
            ".crypt15",
        ],
        DetectedMagicSignature.LUKS_OR_VERACRYPT_HEADER: [
            ".luks",
            ".img",
        ],
        DetectedMagicSignature.OPENPGP_OR_AGE_ARMOR: [
            ".asc",
            ".gpg",
            ".age",
        ],
        DetectedMagicSignature.PKCS12_OR_PEM_PRIVATE_KEY: [
            ".pem",
            ".key",
            ".p12",
            ".pfx",
        ],
    }

    def detect_signature(self, head: bytes, tail: bytes) -> tuple[DetectedMagicSignature, str]:
        """Identifies binary magic signature from head (up to 1024 bytes) and tail (16 bytes)."""
        if not head:
            return DetectedMagicSignature.EMPTY_FILE, ""

        raw_hex = head[:16].hex()

        # 1. SQLite format 3
        if head.startswith(b"SQLite format 3\x00"):
            return DetectedMagicSignature.SQLITE_3_DATABASE, raw_hex

        # 2. SQLite WAL
        if head.startswith(b"\x37\x7f\x06\x82") or head.startswith(b"\x37\x7f\x06\x83"):
            return DetectedMagicSignature.SQLITE_WAL_JOURNAL, raw_hex

        # 3. Apple Binary Plist
        if head.startswith(b"bplist00") or head.startswith(b"bplist15") or head.startswith(b"bplist16"):
            return DetectedMagicSignature.APPLE_BINARY_PLIST, raw_hex

        # 4. Android Binary XML (ABX)
        if head.startswith(b"ABX\x00"):
            return DetectedMagicSignature.ANDROID_BINARY_XML_ABX, raw_hex

        # 5. Apple Biome SEGB
        if head.startswith(b"SEGB") or (tail and tail[-4:] == b"SEGB"):
            return DetectedMagicSignature.APPLE_BIOME_SEGB, raw_hex

        # 6. LevelDB Table Magic (EOF-8)
        if tail and len(tail) >= 8 and tail[-8:] == b"\x57\xfb\x80\x8b\x24\x75\x47\xdb":
            return DetectedMagicSignature.LEVELDB_SSTABLE_LDB, raw_hex

        # 7. Java Dalvik DEX
        if head.startswith(b"dex\n"):
            return DetectedMagicSignature.JAVA_DALVIK_DEX, raw_hex

        # 8. ELF Executable / Shared Object
        if head.startswith(b"\x7fELF"):
            return DetectedMagicSignature.ELF_EXECUTABLE_OR_SO, raw_hex

        # 9. ZIP / APK / JAR / Office XML
        if head.startswith(b"PK\x03\x04"):
            return DetectedMagicSignature.ZIP_APK_JAR_DOCX_XLSX, raw_hex

        # 10. RAR or 7-Zip
        if head.startswith(b"Rar!\x1a\x07") or head.startswith(b"7z\xbc\xaf'\x1c"):
            return DetectedMagicSignature.RAR_OR_7ZIP_ARCHIVE, raw_hex

        # 11. Gzip / Zstd / LZ4 / Bzip2
        if (
            head.startswith(b"\x1f\x8b\x08")
            or head.startswith(b"\x28\xb5\x2f\xfd")
            or head.startswith(b"\x04\x22\x4d\x18")
            or head.startswith(b"BZh")
        ):
            return DetectedMagicSignature.GZIP_ZSTD_LZ4_BZIP2, raw_hex

        # 12. PDF Document (can start within first 1024 bytes)
        if b"%PDF-" in head[:1024]:
            return DetectedMagicSignature.PDF_DOCUMENT, raw_hex

        # 13. JPEG / PNG / WebP / HEIC / MP4 / GIF
        if (
            head.startswith(b"\xff\xd8\xff")
            or head.startswith(b"\x89PNG\r\n\x1a\n")
            or (head.startswith(b"RIFF") and len(head) >= 12 and head[8:12] == b"WEBP")
            or (len(head) >= 8 and head[4:8] == b"ftyp")
            or head.startswith(b"GIF87a")
            or head.startswith(b"GIF89a")
        ):
            return DetectedMagicSignature.JPEG_PNG_WEBP_HEIC_GIF, raw_hex

        # 14. KTX GPU Texture
        if head.startswith(b"\xabKTX 11\xbb") or head.startswith(b"bvx2"):
            return DetectedMagicSignature.KTX_GPU_TEXTURE, raw_hex

        # 16. LUKS Header
        if head.startswith(b"LUKS\xba\xbe"):
            return DetectedMagicSignature.LUKS_OR_VERACRYPT_HEADER, raw_hex

        # 17. OpenPGP / Age armor
        if b"-----BEGIN PGP MESSAGE-----" in head or b"age-encryption.org/v1" in head:
            return DetectedMagicSignature.OPENPGP_OR_AGE_ARMOR, raw_hex

        # 18. Private Key PEM
        if b"-----BEGIN PRIVATE KEY-----" in head or b"-----BEGIN RSA PRIVATE KEY-----" in head:
            return DetectedMagicSignature.PKCS12_OR_PEM_PRIVATE_KEY, raw_hex

        return DetectedMagicSignature.UNKNOWN_BINARY, raw_hex

    def inspect_file(self, file_path: str) -> MagicInspectionResult:
        """Reads head and tail of file on disk to evaluate signature vs extension mismatch."""
        if not os.path.isfile(file_path):
            return MagicInspectionResult(
                detected_magic_signature=DetectedMagicSignature.UNKNOWN_BINARY.value,
                is_extension_spoofed_mismatch=0,
                raw_magic_hex="",
            )

        file_size = os.path.getsize(file_path)
        head = b""
        tail = b""

        with open(file_path, "rb") as f:
            head = f.read(1024)
            if file_size > 16:
                f.seek(max(0, file_size - 16))
                tail = f.read(16)
            else:
                tail = head

        sig_enum, raw_hex = self.detect_signature(head, tail)

        _, ext = os.path.splitext(file_path)
        ext_lower = ext.lower() if ext else ""

        is_mismatch = 0
        if sig_enum in self.SIGNATURE_EXTENSIONS:
            expected = self.SIGNATURE_EXTENSIONS[sig_enum]
            if ext_lower not in expected:
                is_mismatch = 1

        return MagicInspectionResult(
            detected_magic_signature=sig_enum.value,
            is_extension_spoofed_mismatch=is_mismatch,
            raw_magic_hex=raw_hex,
        )


class EntropyAndChiSquareClassifier:
    """Evaluates Shannon Entropy H(X) and Pearson Chi-Square score to identify encrypted payloads."""

    def analyze_bytes(self, data: bytes) -> EntropyAnalysisResult:
        """Computes H(X) and Chi-Square over a sample of up to 1 MB, skipping first 16 bytes."""
        total_len = len(data)
        if total_len == 0:
            return EntropyAnalysisResult(
                shannon_entropy_bits=0.0,
                chi_square_uniformity_score=0.0,
                classification=EntropyCryptoClassification.LOW_ENTROPY_PLAINTEXT_OR_STRUCTURED,
            )

        # Skip first 16 bytes salt/header if available
        sample = data[16 : 16 + 1048576] if total_len > 16 else data
        n_sample = len(sample)

        if n_sample == 0:
            return EntropyAnalysisResult(
                shannon_entropy_bits=0.0,
                chi_square_uniformity_score=0.0,
                classification=EntropyCryptoClassification.LOW_ENTROPY_PLAINTEXT_OR_STRUCTURED,
            )

        # 256-bin byte counts
        counts = [0] * 256
        for b in sample:
            counts[b] += 1

        # Shannon Entropy
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / n_sample
                entropy -= p * math.log2(p)

        # Pearson's Chi-Square against expected uniform count E
        expected = n_sample / 256.0
        chi2 = 0.0
        for c in counts:
            diff = c - expected
            chi2 += (diff * diff) / expected

        # Check page alignment (SQLCipher / WCDB / Realm: 4096 or 1024)
        is_page_aligned = (total_len % 4096 == 0) or (total_len % 1024 == 0)

        # Deterministic classification rules
        if entropy >= 7.980 and 180.0 <= chi2 <= 350.0 and is_page_aligned:
            classification = EntropyCryptoClassification.UNCATALOGED_SQLCIPHER_OR_PAGE_ENCRYPTED_DB
        elif entropy >= 7.980 and 180.0 <= chi2 <= 380.0 and not (total_len % 4096 == 0):
            classification = EntropyCryptoClassification.HIGH_ENTROPY_ENCRYPTED_BLOB_OR_CONTAINER
        elif entropy >= 7.200 and chi2 > 380.0:
            classification = EntropyCryptoClassification.COMPRESSED_OR_PROPRIETARY_BINARY_STREAM
        else:
            classification = EntropyCryptoClassification.LOW_ENTROPY_PLAINTEXT_OR_STRUCTURED

        return EntropyAnalysisResult(
            shannon_entropy_bits=round(entropy, 4),
            chi_square_uniformity_score=round(chi2, 2),
            classification=classification,
        )
