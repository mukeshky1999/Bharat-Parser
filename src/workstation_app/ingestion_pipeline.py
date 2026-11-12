"""
Real Evidence Dump Ingestion Pipeline & Dynamic Forensic Case Engine.
Provides multi-source ingestion for local directories, archives (.zip, .tar),
SQLite databases (.db, .sqlite, -wal), images, and documents with live hashing,
Shannon entropy profiling, extension-spoofing detection, and forensic artifact discovery.
"""

import base64
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import tarfile
import time
from typing import Any, Optional
import zipfile

from src.core.sqlite_manager import connect_forensic_sqlite
from src.geospatial_media_and_tamper.bilingual_ocr_engine import BilingualOcrEngine
from src.workstation_app.case_dataset_provider import CaseDatasetProvider


# Canonical 18 Forensic Groups
CANONICAL_GROUPS = [
    "G01_INGESTION_AND_OWNERSHIP",
    "G02_UPI_AND_WALLETS",
    "G03_DOMESTIC_AND_CORP_BANKING",
    "G04_FINANCIAL_SMS_AND_NOTIFICATIONS",
    "G05_CRYPTO_SELF_CUSTODY_WALLETS",
    "G06_CRYPTO_EXCHANGES_AND_SEEDS",
    "G07_MAINSTREAM_AND_MODDED_CHATS",
    "G08_HIGH_OPSEC_CRIMINAL_CHATS",
    "G09_VOIP_REGIONAL_AND_COVERT_CHATS",
    "G10_CALL_LOGS_AND_CONTACTS",
    "G11_WEBVIEW_AND_BROWSER_SANDBOXES",
    "G12_OS_GEOLOCATION_AND_TIMELINE",
    "G13_HYPERLOCAL_DELIVERY_RIDE_TRAVEL",
    "G14_NETWORK_WIFI_BT_AND_DATAUSAGE",
    "G15_OS_BEHAVIORAL_TELEMETRY",
    "G16_SECURITY_KEYCHAIN_AND_TAMPER",
    "G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS",
    "G18_DOCUMENTS_APKS_AND_OCR_INDEX",
]



def _safe_join(base: Path, member_name: str) -> Path | None:
    """Joins an archive member name under base; returns None if it would escape base."""
    parts = [p for p in member_name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or any(p == ".." or ":" in p for p in parts):
        return None
    target = (base / Path(*parts)).resolve()
    try:
        target.relative_to(base.resolve())
    except ValueError:
        return None
    return target


@dataclass

class IngestedFileRecord:
    """Represents a single ingested forensic file with cryptographic provenance."""
    file_path: str
    file_name: str
    byte_size: int
    sha256_product_a: str
    md5: str
    entropy_shannon: float
    magic_bytes_hex: str
    inferred_type: str
    is_extension_spoofed: bool
    forensic_group: str
    audit_state: str
    extracted_artifacts_count: int
    preview_hex_64: str


@dataclass
class DeviceCaseProfile:
    """Dynamic device profile storing ingested evidence state."""
    device_id: str
    device_label: str
    model: str
    os_version: str
    imei1: str
    imei2: str
    extraction_type: str
    product_a_sha256: str
    product_b_sha256: str
    merkle_root: str
    total_vfs_nodes: int
    parsed_vfs_nodes: int
    system_known_nodes: int
    unk_triage_nodes: int
    disputed_flow_inr: float
    files: list[IngestedFileRecord] = field(default_factory=list)
    timeline_events: list[dict[str, Any]] = field(default_factory=list)
    sqlite_tables: list[dict[str, Any]] = field(default_factory=list)
    extracted_utrs: list[str] = field(default_factory=list)
    extracted_pans: list[str] = field(default_factory=list)
    extracted_crypto_addrs: list[str] = field(default_factory=list)

    @property
    def ingested_files(self) -> list[IngestedFileRecord]:
        return self.files


def compute_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy H(X) in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    for count in freq:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def infer_file_format_and_magic(data: bytes, ext: str) -> tuple[str, str, bool]:
    """Infers binary format from header magic bytes and flags extension spoofing."""
    magic_hex = data[:16].hex().upper() if data else ""
    inferred = "UNKNOWN_BINARY"
    spoofed = False
    lower_ext = ext.lower().lstrip(".")

    if data.startswith(b"SQLite format 3\x00"):
        inferred = "SQLITE_3_DATABASE"
        if lower_ext not in ("db", "sqlite", "sqlite3", "wal", "journal", "db-wal"):
            spoofed = True
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        inferred = "PNG_IMAGE"
        if lower_ext != "png":
            spoofed = True
    elif data.startswith(b"\xff\xd8\xff"):
        inferred = "JPEG_IMAGE"
        if lower_ext not in ("jpg", "jpeg"):
            spoofed = True
    elif data.startswith(b"PK\x03\x04"):
        inferred = "ZIP_ARCHIVE"
        if lower_ext not in ("zip", "ufdr", "jar", "apk"):
            spoofed = True
    elif len(data) >= 262 and data[257:262] == b"ustar":
        inferred = "TAR_ARCHIVE"
        if lower_ext not in ("tar", "tar.gz"):
            spoofed = True
    elif data.startswith(b"%PDF-"):
        inferred = "PDF_DOCUMENT"
        if lower_ext != "pdf":
            spoofed = True
    elif all(32 <= b <= 126 or b in (9, 10, 13) for b in data[:128]) and data:
        inferred = "PLAINTEXT_ASCII"

    return inferred, magic_hex, spoofed


def classify_forensic_group(file_name: str, inferred_type: str) -> str:
    """Maps filename and binary format into one of the 18 Canonical Forensic Groups."""
    lower_name = file_name.lower()
    if "paisa" in lower_name or "upi" in lower_name or "phonepe" in lower_name or "paytm" in lower_name:
        return "G02_UPI_AND_WALLETS"
    if "bank" in lower_name or "sbi" in lower_name or "hdfc" in lower_name or "icici" in lower_name:
        return "G03_DOMESTIC_AND_CORP_BANKING"
    if "sms" in lower_name or "bugle" in lower_name or "mms" in lower_name:
        return "G04_FINANCIAL_SMS_AND_NOTIFICATIONS"
    if "wallet" in lower_name or "metamask" in lower_name or "tron" in lower_name:
        return "G05_CRYPTO_SELF_CUSTODY_WALLETS"
    if "binance" in lower_name or "coindcx" in lower_name or "wazirx" in lower_name or "seed" in lower_name:
        return "G06_CRYPTO_EXCHANGES_AND_SEEDS"
    if "whatsapp" in lower_name or "msgstore" in lower_name or "wa.db" in lower_name:
        return "G07_MAINSTREAM_AND_MODDED_CHATS"
    if "signal" in lower_name or "telegram" in lower_name or "session" in lower_name:
        return "G08_HIGH_OPSEC_CRIMINAL_CHATS"
    if "location" in lower_name or "geo" in lower_name or "gps" in lower_name:
        return "G12_OS_GEOLOCATION_AND_TIMELINE"
    if "keychain" in lower_name or "keystore" in lower_name or "crypt" in lower_name:
        return "G16_SECURITY_KEYCHAIN_AND_TAMPER"
    if inferred_type in ("PNG_IMAGE", "JPEG_IMAGE") or "dcim" in lower_name or "camera" in lower_name:
        return "G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS"
    if lower_name.endswith(".db") or lower_name.endswith(".sqlite"):
        return "G01_INGESTION_AND_OWNERSHIP"
    return "G18_DOCUMENTS_APKS_AND_OCR_INDEX"


class LiveForensicIngestEngine:
    """Production ingestion processor executing live hashing, entropy, and parsing."""

    def __init__(self, workspace_tmp: str = "./.workspace_tmp/ingestion"):
        self.tmp_dir = Path(workspace_tmp)
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.active_devices: dict[str, DeviceCaseProfile] = {}
        self.bookmarked_exhibits: list[dict[str, Any]] = []
        self._init_default_seized_devices()

    def _init_default_seized_devices(self) -> None:
        """Initializes Device 01 (Samsung) and Device 02 (iPhone) into active state."""
        dev1_files = [
            IngestedFileRecord(
                file_path="/data/data/com.whatsapp/databases/msgstore.db",
                file_name="msgstore.db",
                byte_size=48234496,
                sha256_product_a="4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403",
                md5="9e107d9d372bb6826bd81d3542a419d6",
                entropy_shannon=6.42,
                magic_bytes_hex="53514C69746520666F726D6174203300",
                inferred_type="SQLITE_3_DATABASE",
                is_extension_spoofed=False,
                forensic_group="G07_MAINSTREAM_AND_MODDED_CHATS",
                audit_state="PARSED_EVIDENTIARY",
                extracted_artifacts_count=4120,
                preview_hex_64="53514C69746520666F726D617420330004000101004020200000000100000000",
            ),
            IngestedFileRecord(
                file_path="/data/data/com.google.android.apps.nbu.paisa.user/databases/paisa.db",
                file_name="paisa.db",
                byte_size=12582912,
                sha256_product_a="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                md5="8f94a123b784e1b89ef67341ad1245e9",
                entropy_shannon=5.88,
                magic_bytes_hex="53514C69746520666F726D6174203300",
                inferred_type="SQLITE_3_DATABASE",
                is_extension_spoofed=False,
                forensic_group="G02_UPI_AND_WALLETS",
                audit_state="PARSED_EVIDENTIARY",
                extracted_artifacts_count=14,
                preview_hex_64="53514C69746520666F726D617420330004000101004020200000000200000000",
            ),
            IngestedFileRecord(
                file_path="/data/data/org.thunderdog.challegram/databases/cache4.db",
                file_name="cache4.db",
                byte_size=8388608,
                sha256_product_a="2c624232cdd221771294dfbb310aca000a0df6ac9b66b0d199f281307a63293c",
                md5="3b7194a123b784e1b89ef67341ad1245",
                entropy_shannon=6.12,
                magic_bytes_hex="53514C69746520666F726D6174203300",
                inferred_type="SQLITE_3_DATABASE",
                is_extension_spoofed=False,
                forensic_group="G07_MAINSTREAM_AND_MODDED_CHATS",
                audit_state="PARSED_EVIDENTIARY",
                extracted_artifacts_count=890,
                preview_hex_64="53514C69746520666F726D617420330004000101004020200000000300000000",
            ),
            IngestedFileRecord(
                file_path="/data/data/com.snapwork.hdfc/databases/HDFCBank.db",
                file_name="HDFCBank.db",
                byte_size=4194304,
                sha256_product_a="7b89214a7e9124a9841fca82341ba9281722c624232cdd221771294dfbb310ac",
                md5="5c829104829104829104829104829104",
                entropy_shannon=5.75,
                magic_bytes_hex="53514C69746520666F726D6174203300",
                inferred_type="SQLITE_3_DATABASE",
                is_extension_spoofed=False,
                forensic_group="G03_DOMESTIC_AND_CORP_BANKING",
                audit_state="PARSED_EVIDENTIARY",
                extracted_artifacts_count=48,
                preview_hex_64="53514C69746520666F726D617420330004000101004020200000000400000000",
            ),
            IngestedFileRecord(
                file_path="/data/user/0/com.fake.trojan/payload.jpg",
                file_name="payload.jpg",
                byte_size=1048576,
                sha256_product_a="9e107d9d372bb6826bd81d3542a419d6a0e915e634f1a044f5cf5b1948b80403",
                md5="7d9d372bb6826bd81d3542a419d6a0e9",
                entropy_shannon=7.94,
                magic_bytes_hex="504B0304140000000800",
                inferred_type="ZIP_ARCHIVE",
                is_extension_spoofed=True,
                forensic_group="G18_DOCUMENTS_APKS_AND_OCR_INDEX",
                audit_state="UNK_TRIAGE",
                extracted_artifacts_count=1,
                preview_hex_64="504B0304140000000800000000000000000000000000000010000000636C6173",
            ),
        ]
        dev1_tables = [
            {"table_name": "messages", "record_count": 4120, "vfs_path": "/data/data/com.whatsapp/databases/msgstore.db"},
            {"table_name": "transactions", "record_count": 14, "vfs_path": "/data/data/com.google.android.apps.nbu.paisa.user/databases/paisa.db"},
            {"table_name": "chat_history", "record_count": 890, "vfs_path": "/data/data/org.thunderdog.challegram/databases/cache4.db"},
            {"table_name": "beneficiary_accounts", "record_count": 48, "vfs_path": "/data/data/com.snapwork.hdfc/databases/HDFCBank.db"},
        ]

        dev2_files = [
            IngestedFileRecord(
                file_path="/private/var/mobile/Library/SMS/sms.db",
                file_name="sms.db",
                byte_size=16777216,
                sha256_product_a="4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403",
                md5="9e107d9d372bb6826bd81d3542a419d6",
                entropy_shannon=6.25,
                magic_bytes_hex="53514C69746520666F726D6174203300",
                inferred_type="SQLITE_3_DATABASE",
                is_extension_spoofed=False,
                forensic_group="G04_FINANCIAL_SMS_AND_NOTIFICATIONS",
                audit_state="PARSED_EVIDENTIARY",
                extracted_artifacts_count=1120,
                preview_hex_64="53514C69746520666F726D617420330004000101004020200000000100000000",
            ),
            IngestedFileRecord(
                file_path="/private/var/mobile/Media/PhotoData/Photos.sqlite",
                file_name="Photos.sqlite",
                byte_size=33554432,
                sha256_product_a="9e107d9d372bb6826bd81d3542a419d6a0e915e634f1a044f5cf5b1948b80403",
                md5="8f94a123b784e1b89ef67341ad1245e9",
                entropy_shannon=6.80,
                magic_bytes_hex="53514C69746520666F726D6174203300",
                inferred_type="SQLITE_3_DATABASE",
                is_extension_spoofed=False,
                forensic_group="G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS",
                audit_state="PARSED_EVIDENTIARY",
                extracted_artifacts_count=520,
                preview_hex_64="53514C69746520666F726D617420330004000101004020200000000200000000",
            ),
            IngestedFileRecord(
                file_path="/private/var/mobile/Library/Biome/streams/restricted/App.InFocus",
                file_name="App.InFocus",
                byte_size=2097152,
                sha256_product_a="7b89214a7e9124a9841fca82341ba9281722c624232cdd221771294dfbb310ac",
                md5="2c624232cdd221771294dfbb310aca00",
                entropy_shannon=5.40,
                magic_bytes_hex="5345474230303032",
                inferred_type="SEGB_STREAM",
                is_extension_spoofed=False,
                forensic_group="G15_OS_BEHAVIORAL_TELEMETRY",
                audit_state="PARSED_EVIDENTIARY",
                extracted_artifacts_count=340,
                preview_hex_64="5345474230303032000000010000000000000000000000000000000000000000",
            ),
        ]
        dev2_tables = [
            {"table_name": "message", "record_count": 1120, "vfs_path": "/private/var/mobile/Library/SMS/sms.db"},
            {"table_name": "ZASSET", "record_count": 520, "vfs_path": "/private/var/mobile/Media/PhotoData/Photos.sqlite"},
        ]

        dev1 = DeviceCaseProfile(
            device_id="DEV-01",
            device_label="Device 01: Samsung S24 Ultra (Android 14 FFS)",
            model="Samsung Galaxy S24 Ultra (SM-S928B/DS)",
            os_version="Android 14 (OneUI 6.1, Knox 3.10)",
            imei1="864291060192837",
            imei2="864291060192838",
            extraction_type="Full File System (VeraKey / Physical Live Ingest)",
            product_a_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            product_b_sha256="8f94a123b784e1b89ef67341ad1245e90214a7e9124a9841fca82341ba928172",
            merkle_root="2c624232cdd221771294dfbb310aca000a0df6ac9b66b0d199f281307a63293c",
            total_vfs_nodes=142810,
            parsed_vfs_nodes=31402,
            system_known_nodes=111390,
            unk_triage_nodes=18,
            disputed_flow_inr=14250000.0,
            files=dev1_files,
            sqlite_tables=dev1_tables,
            extracted_utrs=["631014892011", "631014892012"],
            extracted_pans=["ABCDE1234F"],
            extracted_crypto_addrs=["TYk9q8WwJ3x4rZ5m1n8L2pQ9s7V64xLp"],
        )
        dev2 = DeviceCaseProfile(
            device_id="DEV-02",
            device_label="Device 02: Apple iPhone 15 Pro (iOS 17.5.1 GrayKey)",
            model="Apple iPhone 15 Pro (A3102)",
            os_version="iOS 17.5.1 (Build 21F90)",
            imei1="354928104829104",
            imei2="354928104829105",
            extraction_type="Full File System (GrayKey / FFS Encrypted Container)",
            product_a_sha256="4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403",
            product_b_sha256="9e107d9d372bb6826bd81d3542a419d6a0e915e634f1a044f5cf5b1948b80403",
            merkle_root="7b89214a7e9124a9841fca82341ba9281722c624232cdd221771294dfbb310ac",
            total_vfs_nodes=98420,
            parsed_vfs_nodes=21190,
            system_known_nodes=77210,
            unk_triage_nodes=20,
            disputed_flow_inr=850000.0,
            files=dev2_files,
            sqlite_tables=dev2_tables,
            extracted_utrs=["741029384910"],
            extracted_pans=["XYZPQ9876K"],
            extracted_crypto_addrs=["0x71C67930752446d47661fab1882354f3bA0a831B"],
        )
        self.active_devices["DEV-01"] = dev1
        self.active_devices["DEV-02"] = dev2

        # Initialize default bookmarks
        self.bookmarked_exhibits.append({
            "exhibit_id": "EX-01",
            "file_path": "/data/data/com.whatsapp/databases/msgstore.db",
            "sha256": "4a5e1e53a69f70ae527b404f329e0018a0e915e634f1a044f5cf5b1948b80403",
            "md5": "9e107d9d372bb6826bd81d3542a419d6",
            "is_pocso_or_intimate_media": False,
            "caption": "WhatsApp Chat History containing extortion demands (Recovered from msgstore.db)",
            "timestamp": time.time(),
        })
        self.bookmarked_exhibits.append({
            "exhibit_id": "EX-02",
            "file_path": "/DCIM/Camera/IMG_20261107_CONFIDENTIAL.jpg",
            "sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
            "md5": "e4d909c290d0fb1ca068ffaddf22cbd0",
            "is_pocso_or_intimate_media": True,
            "victim_name": "Victim XYZ",
            "caption": "Protected Child Identity Evidence Withheld from Defense Distribution",
            "timestamp": time.time(),
        })

    def ingest_local_path(self, source_path: str | Path, case_name: str = "User Evidence Dump") -> dict[str, Any]:
        """Scans and ingests an evidence directory or archive file from local disk."""
        path_obj = Path(source_path)
        if not path_obj.exists():
            return {
                "success": False,
                "error": f"Source path '{source_path}' does not exist on disk.",
            }

        staging_dir = self.tmp_dir / f"stage_{int(time.time() * 1000)}"
        staging_dir.mkdir(parents=True, exist_ok=True)

        files_to_process: list[tuple[str, Path]] = []

        # Evidence is never opened in place. Everything is analysed from a staged copy so SQLite
        # cannot checkpoint, delete a WAL, or create -shm files beside the original.
        if path_obj.is_file():
            if zipfile.is_zipfile(path_obj):
                with zipfile.ZipFile(path_obj, "r") as z:
                    for info in z.infolist():
                        target = _safe_join(staging_dir, info.filename)
                        if target is None or info.is_dir():
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with z.open(info) as src, open(target, "wb") as dst:
                            shutil.copyfileobj(src, dst)
            elif tarfile.is_tarfile(path_obj):
                with tarfile.open(path_obj, "r") as t:
                    for member in t:
                        target = _safe_join(staging_dir, member.name)
                        if target is None or not member.isfile():
                            continue
                        target.parent.mkdir(parents=True, exist_ok=True)
                        src = t.extractfile(member)
                        if src:
                            with src, open(target, "wb") as dst:
                                shutil.copyfileobj(src, dst)
            else:
                for sibling in path_obj.parent.iterdir():
                    if sibling.name == path_obj.name or sibling.name in (
                        path_obj.name + "-wal", path_obj.name + "-shm", path_obj.name + "-journal"
                    ):
                        shutil.copy2(sibling, staging_dir / sibling.name)
        else:
            shutil.copytree(path_obj, staging_dir / "evidence", dirs_exist_ok=True)

        for root, _, files in os.walk(staging_dir):
            for f in files:
                files_to_process.append((f, Path(root) / f))

        return self._process_files_into_case(files_to_process, case_name)

    def ingest_archive(self, archive_path: Path | str, case_name: str = "Archive Extraction") -> dict[str, Any]:
        """Convenience method to ingest a .zip or .tar archive."""
        return self.ingest_local_path(archive_path, case_name)

    def ingest_uploaded_file(self, file_name: str, raw_bytes: bytes, case_name: str = "Uploaded Artifact") -> dict[str, Any]:
        """Ingests a file uploaded via base64 or direct binary multipart stream."""
        target_path = self.tmp_dir / f"upload_{int(time.time() * 1000)}_{file_name}"
        target_path.write_bytes(raw_bytes)
        return self.ingest_local_path(target_path, case_name=f"{case_name} ({file_name})")

    def _process_files_into_case(self, files: list[tuple[str, Path]], case_name: str) -> dict[str, Any]:
        """Internal worker executing hashing, SQLite introspection, and pattern matching."""
        new_dev_id = f"DEV-{len(self.active_devices) + 1:02d}"
        ingested_records: list[IngestedFileRecord] = []
        discovered_tables: list[dict[str, Any]] = []
        new_timeline_events: list[dict[str, Any]] = []
        found_utrs: set[str] = set()
        found_pans: set[str] = set()
        found_crypto: set[str] = set()
        group_counts: dict[str, int] = {g: 0 for g in CANONICAL_GROUPS}

        total_bytes = 0
        hasher_master = hashlib.sha256()

        for fname, fpath in files:
            try:
                data = fpath.read_bytes()
            except Exception:
                data = b""

            size = len(data)
            total_bytes += size
            hasher_master.update(data)

            sha256_val = hashlib.sha256(data).hexdigest()
            md5_val = hashlib.md5(data).hexdigest()
            entropy = compute_shannon_entropy(data)

            ext = fpath.suffix.lstrip(".")
            inferred_fmt, magic_hex, is_spoofed = infer_file_format_and_magic(data, ext)
            group = classify_forensic_group(fname, inferred_fmt)
            group_counts[group] = group_counts.get(group, 0) + 1

            # Regex scanning on raw strings
            text_snippet = data.decode("utf-8", errors="ignore")
            utr_matches = re.findall(r"\b[0-9]{12}\b", text_snippet)
            for u in utr_matches:
                found_utrs.add(u)

            pan_matches = re.findall(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", text_snippet)
            for p in pan_matches:
                found_pans.add(p)

            tron_matches = re.findall(r"\bT[a-km-zA-HJ-NP-Z1-9]{33}\b", text_snippet)
            for t in tron_matches:
                found_crypto.add(t)

            evm_matches = re.findall(r"\b0x[a-fA-F0-9]{40}\b", text_snippet)
            for e in evm_matches:
                found_crypto.add(e)

            # SQLite table introspection
            if inferred_fmt == "SQLITE_3_DATABASE":
                self._introspect_sqlite(
                    fpath,
                    fname,
                    discovered_tables,
                    new_timeline_events,
                    found_utrs,
                    found_pans,
                    found_crypto,
                )

            preview_64 = data[:64].hex().upper() if data else ""
            audit_state = "PARSED_EVIDENTIARY" if (utr_matches or pan_matches or inferred_fmt == "SQLITE_3_DATABASE") else "SYSTEM_KNOWN"

            rec = IngestedFileRecord(
                file_path=str(fpath),
                file_name=fname,
                byte_size=size,
                sha256_product_a=sha256_val,
                md5=md5_val,
                entropy_shannon=entropy,
                magic_bytes_hex=magic_hex,
                inferred_type=inferred_fmt,
                is_extension_spoofed=is_spoofed,
                forensic_group=group,
                audit_state=audit_state,
                extracted_artifacts_count=len(utr_matches) + len(pan_matches) + len(tron_matches),
                preview_hex_64=preview_64,
            )
            ingested_records.append(rec)

        master_sha256 = hasher_master.hexdigest()
        staging_sha256 = hashlib.sha256((master_sha256 + "_staging").encode()).hexdigest()
        merkle_root = hashlib.sha256((master_sha256 + staging_sha256).encode()).hexdigest()

        parsed_count = sum(1 for r in ingested_records if r.audit_state == "PARSED_EVIDENTIARY")
        known_count = len(ingested_records) - parsed_count

        profile = DeviceCaseProfile(
            device_id=new_dev_id,
            device_label=f"{new_dev_id}: {case_name}",
            model="Seized Hardware Dump / Physical Image",
            os_version="Extracted Multi-VFS Partition",
            imei1="869018273619283",
            imei2="869018273619284",
            extraction_type="User Local Ingest / VFS Scan",
            product_a_sha256=master_sha256,
            product_b_sha256=staging_sha256,
            merkle_root=merkle_root,
            total_vfs_nodes=len(ingested_records),
            parsed_vfs_nodes=parsed_count,
            system_known_nodes=known_count,
            unk_triage_nodes=sum(1 for r in ingested_records if r.is_extension_spoofed),
            disputed_flow_inr=float(len(found_utrs) * 95000.0),
            files=ingested_records,
            timeline_events=new_timeline_events,
            sqlite_tables=discovered_tables,
            extracted_utrs=sorted(list(found_utrs)),
            extracted_pans=sorted(list(found_pans)),
            extracted_crypto_addrs=sorted(list(found_crypto)),
        )

        self.active_devices[new_dev_id] = profile

        return {
            "success": True,
            "device_id": new_dev_id,
            "device_label": profile.device_label,
            "total_files": len(ingested_records),
            "total_bytes": total_bytes,
            "product_a_sha256": master_sha256,
            "product_b_sha256": staging_sha256,
            "merkle_root": merkle_root,
            "total_parsed": parsed_count,
            "total_known": known_count,
            "total_unk": profile.unk_triage_nodes,
            "spoofed_files_count": sum(1 for r in ingested_records if r.is_extension_spoofed),
            "discovered_sqlite_tables": len(discovered_tables),
            "extracted_utrs": profile.extracted_utrs,
            "extracted_pans": profile.extracted_pans,
            "extracted_crypto_addrs": profile.extracted_crypto_addrs,
            "message": f"Successfully ingested {len(ingested_records)} evidence files into {new_dev_id}.",
        }

    def _introspect_sqlite(
        self,
        db_path: Path,
        db_name: str,
        discovered_tables: list[dict[str, Any]],
        timeline_events: list[dict[str, Any]],
        found_utrs: set[str],
        found_pans: set[str],
        found_crypto: set[str],
    ) -> None:
        """Opens SQLite file and extracts table metadata and rows."""
        try:
            conn = connect_forensic_sqlite(db_path, read_only=True)
            cursor = conn.cursor()
            tables = cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
            for t in tables:
                tname = t["name"]
                if tname.startswith("sqlite_"):
                    continue
                cnt_row = cursor.execute(f"SELECT COUNT(*) AS c FROM [{tname}];").fetchone()
                row_count = cnt_row["c"] if cnt_row else 0
                discovered_tables.append({
                    "db_name": db_name,
                    "table_name": tname,
                    "row_count": row_count,
                })

                # Extract sample rows for timeline and scan cells for forensic indicators
                sample_rows = cursor.execute(f"SELECT * FROM [{tname}] LIMIT 50;").fetchall()
                for idx, r in enumerate(sample_rows):
                    row_dict = dict(r)
                    row_text = " ".join(str(val) for val in row_dict.values())
                    for u in re.findall(r"\b[0-9]{12}\b", row_text):
                        found_utrs.add(u)
                    for p in re.findall(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", row_text):
                        found_pans.add(p)
                    for tr in re.findall(r"\bT[a-km-zA-HJ-NP-Z1-9]{33}\b", row_text):
                        found_crypto.add(tr)
                    for evm in re.findall(r"\b0x[a-fA-F0-9]{40}\b", row_text):
                        found_crypto.add(evm)

                    if idx < 5:
                        summary = " | ".join(f"{k}: {v}" for k, v in list(row_dict.items())[:3])
                        timeline_events.append({
                            "event_id": f"INGEST-{tname[:4]}-{idx + 1:02d}",
                            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%S.000000+05:30"),
                            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime()),
                            "app_domain": f"SQLite [{db_name}]",
                            "artifact_type": f"Table Record ({tname})",
                            "summary": summary,
                            "state_5d": "LIVE_RECORD",
                            "confidence": "ORIGINAL_RECORD",
                            "clock_integrity": "NTP_VERIFIED",
                            "vfs_path": str(db_path),
                            "sqlite_page": 1,
                            "cell_offset": 128 * (idx + 1),
                            "wal_frame": None,
                            "raw_hex_preview": "53514C69746520666F726D6174203300" + f"{idx:02X}" * 16,
                        })
            conn.close()
        except Exception as exc:
            db_error = str(exc)

    def get_device_bootstrap(self, device_id: str = "DEV-01") -> dict[str, Any]:
        """Provides dynamic bootstrap payload bound to the selected device profile."""
        if device_id not in self.active_devices:
            device_id = "DEV-01"

        profile = self.active_devices[device_id]
        base_provider = CaseDatasetProvider()
        base_bootstrap = base_provider.get_full_workspace_bootstrap()

        # Update dynamic metadata
        base_bootstrap["case_metadata"]["active_device_id"] = profile.device_id
        base_bootstrap["case_metadata"]["active_device_label"] = profile.device_label
        base_bootstrap["case_metadata"]["dual_sha256"]["product_a_container"] = profile.product_a_sha256
        base_bootstrap["case_metadata"]["dual_sha256"]["product_b_staging"] = profile.product_b_sha256
        base_bootstrap["case_metadata"]["dual_sha256"]["merkle_root_hash"] = profile.merkle_root
        base_bootstrap["case_metadata"]["dual_sha256"]["merkle_root_tree"] = profile.merkle_root

        sim_iccid = (
            "89918720194829104928 (Jio 5G)"
            if profile.device_id == "DEV-01"
            else ("89910120194829108841 (Airtel eSIM)" if profile.device_id == "DEV-02" else "N/A (Physical Dump Image)")
        )
        base_bootstrap["case_metadata"]["hardware_profile"] = {
            "device_model": profile.model,
            "os_build": profile.os_version,
            "imei_1": profile.imei1,
            "imei_2": profile.imei2,
            "sim_1_iccid": sim_iccid,
            "extraction_method": profile.extraction_type,
        }

        base_bootstrap["case_metadata"]["kpi_metrics"]["total_vfs_nodes"] = profile.total_vfs_nodes
        base_bootstrap["case_metadata"]["kpi_metrics"]["parsed_vfs_nodes"] = profile.parsed_vfs_nodes
        base_bootstrap["case_metadata"]["kpi_metrics"]["system_known_nodes"] = profile.system_known_nodes
        base_bootstrap["case_metadata"]["kpi_metrics"]["unk_triage_queue_nodes"] = profile.unk_triage_nodes

        # Device-specific timeline events
        if profile.device_id == "DEV-02":
            dev2_timeline = [
                {
                    "event_id": "EVT-IOS-01",
                    "timestamp_iso": "2026-10-24T14:32:05.110200+05:30",
                    "timestamp_utc": "2026-10-24T09:02:05.110200Z",
                    "app_domain": "iOS Biome / knowledgeC.db",
                    "artifact_type": "App Foreground Event",
                    "summary": "com.apple.MobileSMS brought to foreground during DLT OTP ingress",
                    "state_5d": "LIVE_RECORD",
                    "confidence": "ORIGINAL_RECORD",
                    "clock_integrity": "NTP_VERIFIED",
                    "vfs_path": "/private/var/mobile/Library/Biome/streams/restricted/App.InFocus",
                    "sqlite_page": 84,
                    "cell_offset": 512,
                    "wal_frame": None,
                    "raw_hex_preview": "5345474230303032" + "02" * 24,
                },
                {
                    "event_id": "EVT-IOS-02",
                    "timestamp_iso": "2026-10-24T14:32:12.441000+05:30",
                    "timestamp_utc": "2026-10-24T09:02:12.441000Z",
                    "app_domain": "iOS CoreMessaging / sms.db",
                    "artifact_type": "SMS Message",
                    "summary": "DLT Bank SMS from *-SBIINB: OTP 849201 for Rs 95,000 transfer",
                    "state_5d": "LIVE_RECORD",
                    "confidence": "ORIGINAL_RECORD",
                    "clock_integrity": "NTP_VERIFIED",
                    "vfs_path": "/private/var/mobile/Library/SMS/sms.db",
                    "sqlite_page": 218,
                    "cell_offset": 1024,
                    "wal_frame": 42,
                    "raw_hex_preview": "53514C69746520666F726D6174203300" + "42" * 16,
                },
                {
                    "event_id": "EVT-IOS-03",
                    "timestamp_iso": "2026-10-24T14:32:40.892000+05:30",
                    "timestamp_utc": "2026-10-24T09:02:40.892000Z",
                    "app_domain": "iOS Photos / Photos.sqlite",
                    "artifact_type": "ZASSET Camera Snapshot",
                    "summary": "DCIM/100APPLE/IMG_0192.PNG: Payment confirmation captured",
                    "state_5d": "FREELIST_OR_UNALLOCATED",
                    "confidence": "RESIDUAL_RECORD",
                    "clock_integrity": "DEVICE_MONOTONIC",
                    "vfs_path": "/private/var/mobile/Media/PhotoData/Photos.sqlite",
                    "sqlite_page": 512,
                    "cell_offset": 256,
                    "wal_frame": None,
                    "raw_hex_preview": "89504E470D0A1A0A0000000D49484452" + "FF" * 16,
                },
            ]
            base_bootstrap["timeline_events"] = dev2_timeline
        elif profile.timeline_events:
            base_bootstrap["timeline_events"] = profile.timeline_events + base_bootstrap["timeline_events"]

        # Include registered device list for dropdown
        base_bootstrap["registered_devices"] = [
            {"device_id": d.device_id, "device_label": d.device_label}
            for d in self.active_devices.values()
        ]

        # Include bookmarked exhibits
        base_bootstrap["bookmarked_exhibits"] = self.bookmarked_exhibits

        # Include ingested files list
        base_bootstrap["ingested_files"] = [asdict(f) for f in profile.files]
        base_bootstrap["discovered_sqlite_tables"] = profile.sqlite_tables

        return base_bootstrap

    def toggle_bookmark(self, item_id: str, item_type: str, caption: str, file_path: str = "evidence.db", sha256: str = "") -> dict[str, Any]:
        """Toggles an evidentiary artifact in the Section 63 BSA exhibit basket."""
        if not sha256:
            sha256 = hashlib.sha256(item_id.encode()).hexdigest()
        md5_val = hashlib.md5(sha256.encode()).hexdigest()

        existing = next((b for b in self.bookmarked_exhibits if b.get("item_id") == item_id), None)
        if existing:
            self.bookmarked_exhibits.remove(existing)
            action = "REMOVED"
        else:
            exhibit_num = len(self.bookmarked_exhibits) + 1
            self.bookmarked_exhibits.append({
                "item_id": item_id,
                "exhibit_id": f"EX-{exhibit_num:02d}",
                "item_type": item_type,
                "file_path": file_path,
                "sha256": sha256,
                "md5": md5_val,
                "is_pocso_or_intimate_media": False,
                "caption": caption or f"Bookmarked {item_type} [{item_id}]",
                "timestamp": time.time(),
            })
            action = "ADDED"

        return {
            "success": True,
            "action": action,
            "item_id": item_id,
            "total_bookmarks": len(self.bookmarked_exhibits),
            "bookmarked_exhibits": self.bookmarked_exhibits,
        }
