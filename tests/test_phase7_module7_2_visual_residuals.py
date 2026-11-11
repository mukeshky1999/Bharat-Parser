"""
Test Suite: Phase 7, Module 7.2 — Ephemeral Visual Residuals: OS App-Switcher Snapshots
(SplashBoard & TaskSnapshots), Thumbnail Caches (.ithmb, Glide, Fresco, Kingfisher)
& Disguised Calculator Vault Unmasking.
Covers:
  - Sub-Engine 7.2A: iOS SplashBoard .ktx Texture Decoder & Android TaskSnapshots (.jpg + .proto pairing).
  - Sub-Engine 7.2B: iOS .ithmb Orphaned Deleted-Photo Slot Detector & Disk LRU Image Caches.
  - Sub-Engine 7.2C: Disguised Calculator / NQ Vault Known-Plaintext Header XOR & Byte-Swap Restorer.
  - Master SQLite Schema Export to ephemeral_visual_residuals_engine.sqlite.
Complies with Phase 7 Module 7.2 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import struct
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.visual_residuals.models import (
    SnapshotPlatform,
    CacheEngineType,
    VaultUnmaskingMethod,
    AppSwitcherSnapshotRecord,
    ReconstructedThumbnailRecord,
    UnmaskedVaultItemRecord,
)
from src.visual_residuals.app_switcher_decoder import AppSwitcherDecoder
from src.visual_residuals.thumbnail_cache_reconstructor import ThumbnailCacheReconstructor
from src.visual_residuals.vault_unmasker import VaultUnmasker
from src.visual_residuals.engine import VisualResidualsEngine


# ---------------------------------------------------------------------------
# Test 1: Android TaskSnapshots .proto + .jpg Pairing Test
# ---------------------------------------------------------------------------

def test_android_task_snapshots_proto_pairing():
    """
    Test 1: Acceptance Test 1 from Spec Section 7.1.
    Verifies that Sub-Engine 7.2A:
      1. Pairs /data/system_ce/999/snapshots/1055.jpg with companion 1055.proto.
      2. Decodes TaskSnapshotProto fields (is_real_snapshot=true, top_activity_component).
      3. Attributes snapshot to com.phonepe.app under Cloned User Profile 999.
    """
    base_dir = Path("./.workspace_tmp/test_snapshots_sandbox")
    snapshots_dir = base_dir / "data" / "system_ce" / "999" / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)

    jpg_file = snapshots_dir / "1055.jpg"
    with open(jpg_file, "wb") as f:
        # Valid JPEG minimal bytes
        f.write(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00\xff\xdb\x00\x43" + (b"\x00" * 64) + b"\xff\xd9")

    # Encode binary Protobuf wire bytes for TaskSnapshotProto:
    # Field 1 (orientation, varint = 1): tag = (1 << 3) | 0 = 0x08, val = 1 -> b"\x08\x01"
    # Field 3 (is_real_snapshot, varint = 1): tag = (3 << 3) | 0 = 0x18, val = 1 -> b"\x18\x01"
    # Field 7 (top_activity_component, string): tag = (7 << 3) | 2 = 0x3A, len + bytes
    component_str = b"com.phonepe.app/.ui.TransactionDetailsActivity"
    proto_payload = (
        b"\x08\x01"
        + b"\x18\x01"
        + b"\x3a" + bytes([len(component_str)]) + component_str
        + b"\x48\x9f\x08"  # Field 9 (id, varint = 1055)
    )

    proto_file = snapshots_dir / "1055.proto"
    with open(proto_file, "wb") as f:
        f.write(proto_payload)

    decoder = AppSwitcherDecoder()
    records = decoder.decode_android_snapshots(str(snapshots_dir), user_id=999, source_vfs_file_id=7201)

    assert len(records) == 1
    rec = records[0]
    assert rec.os_platform == SnapshotPlatform.ANDROID_TASKSNAPSHOTS
    assert rec.android_user_profile_id == 999
    assert rec.captured_app_bundle_or_pkg == "com.phonepe.app"
    assert "com.phonepe.app/.ui.TransactionDetailsActivity" in (rec.captured_activity_or_scene or "")
    assert rec.is_real_content_snapshot == 1
    assert "1055.jpg" in rec.snapshot_file_path


# ---------------------------------------------------------------------------
# Test 2: iOS SplashBoard .ktx Texture Decoding Test
# ---------------------------------------------------------------------------

def test_ios_splashboard_ktx_texture_decoding():
    """
    Test 2: Acceptance Test from Spec Section 3.1.
    Verifies that Sub-Engine 7.2A unpacks a Khronos Texture 1.1 (.ktx) file,
    reads the 64-byte KTX header, extracts dimensions (pixelWidth, pixelHeight),
    and converts the texture payload into a viewable PNG derivative.
    """
    base_dir = Path("./.workspace_tmp/test_snapshots_sandbox")
    splashboard_dir = base_dir / "SplashBoard" / "Snapshots" / "org.telegram.messenger - scene"
    out_dir = base_dir / "converted_pngs"
    splashboard_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    ktx_file = splashboard_dir / "A1B2C3D4.ktx"

    # Build 64-byte KTX 1.1 header:
    # Identifier (12 bytes): \xABKTX 11\xBB\r\n\x1A\n
    identifier = b"\xab\x4b\x54\x58\x20\x31\x31\xbb\x0d\x0a\x1a\x0a"
    endianness = struct.pack("<I", 0x04030201)  # Little-Endian
    gl_type = struct.pack("<I", 0x1401)          # GL_UNSIGNED_BYTE
    gl_type_size = struct.pack("<I", 1)
    gl_format = struct.pack("<I", 0x1908)        # GL_RGBA
    gl_internal_format = struct.pack("<I", 0x80E1)  # GL_BGRA8_EXT
    gl_base_internal_format = struct.pack("<I", 0x1908)
    pixel_width = struct.pack("<I", 120)
    pixel_height = struct.pack("<I", 120)
    pixel_depth = struct.pack("<I", 0)
    number_of_array_elements = struct.pack("<I", 0)
    number_of_faces = struct.pack("<I", 1)
    number_of_mipmap_levels = struct.pack("<I", 1)
    bytes_of_key_value_data = struct.pack("<I", 0)

    header_64 = (
        identifier
        + endianness
        + gl_type
        + gl_type_size
        + gl_format
        + gl_internal_format
        + gl_base_internal_format
        + pixel_width
        + pixel_height
        + pixel_depth
        + number_of_array_elements
        + number_of_faces
        + number_of_mipmap_levels
        + bytes_of_key_value_data
    )
    assert len(header_64) == 64

    # Raw image payload: uint32 imageSize followed by image bytes (120 * 120 * 4 = 57600 bytes)
    img_size = 120 * 120 * 4
    image_size_field = struct.pack("<I", img_size)
    raw_pixels = b"\x00\x00\xff\xff" * (120 * 120)  # Solid red BGRA

    with open(ktx_file, "wb") as f:
        f.write(header_64 + image_size_field + raw_pixels)

    decoder = AppSwitcherDecoder()
    records = decoder.decode_ios_splashboard(
        str(splashboard_dir),
        bundle_id="org.telegram.messenger",
        output_dir=str(out_dir),
        source_vfs_file_id=7202,
    )

    assert len(records) == 1
    rec = records[0]
    assert rec.os_platform == SnapshotPlatform.IOS_SPLASHBOARD
    assert rec.captured_app_bundle_or_pkg == "org.telegram.messenger"
    assert "120x120" in (rec.pixel_dimensions_and_orient or "")
    assert rec.is_real_content_snapshot == 1


# ---------------------------------------------------------------------------
# Test 3: iOS .ithmb Orphaned Deleted-Photo Slot Detection Test
# ---------------------------------------------------------------------------

def test_ios_ithmb_orphaned_deleted_photo_detection():
    """
    Test 3: Acceptance Test 2 from Spec Section 7.2.
    Verifies that Sub-Engine 7.2B:
      1. Parses consolidated .ithmb file containing 10 slots (k = 0..9).
      2. Cross-references against Photos.sqlite active thumbnail indices {0..7}.
      3. Reconstructs all 10 slots and flags slots 8 and 9 as orphaned thumbnails
         of permanently purged photos (is_parent_original_deleted = 1, RESIDUAL_RECORD).
    """
    base_dir = Path("./.workspace_tmp/test_ithmb_sandbox")
    out_dir = base_dir / "reconstructed_thumbs"
    base_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    ithmb_file = base_dir / "3303.ithmb"

    # Construct 10 slots, each 1024 bytes (with synthetic thumbnail bitmap pattern)
    slot_size = 1024
    num_slots = 10
    with open(ithmb_file, "wb") as f:
        for k in range(num_slots):
            # Synthetic slot with non-zero header and payload
            f.write(b"\xff\xd8\xff\xe0" + bytes([k] * (slot_size - 4)))

    active_indices = {0, 1, 2, 3, 4, 5, 6, 7}  # Photos 8 and 9 were purged from DB

    reconstructor = ThumbnailCacheReconstructor()
    records = reconstructor.decode_ithmb(
        ithmb_path=str(ithmb_file),
        active_thumbnail_indices=active_indices,
        slot_size=slot_size,
        output_dir=str(out_dir),
        source_vfs_file_id=7203,
    )

    assert len(records) == 10

    # Check active records
    active_recs = [r for r in records if r.slot_index_or_cache_key in [str(i) for i in range(8)]]
    for r in active_recs:
        assert r.is_parent_original_deleted == 0
        assert r.recovery_classification == ResidualConfidence.ORIGINAL_RECORD

    # Check orphaned records (slots 8 and 9)
    orphaned_recs = [r for r in records if r.slot_index_or_cache_key in ["8", "9"]]
    assert len(orphaned_recs) == 2
    for r in orphaned_recs:
        assert r.is_parent_original_deleted == 1
        assert r.recovery_classification == ResidualConfidence.RESIDUAL_RECORD


# ---------------------------------------------------------------------------
# Test 4: Disguised Vault Known-Plaintext Header XOR Restoration Test
# ---------------------------------------------------------------------------

def test_disguised_vault_kpa_xor_header_restoration():
    """
    Test 4: Acceptance Test 3 from Spec Section 7.3.
    Verifies that Sub-Engine 7.2C:
      1. Detects unencrypted JPEG body (FF DB, FF C4, FF DA, FF D9).
      2. Computes KPA XOR key: k1 = 0xA5 ^ 0xFF = 0x5A, verifying (0x82 ^ 0x5A) == 0xD8.
      3. XORs the first 128 bytes with 0x5A to restore a valid JPEG image file.
    """
    base_dir = Path("./.workspace_tmp/test_vault_sandbox")
    out_dir = base_dir / "unmasked_vault_items"
    base_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    obfuscated_file = base_dir / "secret_001.bin"

    # Construct genuine JPEG image bytes
    jpeg_magic = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00"
    jpeg_tables = (
        b"\xff\xdb\x00\x43" + (b"\x01" * 65)  # DQT
        + b"\xff\xc4\x00\x1f" + (b"\x02" * 29)  # DHT
        + b"\xff\xda\x00\x0c" + (b"\x03" * 10)  # SOS
    )
    jpeg_body = b"\xaa" * 4096 + b"\xff\xd9"  # EOI
    plain_jpeg = (jpeg_magic + jpeg_tables).ljust(128, b"\x00") + jpeg_body

    # XOR the first 128 bytes with 0x5A
    xor_key = 0x5A
    obfuscated_head = bytes([b ^ xor_key for b in plain_jpeg[:128]])
    obfuscated_payload = obfuscated_head + plain_jpeg[128:]

    assert obfuscated_payload[0] == (0xFF ^ 0x5A)  # 0xA5
    assert obfuscated_payload[1] == (0xD8 ^ 0x5A)  # 0x82
    assert obfuscated_payload[2] == (0xFF ^ 0x5A)  # 0xA5

    with open(obfuscated_file, "wb") as f:
        f.write(obfuscated_payload)

    unmasker = VaultUnmasker()
    record = unmasker.unmask_vault_file(
        file_path=str(obfuscated_file),
        output_dir=str(out_dir),
        vault_app_name_and_pkg="NQ Vault (com.netqin.ps)",
        source_vfs_file_id=7204,
    )

    assert record is not None
    assert record.unmasking_method_applied == VaultUnmaskingMethod.HEADER_1BYTE_XOR_RESTORED
    assert record.recovered_xor_or_aes_key_hex == "5a"
    assert record.restored_mime_type == "image/jpeg"
    assert Path(record.restored_file_path).exists()

    with open(record.restored_file_path, "rb") as rf:
        restored_data = rf.read()
        assert restored_data[:4] == b"\xff\xd8\xff\xe0"
        assert restored_data[-2:] == b"\xff\xd9"


# ---------------------------------------------------------------------------
# Test 5: Visual Residuals Master SQLite Schema Export Test
# ---------------------------------------------------------------------------

def test_visual_residuals_master_sqlite_export():
    """
    Test 5: Master Case Export Validation.
    Verifies that VisualResidualsEngine populates all three tables in
    ephemeral_visual_residuals_engine.sqlite.
    """
    export_db_path = Path("./.workspace_tmp/ephemeral_visual_residuals_engine.sqlite")
    if export_db_path.exists():
        export_db_path.unlink()

    sample_snapshot = [
        AppSwitcherSnapshotRecord(
            os_platform=SnapshotPlatform.ANDROID_TASKSNAPSHOTS,
            android_user_profile_id=999,
            source_vfs_file_id=7201,
            snapshot_file_path="/data/system_ce/999/snapshots/1055.jpg",
            captured_app_bundle_or_pkg="com.phonepe.app",
            captured_activity_or_scene="com.phonepe.app/.ui.TransactionDetailsActivity",
            is_real_content_snapshot=1,
            pixel_dimensions_and_orient="1080x2400 (Portrait)",
            snapshot_captured_utc_iso="2026-11-05T14:30:00.000000Z",
        )
    ]

    sample_thumb = [
        ReconstructedThumbnailRecord(
            cache_engine_type=CacheEngineType.IOS_ITHMB_SLOT,
            owning_app_bundle_or_pkg="com.apple.mobileslideshow",
            source_vfs_file_id=7203,
            slot_index_or_cache_key="8",
            reconstructed_file_path="./.workspace_tmp/reconstructed_thumbs/slot_8.png",
            is_parent_original_deleted=1,
            cached_or_accessed_utc_iso="2026-11-05T14:30:00.000000Z",
            recovery_classification=ResidualConfidence.RESIDUAL_RECORD,
        )
    ]

    sample_vault = [
        UnmaskedVaultItemRecord(
            vault_app_name_and_pkg="NQ Vault (com.netqin.ps)",
            obfuscated_vfs_file_id=7204,
            unmasking_method_applied=VaultUnmaskingMethod.HEADER_1BYTE_XOR_RESTORED,
            recovered_xor_or_aes_key_hex="5a",
            restored_mime_type="image/jpeg",
            restored_file_path="./.workspace_tmp/unmasked_vault_items/secret_001.jpg",
            restored_derivative_staging_id=901,
            hidden_into_vault_utc_iso="2026-11-05T14:30:00.000000Z",
        )
    ]

    engine = VisualResidualsEngine()
    engine.export_to_sqlite(
        snapshots=sample_snapshot,
        thumbnails=sample_thumb,
        vault_items=sample_vault,
        output_db_path=str(export_db_path),
    )

    assert export_db_path.exists()
    conn = sqlite3.connect(export_db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    assert "os_app_switcher_snapshots_ledger" in tables
    assert "reconstructed_thumbnails_and_disk_caches" in tables
    assert "unmasked_vault_and_hidden_media_ledger" in tables

    cur.execute("SELECT COUNT(*) FROM os_app_switcher_snapshots_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM reconstructed_thumbnails_and_disk_caches")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM unmasked_vault_and_hidden_media_ledger")
    assert cur.fetchone()[0] == 1

    conn.close()
