"""
Data models, canonical enums, and Protobuf/KTX binary struct readers for Ephemeral Visual Residuals.
Covers iOS SplashBoard .ktx textures, Android TaskSnapshots (.proto + .jpg),
.ithmb thumbnail caches, and Disguised Vault KPA header restoration.
Complies with Section 6 of Phase 7 Module 7.2 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
import json
import os
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple, Union
import zlib

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


@unique
class SnapshotPlatform(str, Enum):
    """Platform compositor generating app-switcher multitasking snapshots."""
    IOS_SPLASHBOARD = "IOS_SPLASHBOARD"
    ANDROID_TASKSNAPSHOTS = "ANDROID_TASKSNAPSHOTS"


@unique
class CacheEngineType(str, Enum):
    """Engine or UI framework responsible for thumbnail/image caching."""
    IOS_ITHMB_SLOT = "IOS_ITHMB_SLOT"
    IOS_THUMBNAILS_V2_FILE = "IOS_THUMBNAILS_V2_FILE"
    ANDROID_THUMBDATA4_CARVED = "ANDROID_THUMBDATA4_CARVED"
    GLIDE_DISKLRLUCACHE = "GLIDE_DISKLRLUCACHE"
    FRESCO_CNT_CACHE = "FRESCO_CNT_CACHE"
    COIL_OKHTTP_CACHE = "COIL_OKHTTP_CACHE"
    KINGFISHER_SDWEBIMAGE_IOS = "KINGFISHER_SDWEBIMAGE_IOS"


@unique
class VaultUnmaskingMethod(str, Enum):
    """Mathematical or cryptographic method used to unmask hidden vault media."""
    HEADER_1BYTE_XOR_RESTORED = "HEADER_1BYTE_XOR_RESTORED"
    HEADER_MULTIBYTE_XOR_RESTORED = "HEADER_MULTIBYTE_XOR_RESTORED"
    HEADER_BYTE_SWAP_REVERSED = "HEADER_BYTE_SWAP_REVERSED"
    PREPENDED_VAULT_HEADER_STRIPPED = "PREPENDED_VAULT_HEADER_STRIPPED"
    VAULT_KEY_AES_DECRYPTED = "VAULT_KEY_AES_DECRYPTED"
    EXTENSION_RENAME_ONLY = "EXTENSION_RENAME_ONLY"


@dataclass
class AppSwitcherSnapshotRecord:
    """Record representing an operating-system multitasking screen snapshot."""
    os_platform: SnapshotPlatform
    source_vfs_file_id: int
    snapshot_file_path: str
    captured_app_bundle_or_pkg: str
    snapshot_captured_utc_iso: str
    snapshot_uid: Optional[int] = None
    android_user_profile_id: int = 0
    converted_png_staging_id: Optional[int] = None
    captured_activity_or_scene: Optional[str] = None
    is_real_content_snapshot: int = 1
    pixel_dimensions_and_orient: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS
    dim_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    dim_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    dim_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    dim_provenance: str = ""
    dim_corroboration: float = 1.0


@dataclass
class ReconstructedThumbnailRecord:
    """Record representing a recovered or orphaned thumbnail from .ithmb or image caches."""
    cache_engine_type: CacheEngineType
    owning_app_bundle_or_pkg: str
    source_vfs_file_id: int
    slot_index_or_cache_key: str
    reconstructed_file_path: str
    thumb_cache_uid: Optional[int] = None
    is_parent_original_deleted: int = 0
    matched_source_url: Optional[str] = None
    cached_or_accessed_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS
    dim_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    dim_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    dim_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    dim_provenance: str = ""
    dim_corroboration: float = 1.0


@dataclass
class UnmaskedVaultItemRecord:
    """Record representing an unmasked photo, video, or PDF from a disguised vault app."""
    vault_app_name_and_pkg: str
    obfuscated_vfs_file_id: int
    unmasking_method_applied: VaultUnmaskingMethod
    restored_mime_type: str
    restored_file_path: str
    vault_item_uid: Optional[int] = None
    recovered_xor_or_aes_key_hex: Optional[str] = None
    original_filename_from_vault_db: Optional[str] = None
    restored_derivative_staging_id: int = 0
    hidden_into_vault_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.RESIDUAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS
    dim_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    dim_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    dim_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    dim_provenance: str = ""
    dim_corroboration: float = 1.0


# ---------------------------------------------------------------------------
# Binary Decoding Helpers: Protobuf & KTX
# ---------------------------------------------------------------------------

def decode_task_snapshot_proto(data: bytes) -> Dict[str, Any]:
    """
    Decodes Android TaskSnapshotProto wire bytes without external protobuf dependencies.
    Extracts orientation (field 1), is_real_snapshot (field 3),
    top_activity_component (field 7), and snapshot id (field 9).
    """
    res: Dict[str, Any] = {
        "orientation": 1,
        "is_real_snapshot": 1,
        "top_activity_component": "",
        "id": 0,
    }
    idx = 0
    total = len(data)

    while idx < total:
        tag = data[idx]
        idx += 1
        wire_type = tag & 0x07
        field_num = tag >> 3

        if wire_type == 0:  # Varint
            val = 0
            shift = 0
            while idx < total:
                b = data[idx]
                idx += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if field_num == 1:
                res["orientation"] = val
            elif field_num == 3:
                res["is_real_snapshot"] = val
            elif field_num == 9:
                res["id"] = val
        elif wire_type == 2:  # Length-delimited string/bytes
            length = 0
            shift = 0
            while idx < total:
                b = data[idx]
                idx += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            content = data[idx : idx + length]
            idx += length
            if field_num == 7:
                res["top_activity_component"] = content.decode("utf-8", errors="ignore")
        elif wire_type == 5:  # 32-bit fixed
            idx += 4
        elif wire_type == 1:  # 64-bit fixed
            idx += 8
        else:
            break

    return res


def parse_ktx_header(data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parses a 64-byte Khronos Texture 1.1 (KTX) header.
    Returns width, height, glInternalFormat, and image data offset.
    """
    if len(data) < 64:
        return None
    magic = data[:12]
    if magic != b"\xab\x4b\x54\x58\x20\x31\x31\xbb\x0d\x0a\x1a\x0a":
        return None

    try:
        endianness = struct.unpack("<I", data[12:16])[0]
        fmt = "<" if endianness == 0x04030201 else ">"
        (
            gl_type,
            gl_type_size,
            gl_format,
            gl_internal_format,
            gl_base_internal_format,
            pixel_width,
            pixel_height,
            pixel_depth,
            number_of_array_elements,
            number_of_faces,
            number_of_mipmap_levels,
            bytes_of_key_value_data,
        ) = struct.unpack(f"{fmt}12I", data[16:64])

        data_offset = 64 + bytes_of_key_value_data
        image_size = 0
        if len(data) >= data_offset + 4:
            image_size = struct.unpack(f"{fmt}I", data[data_offset : data_offset + 4])[0]

        return {
            "pixel_width": pixel_width,
            "pixel_height": pixel_height,
            "gl_internal_format": gl_internal_format,
            "data_offset": data_offset + 4,
            "image_size": image_size,
        }
    except struct.error:
        return None


def write_rgba_png(width: int, height: int, raw_bgra: bytes, out_path: str) -> None:
    """
    Encodes raw BGRA pixels into a standard lossless PNG file using standard library zlib.
    """
    # Convert BGRA to RGBA scanlines with filter byte 0
    raw_len = len(raw_bgra)
    scanline_len = width * 4
    rgba_scanlines = bytearray()

    for y in range(height):
        rgba_scanlines.append(0)  # Filter type 0 (None)
        row_offset = y * scanline_len
        if row_offset + scanline_len <= raw_len:
            for x in range(width):
                px_idx = row_offset + (x * 4)
                b = raw_bgra[px_idx]
                g = raw_bgra[px_idx + 1]
                r = raw_bgra[px_idx + 2]
                a = raw_bgra[px_idx + 3]
                rgba_scanlines.extend((r, g, b, a))
        else:
            rgba_scanlines.extend(b"\x00" * scanline_len)

    compressed = zlib.compress(bytes(rgba_scanlines), level=6)

    def _make_chunk(chunk_type: bytes, chunk_data: bytes) -> bytes:
        length = struct.pack(">I", len(chunk_data))
        crc = struct.pack(">I", zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF)
        return length + chunk_type + chunk_data + crc

    png_header = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr_chunk = _make_chunk(b"IHDR", ihdr_data)
    idat_chunk = _make_chunk(b"IDAT", compressed)
    iend_chunk = _make_chunk(b"IEND", b"")

    with open(out_path, "wb") as f:
        f.write(png_header + ihdr_chunk + idat_chunk + iend_chunk)
