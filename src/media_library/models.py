"""
Data models, canonical enums, and timestamp converters for Mobile OS Media Library Forensics.
Covers Photos.sqlite, MediaProvider external.db, Mutations uncropped masters,
EXIF/HEIC/ISO-BMFF provenance, and Motion/Live Photo video pairings.
Complies with Section 6 of Phase 7 Module 7.1 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


@unique
class OSPlatformSource(str, Enum):
    """Source database or extraction origin for media metadata."""
    IOS_PHOTOS_SQLITE = "IOS_PHOTOS_SQLITE"
    IOS_SYNDICATION_SQLITE = "IOS_SYNDICATION_SQLITE"
    ANDROID_MEDIAPROVIDER_EXTERNAL_DB = "ANDROID_MEDIAPROVIDER_EXTERNAL_DB"
    ANDROID_GOOGLE_PHOTOS_DB = "ANDROID_GOOGLE_PHOTOS_DB"
    ANDROID_MARS_LOCKED_FOLDER = "ANDROID_MARS_LOCKED_FOLDER"
    RAW_FILESYSTEM_CARVED = "RAW_FILESYSTEM_CARVED"


@unique
class ProvenanceClassification(str, Enum):
    """Authenticity and provenance origin classification of media asset."""
    AUTHENTIC_CAMERA_ORIGINAL = "AUTHENTIC_CAMERA_ORIGINAL"
    OS_SCREENSHOT_OR_SCREEN_RECORDING = "OS_SCREENSHOT_OR_SCREEN_RECORDING"
    MESSENGER_TRANSMITTED_REENCODED = "MESSENGER_TRANSMITTED_REENCODED"
    SOFTWARE_EDITED_OR_MANIPULATED = "SOFTWARE_EDITED_OR_MANIPULATED"
    CLOUD_SHARED_BY_OTHER_USER = "CLOUD_SHARED_BY_OTHER_USER"


@unique
class UserConcealmentState(str, Enum):
    """Forensic concealment or lifecycle state of the media asset."""
    ACTIVE_VISIBLE = "ACTIVE_VISIBLE"
    IN_RECENTLY_DELETED_TRASH = "IN_RECENTLY_DELETED_TRASH"
    IN_BIOMETRIC_HIDDEN_OR_LOCKED_ALBUM = "IN_BIOMETRIC_HIDDEN_OR_LOCKED_ALBUM"
    PERMANENTLY_PURGED_DB_RESIDUAL_ONLY = "PERMANENTLY_PURGED_DB_RESIDUAL_ONLY"


@dataclass
class MediaAssetRecord:
    """Unified record representing an analyzed photo or video asset in the case ledger."""
    os_platform_source: OSPlatformSource
    canonical_file_path: str
    provenance_classification: ProvenanceClassification
    media_asset_uid: Optional[int] = None
    vfs_file_id: Optional[int] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    original_pre_import_filename: Optional[str] = None
    originating_app_bundle_or_pkg: Optional[str] = None
    user_concealment_state: UserConcealmentState = UserConcealmentState.ACTIVE_VISIBLE
    trashed_or_deleted_utc_iso: Optional[str] = None
    has_uncropped_original_recovered: int = 0
    mutations_edited_vfs_file_id: Optional[int] = None
    mutations_edited_file_path: Optional[str] = None
    paired_live_or_motion_video_id: Optional[int] = None
    paired_video_file_path: Optional[str] = None
    linked_chat_syndication_id: Optional[str] = None
    capture_created_utc_iso: Optional[str] = None
    library_imported_utc_iso: Optional[str] = None
    capture_timezone_offset_str: Optional[str] = None
    gps_lat_lon_alt_heading_json: Optional[str] = None
    camera_make_model_lens: Optional[str] = None
    file_sha256: Optional[str] = None
    forensic_group: ForensicGroup = ForensicGroup.G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS
    dim_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    dim_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    dim_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    dim_provenance: str = ""
    dim_corroboration: float = 1.0


# ---------------------------------------------------------------------------
# Timestamp Conversion Helpers
# ---------------------------------------------------------------------------

COCOA_EPOCH_DIFF_SECONDS = 978307200.0  # 2001-01-01 00:00:00 UTC in Unix epoch
QUICKTIME_EPOCH_DIFF_SECONDS = 2082844800  # 1904-01-01 00:00:00 UTC in Unix epoch


def cocoa_seconds_to_utc_iso(cocoa_seconds: Optional[float]) -> Optional[str]:
    """Converts Apple Cocoa CoreData timestamp (seconds since 2001-01-01) to UTC ISO-8601 string."""
    if cocoa_seconds is None or cocoa_seconds == 0.0:
        return None
    try:
        unix_ts = cocoa_seconds + COCOA_EPOCH_DIFF_SECONDS
        dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, OverflowError, OSError):
        return None


def quicktime_seconds_to_utc_iso(qt_seconds: Optional[int]) -> Optional[str]:
    """Converts ISO-BMFF / QuickTime timestamp (seconds since 1904-01-01) to UTC ISO-8601 string."""
    if qt_seconds is None or qt_seconds == 0:
        return None
    try:
        unix_ts = qt_seconds - QUICKTIME_EPOCH_DIFF_SECONDS
        dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, OverflowError, OSError):
        return None


def unix_seconds_or_ms_to_utc_iso(ts_value: Optional[Union[int, float]]) -> Optional[str]:
    """Converts Unix seconds or milliseconds to UTC ISO-8601 string."""
    if ts_value is None or ts_value == 0:
        return None
    try:
        val = float(ts_value)
        sec = val / 1000.0 if val > 1e11 else val
        dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (ValueError, OverflowError, OSError):
        return None
