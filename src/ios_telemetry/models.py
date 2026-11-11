"""
Data models and canonical enums for iOS Behavioral Telemetry, Pattern-of-Life & Unified Logs.
Covers CoreDuet, Apple Biome, Screen Time, Apple Unified Logs, Physical Orientation, Apple Health, and FSEvents.
Complies with Section 8 of Phase 6 Module 6.1 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)

# Apple Cocoa Epoch offset: 2001-01-01 00:00:00 UTC = 978307200 Unix seconds
COCOA_EPOCH_OFFSET_SEC = 978307200


@unique
class TelemetrySourceEngine(str, Enum):
    """Origin telemetry engine."""
    COREDUET_KNOWLEDGEC = "COREDUET_KNOWLEDGEC"
    APPLE_BIOME_SEGB = "APPLE_BIOME_SEGB"
    SCREENTIME_RMADMIN = "SCREENTIME_RMADMIN"
    UNIFIED_LOG_TRACEV3 = "UNIFIED_LOG_TRACEV3"


@unique
class TelemetryEventCategory(str, Enum):
    """Forensic classification of behavioral telemetry event."""
    APP_IN_FOCUS = "APP_IN_FOCUS"
    SCREEN_LOCK_UNLOCK = "SCREEN_LOCK_UNLOCK"
    DISPLAY_BACKLIGHT = "DISPLAY_BACKLIGHT"
    PHYSICAL_SENSOR_ORIENTATION = "PHYSICAL_SENSOR_ORIENTATION"
    DISPLAY_UI_ORIENTATION = "DISPLAY_UI_ORIENTATION"
    FACEID_TOUCHID_AUTH = "FACEID_TOUCHID_AUTH"
    KEYBOARD_TYPING_SESSION = "KEYBOARD_TYPING_SESSION"
    TORCH_FLASHLIGHT = "TORCH_FLASHLIGHT"
    AUDIO_BT_CARPLAY_ROUTE = "AUDIO_BT_CARPLAY_ROUTE"
    SIRI_APP_INTENT = "SIRI_APP_INTENT"
    HARDWARE_BUTTON_PRESS = "HARDWARE_BUTTON_PRESS"


@unique
class HealthSensorMetricType(str, Enum):
    """Apple Health metric classification."""
    STEP_COUNT = "STEP_COUNT"
    DISTANCE_WALK_RUN_METERS = "DISTANCE_WALK_RUN_METERS"
    FLIGHTS_CLIMBED = "FLIGHTS_CLIMBED"
    HEART_RATE_BPM = "HEART_RATE_BPM"
    SLEEP_STAGE = "SLEEP_STAGE"
    ACTIVE_ENERGY = "ACTIVE_ENERGY"


@unique
class PhysicalOrientation(int, Enum):
    """CMDeviceOrientation codes from hardware accelerometer/gyroscope."""
    PORTRAIT = 1
    PORTRAIT_UPSIDE_DOWN = 2
    LANDSCAPE_LEFT = 3
    LANDSCAPE_RIGHT = 4
    FACE_UP = 5
    FACE_DOWN = 6


def cocoa_to_utc_ns(cocoa_sec: float) -> int:
    """Converts Cocoa seconds since 2001-01-01 to 64-bit UTC nanoseconds."""
    unix_sec = cocoa_sec + COCOA_EPOCH_OFFSET_SEC
    return int(unix_sec * 1_000_000_000)


def cocoa_to_utc_iso(cocoa_sec: float) -> str:
    """Converts Cocoa seconds since 2001-01-01 to UTC ISO-8601 string."""
    unix_sec = cocoa_sec + COCOA_EPOCH_OFFSET_SEC
    sec = int(unix_sec)
    us = int(round((unix_sec - sec) * 1_000_000))
    if us >= 1_000_000:
        sec += 1
        us = 0
    dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def decode_fsevent_flags(flags: int) -> str:
    """Decodes 32-bit FSEvents bitmask into human-readable flags list."""
    flag_defs = [
        (0x01000000, "IsFile"),
        (0x02000000, "IsDir"),
        (0x04000000, "IsSymlink"),
        (0x08000000, "Mount"),
        (0x00000001, "ItemCreated"),
        (0x00000002, "ItemRemoved"),
        (0x00000004, "InodeMetaMod"),
        (0x00000008, "ItemRenamed"),
        (0x00000010, "ItemModified"),
        (0x00000020, "FinderInfoMod"),
        (0x00000040, "ChangeOwner"),
        (0x00000080, "XattrMod"),
    ]
    parts = []
    for bit, name in flag_defs:
        if flags & bit:
            parts.append(name)
    return " | ".join(parts) if parts else "Unknown"


@dataclass
class IOSTelemetryEventRecord:
    """Model for Table 1: ios_behavioral_timeline_ledger."""
    telemetry_source_engine: TelemetrySourceEngine = TelemetrySourceEngine.COREDUET_KNOWLEDGEC
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    device_locality: str = "LOCAL_SEIZED_IPHONE"
    stream_or_subsystem_name: str = ""
    event_category: TelemetryEventCategory = TelemetryEventCategory.APP_IN_FOCUS
    target_app_bundle_id: Optional[str] = None
    primary_state_or_value: str = ""
    unpacked_metadata_json: Optional[str] = None
    start_utc_ns: int = 0
    start_utc_iso: str = ""
    end_utc_iso: Optional[str] = None
    duration_seconds: Optional[float] = None
    recorded_tz_offset_sec: Optional[int] = None
    forensic_group: ForensicGroup = ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY
    ios_telemetry_uid: Optional[int] = None


@dataclass
class IOSHealthSampleRecord:
    """Model for Table 2: ios_health_sensor_alibi_ledger."""
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    sensor_metric_type: HealthSensorMetricType = HealthSensorMetricType.STEP_COUNT
    metric_value: float = 0.0
    hardware_source_model: str = ""
    is_local_iphone_sensor: int = 1
    was_manually_user_entered: int = 0
    activity_start_utc_iso: str = ""
    activity_end_utc_iso: str = ""
    db_sync_committed_utc_iso: str = ""
    forensic_group: ForensicGroup = ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY
    health_sample_uid: Optional[int] = None


@dataclass
class IOSFSEventRecord:
    """Model for Table 3: ios_fsevents_filesystem_audit."""
    gzip_source_file_name: str = ""
    fsevent_format_version: str = "2SLG"
    monotonic_event_id: int = 0
    target_file_path: str = ""
    apfs_inode_node_id: Optional[int] = None
    decoded_flags_list: str = ""
    does_file_still_exist: int = 0
    bracket_earliest_utc_iso: Optional[str] = None
    bracket_latest_utc_iso: str = ""
    forensic_group: ForensicGroup = ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY
    fsevent_uid: Optional[int] = None
