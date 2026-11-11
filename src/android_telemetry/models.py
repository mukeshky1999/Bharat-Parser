"""
Data models and canonical enums for Android Behavioral Telemetry, Sensor & Usage Engine.
Covers UsageStats (Protobuf & XML), AppOps 3-Source Privacy Auditor, Digital Wellbeing, Health Connect, and Netstats.
Complies with Section 8 of Phase 6 Module 6.2 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Any, Dict, List, Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


@unique
class TelemetrySource(str, Enum):
    """Source subsystem for Android usage and lifecycle events."""
    USAGESTATS_DAILY_EVENTLOG = "USAGESTATS_DAILY_EVENTLOG"
    USAGESTATS_AGGREGATE_ROLLUP = "USAGESTATS_AGGREGATE_ROLLUP"
    GOOGLE_DIGITAL_WELLBEING = "GOOGLE_DIGITAL_WELLBEING"
    SAMSUNG_FOREST_DWB = "SAMSUNG_FOREST_DWB"
    SYSTEM_DROPBOX_LOG = "SYSTEM_DROPBOX_LOG"


@unique
class AndroidEventCategory(str, Enum):
    """Canonical Android event categories."""
    ACTIVITY_RESUMED_FOREGROUND = "ACTIVITY_RESUMED_FOREGROUND"
    ACTIVITY_PAUSED_BACKGROUND = "ACTIVITY_PAUSED_BACKGROUND"
    KEYGUARD_UNLOCKED = "KEYGUARD_UNLOCKED"
    KEYGUARD_LOCKED = "KEYGUARD_LOCKED"
    SCREEN_ON_INTERACTIVE = "SCREEN_ON_INTERACTIVE"
    SCREEN_OFF_DARK = "SCREEN_OFF_DARK"
    SCREEN_ROTATION_CONFIG = "SCREEN_ROTATION_CONFIG"
    FOREGROUND_SERVICE_START = "FOREGROUND_SERVICE_START"
    FOREGROUND_SERVICE_STOP = "FOREGROUND_SERVICE_STOP"
    DEVICE_SHUTDOWN = "DEVICE_SHUTDOWN"
    DEVICE_STARTUP = "DEVICE_STARTUP"
    APP_CRASH_OR_ANR = "APP_CRASH_OR_ANR"
    AGGREGATED_USAGE_WINDOW = "AGGREGATED_USAGE_WINDOW"


@unique
class AppOpsSourceSubsystem(str, Enum):
    """Source origin for AppOps and Privacy Dashboard logs."""
    APPOPS_DISCRETE_7DAY_HISTORY = "APPOPS_DISCRETE_7DAY_HISTORY"
    APPOPS_XML_SUMMARY = "APPOPS_XML_SUMMARY"
    PERMISSION_CONTROLLER_APEX_DB = "PERMISSION_CONTROLLER_APEX_DB"


@unique
class AndroidHealthDomain(str, Enum):
    """Domain classification for Android Health Connect and Netstats ledgers."""
    HEALTH_CONNECT_FRAMEWORK = "HEALTH_CONNECT_FRAMEWORK"
    HEALTH_CONNECT_APK = "HEALTH_CONNECT_APK"
    SAMSUNG_OR_GOOGLE_FIT = "SAMSUNG_OR_GOOGLE_FIT"
    NETSTATS_UID_BANDWIDTH = "NETSTATS_UID_BANDWIDTH"


def unix_ms_to_utc_ns(unix_ms: int) -> int:
    """Converts 13-digit Unix milliseconds to 64-bit UTC nanoseconds."""
    return int(unix_ms) * 1_000_000


def unix_ms_to_utc_iso(unix_ms: int) -> str:
    """Converts 13-digit Unix milliseconds to UTC ISO-8601 string."""
    sec = unix_ms // 1000
    us = (unix_ms % 1000) * 1000
    dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class AndroidUsageEventRecord:
    """Model for Table 1: android_usagestats_and_lifecycle_ledger."""
    android_user_profile_id: int = 0
    telemetry_source: TelemetrySource = TelemetrySource.USAGESTATS_DAILY_EVENTLOG
    source_vfs_file_id: int = 0
    granularity_level: str = "GRANULAR_MILLISECOND_EVENT"
    package_name: str = ""
    activity_or_service_class: Optional[str] = None
    is_uninstalled_ghost_app: int = 0
    event_category: AndroidEventCategory = AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND
    event_timestamp_utc_ns: int = 0
    event_timestamp_utc_iso: str = ""
    aggregated_fg_duration_sec: Optional[float] = None
    forensic_group: ForensicGroup = ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY
    android_event_uid: Optional[int] = None


@dataclass
class AndroidAppOpRecord:
    """Model for Table 2: android_appops_and_privacy_sensor_audit."""
    source_subsystem: AppOpsSourceSubsystem = AppOpsSourceSubsystem.APPOPS_DISCRETE_7DAY_HISTORY
    source_vfs_file_id: int = 0
    package_name: str = ""
    linux_uid: Optional[int] = None
    op_code_and_name: str = ""
    process_uid_state: Optional[str] = None
    access_outcome: str = "ALLOWED_GRANTED"
    access_timestamp_utc_iso: str = ""
    access_duration_seconds: Optional[float] = None
    forensic_group: ForensicGroup = ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY
    appop_record_uid: Optional[int] = None


@dataclass
class AndroidHealthNetworkRecord:
    """Model for Table 3: android_health_and_network_usage_ledger."""
    ledger_domain: AndroidHealthDomain = AndroidHealthDomain.HEALTH_CONNECT_FRAMEWORK
    package_or_source_app: str = ""
    metric_type: str = "STEP_COUNT"
    primary_numeric_value: float = 0.0
    secondary_detail_json: Optional[str] = None
    window_start_utc_iso: str = ""
    window_end_utc_iso: str = ""
    forensic_group: ForensicGroup = ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY
    record_uid: Optional[int] = None
