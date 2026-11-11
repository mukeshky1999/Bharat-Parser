"""
Data models, canonical enums, and mathematical helper decoders for Anti-Forensics,
Tamper Detection, OS Integrity, Clock Manipulation, Mock GPS, and Indian Banking Trojan Audits.
Complies with Phase 6 Module 6.5 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
import json
import math
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
class IntegrityFindingCategory(str, Enum):
    """Classification of root, bootloader, kernel hook, or jailbreak integrity findings."""
    BOOTLOADER_UNLOCKED = "BOOTLOADER_UNLOCKED"
    MAGISK_ROOT_POLICY = "MAGISK_ROOT_POLICY"
    MAGISK_ZYGISK_DENYLIST_HIDE = "MAGISK_ZYGISK_DENYLIST_HIDE"
    MAGISK_REPACKAGED_HIDDEN_APP = "MAGISK_REPACKAGED_HIDDEN_APP"
    KERNELSU_OR_APATCH_ROOT = "KERNELSU_OR_APATCH_ROOT"
    LSPOSED_XPOSED_APP_HOOK = "LSPOSED_XPOSED_APP_HOOK"
    IOS_JAILBREAK_OR_TROLLSTORE = "IOS_JAILBREAK_OR_TROLLSTORE"
    ADB_DEVELOPER_OPTIONS_ENABLED = "ADB_DEVELOPER_OPTIONS_ENABLED"


@unique
class TamperCategory(str, Enum):
    """Classification of clock tampering, mass deletion, and database wiping events."""
    CLOCK_ROLLBACK_ROWID_INVERSION = "CLOCK_ROLLBACK_ROWID_INVERSION"
    OS_MANUAL_CLOCK_SET_EVENT = "OS_MANUAL_CLOCK_SET_EVENT"
    TIMESYNC_KERNEL_WALLCLOCK_JUMP = "TIMESYNC_KERNEL_WALLCLOCK_JUMP"
    SQLITE_SEQUENCE_TAIL_DELETION_GAP = "SQLITE_SEQUENCE_TAIL_DELETION_GAP"
    TELEMETRY_PROVEN_DB_WIPING_GAP = "TELEMETRY_PROVEN_DB_WIPING_GAP"
    FSEVENTS_GAP_OF_DARKNESS = "FSEVENTS_GAP_OF_DARKNESS"
    SURGICAL_FILE_TIMESTOMP = "SURGICAL_FILE_TIMESTOMP"
    BULK_BACKUP_RESTORE_MIGRATION = "BULK_BACKUP_RESTORE_MIGRATION"
    WIPER_OR_VAULT_APP_DETECTED = "WIPER_OR_VAULT_APP_DETECTED"


@unique
class SpoofMethod(str, Enum):
    """Classification of location spoofing and multi-sensor physical contradictions."""
    APPOPS_MOCK_LOCATION_OP_58 = "APPOPS_MOCK_LOCATION_OP_58"
    IOS_USB_SIMULATED_LOCATION = "IOS_USB_SIMULATED_LOCATION"
    SPOOF_APP_INSTALLED_OR_GHOST = "SPOOF_APP_INSTALLED_OR_GHOST"
    GPS_VS_CELL_WIFI_RADIO_CONTRADICTION = "GPS_VS_CELL_WIFI_RADIO_CONTRADICTION"
    GPS_MOVEMENT_WHILE_CHARGING_ZERO_STEPS = "GPS_MOVEMENT_WHILE_CHARGING_ZERO_STEPS"


@unique
class ThreatCategory(str, Enum):
    """Classification of Indian cybercrime APK trojans, C2 endpoints, and remote takeovers."""
    SIDELOADED_SMS_OR_OVERLAY_TROJAN_APK = "SIDELOADED_SMS_OR_OVERLAY_TROJAN_APK"
    EXTRACTED_TELEGRAM_BOT_C2_TOKEN = "EXTRACTED_TELEGRAM_BOT_C2_TOKEN"
    EXTRACTED_FIREBASE_OR_WEB_C2 = "EXTRACTED_FIREBASE_OR_WEB_C2"
    USSD_CALL_FORWARDING_HIJACK = "USSD_CALL_FORWARDING_HIJACK"
    ANYDESK_OR_REMOTE_DESKTOP_SESSION = "ANYDESK_OR_REMOTE_DESKTOP_SESSION"


@dataclass
class OSIntegrityAuditRecord:
    """Record representing an operating system root, bootloader, or jailbreak finding."""
    finding_category: IntegrityFindingCategory
    source_vfs_file_id: int
    policy_or_state: str
    integrity_uid: Optional[int] = None
    target_or_requester_pkg: Optional[str] = None
    hook_module_or_detail: Optional[str] = None
    event_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER
    dim_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    dim_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    dim_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    dim_provenance: str = ""
    dim_corroboration: float = 1.0


@dataclass
class ClockTamperGapRecord:
    """Record representing clock manipulation, monotonic sequence inversion, or tail-row wiping."""
    tamper_category: TamperCategory
    severity_level: str  # "CRITICAL", "HIGH", "INFO_MIGRATION"
    affected_app_or_database: str
    source_vfs_file_id: int
    monotonic_anchor_detail: str
    courtroom_explanation_note: str
    tamper_event_uid: Optional[int] = None
    claimed_wallclock_utc_iso: Optional[str] = None
    true_bracketed_window_utc: Optional[str] = None
    forensic_group: ForensicGroup = ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    dim_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    dim_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    dim_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    dim_provenance: str = ""
    dim_corroboration: float = 1.0


@dataclass
class LocationSpoofContradictionRecord:
    """Record representing a detected Mock GPS setting or multi-sensor physical contradiction."""
    detection_method: SpoofMethod
    contradicting_sensor_proof: str
    event_utc_iso: str
    spoof_flag_uid: Optional[int] = None
    spoofer_package_or_tool: Optional[str] = None
    claimed_gps_lat_lon: Optional[str] = None
    forensic_group: ForensicGroup = ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    dim_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    dim_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    dim_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    dim_provenance: str = ""
    dim_corroboration: float = 1.0


@dataclass
class MalwareThreatRecord:
    """Record representing a sideloaded trojan, hardcoded C2 endpoint, or remote session."""
    threat_category: ThreatCategory
    malicious_pkg_or_tool_name: str
    extracted_c2_or_remote_id: str
    threat_record_uid: Optional[int] = None
    installer_or_sideload_source: Optional[str] = None
    abused_permissions_list: Optional[str] = None
    session_start_or_install_utc: Optional[str] = None
    session_end_utc_iso: Optional[str] = None
    overlapped_financial_tx_uids: Optional[str] = None
    forensic_group: ForensicGroup = ForensicGroup.G16_SECURITY_KEYCHAIN_AND_TAMPER
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    dim_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    dim_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    dim_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    dim_provenance: str = ""
    dim_corroboration: float = 1.0


# ---------------------------------------------------------------------------
# Mathematical & Forensic String Extraction Helpers
# ---------------------------------------------------------------------------

_TELEGRAM_TOKEN_REGEX = re.compile(r"bot([0-9]{8,12}:[A-Za-z0-9_-]{35})")
_TELEGRAM_CHAT_ID_REGEX = re.compile(r"chat_id=(-?[0-9]{8,14}|@[A-Za-z0-9_]+)")
_FIREBASE_URL_REGEX = re.compile(r"https://[a-zA-Z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)")
_GENERIC_C2_URL_REGEX = re.compile(r"https?://[^\"'\s<>\\]+/(?:sms|otp|api|login|upload|panel)[^\"'\s<>\\]*")

_USSD_FORWARDING_REGEX = re.compile(
    r"^\*(\*?(?:21|67|61|62|002|004|401|403|405|409))\*(\+?[0-9]{10,13})#?$"
)


def extract_telegram_c2(data: Union[bytes, str]) -> Optional[Dict[str, str]]:
    """
    Extracts hardcoded Telegram Bot token and target chat ID from Dalvik bytecode or plaintext strings.
    Returns dict with keys 'bot_token' and optional 'chat_id', or None if not found.
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="ignore")
    else:
        text = data

    token_match = _TELEGRAM_TOKEN_REGEX.search(text)
    if not token_match:
        # Check without 'bot' prefix if raw token
        raw_match = re.search(r"([0-9]{8,12}:[A-Za-z0-9_-]{35})", text)
        if raw_match:
            token = raw_match.group(1)
        else:
            return None
    else:
        token = token_match.group(1)

    chat_match = _TELEGRAM_CHAT_ID_REGEX.search(text)
    chat_id = chat_match.group(1) if chat_match else None

    return {
        "bot_token": token,
        "chat_id": chat_id if chat_id else "",
    }


def parse_ussd_forwarding(number: str) -> Optional[Tuple[str, str]]:
    """
    Detects unconditional or conditional call forwarding USSD codes.
    Returns tuple of (code, destination_phone_number), or None if not a forwarding USSD string.
    Supported: GSM (*21*, *67*, *61*, *62*, *002*, *004*) and Reliance Jio (*401*, *403*, *405*, *409*).
    """
    cleaned = number.strip().replace(" ", "")
    m = _USSD_FORWARDING_REGEX.match(cleaned)
    if m:
        code = m.group(1)
        dest = m.group(2)
        return code, dest
    return None


def calculate_haversine_distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculates great-circle distance between two points on the Earth surface in meters.
    """
    earth_radius_m = 6371000.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return earth_radius_m * c


def parse_anydesk_trace_events(lines: List[str]) -> List[Dict[str, Any]]:
    """
    Parses AnyDesk ad_svc.trace / ad_app.trace log lines to extract incoming sessions,
    remote client IDs, source IP addresses, and session start/end timestamps.
    """
    sessions: List[Dict[str, Any]] = []
    current_session: Optional[Dict[str, Any]] = None

    login_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\w+\s+Logged in from\s+(\d+)(?:\s+\(([^)]+)\))?"
    )
    close_pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\w+\s+Session closed"
    )

    for line in lines:
        line_clean = line.strip()
        login_match = login_pattern.match(line_clean)
        if login_match:
            raw_ts = login_match.group(1).replace(" ", "T")
            if "." in raw_ts:
                dt_iso = f"{raw_ts}Z"
            else:
                dt_iso = f"{raw_ts}.000000Z"

            remote_id = login_match.group(2)
            ip_info = login_match.group(3) or ""

            current_session = {
                "remote_id": remote_id,
                "remote_ip_port": ip_info,
                "start_utc": dt_iso,
                "end_utc": None,
            }
            sessions.append(current_session)
            continue

        close_match = close_pattern.match(line_clean)
        if close_match and current_session:
            raw_ts = close_match.group(1).replace(" ", "T")
            if "." in raw_ts:
                dt_iso = f"{raw_ts}Z"
            else:
                dt_iso = f"{raw_ts}.000000Z"
            current_session["end_utc"] = dt_iso
            current_session = None

    return sessions
