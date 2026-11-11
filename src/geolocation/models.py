"""
Data models, canonical enums, and mathematical algorithms for Geolocation, Triangulation & Timelines.
Covers 4-tier provenance separation, MAC normalizer, Haversine velocity validator, and Indian cellular CGI math.
Complies with Section 7 of Phase 6 Module 6.3 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
import math
import re
from typing import Any, Dict, List, Optional, Tuple

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
class ProvenanceTier(str, Enum):
    """Mandatory 4-Tier Geolocation Provenance Hierarchy."""
    TIER_1_ACTIVE_DEVICE_FIX = "TIER_1_ACTIVE_DEVICE_FIX"
    TIER_2_CONNECTED_RADIO_HANDSHAKE = "TIER_2_CONNECTED_RADIO_HANDSHAKE"
    TIER_3_PASSIVE_RADIO_SIGHTING = "TIER_3_PASSIVE_RADIO_SIGHTING"
    TIER_4_CROWDSOURCED_LOOKUP_TILE_OR_SEARCH = "TIER_4_CROWDSOURCED_LOOKUP_TILE_OR_SEARCH"


@unique
class SpatialPrecisionClass(str, Enum):
    """Spatial precision classification based on horizontal accuracy radius."""
    PINPOINT_GNSS_UNDER_25M = "PINPOINT_GNSS_UNDER_25M"
    BUILDING_WIFI_25_TO_100M = "BUILDING_WIFI_25_TO_100M"
    NEIGHBORHOOD_CELL_100_TO_1000M = "NEIGHBORHOOD_CELL_100_TO_1000M"
    BROAD_SECTOR_OVER_1000M = "BROAD_SECTOR_OVER_1000M"
    UNSPECIFIED_RADIUS = "UNSPECIFIED_RADIUS"


@unique
class RadioCategory(str, Enum):
    """Classification of radio connections, hotspot leases, and Bluetooth pairings."""
    WIFI_KNOWN_CONNECTED_NETWORK = "WIFI_KNOWN_CONNECTED_NETWORK"
    MOBILE_HOTSPOT_SOFTAP_CLIENT_LEASE = "MOBILE_HOTSPOT_SOFTAP_CLIENT_LEASE"
    ACTIVE_PAIRED_BLUETOOTH_DEVICE = "ACTIVE_PAIRED_BLUETOOTH_DEVICE"
    PASSIVE_AMBIENT_BLE_SIGHTING = "PASSIVE_AMBIENT_BLE_SIGHTING"


@unique
class TripRecordType(str, Enum):
    """Type of significant location visit, trip, or turn-by-turn navigation record."""
    ROUTINED_SIGNIFICANT_VISIT = "ROUTINED_SIGNIFICANT_VISIT"
    GOOGLE_TIMELINE_PLACE_VISIT = "GOOGLE_TIMELINE_PLACE_VISIT"
    GOOGLE_TIMELINE_TRANSIT_SEGMENT = "GOOGLE_TIMELINE_TRANSIT_SEGMENT"
    MAPS_TURN_BY_TURN_NAVIGATION = "MAPS_TURN_BY_TURN_NAVIGATION"


def normalize_mac_6_octet(mac_str: str) -> str:
    """
    Normalizes any 6-octet MAC / BSSID string into canonical zero-padded lowercase:
    e.g. '0:1a:2b:3c:4:f0' -> '00:1a:2b:3c:04:f0'.
    Handles colon, hyphen, or continuous 12-char hex strings.
    """
    if not mac_str:
        return "00:00:00:00:00:00"

    cleaned = mac_str.strip()
    if ":" in cleaned or "-" in cleaned:
        tokens = re.split(r"[:\-]", cleaned)
    elif len(cleaned) == 12:
        tokens = [cleaned[i : i + 2] for i in range(0, 12, 2)]
    else:
        tokens = [cleaned]

    if len(tokens) == 6:
        padded = [tok.zfill(2).lower() for tok in tokens]
        return ":".join(padded)

    return cleaned.lower()


def haversine_distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Computes great-circle distance between two coordinates in meters using the Haversine formula.
    Earth radius = 6,371,000 meters.
    """
    r_earth = 6_371_000.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
    a = min(1.0, max(0.0, a))
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r_earth * c


def compute_velocity_kmh(
    lat1: float,
    lon1: float,
    r1: float,
    lat2: float,
    lon2: float,
    r2: float,
    delta_sec: float,
) -> float:
    """
    Computes minimum edge-adjusted speed v_kmh between two location fixes
    accounting for horizontal uncertainty circles R1 and R2:
      d_min_edge = max(0.0, d_meters - (R1 + R2))
      v_kmh = (d_min_edge / delta_sec) * 3.6
    """
    if delta_sec <= 0.0:
        return 0.0

    d_raw = haversine_distance_meters(lat1, lon1, lat2, lon2)
    d_min_edge = max(0.0, d_raw - (r1 + r2))
    return (d_min_edge / delta_sec) * 3.6


def unpack_lte_eci(eci: int) -> Tuple[int, int]:
    """
    Unpacks 28-bit 4G LTE ECI (E-UTRAN Cell Identifier) into:
      eNodeB_ID = ECI >> 8 (upper 20 bits)
      Sector_ID = ECI & 0xFF (lower 8 bits)
    """
    enodeb_id = eci >> 8
    sector_id = eci & 0xFF
    return enodeb_id, sector_id


def unpack_5g_nci(nci: int) -> Tuple[int, int]:
    """
    Unpacks 36-bit 5G NR NCI (NR Cell Identity) into:
      gNodeB_ID = NCI >> 12 (upper 24 bits) or NCI >> 8
      Sector_ID = NCI & 0xFFF
    """
    gnodeb_id = nci >> 12
    sector_id = nci & 0xFFF
    return gnodeb_id, sector_id


def unix_ms_to_utc_iso(unix_ms: int) -> str:
    """Converts 13-digit Unix milliseconds to UTC ISO-8601 string."""
    sec = unix_ms // 1000
    us = (unix_ms % 1000) * 1000
    dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cocoa_to_utc_iso(cocoa_sec: float) -> str:
    """Converts Apple Cocoa seconds since 2001-01-01 to UTC ISO-8601 string."""
    unix_sec = cocoa_sec + COCOA_EPOCH_OFFSET_SEC
    sec = int(unix_sec)
    us = int(round((unix_sec - sec) * 1_000_000))
    if us >= 1_000_000:
        sec += 1
        us = 0
    dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cocoa_to_utc_ns(cocoa_sec: float) -> int:
    """Converts Apple Cocoa seconds since 2001-01-01 to 64-bit UTC nanoseconds."""
    unix_sec = cocoa_sec + COCOA_EPOCH_OFFSET_SEC
    return int(unix_sec * 1_000_000_000)


@dataclass
class UnifiedGeoFixRecord:
    """Model for Table 1: unified_geolocation_fixes_ledger."""
    provenance_tier: ProvenanceTier = ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX
    source_subsystem: str = "UNKNOWN"
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    device_locality: str = "LOCAL_SEIZED_HANDSET"
    latitude_wgs84: float = 0.0
    longitude_wgs84: float = 0.0
    horizontal_accuracy_meters: Optional[float] = None
    spatial_precision_class: SpatialPrecisionClass = SpatialPrecisionClass.UNSPECIFIED_RADIUS
    altitude_meters: Optional[float] = None
    speed_kmh: Optional[float] = None
    implied_velocity_from_prev_kmh: Optional[float] = None
    is_impossible_velocity_flagged: int = 0
    resolved_address_or_place_name: Optional[str] = None
    associated_bssid_or_cgi: Optional[str] = None
    fix_start_utc_ns: int = 0
    fix_start_utc_iso: str = ""
    fix_end_utc_iso: Optional[str] = None
    forensic_group: ForensicGroup = ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE
    geo_fix_uid: Optional[int] = None


@dataclass
class RadioConnectionRecord:
    """Model for Table 2: wifi_hotspot_and_bluetooth_connections_ledger."""
    radio_category: RadioCategory = RadioCategory.WIFI_KNOWN_CONNECTED_NETWORK
    source_vfs_file_id: int = 0
    ssid_or_device_name: Optional[str] = None
    normalized_bssid_or_mac: Optional[str] = None
    saved_wifi_password_psk: Optional[str] = None
    device_type_or_captive_url: Optional[str] = None
    first_added_utc_iso: Optional[str] = None
    last_connected_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G14_NETWORK_WIFI_BT_AND_DATAUSAGE
    radio_conn_uid: Optional[int] = None


@dataclass
class CellularObservationRecord:
    """Model for Table 3: cellular_tower_cgi_observations."""
    provenance_tier: str = "TIER_2_SERVING_CELL"
    rat_generation: str = "4G_LTE"
    mcc_mnc: str = "405-86"
    lac_or_tac: int = 0
    raw_ci_eci_or_nci: int = 0
    unpacked_enodeb_or_gnodeb_id: Optional[int] = None
    unpacked_sector_id: Optional[int] = None
    tower_lat_wgs84: Optional[float] = None
    tower_lon_wgs84: Optional[float] = None
    observed_utc_iso: str = ""
    forensic_group: ForensicGroup = ForensicGroup.G14_NETWORK_WIFI_BT_AND_DATAUSAGE
    cell_obs_uid: Optional[int] = None


@dataclass
class SignificantPlaceTripRecord:
    """Model for Table 4: significant_places_and_navigation_trips."""
    record_type: TripRecordType = TripRecordType.ROUTINED_SIGNIFICANT_VISIT
    semantic_label: Optional[str] = None
    place_title_and_address: Optional[str] = None
    origin_lat_lon_json: Optional[str] = None
    destination_lat_lon_json: str = "{}"
    data_point_count_or_confidence: Optional[str] = None
    arrival_or_start_utc_iso: str = ""
    departure_or_end_utc_iso: Optional[str] = None
    dwell_duration_minutes: Optional[float] = None
    forensic_group: ForensicGroup = ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE
    place_trip_uid: Optional[int] = None
