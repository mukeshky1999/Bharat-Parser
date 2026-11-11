"""
OS Geolocation, Wi-Fi/BLE/Cellular Triangulation & Timeline Engine.
Sub-engines for iOS CoreLocation, Google Timeline, Cellular Tower CGI, and Haversine velocity validation.
Phase 6 Module 6.3.
"""

from src.geolocation.models import (
    ProvenanceTier,
    SpatialPrecisionClass,
    RadioCategory,
    TripRecordType,
    UnifiedGeoFixRecord,
    RadioConnectionRecord,
    CellularObservationRecord,
    SignificantPlaceTripRecord,
    normalize_mac_6_octet,
    haversine_distance_meters,
    compute_velocity_kmh,
    unpack_lte_eci,
    unpack_5g_nci,
    unix_ms_to_utc_iso,
    cocoa_to_utc_iso,
    cocoa_to_utc_ns,
)
from src.geolocation.ios_location_decoder import IOSLocationDecoder
from src.geolocation.google_timeline_decoder import GoogleTimelineMapsDecoder
from src.geolocation.cellular_decoder import CellularRadioDecoder
from src.geolocation.engine import GeolocationEngine

__all__ = [
    "ProvenanceTier",
    "SpatialPrecisionClass",
    "RadioCategory",
    "TripRecordType",
    "UnifiedGeoFixRecord",
    "RadioConnectionRecord",
    "CellularObservationRecord",
    "SignificantPlaceTripRecord",
    "normalize_mac_6_octet",
    "haversine_distance_meters",
    "compute_velocity_kmh",
    "unpack_lte_eci",
    "unpack_5g_nci",
    "unix_ms_to_utc_iso",
    "cocoa_to_utc_iso",
    "cocoa_to_utc_ns",
    "IOSLocationDecoder",
    "GoogleTimelineMapsDecoder",
    "CellularRadioDecoder",
    "GeolocationEngine",
]
