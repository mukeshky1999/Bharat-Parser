"""
Data models and canonical enums for Phase 9, Module 9.4:
Offline 4-Tier Geospatial Telemetry Map, Virtualized Media Wall & Interactive Tamper Inspector.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class GeolocationTier(str, Enum):
    """The 4-tier visual provenance classification for location fixes."""
    TIER_1_ACTIVE_DEVICE_FIX = "TIER_1_ACTIVE_DEVICE_FIX"
    TIER_2_CONNECTED_RADIO_AND_VERIFIED_HIDEOUT = "TIER_2_CONNECTED_RADIO_AND_VERIFIED_HIDEOUT"
    TIER_3_PASSIVE_RADIO_SIGHTING = "TIER_3_PASSIVE_RADIO_SIGHTING"
    TIER_4_LOOKUP_TILE_OR_SPOOFED_PIN = "TIER_4_LOOKUP_TILE_OR_SPOOFED_PIN"


@dataclass
class MapLocationFix:
    """Geographic coordinate fix with accuracy circle and VFS provenance."""
    fix_uid: int
    latitude: float
    longitude: float
    tier: GeolocationTier
    horizontal_accuracy_meters: float = 10.0
    timestamp_utc_ns: int = 0
    source_vfs_file_id: int = 0
    physical_byte_offset: Optional[int] = None
    dwell_duration_seconds: int = 0
    label: str = ""


@dataclass
class CellularSectorWedge:
    """Directional 4G/5G base station antenna sector wedge geometry."""
    tower_lat: float
    tower_lon: float
    azimuth_deg: float
    beamwidth_deg: float
    range_meters: float
    polygon_coordinates: list[tuple[float, float]] = field(default_factory=list)


@dataclass
class PerceptualDHashResult:
    """64-bit perceptual difference hash (dHash) computed from 9x8 image gradient."""
    image_id: str
    dhash_uint64: int
    dhash_hex: str
    originating_app: str = "Unknown"
    source_vfs_file_id: int = 0
    physical_byte_offset: Optional[int] = None


@dataclass
class MediaClusterStackCard:
    """Near-duplicate media stack card grouping identical re-compressed copies."""
    cluster_id: int
    master_image_id: str
    total_copy_count: int
    member_image_ids: list[str]
    stack_badge_text: str
    apps_involved: list[str] = field(default_factory=list)


@dataclass
class CurtainWipeComparisonResult:
    """Mode 1 uncrop curtain wipe slider registration between master and edited render."""
    has_uncropped_recovered: bool
    curtain_slider_x: float
    crop_bounding_box: list[int]
    markup_redaction_boxes: list[dict[str, Any]]
    uncropped_header_revealed: bool
    pixel_diff_heatmap_generated: bool


@dataclass
class AadhaarQrVerificationResult:
    """Mode 2 UIDAI Aadhaar Secure QR cryptographic & biometric verification result."""
    is_rsa_signature_valid: bool
    name_matches: bool
    dob_matches: bool
    face_photo_matches: bool
    has_critical_tamper_alert: bool
    verdict_banner: str
    embedded_jp2_extracted: bool
    signed_details: dict[str, Any] = field(default_factory=dict)
    printed_details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ForgedReceiptDiagnosticResult:
    """Mode 3 5-point mathematical verification output for payment receipts."""
    is_forged: bool
    julian_date_mismatch: bool
    julian_date_explanation: str
    editor_exif_detected: bool
    absent_from_local_ledger: bool
    duplicate_utr_detected: bool = False
    verdict_title: str = ""
    audit_checks_passed: int = 0
    audit_checks_failed: int = 0


@dataclass
class VisualMediaCacheRecord:
    """Persistent thumbnail metadata, dHash, and safety blur flags in SQLite."""
    source_vfs_file_id: int
    grid_thumb_256_staging_id: int
    dhash_uint64_hex: str
    near_duplicate_cluster_id: int
    cluster_copy_count: int = 1
    requires_safety_blur_gate: int = 0
    aspect_ratio_w_div_h: float = 1.0
    media_cache_uid: Optional[int] = None
    physical_byte_offset: Optional[int] = None
