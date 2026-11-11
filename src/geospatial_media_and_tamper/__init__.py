"""
Phase 9, Module 9.4: Offline 4-Tier Geospatial Telemetry Map,
Virtualized Media Wall & Interactive Forged-Receipt / Aadhaar-QR Tamper Inspector.
Includes Phase 10 Bilingual Hindi+English OCR and Hybrid Online/Offline Reverse Geocoder.
"""

from src.geospatial_media_and_tamper.models import (
    AadhaarQrVerificationResult,
    CellularSectorWedge,
    CurtainWipeComparisonResult,
    ForgedReceiptDiagnosticResult,
    GeolocationTier,
    MapLocationFix,
    MediaClusterStackCard,
    PerceptualDHashResult,
    VisualMediaCacheRecord,
)
from src.geospatial_media_and_tamper.pmtiles_map_engine import (
    OfflinePMTilesMapEngine,
    WebMercatorProjectionCalculator,
)
from src.geospatial_media_and_tamper.perceptual_dhash_clustering import (
    PerceptualDHashClusterer,
)
from src.geospatial_media_and_tamper.tamper_inspector_modal import (
    VisualTamperInspectorModal,
)
from src.geospatial_media_and_tamper.engine import (
    GeospatialMediaAndTamperEngine,
)
from src.geospatial_media_and_tamper.bilingual_ocr_engine import (
    BilingualOcrResult,
    BilingualOcrEngine,
    normalize_indic_text,
    detect_scripts_in_text,
)
from src.geospatial_media_and_tamper.hybrid_map_geocoder import (
    ResolvedLocation,
    INDIAN_GAZETTEER_HUBS,
    haversine_distance_km,
    HybridReverseGeocoder,
)

__all__ = [
    "AadhaarQrVerificationResult",
    "CellularSectorWedge",
    "CurtainWipeComparisonResult",
    "ForgedReceiptDiagnosticResult",
    "GeolocationTier",
    "GeospatialMediaAndTamperEngine",
    "MapLocationFix",
    "MediaClusterStackCard",
    "OfflinePMTilesMapEngine",
    "PerceptualDHashClusterer",
    "PerceptualDHashResult",
    "VisualMediaCacheRecord",
    "VisualTamperInspectorModal",
    "WebMercatorProjectionCalculator",
    "BilingualOcrResult",
    "BilingualOcrEngine",
    "normalize_indic_text",
    "detect_scripts_in_text",
    "ResolvedLocation",
    "INDIAN_GAZETTEER_HUBS",
    "haversine_distance_km",
    "HybridReverseGeocoder",
]
