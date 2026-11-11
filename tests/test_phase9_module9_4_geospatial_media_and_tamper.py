"""
Acceptance Test Suite for Phase 9, Module 9.4:
Offline 4-Tier Geospatial Telemetry Map, Virtualized Media/Snapshot/KYC Wall
& Interactive Forged-Receipt / Aadhaar-QR Tamper Inspector.

Test Scope (5 Acceptance Tests):
1. test_offline_pmtiles_hilbert_and_web_mercator_meter_circle:
   Verifies PMTiles v3 binary header and Hilbert TileID conversion, Web Mercator ground-resolution
   meter-uncertainty circle scaling (scaling by 2^delta_z across zoom levels), and 4G/5G cell sector wedge geometry.
2. test_64bit_perceptual_dhash_near_duplicate_clustering:
   Validates 64-bit perceptual dHash (9x8 grayscale gradient), pairwise Hamming distance calculation (dH <= 6),
   and automatic collapsing of re-compressed/forwarded copies into a single near-duplicate stack card.
3. test_mutations_uncrop_curtain_wipe_and_pixel_diff_heatmap:
   Evaluates Mode 1 /Mutations/ uncrop comparator registering unedited master and cropped render,
   curtain wipe slider at x=52%, and absolute difference pixel heatmap.
4. test_uidai_aadhaar_qr_jp2_biometric_face_and_ocr_mismatch:
   Evaluates Mode 2 UIDAI Aadhaar Secure QR verifier comparing printed OCR details against RSA-signed QR payload,
   unpacked .jp2 facial photo byte comparison, and CRITICAL TAMPER ALERT triggering.
5. test_forged_upi_receipt_5point_diagnostic_and_db_persistence:
   Validates 5-point mathematical forgery checks (Julian day YDDD prefix mismatch, absent local app ledger, editor EXIF),
   and SQLite persistence in visual_media_dhash_and_safety_cache with Pane 3 hex jump offset binding.
"""

import os
import sqlite3
import pytest

from src.geospatial_media_and_tamper.models import (
    GeolocationTier,
    MapLocationFix,
    CellularSectorWedge,
    PerceptualDHashResult,
    MediaClusterStackCard,
    CurtainWipeComparisonResult,
    AadhaarQrVerificationResult,
    ForgedReceiptDiagnosticResult,
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


def test_offline_pmtiles_hilbert_and_web_mercator_meter_circle():
    """Acceptance Test 1: PMTiles v3 Hilbert Curve indexing, Web Mercator meter uncertainty circle, and Cell Sector Wedges."""
    map_engine = OfflinePMTilesMapEngine()
    calc = WebMercatorProjectionCalculator()

    # 1. PMTiles v3 Binary Header Validation
    # Header starts with 8 magic bytes: 'PMTiles\x03'
    valid_pmtiles_header = b"PMTiles\x03" + (b"\x00" * 119)
    assert map_engine.validate_pmtiles_header(valid_pmtiles_header) is True

    corrupt_header = b"NOT_PMTILES" + (b"\x00" * 116)
    assert map_engine.validate_pmtiles_header(corrupt_header) is False

    # 2. 64-bit Hilbert Curve TileID conversion for (Z=14, X=8192, Y=8192)
    tile_id = map_engine.compute_hilbert_tile_id(z=14, x=8192, y=8192)
    assert tile_id > 0

    # 3. Web Mercator Ground Resolution & Meter Uncertainty Radius Scaling
    # Latitude: 25.3176° N (Varanasi), R_horiz = 500.0 meters
    lat = 25.3176
    r_horiz_m = 500.0

    # At Zoom Z=12
    m_per_px_z12 = calc.compute_meters_per_pixel(latitude=lat, zoom=12)
    r_px_z12 = calc.compute_uncertainty_pixel_radius(
        latitude=lat, zoom=12, r_horiz_meters=r_horiz_m
    )

    # At Zoom Z=16 (Delta Z = 4 -> resolution increases by 2^4 = 16x)
    m_per_px_z16 = calc.compute_meters_per_pixel(latitude=lat, zoom=16)
    r_px_z16 = calc.compute_uncertainty_pixel_radius(
        latitude=lat, zoom=16, r_horiz_meters=r_horiz_m
    )

    assert m_per_px_z12 > m_per_px_z16
    # Pixel radius at Z=16 must be exactly 16 times larger than at Z=12 (within 0.1% rounding)
    assert pytest.approx(r_px_z16 / r_px_z12, rel=1e-3) == 16.0

    # 4. 4G/5G Cellular Sector Wedge Geometry (120° antenna beamwidth)
    wedge: CellularSectorWedge = map_engine.compute_cellular_sector_wedge(
        tower_lat=25.3176,
        tower_lon=82.9739,
        azimuth_deg=60.0,
        beamwidth_deg=120.0,
        range_meters=1800.0,
    )

    assert wedge.azimuth_deg == 60.0
    assert len(wedge.polygon_coordinates) >= 32  # 32-vertex smooth geodesic arc
    assert wedge.polygon_coordinates[0] == (25.3176, 82.9739)  # Apex at tower


def test_64bit_perceptual_dhash_near_duplicate_clustering():
    """Acceptance Test 2: 64-Bit Perceptual dHash, Hamming Distance (dH <= 6), and Near-Duplicate Cluster Stacks."""
    clusterer = PerceptualDHashClusterer(hamming_threshold=6)

    # 1. Generate 5 synthetic 9x8 image gradient byte buffers simulating
    # a single image re-saved 5 times with slight re-compression noise
    # Base gradient: pixel values increasing horizontally: G[y, x] = x * 28 + y
    base_pixels = [
        [(x * 28 + y) % 256 for x in range(9)] for y in range(8)
    ]

    base_dhash = clusterer.compute_dhash_uint64(base_pixels)
    assert isinstance(base_dhash, int)
    assert 0 <= base_dhash < (1 << 64)

    # Create 5 variations with 1 to 3 flipped bits
    images = [
        {"image_id": "IMG_CAMERA_01", "app": "Camera", "pixels": base_pixels},
        {
            "image_id": "IMG_WA_01",
            "app": "WhatsApp",
            "pixels": [[base_pixels[y][x] ^ (1 if (x == 1 and y == 1) else 0) for x in range(9)] for y in range(8)],
        },
        {
            "image_id": "IMG_WA_02",
            "app": "WhatsApp",
            "pixels": [[base_pixels[y][x] ^ (1 if (x == 3 and y == 2) else 0) for x in range(9)] for y in range(8)],
        },
        {
            "image_id": "IMG_TG_01",
            "app": "Telegram",
            "pixels": [[base_pixels[y][x] ^ (1 if (x == 5 and y == 4) else 0) for x in range(9)] for y in range(8)],
        },
        {
            "image_id": "IMG_TG_02",
            "app": "Telegram",
            "pixels": [[base_pixels[y][x] ^ (1 if (x == 7 and y == 6) else 0) for x in range(9)] for y in range(8)],
        },
    ]

    # Compute dHash for all 5 images
    dhash_records: list[PerceptualDHashResult] = []
    for item in images:
        h = clusterer.compute_dhash_uint64(item["pixels"])
        dhash_records.append(
            PerceptualDHashResult(
                image_id=item["image_id"],
                dhash_uint64=h,
                dhash_hex=f"{h:016x}",
                originating_app=item["app"],
            )
        )

    # 2. Pairwise Hamming distance must all be <= 4 bits
    for i in range(len(dhash_records)):
        for j in range(i + 1, len(dhash_records)):
            dist = clusterer.compute_hamming_distance(
                dhash_records[i].dhash_uint64, dhash_records[j].dhash_uint64
            )
            assert dist <= 4

    # 3. Cluster all 5 copies into a single stack card
    clusters: list[MediaClusterStackCard] = clusterer.cluster_media_items(dhash_records)

    assert len(clusters) == 1
    stack = clusters[0]
    assert stack.total_copy_count == 5
    assert "5 Copies" in stack.stack_badge_text
    assert "Camera" in stack.stack_badge_text
    assert "WhatsApp" in stack.stack_badge_text
    assert "Telegram" in stack.stack_badge_text


def test_mutations_uncrop_curtain_wipe_and_pixel_diff_heatmap():
    """Acceptance Test 3: Mode 1 /Mutations/ Uncrop Curtain Wipe Slider & Pixel-Difference Heatmap."""
    inspector = VisualTamperInspectorModal()

    # Simulate an original 800x600 screenshot and a cropped 600x400 mutation with black markup ink
    orig_metadata = {
        "vfs_file_id": 841,
        "path": "/DCIM/100APPLE/IMG_4821.PNG",
        "width": 800,
        "height": 600,
        "has_uncropped_original_recovered": 1,
    }

    mut_metadata = {
        "vfs_file_id": 842,
        "path": "/PhotoData/Mutations/IMG_4821/FullSizeRender.jpg",
        "width": 600,
        "height": 400,
        "crop_rect": [100, 100, 700, 500],  # Sub-rectangle cropped from original
        "redacted_regions": [{"x": 200, "y": 250, "w": 180, "h": 30}],  # Black markup ink over account no
    }

    result: CurtainWipeComparisonResult = inspector.compute_uncrop_curtain_comparison(
        orig_metadata, mut_metadata, curtain_slider_x=0.52
    )

    assert result.has_uncropped_recovered is True
    assert result.curtain_slider_x == 0.52
    assert result.crop_bounding_box == [100, 100, 700, 500]
    assert len(result.markup_redaction_boxes) == 1
    assert result.uncropped_header_revealed is True
    assert result.pixel_diff_heatmap_generated is True


def test_uidai_aadhaar_qr_jp2_biometric_face_and_ocr_mismatch():
    """Acceptance Test 4: Mode 2 UIDAI Aadhaar Secure QR Cryptographic Verifier & Face Mismatch Alert."""
    inspector = VisualTamperInspectorModal()

    # 1. Printed card OCR (Suspect pasted a different face and name in Photoshop)
    printed_ocr = {
        "printed_name": "AMIT KUMAR VERMA",
        "printed_dob": "12/04/1994",
        "printed_gender": "M",
        "printed_last4": "9988",
        "has_face_detected": True,
    }

    # 2. UIDAI 2048-Bit RSA Signed QR Payload (Cryptographically decoded via Module 7.3B)
    signed_qr_payload = {
        "signed_name": "RAHUL KUMAR SHARMA",
        "signed_dob": "15-08-1995",
        "signed_gender": "M",
        "signed_last4": "4821",
        "reference_id": "482120261001",
        "has_embedded_jp2_face": True,
        "embedded_jp2_bytes_length": 8192,  # Raw JPEG-2000 face bytes unpacked from QR
        "rsa_signature_valid": True,
    }

    verification: AadhaarQrVerificationResult = inspector.verify_aadhaar_qr_tamper(
        printed_card_ocr=printed_ocr,
        signed_qr_data=signed_qr_payload,
    )

    # Tamper detection checks
    assert verification.is_rsa_signature_valid is True
    assert verification.name_matches is False
    assert verification.dob_matches is False
    assert verification.face_photo_matches is False
    assert verification.has_critical_tamper_alert is True
    assert "CRITICAL TAMPER ALERT" in verification.verdict_banner
    assert verification.embedded_jp2_extracted is True


def test_forged_upi_receipt_5point_diagnostic_and_db_persistence():
    """Acceptance Test 5: Mode 3 Forged UPI Receipt Diagnostic & SQLite Persistence with Pane 3 Hex Binding."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_tamper_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    db_path = os.path.join(sandbox, "visual_media_dhash_and_safety_cache.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    engine = GeospatialMediaAndTamperEngine()
    engine.initialize_cache_db(db_path)

    # 1. 5-Point Forgery Diagnostic for Fake PhonePe Payment Receipt
    receipt_data = {
        "displayed_utr": "412014829104",  # Starts with 4120 (Year 2024, Julian Day 120 = 29 April 2024)
        "displayed_date": "05 Nov 2026",   # Expected Julian Day: 309 (Expected prefix: 6309)
        "exif_software": "PicsArt Photo Studio",
        "is_present_in_local_db": False,   # Absent from phonepe.db
        "is_present_in_dlt_sms": False,    # Absent from mmssms.db
        "source_vfs_file_id": 912,
        "physical_byte_offset": 65536,
    }

    diagnostic: ForgedReceiptDiagnosticResult = engine.diagnose_payment_receipt_forgery(receipt_data)

    assert diagnostic.is_forged is True
    assert diagnostic.julian_date_mismatch is True
    assert "4120" in diagnostic.julian_date_explanation
    assert "6309" in diagnostic.julian_date_explanation
    assert diagnostic.editor_exif_detected is True
    assert diagnostic.absent_from_local_ledger is True
    assert "FORGED PAYMENT RECEIPT" in diagnostic.verdict_title

    # 2. Persist Media Cache Record in SQLite
    cache_record = VisualMediaCacheRecord(
        source_vfs_file_id=912,
        grid_thumb_256_staging_id=142,
        dhash_uint64_hex="a1b2c3d4e5f60718",
        near_duplicate_cluster_id=1,
        cluster_copy_count=1,
        requires_safety_blur_gate=0,
        aspect_ratio_w_div_h=1.3333,
        physical_byte_offset=65536,
    )

    allocated_uid = engine.save_media_cache_record(db_path, cache_record)
    assert allocated_uid > 0

    # 3. Read back and verify persistence & Pane 3 byte offset binding
    loaded = engine.get_media_cache_record_by_file_id(db_path, file_id=912)
    assert loaded is not None
    assert loaded.source_vfs_file_id == 912
    assert loaded.dhash_uint64_hex == "a1b2c3d4e5f60718"
    assert loaded.physical_byte_offset == 65536
