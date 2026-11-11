"""
Test Suite: Phase 6, Module 6.3 — OS Geolocation, Wi-Fi/BLE/Cellular Triangulation,
Significant Locations & On-Device Google Timeline Engine.
Covers:
  - Sub-Engine 6.3A: iOS CoreLocation (cache_encryptedB.db) Tile Disambiguation & routined Significant Visits.
  - Sub-Engine 6.3B: Android On-Device Google Timeline (E7 math, PlaceVisit) & da_destination_history.
  - Sub-Engine 6.3C: Wi-Fi BSSID Normalizer (6-octet), SoftAP Hotspot & Indian 4G/5G Cellular ECI Bit Unpacking.
  - Sub-Engine 6.3D: Haversine Velocity Validator & Impossible-Velocity Teleportation Detection.
  - Sub-Engine 6.3E: Geolocation Master SQLite Export (4 Tables).
Complies with Phase 6 Module 6.3 Specification and AGENTS.md Constitution.
"""

import json
import math
import os
from pathlib import Path
import sqlite3
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
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
)
from src.geolocation.ios_location_decoder import IOSLocationDecoder
from src.geolocation.google_timeline_decoder import GoogleTimelineMapsDecoder
from src.geolocation.cellular_decoder import CellularRadioDecoder
from src.geolocation.engine import GeolocationEngine


# ---------------------------------------------------------------------------
# Test 1: cache_encryptedB.db Batch Tile vs Connected Wi-Fi Disambiguation
# ---------------------------------------------------------------------------

def test_cache_encryptedb_batch_tile_vs_connected_wifi_disambiguation():
    """
    Test 1: Acceptance Test 1 from Spec Section 8.1.
    Verifies that Sub-Engine 6.3A/C normalizes stripped-zero MAC '0:1a:2b:3c:4:f0'
    to '00:1a:2b:3c:04:f0', upgrades Row 1 to TIER_2_CONNECTED_RADIO_HANDSHAKE
    because it exists in known-networks.plist, and classifies Rows 2-50
    as TIER_4_CROWDSOURCED_LOOKUP_TILE_OR_SEARCH.
    """
    base_dir = Path("./.workspace_tmp/test_geo_sandbox")
    locationd_dir = base_dir / "Library" / "Caches" / "locationd"
    locationd_dir.mkdir(parents=True, exist_ok=True)

    db_path = locationd_dir / "cache_encryptedB.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE WifiLocation (
            MAC TEXT PRIMARY KEY,
            Timestamp REAL NOT NULL,
            Latitude REAL NOT NULL,
            Longitude REAL NOT NULL,
            HorizontalAccuracy REAL,
            Confidence INTEGER
        )
    """)

    batch_ts = 784041600.0  # Cocoa seconds (2025-11-05T13:20:00Z)

    # Row 1: Target connected router with stripped zeroes in MAC
    cur.execute(
        "INSERT INTO WifiLocation VALUES (?, ?, ?, ?, ?, ?)",
        ("0:1a:2b:3c:4:f0", batch_ts, 25.3176, 82.9739, 30.0, 100),
    )

    # Rows 2 to 50: 49 neighboring crowd-sourced routers in the same batch
    for i in range(2, 51):
        mac_str = f"0:1a:2b:3c:4:{i:02x}"
        cur.execute(
            "INSERT INTO WifiLocation VALUES (?, ?, ?, ?, ?, ?)",
            (mac_str, batch_ts, 25.3176 + (i * 0.0001), 82.9739 + (i * 0.0001), 50.0, 80),
        )

    conn.commit()
    conn.close()

    # Known networks dictionary (from com.apple.wifi.known-networks.plist)
    known_networks = {
        "00:1a:2b:3c:04:f0": {
            "ssid": "CrimeScene_Fiber_5G",
            "last_joined": "2025-11-05T13:20:00.000000Z",
        }
    }

    decoder = IOSLocationDecoder()
    fixes = decoder.decode_cache_encryptedb(
        db_path=str(db_path),
        known_networks=known_networks,
        source_vfs_file_id=1001,
    )

    assert len(fixes) == 50

    # Row 1 (matched against known-networks)
    target_fix = [f for f in fixes if f.associated_bssid_or_cgi == "00:1a:2b:3c:04:f0"][0]
    assert target_fix.provenance_tier == ProvenanceTier.TIER_2_CONNECTED_RADIO_HANDSHAKE
    assert target_fix.latitude_wgs84 == 25.3176
    assert target_fix.longitude_wgs84 == 82.9739

    # Rows 2-50 (batch size 50 >= 5) must be classified as Tier 4 crowd-sourced tile
    neighbor_fixes = [f for f in fixes if f.associated_bssid_or_cgi != "00:1a:2b:3c:04:f0"]
    assert len(neighbor_fixes) == 49
    for nf in neighbor_fixes:
        assert nf.provenance_tier == ProvenanceTier.TIER_4_CROWDSOURCED_LOOKUP_TILE_OR_SEARCH


# ---------------------------------------------------------------------------
# Test 2: Google Timeline E7 Coordinate & da_destination_history Test
# ---------------------------------------------------------------------------

def test_google_timeline_e7_and_destination_history():
    """
    Test 2: Acceptance Test 2 from Spec Section 8.2.
    Verifies that Sub-Engine 6.3B parses on-device Google Timeline PlaceVisit
    dividing E7 integers by 10^7 (253176452, 829739140 -> 25.3176452, 82.9739140),
    computes 60.0 min dwell duration, and outputs TIER_1_ACTIVE_DEVICE_FIX.
    """
    timeline_decoder = GoogleTimelineMapsDecoder()

    raw_place_visit = {
        "place_id": "ChIJN1t_tDeuEmsRUsoyG83frY4",
        "latitude_e7": 253176452,
        "longitude_e7": 829739140,
        "arrival_timestamp_ms": 1762348800000,
        "departure_timestamp_ms": 1762352400000,
        "place_name": "Hotel Taj Ganges",
        "semantic_type": "TYPE_HOTEL",
    }

    fix_record, trip_record = timeline_decoder.parse_timeline_place_visit(
        raw_place_visit,
        source_vfs_file_id=1002,
    )

    assert round(fix_record.latitude_wgs84, 7) == 25.3176452
    assert round(fix_record.longitude_wgs84, 7) == 82.9739140
    assert fix_record.provenance_tier == ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX
    assert fix_record.spatial_precision_class == SpatialPrecisionClass.PINPOINT_GNSS_UNDER_25M

    assert trip_record.record_type == TripRecordType.GOOGLE_TIMELINE_PLACE_VISIT
    assert trip_record.dwell_duration_minutes == 60.0
    assert "Hotel Taj Ganges" in trip_record.place_title_and_address


# ---------------------------------------------------------------------------
# Test 3: Indian 4G LTE 28-Bit ECI Bit-Unpacking Test
# ---------------------------------------------------------------------------

def test_indian_4g_lte_eci_bit_unpacking():
    """
    Test 3: Acceptance Test 3 from Spec Section 8.3.
    Verifies that Sub-Engine 6.3C unpacks a Reliance Jio 4G LTE 28-bit ECI
    268435714 (0x10000102) into:
      eNodeB_id = ECI >> 8 = 1048577
      sector_id = ECI & 0xFF = 2
    """
    cell_decoder = CellularRadioDecoder()

    cell_data = {
        "rat_generation": "4G_LTE",
        "mcc": 405,
        "mnc": 86,  # Reliance Jio
        "lac_or_tac": 1042,
        "raw_ci_eci": 268435714,
        "observed_timestamp_iso": "2025-11-05T13:20:00.000000Z",
    }

    obs = cell_decoder.decode_cellular_tower_record(cell_data, source_vfs_file_id=1003)

    assert obs.mcc_mnc == "405-86"
    assert obs.rat_generation == "4G_LTE"
    assert obs.lac_or_tac == 1042
    assert obs.raw_ci_eci_or_nci == 268435714
    assert obs.unpacked_enodeb_or_gnodeb_id == 1048577
    assert obs.unpacked_sector_id == 2
    assert obs.provenance_tier == "TIER_2_SERVING_CELL"


# ---------------------------------------------------------------------------
# Test 4: Haversine Impossible-Velocity Teleportation Test
# ---------------------------------------------------------------------------

def test_haversine_impossible_velocity_teleportation_flag():
    """
    Test 4: Acceptance Test 4 from Spec Section 8.4.
    Inserts two Tier-1 GPS fixes separated by 10 seconds:
      Fix 1: Varanasi (25.3176, 82.9739, R=10m)
      Fix 2: Mumbai (19.0760, 72.8777, R=10m)
    Verifies that Sub-Engine 6.3D computes d_meters ~ 1,252 km,
    v_kmh > 400,000 km/h, and sets is_impossible_velocity_flagged = 1.
    """
    d_meters = haversine_distance_meters(25.3176, 82.9739, 19.0760, 72.8777)
    assert 1_200_000 <= d_meters <= 1_300_000

    v_kmh = compute_velocity_kmh(
        lat1=25.3176, lon1=82.9739, r1=10.0,
        lat2=19.0760, lon2=72.8777, r2=10.0,
        delta_sec=10.0,
    )
    assert v_kmh > 400_000.0

    # Build sequence of two fixes
    fixes = [
        UnifiedGeoFixRecord(
            provenance_tier=ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX,
            source_subsystem="IOS_LOCATION_HARVEST",
            source_vfs_file_id=1001,
            latitude_wgs84=25.3176,
            longitude_wgs84=82.9739,
            horizontal_accuracy_meters=10.0,
            fix_start_utc_ns=1762348800000000000,
            fix_start_utc_iso="2025-11-05T13:20:00.000000Z",
        ),
        UnifiedGeoFixRecord(
            provenance_tier=ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX,
            source_subsystem="IOS_LOCATION_HARVEST",
            source_vfs_file_id=1001,
            latitude_wgs84=19.0760,
            longitude_wgs84=72.8777,
            horizontal_accuracy_meters=10.0,
            fix_start_utc_ns=1762348810000000000,
            fix_start_utc_iso="2025-11-05T13:20:10.000000Z",
        ),
    ]

    engine = GeolocationEngine()
    validated_fixes = engine.validate_velocity_anomalies(fixes)

    assert validated_fixes[0].is_impossible_velocity_flagged == 0
    assert validated_fixes[1].is_impossible_velocity_flagged == 1
    assert validated_fixes[1].implied_velocity_from_prev_kmh > 400_000.0


# ---------------------------------------------------------------------------
# Test 5: Geolocation Master SQLite Export Validation
# ---------------------------------------------------------------------------

def test_geolocation_master_sqlite_export():
    """
    Test 5: Master Export Validation.
    Verifies that GeolocationEngine populates all four tables in
    geolocation_and_triangulation_engine.sqlite.
    """
    export_db_path = Path("./.workspace_tmp/geolocation_and_triangulation_engine.sqlite")
    if export_db_path.exists():
        export_db_path.unlink()

    sample_fixes = [
        UnifiedGeoFixRecord(
            provenance_tier=ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX,
            source_subsystem="IOS_LOCATION_HARVEST",
            source_vfs_file_id=1001,
            latitude_wgs84=25.3176,
            longitude_wgs84=82.9739,
            horizontal_accuracy_meters=15.0,
            spatial_precision_class=SpatialPrecisionClass.PINPOINT_GNSS_UNDER_25M,
            fix_start_utc_ns=1762348800000000000,
            fix_start_utc_iso="2025-11-05T13:20:00.000000Z",
        )
    ]

    sample_radios = [
        RadioConnectionRecord(
            radio_category=RadioCategory.WIFI_KNOWN_CONNECTED_NETWORK,
            source_vfs_file_id=1004,
            ssid_or_device_name="CrimeScene_Fiber_5G",
            normalized_bssid_or_mac="00:1a:2b:3c:04:f0",
            saved_wifi_password_psk="Pass12345",
            last_connected_utc_iso="2025-11-05T13:20:00.000000Z",
        )
    ]

    sample_cells = [
        CellularObservationRecord(
            provenance_tier="TIER_2_SERVING_CELL",
            rat_generation="4G_LTE",
            mcc_mnc="405-86",
            lac_or_tac=1042,
            raw_ci_eci_or_nci=268435714,
            unpacked_enodeb_or_gnodeb_id=1048577,
            unpacked_sector_id=2,
            observed_utc_iso="2025-11-05T13:20:00.000000Z",
        )
    ]

    sample_trips = [
        SignificantPlaceTripRecord(
            record_type=TripRecordType.GOOGLE_TIMELINE_PLACE_VISIT,
            semantic_label="HOTEL",
            place_title_and_address="Hotel Taj Ganges, Varanasi",
            destination_lat_lon_json=json.dumps({"lat": 25.3176, "lon": 82.9739}),
            arrival_or_start_utc_iso="2025-11-05T13:20:00.000000Z",
            departure_or_end_utc_iso="2025-11-05T14:20:00.000000Z",
            dwell_duration_minutes=60.0,
        )
    ]

    engine = GeolocationEngine()
    engine.export_to_sqlite(
        geo_fixes=sample_fixes,
        radio_connections=sample_radios,
        cellular_observations=sample_cells,
        significant_trips=sample_trips,
        output_db_path=str(export_db_path),
    )

    assert export_db_path.exists()
    conn = sqlite3.connect(export_db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    assert "unified_geolocation_fixes_ledger" in tables
    assert "wifi_hotspot_and_bluetooth_connections_ledger" in tables
    assert "cellular_tower_cgi_observations" in tables
    assert "significant_places_and_navigation_trips" in tables

    cur.execute("SELECT COUNT(*) FROM unified_geolocation_fixes_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM wifi_hotspot_and_bluetooth_connections_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM cellular_tower_cgi_observations")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM significant_places_and_navigation_trips")
    assert cur.fetchone()[0] == 1

    conn.close()
