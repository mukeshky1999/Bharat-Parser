"""
Sub-Engine 6.3A: iOS CoreLocation (cache_encryptedB.db) & routined Significant Locations Decoder.
Disambiguates crowd-sourced batch Wi-Fi/LTE tiles from true connected and GPS fixes.
Complies with Section 3 of Phase 6 Module 6.3 Specification and AGENTS.md Constitution.
"""

from collections import defaultdict
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import ForensicGroup, ResidualConfidence
from src.geolocation.models import (
    ProvenanceTier,
    SpatialPrecisionClass,
    TripRecordType,
    UnifiedGeoFixRecord,
    SignificantPlaceTripRecord,
    normalize_mac_6_octet,
    cocoa_to_utc_iso,
    cocoa_to_utc_ns,
)

logger = logging.getLogger(__name__)


def classify_spatial_precision(h_acc: Optional[float]) -> SpatialPrecisionClass:
    """Classifies horizontal accuracy radius in meters into spatial precision tier."""
    if h_acc is None or h_acc <= 0.0:
        return SpatialPrecisionClass.UNSPECIFIED_RADIUS
    if h_acc < 25.0:
        return SpatialPrecisionClass.PINPOINT_GNSS_UNDER_25M
    elif h_acc <= 100.0:
        return SpatialPrecisionClass.BUILDING_WIFI_25_TO_100M
    elif h_acc <= 1000.0:
        return SpatialPrecisionClass.NEIGHBORHOOD_CELL_100_TO_1000M
    else:
        return SpatialPrecisionClass.BROAD_SECTOR_OVER_1000M


class IOSLocationDecoder:
    """Decoder for Apple iOS location caches and significant location databases."""

    def decode_cache_encryptedb(
        self,
        db_path: str,
        known_networks: Optional[Dict[str, Dict[str, Any]]] = None,
        source_vfs_file_id: int = 1001,
    ) -> List[UnifiedGeoFixRecord]:
        """
        Parses cache_encryptedB.db (WifiLocation, LocationHarvest, AppHarvest).
        Disambiguates batch tile lookups from connected Wi-Fi handshakes.
        """
        fixes: List[UnifiedGeoFixRecord] = []
        if not os.path.exists(db_path):
            return fixes

        if known_networks is None:
            known_networks = {}

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # 1. Process WifiLocation
            if "WifiLocation" in tables:
                cur.execute("SELECT MAC, Timestamp, Latitude, Longitude, HorizontalAccuracy, Confidence FROM WifiLocation")
                raw_rows = cur.fetchall()

                # Group by rounded integer timestamp to detect crowd-sourced batch tiles (>= 5 rows)
                batch_counts: Dict[int, int] = defaultdict(int)
                parsed_rows = []

                for r in raw_rows:
                    mac, ts, lat, lon, h_acc, conf = r
                    if lat == 0.0 and lon == 0.0:
                        continue
                    norm_mac = normalize_mac_6_octet(str(mac))
                    batch_key = int(round(float(ts)))
                    batch_counts[batch_key] += 1
                    parsed_rows.append((norm_mac, float(ts), float(lat), float(lon), float(h_acc or 50.0), conf, batch_key))

                for norm_mac, ts, lat, lon, h_acc, conf, b_key in parsed_rows:
                    is_batch = batch_counts[b_key] >= 5

                    # Rule A: Cross-match against known connected Wi-Fi
                    if norm_mac in known_networks:
                        tier = ProvenanceTier.TIER_2_CONNECTED_RADIO_HANDSHAKE
                        subsystem = "IOS_WIFI_CONNECTED_HANDSHAKE"
                    elif is_batch:
                        # Rule B: Batch tile lookup
                        tier = ProvenanceTier.TIER_4_CROWDSOURCED_LOOKUP_TILE_OR_SEARCH
                        subsystem = "IOS_WIFI_TILE_CACHE"
                    else:
                        tier = ProvenanceTier.TIER_3_PASSIVE_RADIO_SIGHTING
                        subsystem = "IOS_WIFI_PASSIVE_SIGHTING"

                    start_ns = cocoa_to_utc_ns(ts)
                    start_iso = cocoa_to_utc_iso(ts)
                    prec = classify_spatial_precision(h_acc)

                    rec = UnifiedGeoFixRecord(
                        provenance_tier=tier,
                        source_subsystem=subsystem,
                        source_vfs_file_id=source_vfs_file_id,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        device_locality="LOCAL_SEIZED_HANDSET",
                        latitude_wgs84=lat,
                        longitude_wgs84=lon,
                        horizontal_accuracy_meters=h_acc,
                        spatial_precision_class=prec,
                        associated_bssid_or_cgi=norm_mac,
                        fix_start_utc_ns=start_ns,
                        fix_start_utc_iso=start_iso,
                        forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
                    )
                    fixes.append(rec)

            # 2. Process LocationHarvest (Tier 1 True Device GPS Fixes)
            if "LocationHarvest" in tables:
                cur.execute("SELECT Timestamp, Latitude, Longitude, HorizontalAccuracy, Altitude, Speed, Course FROM LocationHarvest")
                for ts, lat, lon, h_acc, alt, spd, crs in cur.fetchall():
                    if lat == 0.0 and lon == 0.0:
                        continue
                    speed_kmh = (float(spd) * 3.6) if (spd is not None and spd >= 0.0) else None
                    rec = UnifiedGeoFixRecord(
                        provenance_tier=ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX,
                        source_subsystem="IOS_LOCATION_HARVEST",
                        source_vfs_file_id=source_vfs_file_id,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        device_locality="LOCAL_SEIZED_HANDSET",
                        latitude_wgs84=float(lat),
                        longitude_wgs84=float(lon),
                        horizontal_accuracy_meters=float(h_acc) if h_acc is not None else None,
                        spatial_precision_class=classify_spatial_precision(float(h_acc) if h_acc else None),
                        altitude_meters=float(alt) if alt is not None else None,
                        speed_kmh=speed_kmh,
                        fix_start_utc_ns=cocoa_to_utc_ns(float(ts)),
                        fix_start_utc_iso=cocoa_to_utc_iso(float(ts)),
                        forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
                    )
                    fixes.append(rec)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening cache_encryptedB.db %s: %s", db_path, exc)

        return fixes

    def decode_routined_significant_locations(
        self,
        db_path: str,
        source_vfs_file_id: int = 1002,
    ) -> Tuple[List[UnifiedGeoFixRecord], List[SignificantPlaceTripRecord]]:
        """Parses routined Local.sqlite and Cloud.sqlite significant locations."""
        fixes: List[UnifiedGeoFixRecord] = []
        trips: List[SignificantPlaceTripRecord] = []
        if not os.path.exists(db_path):
            return fixes, trips

        is_cloud = "Cloud" in db_path
        locality = "CLOUD_SYNCED_ACCOUNT_HISTORY" if is_cloud else "LOCAL_SEIZED_HANDSET"

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            visit_table = "ZRTLEARNEDLOCATIONOFINTERESTVISITMO"
            place_table = "ZRTLEARNEDLOCATIONOFINTERESTMO"

            if visit_table in tables and place_table in tables:
                query = f"""
                    SELECT
                        v.ZENTRYDATE,
                        v.ZEXITDATE,
                        v.ZLOCATIONLATITUDE,
                        v.ZLOCATIONLONGITUDE,
                        v.ZLOCATIONUNCERTAINTY,
                        v.ZCONFIDENCE,
                        v.ZDATAPOINTCOUNT,
                        p.ZTYPE
                    FROM {visit_table} v
                    LEFT JOIN {place_table} p ON v.ZLOCATIONOFINTEREST = p.Z_PK
                """
                cur.execute(query)
                for entry_date, exit_date, lat, lon, uncert, conf, count_pts, ztype in cur.fetchall():
                    if lat == 0.0 and lon == 0.0:
                        continue
                    e_ts = float(entry_date) if entry_date else 0.0
                    x_ts = float(exit_date) if exit_date else e_ts

                    entry_iso = cocoa_to_utc_iso(e_ts)
                    exit_iso = cocoa_to_utc_iso(x_ts)
                    dwell_min = round(max(0.0, (x_ts - e_ts) / 60.0), 2)

                    type_map = {1: "HOME", 2: "WORK", 3: "SCHOOL", 4: "GYM"}
                    semantic = type_map.get(int(ztype or 0), "FREQUENT_LOCATION")

                    # Geo Fix
                    fix = UnifiedGeoFixRecord(
                        provenance_tier=ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX,
                        source_subsystem="IOS_ROUTINED_VISIT",
                        source_vfs_file_id=source_vfs_file_id,
                        device_locality=locality,
                        latitude_wgs84=float(lat),
                        longitude_wgs84=float(lon),
                        horizontal_accuracy_meters=float(uncert) if uncert else None,
                        spatial_precision_class=classify_spatial_precision(float(uncert) if uncert else None),
                        resolved_address_or_place_name=semantic,
                        fix_start_utc_ns=cocoa_to_utc_ns(e_ts),
                        fix_start_utc_iso=entry_iso,
                        fix_end_utc_iso=exit_iso,
                    )
                    fixes.append(fix)

                    # Trip Record
                    trip = SignificantPlaceTripRecord(
                        record_type=TripRecordType.ROUTINED_SIGNIFICANT_VISIT,
                        semantic_label=semantic,
                        place_title_and_address=f"SignificantLocation ({semantic})",
                        destination_lat_lon_json=json.dumps({"lat": float(lat), "lon": float(lon), "uncert_m": float(uncert or 0.0)}),
                        data_point_count_or_confidence=f"{count_pts or 0} points (Conf: {conf or 1.0})",
                        arrival_or_start_utc_iso=entry_iso,
                        departure_or_end_utc_iso=exit_iso,
                        dwell_duration_minutes=dwell_min,
                    )
                    trips.append(trip)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening routined db %s: %s", db_path, exc)

        return fixes, trips
