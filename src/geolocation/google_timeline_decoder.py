"""
Sub-Engine 6.3B: Android On-Device Google Timeline & Google Maps Navigation Decoder.
Parses on-device PlaceVisit structures, E7 coordinate math, and da_destination_history.
Complies with Section 4 of Phase 6 Module 6.3 Specification and AGENTS.md Constitution.
"""

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
    unix_ms_to_utc_iso,
)

logger = logging.getLogger(__name__)


class GoogleTimelineMapsDecoder:
    """Decoder for Android On-Device Google Timeline and Google Maps databases."""

    def parse_timeline_place_visit(
        self,
        raw_place_visit: Dict[str, Any],
        source_vfs_file_id: int = 1002,
    ) -> Tuple[UnifiedGeoFixRecord, SignificantPlaceTripRecord]:
        """
        Parses an on-device Google Timeline PlaceVisit dictionary:
        Converts E7 integers to decimal degrees (degrees = E7 / 10,000,000.0).
        Computes dwell duration in minutes.
        """
        lat_e7 = int(raw_place_visit.get("latitude_e7", 0))
        lon_e7 = int(raw_place_visit.get("longitude_e7", 0))

        lat_wgs84 = lat_e7 / 10_000_000.0
        lon_wgs84 = lon_e7 / 10_000_000.0

        arr_ms = int(raw_place_visit.get("arrival_timestamp_ms", 0))
        dep_ms = int(raw_place_visit.get("departure_timestamp_ms", arr_ms))

        dwell_min = round(max(0.0, (dep_ms - arr_ms) / 60000.0), 2)

        arr_iso = unix_ms_to_utc_iso(arr_ms)
        dep_iso = unix_ms_to_utc_iso(dep_ms)

        place_name = str(raw_place_visit.get("place_name", "PlaceVisit"))
        place_id = raw_place_visit.get("place_id")
        semantic = str(raw_place_visit.get("semantic_type", "HOTEL"))

        # Fix Record
        fix = UnifiedGeoFixRecord(
            provenance_tier=ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX,
            source_subsystem="ANDROID_GMS_SEMANTIC_TIMELINE",
            source_vfs_file_id=source_vfs_file_id,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            device_locality="LOCAL_SEIZED_HANDSET",
            latitude_wgs84=lat_wgs84,
            longitude_wgs84=lon_wgs84,
            horizontal_accuracy_meters=15.0,
            spatial_precision_class=SpatialPrecisionClass.PINPOINT_GNSS_UNDER_25M,
            resolved_address_or_place_name=f"{place_name} ({place_id or ''})".strip(),
            fix_start_utc_ns=arr_ms * 1_000_000,
            fix_start_utc_iso=arr_iso,
            fix_end_utc_iso=dep_iso,
            forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
        )

        # Significant Place Trip Record
        trip = SignificantPlaceTripRecord(
            record_type=TripRecordType.GOOGLE_TIMELINE_PLACE_VISIT,
            semantic_label=semantic,
            place_title_and_address=f"{place_name} (PlaceID: {place_id})",
            destination_lat_lon_json=json.dumps({"lat": lat_wgs84, "lon": lon_wgs84}),
            arrival_or_start_utc_iso=arr_iso,
            departure_or_end_utc_iso=dep_iso,
            dwell_duration_minutes=dwell_min,
            forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
        )

        return fix, trip

    def decode_destination_history_db(
        self,
        db_path: str,
        source_vfs_file_id: int = 1003,
    ) -> List[SignificantPlaceTripRecord]:
        """Parses Google Maps da_destination_history SQLite table."""
        trips: List[SignificantPlaceTripRecord] = []
        if not os.path.exists(db_path):
            return trips

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            target_table = None
            for tbl in ("da_destination_history", "destination_history", "destinations"):
                if tbl in tables:
                    target_table = tbl
                    break

            if target_table:
                cur.execute(f"SELECT * FROM {target_table}")
                rows = cur.fetchall()
                col_names = [d[0].lower() for d in cur.description]

                for row in rows:
                    row_dict = dict(zip(col_names, row))
                    time_ms = int(row_dict.get("time") or row_dict.get("timestamp") or 0)
                    time_iso = unix_ms_to_utc_iso(time_ms) if time_ms > 0 else "1970-01-01T00:00:00.000000Z"

                    raw_dlat = float(row_dict.get("dest_lat") or 0.0)
                    raw_dlng = float(row_dict.get("dest_lng") or 0.0)

                    # Check E6 vs decimal
                    dlat = raw_dlat / 1e6 if abs(raw_dlat) > 90.0 else raw_dlat
                    dlng = raw_dlng / 1e6 if abs(raw_dlng) > 180.0 else raw_dlng

                    raw_slat = float(row_dict.get("source_lat") or 0.0)
                    raw_slng = float(row_dict.get("source_lng") or 0.0)
                    slat = raw_slat / 1e6 if abs(raw_slat) > 90.0 else raw_slat
                    slng = raw_slng / 1e6 if abs(raw_slng) > 180.0 else raw_slng

                    dest_title = str(row_dict.get("dest_title") or row_dict.get("title") or "")
                    dest_addr = str(row_dict.get("dest_address") or row_dict.get("address") or "")
                    full_addr = f"{dest_title}: {dest_addr}".strip(": ")

                    orig_json = json.dumps({"lat": slat, "lon": slng}) if (slat != 0.0 or slng != 0.0) else None
                    dest_json = json.dumps({"lat": dlat, "lon": dlng})

                    trip = SignificantPlaceTripRecord(
                        record_type=TripRecordType.MAPS_TURN_BY_TURN_NAVIGATION,
                        semantic_label="SEARCHED_DESTINATION",
                        place_title_and_address=full_addr,
                        origin_lat_lon_json=orig_json,
                        destination_lat_lon_json=dest_json,
                        arrival_or_start_utc_iso=time_iso,
                        forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
                    )
                    trips.append(trip)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening destination history %s: %s", db_path, exc)

        return trips
