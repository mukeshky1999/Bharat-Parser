"""
Sub-Engine 6.3: Unified Geolocation, Triangulation & Movement Master Engine.
Orchestrates velocity validation (impossible velocity detection) and database exports.
Populates geolocation_and_triangulation_engine.sqlite across the 4 canonical tables.
Complies with Section 6 & 7 of Phase 6 Module 6.3 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import List, Optional

from src.core.enums import ForensicGroup
from src.geolocation.models import (
    ProvenanceTier,
    UnifiedGeoFixRecord,
    RadioConnectionRecord,
    CellularObservationRecord,
    SignificantPlaceTripRecord,
    compute_velocity_kmh,
)

logger = logging.getLogger(__name__)


class GeolocationEngine:
    """Master export and movement validation engine for mobile geolocation."""

    def validate_velocity_anomalies(
        self,
        fixes: List[UnifiedGeoFixRecord],
    ) -> List[UnifiedGeoFixRecord]:
        """
        Validates consecutive Tier-1/Tier-2 location fixes using Haversine edge-adjusted velocity.
        Flags transitions with v_kmh > 1,000 km/h as IMPOSSIBLE_VELOCITY_TELEPORTATION.
        """
        if not fixes:
            return []

        # Ensure fixes are ordered chronologically by fix_start_utc_ns
        sorted_fixes = sorted(fixes, key=lambda f: f.fix_start_utc_ns)

        prev_t1: Optional[UnifiedGeoFixRecord] = None

        for current in sorted_fixes:
            # We evaluate velocity between active device fixes (Tier 1)
            if current.provenance_tier in (ProvenanceTier.TIER_1_ACTIVE_DEVICE_FIX, "TIER_1_ACTIVE_DEVICE_FIX"):
                if prev_t1 is not None:
                    delta_sec = abs(current.fix_start_utc_ns - prev_t1.fix_start_utc_ns) / 1_000_000_000.0
                    r1 = float(prev_t1.horizontal_accuracy_meters or 10.0)
                    r2 = float(current.horizontal_accuracy_meters or 10.0)

                    if delta_sec > 0.0:
                        v_kmh = compute_velocity_kmh(
                            lat1=prev_t1.latitude_wgs84,
                            lon1=prev_t1.longitude_wgs84,
                            r1=r1,
                            lat2=current.latitude_wgs84,
                            lon2=current.longitude_wgs84,
                            r2=r2,
                            delta_sec=delta_sec,
                        )
                        current.implied_velocity_from_prev_kmh = round(v_kmh, 2)
                        if v_kmh > 1000.0:
                            current.is_impossible_velocity_flagged = 1
                        else:
                            current.is_impossible_velocity_flagged = 0

                prev_t1 = current

        return sorted_fixes

    def init_database(self, db_path: str) -> None:
        """Initializes the SQLite schema with the 4 canonical tables."""
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Table 1: unified_geolocation_fixes_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS unified_geolocation_fixes_ledger (
                geo_fix_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                provenance_tier TEXT NOT NULL,
                source_subsystem TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                device_locality TEXT NOT NULL,
                latitude_wgs84 REAL NOT NULL,
                longitude_wgs84 REAL NOT NULL,
                horizontal_accuracy_meters REAL,
                spatial_precision_class TEXT NOT NULL,
                altitude_meters REAL,
                speed_kmh REAL,
                implied_velocity_from_prev_kmh REAL,
                is_impossible_velocity_flagged INTEGER DEFAULT 0,
                resolved_address_or_place_name TEXT,
                associated_bssid_or_cgi TEXT,
                fix_start_utc_ns INTEGER NOT NULL,
                fix_start_utc_iso TEXT NOT NULL,
                fix_end_utc_iso TEXT,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 2: wifi_hotspot_and_bluetooth_connections_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS wifi_hotspot_and_bluetooth_connections_ledger (
                radio_conn_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                radio_category TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                ssid_or_device_name TEXT,
                normalized_bssid_or_mac TEXT,
                saved_wifi_password_psk TEXT,
                device_type_or_captive_url TEXT,
                first_added_utc_iso TEXT,
                last_connected_utc_iso TEXT,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 3: cellular_tower_cgi_observations
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cellular_tower_cgi_observations (
                cell_obs_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                provenance_tier TEXT NOT NULL,
                rat_generation TEXT NOT NULL,
                mcc_mnc TEXT NOT NULL,
                lac_or_tac INTEGER NOT NULL,
                raw_ci_eci_or_nci INTEGER NOT NULL,
                unpacked_enodeb_or_gnodeb_id INTEGER,
                unpacked_sector_id INTEGER,
                tower_lat_wgs84 REAL,
                tower_lon_wgs84 REAL,
                observed_utc_iso TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 4: significant_places_and_navigation_trips
        cur.execute("""
            CREATE TABLE IF NOT EXISTS significant_places_and_navigation_trips (
                place_trip_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                record_type TEXT NOT NULL,
                semantic_label TEXT,
                place_title_and_address TEXT,
                origin_lat_lon_json TEXT,
                destination_lat_lon_json TEXT NOT NULL,
                data_point_count_or_confidence TEXT,
                arrival_or_start_utc_iso TEXT NOT NULL,
                departure_or_end_utc_iso TEXT,
                dwell_duration_minutes REAL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_geo_lat_lon ON unified_geolocation_fixes_ledger(latitude_wgs84, longitude_wgs84)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_geo_time ON unified_geolocation_fixes_ledger(fix_start_utc_ns)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_radio_mac ON wifi_hotspot_and_bluetooth_connections_ledger(normalized_bssid_or_mac)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cell_cgi ON cellular_tower_cgi_observations(mcc_mnc, raw_ci_eci_or_nci)")

        conn.commit()
        conn.close()

    def export_to_sqlite(
        self,
        geo_fixes: Optional[List[UnifiedGeoFixRecord]] = None,
        radio_connections: Optional[List[RadioConnectionRecord]] = None,
        cellular_observations: Optional[List[CellularObservationRecord]] = None,
        significant_trips: Optional[List[SignificantPlaceTripRecord]] = None,
        output_db_path: str = "./.workspace_tmp/geolocation_and_triangulation_engine.sqlite",
    ) -> None:
        """Populates the 4 tables in the case database with extracted records."""
        out_path = Path(output_db_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        self.init_database(output_db_path)

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        if geo_fixes:
            for g in geo_fixes:
                cur.execute(
                    """
                    INSERT INTO unified_geolocation_fixes_ledger (
                        provenance_tier,
                        source_subsystem,
                        source_vfs_file_id,
                        recovery_classification,
                        device_locality,
                        latitude_wgs84,
                        longitude_wgs84,
                        horizontal_accuracy_meters,
                        spatial_precision_class,
                        altitude_meters,
                        speed_kmh,
                        implied_velocity_from_prev_kmh,
                        is_impossible_velocity_flagged,
                        resolved_address_or_place_name,
                        associated_bssid_or_cgi,
                        fix_start_utc_ns,
                        fix_start_utc_iso,
                        fix_end_utc_iso,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(g.provenance_tier.value if hasattr(g.provenance_tier, "value") else g.provenance_tier),
                        g.source_subsystem,
                        g.source_vfs_file_id,
                        str(g.recovery_classification.value if hasattr(g.recovery_classification, "value") else g.recovery_classification),
                        g.device_locality,
                        g.latitude_wgs84,
                        g.longitude_wgs84,
                        g.horizontal_accuracy_meters,
                        str(g.spatial_precision_class.value if hasattr(g.spatial_precision_class, "value") else g.spatial_precision_class),
                        g.altitude_meters,
                        g.speed_kmh,
                        g.implied_velocity_from_prev_kmh,
                        g.is_impossible_velocity_flagged,
                        g.resolved_address_or_place_name,
                        g.associated_bssid_or_cgi,
                        g.fix_start_utc_ns,
                        g.fix_start_utc_iso,
                        g.fix_end_utc_iso,
                        str(g.forensic_group.value if hasattr(g.forensic_group, "value") else g.forensic_group),
                    ),
                )

        if radio_connections:
            for r in radio_connections:
                cur.execute(
                    """
                    INSERT INTO wifi_hotspot_and_bluetooth_connections_ledger (
                        radio_category,
                        source_vfs_file_id,
                        ssid_or_device_name,
                        normalized_bssid_or_mac,
                        saved_wifi_password_psk,
                        device_type_or_captive_url,
                        first_added_utc_iso,
                        last_connected_utc_iso,
                        recovery_classification,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(r.radio_category.value if hasattr(r.radio_category, "value") else r.radio_category),
                        r.source_vfs_file_id,
                        r.ssid_or_device_name,
                        r.normalized_bssid_or_mac,
                        r.saved_wifi_password_psk,
                        r.device_type_or_captive_url,
                        r.first_added_utc_iso,
                        r.last_connected_utc_iso,
                        str(r.recovery_classification.value if hasattr(r.recovery_classification, "value") else r.recovery_classification),
                        str(r.forensic_group.value if hasattr(r.forensic_group, "value") else r.forensic_group),
                    ),
                )

        if cellular_observations:
            for c in cellular_observations:
                cur.execute(
                    """
                    INSERT INTO cellular_tower_cgi_observations (
                        provenance_tier,
                        rat_generation,
                        mcc_mnc,
                        lac_or_tac,
                        raw_ci_eci_or_nci,
                        unpacked_enodeb_or_gnodeb_id,
                        unpacked_sector_id,
                        tower_lat_wgs84,
                        tower_lon_wgs84,
                        observed_utc_iso,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(c.provenance_tier),
                        c.rat_generation,
                        c.mcc_mnc,
                        c.lac_or_tac,
                        c.raw_ci_eci_or_nci,
                        c.unpacked_enodeb_or_gnodeb_id,
                        c.unpacked_sector_id,
                        c.tower_lat_wgs84,
                        c.tower_lon_wgs84,
                        c.observed_utc_iso,
                        str(c.forensic_group.value if hasattr(c.forensic_group, "value") else c.forensic_group),
                    ),
                )

        if significant_trips:
            for s in significant_trips:
                cur.execute(
                    """
                    INSERT INTO significant_places_and_navigation_trips (
                        record_type,
                        semantic_label,
                        place_title_and_address,
                        origin_lat_lon_json,
                        destination_lat_lon_json,
                        data_point_count_or_confidence,
                        arrival_or_start_utc_iso,
                        departure_or_end_utc_iso,
                        dwell_duration_minutes,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(s.record_type.value if hasattr(s.record_type, "value") else s.record_type),
                        s.semantic_label,
                        s.place_title_and_address,
                        s.origin_lat_lon_json,
                        s.destination_lat_lon_json,
                        s.data_point_count_or_confidence,
                        s.arrival_or_start_utc_iso,
                        s.departure_or_end_utc_iso,
                        s.dwell_duration_minutes,
                        str(s.forensic_group.value if hasattr(s.forensic_group, "value") else s.forensic_group),
                    ),
                )

        conn.commit()
        conn.close()
