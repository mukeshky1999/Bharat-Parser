"""
Sub-Engine 6.5D: Mock GPS, Virtual Location Spoofer, and Multi-Sensor Contradiction Engine.
Complies with Section 6 of Phase 6 Module 6.5 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.antiforensics.models import (
    SpoofMethod,
    LocationSpoofContradictionRecord,
    calculate_haversine_distance_meters,
)

KNOWN_LOCATION_SPOOFER_PACKAGES = [
    "com.lexa.fakegps",
    "com.incorporateapps.fakegps",
    "com.blogspot.newapphorizons.fakegps",
    "ru.gavrikov.mocklocations",
    "com.gpsjoystick",
    "io.github.jqssun.gpssetter",
    "com.lerist.fakelocation",
    "LocSim",
    "Geranium",
]


class LocationSpoofAuditor:
    """Audits Mock GPS grants, installed spoofing packages, and multi-sensor contradictions."""

    def audit_appops_mock_location(
        self,
        appops_xml_path: str,
        source_vfs_file_id: int,
    ) -> List[LocationSpoofContradictionRecord]:
        """
        Parses Android /data/system/appops.xml for op 58 (MOCK_LOCATION) permission grants.
        """
        records: List[LocationSpoofContradictionRecord] = []
        if not os.path.exists(appops_xml_path):
            return records

        try:
            tree = ET.parse(appops_xml_path)
            root = tree.getroot()
            for pkg_elem in root.findall(".//pkg"):
                pkg_name = pkg_elem.attrib.get("name", "")
                for op_elem in pkg_elem.findall("op"):
                    op_id = op_elem.attrib.get("id") or op_elem.attrib.get("name")
                    if op_id in ("58", "android:mock_location"):
                        mode = op_elem.attrib.get("mode", "0")
                        # mode 0 = MODE_ALLOWED
                        if mode == "0":
                            records.append(
                                LocationSpoofContradictionRecord(
                                    detection_method=SpoofMethod.APPOPS_MOCK_LOCATION_OP_58,
                                    spoofer_package_or_tool=pkg_name,
                                    claimed_gps_lat_lon=None,
                                    contradicting_sensor_proof=(
                                        f"Package {pkg_name} granted active Mock Location provider "
                                        f"privileges in Android AppOps (op 58, mode 0)."
                                    ),
                                    event_utc_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                    forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
                                    dim_existence=EvidentiaryExistence.OBSERVED,
                                    dim_access=EvidentiaryAccess.PLAINTEXT,
                                    dim_storage=EvidentiaryStorage.LIVE_RECORD,
                                    dim_provenance=f"appops.xml:pkg={pkg_name}:op=58",
                                    dim_corroboration=1.0,
                                )
                            )
        except Exception as _err:
            records.extend([])

        return records

    def audit_spoof_apps(
        self,
        installed_packages: List[str],
        source_vfs_file_id: int = 0,
    ) -> List[LocationSpoofContradictionRecord]:
        """
        Identifies active or uninstalled ghost location spoofer tools on device.
        """
        records: List[LocationSpoofContradictionRecord] = []
        for pkg in installed_packages:
            for known_spoofer in KNOWN_LOCATION_SPOOFER_PACKAGES:
                if known_spoofer.lower() in pkg.lower():
                    records.append(
                        LocationSpoofContradictionRecord(
                            detection_method=SpoofMethod.SPOOF_APP_INSTALLED_OR_GHOST,
                            spoofer_package_or_tool=pkg,
                            claimed_gps_lat_lon=None,
                            contradicting_sensor_proof=(
                                f"Known location mocking/spoofing utility package identified: {pkg}"
                            ),
                            event_utc_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                            forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
                            dim_existence=EvidentiaryExistence.OBSERVED,
                            dim_access=EvidentiaryAccess.PLAINTEXT,
                            dim_storage=EvidentiaryStorage.LIVE_RECORD,
                            dim_provenance=f"package_inventory:{pkg}",
                            dim_corroboration=1.0,
                        )
                    )
                    break
        return records

    def audit_gps_vs_radio_contradiction(
        self,
        gps_fixes: List[Dict[str, Any]],
        radio_fixes: List[Dict[str, Any]],
        max_km: float = 35.0,
        source_vfs_file_id: int = 0,
    ) -> List[LocationSpoofContradictionRecord]:
        """
        Cross-validates GPS fixes against serving cell towers (CGI) or connected Wi-Fi (BSSID).
        Emits GPS_VS_CELL_WIFI_RADIO_CONTRADICTION if distance exceeds max_km threshold (default 35 km).
        """
        records: List[LocationSpoofContradictionRecord] = []
        max_meters = max_km * 1000.0

        for gps in gps_fixes:
            gps_lat = float(gps.get("lat", 0.0))
            gps_lon = float(gps.get("lon", 0.0))
            gps_ts = float(gps.get("timestamp", 0.0))
            gps_iso = gps.get("utc_iso") or datetime.fromtimestamp(gps_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            for radio in radio_fixes:
                radio_lat = float(radio.get("lat", 0.0))
                radio_lon = float(radio.get("lon", 0.0))
                radio_ts = float(radio.get("timestamp", 0.0))
                radio_desc = radio.get("detail", "Cell/Wi-Fi Radio")

                # Check if fixes occurred within +/- 300 seconds (5 minutes)
                if abs(gps_ts - radio_ts) <= 300.0:
                    dist_m = calculate_haversine_distance_meters(gps_lat, gps_lon, radio_lat, radio_lon)
                    if dist_m > max_meters:
                        dist_km = dist_m / 1000.0
                        proof = (
                            f"Simultaneous serving radio ({radio_desc}) was located in "
                            f"coordinates ({radio_lat:.4f}, {radio_lon:.4f})—{dist_km:.1f} km away "
                            f"from claimed GPS fix ({gps_lat:.4f}, {gps_lon:.4f}), physically disproving GPS validity."
                        )
                        records.append(
                            LocationSpoofContradictionRecord(
                                detection_method=SpoofMethod.GPS_VS_CELL_WIFI_RADIO_CONTRADICTION,
                                spoofer_package_or_tool=gps.get("source_app", "unknown_spoofer"),
                                claimed_gps_lat_lon=f"{gps_lat:.4f}, {gps_lon:.4f}",
                                contradicting_sensor_proof=proof,
                                event_utc_iso=gps_iso,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
                                dim_existence=EvidentiaryExistence.OBSERVED,
                                dim_access=EvidentiaryAccess.PLAINTEXT,
                                dim_storage=EvidentiaryStorage.LIVE_RECORD,
                                dim_provenance=f"gps_vs_radio:delta={dist_km:.1f}km",
                                dim_corroboration=1.0,
                            )
                        )
        return records

    def audit_motion_vs_speed_contradiction(
        self,
        gps_fixes: List[Dict[str, Any]],
        charger_and_motion_logs: List[Dict[str, Any]],
        source_vfs_file_id: int = 0,
    ) -> List[LocationSpoofContradictionRecord]:
        """
        Detects simulated GPS joystick movements while device is charging with 0 steps.
        """
        records: List[LocationSpoofContradictionRecord] = []
        for gps in gps_fixes:
            speed = float(gps.get("speed_kmh", 0.0))
            gps_ts = float(gps.get("timestamp", 0.0))
            if speed > 15.0:
                for motion in charger_and_motion_logs:
                    motion_ts = float(motion.get("timestamp", 0.0))
                    if abs(gps_ts - motion_ts) <= 120.0:
                        is_plugged = motion.get("is_plugged", False)
                        step_count = motion.get("steps", 0)
                        if is_plugged and step_count == 0:
                            proof = (
                                f"GPS reported high-speed travel ({speed:.1f} km/h), while device telemetry "
                                f"records handset stationary on AC charger (0 steps registered)."
                            )
                            records.append(
                                LocationSpoofContradictionRecord(
                                    detection_method=SpoofMethod.GPS_MOVEMENT_WHILE_CHARGING_ZERO_STEPS,
                                    spoofer_package_or_tool=gps.get("source_app", "virtual_joystick"),
                                    claimed_gps_lat_lon=f"{gps.get('lat', 0.0):.4f}, {gps.get('lon', 0.0):.4f}",
                                    contradicting_sensor_proof=proof,
                                    event_utc_iso=gps.get("utc_iso", ""),
                                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                    forensic_group=ForensicGroup.G12_OS_GEOLOCATION_AND_TIMELINE,
                                    dim_existence=EvidentiaryExistence.OBSERVED,
                                    dim_access=EvidentiaryAccess.PLAINTEXT,
                                    dim_storage=EvidentiaryStorage.LIVE_RECORD,
                                    dim_provenance="motion_vs_speed",
                                    dim_corroboration=1.0,
                                )
                            )
        return records
