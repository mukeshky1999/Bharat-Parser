"""
Sub-Engine 6.3C: Cellular Tower CGI Decoder & Radio Handshake Auditor.
Unpacks Indian 4G LTE 28-bit ECI (eNodeB + Sector) and 5G NR 36-bit NCI (gNodeB).
Decodes Wi-Fi known networks, SoftAP mobile hotspots, and Bluetooth pairings.
Complies with Section 5 of Phase 6 Module 6.3 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import plistlib
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET

from src.core.enums import ForensicGroup, ResidualConfidence
from src.geolocation.models import (
    RadioCategory,
    CellularObservationRecord,
    RadioConnectionRecord,
    normalize_mac_6_octet,
    unpack_lte_eci,
    unpack_5g_nci,
)

logger = logging.getLogger(__name__)


class CellularRadioDecoder:
    """Decoder for Cellular Tower CGIs, Wi-Fi connections, and Bluetooth pairings."""

    def decode_cellular_tower_record(
        self,
        cell_data: Dict[str, Any],
        source_vfs_file_id: int = 1003,
    ) -> CellularObservationRecord:
        """
        Decodes a cellular tower record:
        Unpacks 28-bit LTE ECI into eNodeB_ID and Sector_ID.
        Unpacks 36-bit 5G NCI into gNodeB_ID and Sector_ID.
        """
        rat = str(cell_data.get("rat_generation", "4G_LTE")).upper()
        mcc = cell_data.get("mcc", 405)
        mnc = cell_data.get("mnc", 86)
        mcc_mnc_str = f"{mcc}-{mnc}"

        lac_or_tac = int(cell_data.get("lac_or_tac", 0))
        raw_ci = int(cell_data.get("raw_ci_eci") or cell_data.get("raw_ci_eci_or_nci") or 0)

        unpacked_node: Optional[int] = None
        unpacked_sector: Optional[int] = None

        if "4G" in rat or "LTE" in rat:
            unpacked_node, unpacked_sector = unpack_lte_eci(raw_ci)
        elif "5G" in rat or "NR" in rat:
            unpacked_node, unpacked_sector = unpack_5g_nci(raw_ci)
        else:
            unpacked_node = raw_ci >> 8
            unpacked_sector = raw_ci & 0xFF

        obs_iso = str(cell_data.get("observed_timestamp_iso") or cell_data.get("observed_utc_iso") or "1970-01-01T00:00:00.000000Z")
        tower_lat = cell_data.get("tower_lat_wgs84")
        tower_lon = cell_data.get("tower_lon_wgs84")
        tier = str(cell_data.get("provenance_tier", "TIER_2_SERVING_CELL"))

        return CellularObservationRecord(
            provenance_tier=tier,
            rat_generation=rat,
            mcc_mnc=mcc_mnc_str,
            lac_or_tac=lac_or_tac,
            raw_ci_eci_or_nci=raw_ci,
            unpacked_enodeb_or_gnodeb_id=unpacked_node,
            unpacked_sector_id=unpacked_sector,
            tower_lat_wgs84=float(tower_lat) if tower_lat is not None else None,
            tower_lon_wgs84=float(tower_lon) if tower_lon is not None else None,
            observed_utc_iso=obs_iso,
            forensic_group=ForensicGroup.G14_NETWORK_WIFI_BT_AND_DATAUSAGE,
        )

    def decode_apple_known_networks_plist(
        self,
        plist_path: str,
        source_vfs_file_id: int = 1004,
    ) -> List[RadioConnectionRecord]:
        """Parses Apple com.apple.wifi.known-networks.plist extracting SSIDs, BSSIDs, and LastJoined dates."""
        records: List[RadioConnectionRecord] = []
        if not os.path.exists(plist_path):
            return records

        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)

            if isinstance(data, dict):
                for k, v in data.items():
                    if not isinstance(v, dict):
                        continue
                    ssid = v.get("SSID_STR") or v.get("SSID")
                    bssid = v.get("BSSID")
                    last_joined = v.get("LastJoined") or v.get("UserPreferredTimestamp")
                    added_at = v.get("AddedAt")

                    norm_mac = normalize_mac_6_octet(str(bssid)) if bssid else None
                    last_iso = last_joined.isoformat() + "Z" if hasattr(last_joined, "isoformat") else (str(last_joined) if last_joined else None)
                    added_iso = added_at.isoformat() + "Z" if hasattr(added_at, "isoformat") else (str(added_at) if added_at else None)

                    rec = RadioConnectionRecord(
                        radio_category=RadioCategory.WIFI_KNOWN_CONNECTED_NETWORK,
                        source_vfs_file_id=source_vfs_file_id,
                        ssid_or_device_name=str(ssid) if ssid else None,
                        normalized_bssid_or_mac=norm_mac,
                        first_added_utc_iso=added_iso,
                        last_connected_utc_iso=last_iso,
                        forensic_group=ForensicGroup.G14_NETWORK_WIFI_BT_AND_DATAUSAGE,
                    )
                    records.append(rec)
        except Exception as exc:
            logger.debug("Failed opening known-networks plist %s: %s", plist_path, exc)

        return records

    def decode_android_wifi_config_store(
        self,
        xml_path: str,
        source_vfs_file_id: int = 1005,
    ) -> List[RadioConnectionRecord]:
        """Parses Android WifiConfigStore.xml extracting SSID, PreSharedKey (password), and Gateway MAC."""
        records: List[RadioConnectionRecord] = []
        if not os.path.exists(xml_path):
            return records

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for net_elem in root.iter("Network"):
                ssid = None
                psk = None
                gw_mac = None

                for item in net_elem.iter("string"):
                    name = item.get("name")
                    val = item.text
                    if name == "SSID":
                        ssid = val.strip('"') if val else None
                    elif name == "PreSharedKey":
                        psk = val.strip('"') if val else None
                    elif name in ("DefaultGwMacAddress", "BSSID"):
                        gw_mac = val

                norm_mac = normalize_mac_6_octet(str(gw_mac)) if gw_mac else None

                rec = RadioConnectionRecord(
                    radio_category=RadioCategory.WIFI_KNOWN_CONNECTED_NETWORK,
                    source_vfs_file_id=source_vfs_file_id,
                    ssid_or_device_name=ssid,
                    normalized_bssid_or_mac=norm_mac,
                    saved_wifi_password_psk=psk,
                    forensic_group=ForensicGroup.G14_NETWORK_WIFI_BT_AND_DATAUSAGE,
                )
                records.append(rec)
        except Exception as exc:
            logger.debug("Failed parsing WifiConfigStore.xml %s: %s", xml_path, exc)

        return records
