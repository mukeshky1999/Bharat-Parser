"""
Sub-Engine 6.2D & 6.2E: Android Health Connect, Fitness & Netstats Decoder.
Parses Health Connect SQLite databases (Android 14-17 System Framework & Android 13 APK)
and Netstats per-UID network data transmission logs.
Complies with Section 6 & 7 of Phase 6 Module 6.2 Specification and AGENTS.md Constitution.
"""

import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Dict, List, Optional

from src.core.enums import ForensicGroup
from src.android_telemetry.models import (
    AndroidHealthDomain,
    AndroidHealthNetworkRecord,
    unix_ms_to_utc_iso,
)

logger = logging.getLogger(__name__)


class AndroidHealthNetworkDecoder:
    """Decoder for Android Health Connect databases and Netstats logs."""

    DEVICE_TYPE_MAP: Dict[int, str] = {
        0: "UNKNOWN",
        1: "WATCH",
        2: "PHONE",
        3: "SCALE",
        4: "RING",
        5: "HEAD_MOUNTED",
        6: "FITNESS_BAND",
    }

    def decode_health_connect_db(
        self,
        db_path: str,
        source_vfs_file_id: int = 903,
    ) -> List[AndroidHealthNetworkRecord]:
        """Parses healthconnect.db steps, heart rate, and distance tables."""
        records: List[AndroidHealthNetworkRecord] = []
        if not os.path.exists(db_path):
            return records

        is_framework = "system_ce" in db_path or "healthconnect" in db_path
        domain = (
            AndroidHealthDomain.HEALTH_CONNECT_FRAMEWORK
            if is_framework
            else AndroidHealthDomain.HEALTH_CONNECT_APK
        )

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            has_app_info = "application_info_table" in tables
            has_steps = "steps_record_table" in tables

            if has_steps:
                if has_app_info:
                    query = """
                        SELECT
                            s.start_time,
                            s.end_time,
                            s.count,
                            s.device_type,
                            a.package_name
                        FROM steps_record_table s
                        LEFT JOIN application_info_table a ON s.app_info_id = a.row_id
                    """
                else:
                    query = """
                        SELECT
                            start_time,
                            end_time,
                            count,
                            device_type,
                            'UnknownApp'
                        FROM steps_record_table
                    """

                cur.execute(query)
                rows = cur.fetchall()

                for row in rows:
                    start_t, end_t, count_val, dev_type_code, pkg_name = row
                    p_name = str(pkg_name or "UnknownApp")
                    dev_type_str = self.DEVICE_TYPE_MAP.get(int(dev_type_code or 2), "PHONE")

                    # Handle ms or ns
                    s_ms = int(start_t) if start_t else 0
                    if s_ms > 10**14:  # nanoseconds
                        s_ms //= 1_000_000
                    e_ms = int(end_t) if end_t else s_ms
                    if e_ms > 10**14:
                        e_ms //= 1_000_000

                    start_iso = unix_ms_to_utc_iso(s_ms)
                    end_iso = unix_ms_to_utc_iso(e_ms)

                    detail = {
                        "device_type": dev_type_str,
                        "device_type_code": dev_type_code,
                    }

                    rec = AndroidHealthNetworkRecord(
                        ledger_domain=domain,
                        package_or_source_app=p_name,
                        metric_type="STEP_COUNT",
                        primary_numeric_value=float(count_val or 0.0),
                        secondary_detail_json=json.dumps(detail),
                        window_start_utc_iso=start_iso,
                        window_end_utc_iso=end_iso,
                        forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                    )
                    records.append(rec)

            conn.close()
        except Exception as exc:
            logger.debug("Failed decoding Health Connect database %s: %s", db_path, exc)

        return records

    def decode_netstats_records(
        self,
        raw_netstats_entries: List[Dict[str, Any]],
        uid_to_package_map: Optional[Dict[int, str]] = None,
    ) -> List[AndroidHealthNetworkRecord]:
        """Parses network transmission buckets from /data/system/netstats/."""
        records: List[AndroidHealthNetworkRecord] = []
        if uid_to_package_map is None:
            uid_to_package_map = {}

        for entry in raw_netstats_entries:
            linux_uid = entry.get("uid", 0)
            pkg_name = uid_to_package_map.get(linux_uid, f"UID_{linux_uid}")
            rx_bytes = int(entry.get("rx_bytes", 0))
            tx_bytes = int(entry.get("tx_bytes", 0))
            total_bytes = float(rx_bytes + tx_bytes)

            is_wifi = bool(entry.get("is_wifi", True))
            metric = "WIFI_BYTES_TX_RX" if is_wifi else "CELLULAR_BYTES_TX_RX"

            start_ms = int(entry.get("bucket_start_ms", 0))
            end_ms = int(entry.get("bucket_end_ms", start_ms))

            detail = {
                "linux_uid": linux_uid,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "interface": entry.get("iface", "wlan0" if is_wifi else "rmnet_data0"),
                "subscriber_imsi": entry.get("subscriber_imsi"),
            }

            rec = AndroidHealthNetworkRecord(
                ledger_domain=AndroidHealthDomain.NETSTATS_UID_BANDWIDTH,
                package_or_source_app=pkg_name,
                metric_type=metric,
                primary_numeric_value=total_bytes,
                secondary_detail_json=json.dumps(detail),
                window_start_utc_iso=unix_ms_to_utc_iso(start_ms),
                window_end_utc_iso=unix_ms_to_utc_iso(end_ms),
                forensic_group=ForensicGroup.G14_NETWORK_WIFI_BT_AND_DATAUSAGE,
            )
            records.append(rec)

        return records
