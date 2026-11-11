"""
Sub-Engine 6.2C: Google Digital Wellbeing & Samsung Digital Wellbeing (Forest) Decoder.
Decodes SQLite databases app_usage and dwbCommon.db to extract app lifecycles,
screen unlock history, and uninstalled ghost-app usage.
Complies with Section 5 of Phase 6 Module 6.2 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import Dict, List, Optional

from src.core.enums import ForensicGroup
from src.android_telemetry.models import (
    TelemetrySource,
    AndroidEventCategory,
    AndroidUsageEventRecord,
    unix_ms_to_utc_iso,
    unix_ms_to_utc_ns,
)

logger = logging.getLogger(__name__)


class WellbeingDecoder:
    """Decoder for Google Digital Wellbeing and Samsung Forest usage databases."""

    EVENT_TYPE_MAP: Dict[int, AndroidEventCategory] = {
        1: AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND,
        2: AndroidEventCategory.ACTIVITY_PAUSED_BACKGROUND,
        15: AndroidEventCategory.SCREEN_ON_INTERACTIVE,
        16: AndroidEventCategory.SCREEN_OFF_DARK,
        17: AndroidEventCategory.KEYGUARD_LOCKED,
        18: AndroidEventCategory.KEYGUARD_UNLOCKED,
    }

    def decode_google_wellbeing_db(
        self,
        db_path: str,
        android_user_profile_id: int = 0,
        source_vfs_file_id: int = 904,
        known_installed_packages: Optional[List[str]] = None,
    ) -> List[AndroidUsageEventRecord]:
        """Parses Google Digital Wellbeing app_usage SQLite database."""
        records: List[AndroidUsageEventRecord] = []
        if not os.path.exists(db_path):
            return records

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            # Check if events and packages tables exist
            has_events = "events" in tables or "app_usage_events" in tables
            has_packages = "packages" in tables
            if not has_events:
                conn.close()
                return records

            events_tbl = "events" if "events" in tables else "app_usage_events"

            if has_packages:
                query = f"""
                    SELECT e.package_id, p.package_name, e.timestamp, e.event_type
                    FROM {events_tbl} e
                    LEFT JOIN packages p ON e.package_id = p._id
                """
            else:
                query = f"SELECT NULL, package_name, timestamp, event_type FROM {events_tbl}"

            cur.execute(query)
            rows = cur.fetchall()

            for row in rows:
                pkg_id, pkg_name, ts_val, ev_type = row
                p_name = str(pkg_name or f"PackageID_{pkg_id}")
                t_ms = int(ts_val) if ts_val else 0
                cat = self.EVENT_TYPE_MAP.get(int(ev_type or 1), AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND)

                is_ghost = 1 if (known_installed_packages and p_name not in known_installed_packages) else 0

                rec = AndroidUsageEventRecord(
                    android_user_profile_id=android_user_profile_id,
                    telemetry_source=TelemetrySource.GOOGLE_DIGITAL_WELLBEING,
                    source_vfs_file_id=source_vfs_file_id,
                    granularity_level="GRANULAR_MILLISECOND_EVENT",
                    package_name=p_name,
                    activity_or_service_class=None,
                    is_uninstalled_ghost_app=is_ghost,
                    event_category=cat,
                    event_timestamp_utc_ns=unix_ms_to_utc_ns(t_ms),
                    event_timestamp_utc_iso=unix_ms_to_utc_iso(t_ms),
                    forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                )
                records.append(rec)

            conn.close()
        except Exception as exc:
            logger.debug("Failed decoding Google Wellbeing %s: %s", db_path, exc)

        return records

    def decode_samsung_wellbeing_db(
        self,
        db_path: str,
        android_user_profile_id: int = 0,
        source_vfs_file_id: int = 905,
        known_installed_packages: Optional[List[str]] = None,
    ) -> List[AndroidUsageEventRecord]:
        """Parses Samsung Forest dwbCommon.db SQLite database."""
        records: List[AndroidUsageEventRecord] = []
        if not os.path.exists(db_path):
            return records

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            if "usage_events" in tables:
                cur.execute("SELECT package_name, timestamp, event_type FROM usage_events")
                for p_name, t_val, ev_type in cur.fetchall():
                    t_ms = int(t_val) if t_val else 0
                    cat = self.EVENT_TYPE_MAP.get(int(ev_type or 1), AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND)
                    is_ghost = 1 if (known_installed_packages and p_name not in known_installed_packages) else 0

                    rec = AndroidUsageEventRecord(
                        android_user_profile_id=android_user_profile_id,
                        telemetry_source=TelemetrySource.SAMSUNG_FOREST_DWB,
                        source_vfs_file_id=source_vfs_file_id,
                        granularity_level="GRANULAR_MILLISECOND_EVENT",
                        package_name=str(p_name),
                        activity_or_service_class=None,
                        is_uninstalled_ghost_app=is_ghost,
                        event_category=cat,
                        event_timestamp_utc_ns=unix_ms_to_utc_ns(t_ms),
                        event_timestamp_utc_iso=unix_ms_to_utc_iso(t_ms),
                        forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                    )
                    records.append(rec)

            conn.close()
        except Exception as exc:
            logger.debug("Failed decoding Samsung Wellbeing %s: %s", db_path, exc)

        return records
