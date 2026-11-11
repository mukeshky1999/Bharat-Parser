"""
Sub-Engine 6.2: Unified Android Behavioral Telemetry Master Engine.
Orchestrates ingestion and normalizes events across UsageStats, AppOps, Digital Wellbeing, Health Connect, and Netstats.
Exports the normalized forensic timeline into android_behavioral_telemetry_engine.sqlite.
Complies with Section 8 of Phase 6 Module 6.2 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import List, Optional

from src.core.enums import ForensicGroup
from src.android_telemetry.models import (
    AndroidUsageEventRecord,
    AndroidAppOpRecord,
    AndroidHealthNetworkRecord,
)

logger = logging.getLogger(__name__)


class AndroidTelemetryEngine:
    """Master export and coordination engine for Android Behavioral Telemetry."""

    def init_database(self, db_path: str) -> None:
        """Initializes the SQLite schema with the 3 canonical tables."""
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Table 1: android_usagestats_and_lifecycle_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS android_usagestats_and_lifecycle_ledger (
                android_event_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                android_user_profile_id INTEGER NOT NULL,
                telemetry_source TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                granularity_level TEXT NOT NULL,
                package_name TEXT NOT NULL,
                activity_or_service_class TEXT,
                is_uninstalled_ghost_app INTEGER DEFAULT 0,
                event_category TEXT NOT NULL,
                event_timestamp_utc_ns INTEGER NOT NULL,
                event_timestamp_utc_iso TEXT NOT NULL,
                aggregated_fg_duration_sec REAL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 2: android_appops_and_privacy_sensor_audit
        cur.execute("""
            CREATE TABLE IF NOT EXISTS android_appops_and_privacy_sensor_audit (
                appop_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                source_subsystem TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                package_name TEXT NOT NULL,
                linux_uid INTEGER,
                op_code_and_name TEXT NOT NULL,
                process_uid_state TEXT,
                access_outcome TEXT NOT NULL,
                access_timestamp_utc_iso TEXT NOT NULL,
                access_duration_seconds REAL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 3: android_health_and_network_usage_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS android_health_and_network_usage_ledger (
                record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                ledger_domain TEXT NOT NULL,
                package_or_source_app TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                primary_numeric_value REAL NOT NULL,
                secondary_detail_json TEXT,
                window_start_utc_iso TEXT NOT NULL,
                window_end_utc_iso TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_usagestats_time ON android_usagestats_and_lifecycle_ledger(event_timestamp_utc_ns)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_usagestats_pkg ON android_usagestats_and_lifecycle_ledger(package_name)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_appops_time ON android_appops_and_privacy_sensor_audit(access_timestamp_utc_iso)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_health_time ON android_health_and_network_usage_ledger(window_start_utc_iso)")

        conn.commit()
        conn.close()

    def export_to_sqlite(
        self,
        usage_events: Optional[List[AndroidUsageEventRecord]] = None,
        appops_records: Optional[List[AndroidAppOpRecord]] = None,
        health_network_records: Optional[List[AndroidHealthNetworkRecord]] = None,
        output_db_path: str = "./.workspace_tmp/android_behavioral_telemetry_engine.sqlite",
    ) -> None:
        """Populates the 3 tables in the case database with extracted records."""
        out_path = Path(output_db_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        self.init_database(output_db_path)

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        if usage_events:
            for u in usage_events:
                cur.execute(
                    """
                    INSERT INTO android_usagestats_and_lifecycle_ledger (
                        android_user_profile_id,
                        telemetry_source,
                        source_vfs_file_id,
                        granularity_level,
                        package_name,
                        activity_or_service_class,
                        is_uninstalled_ghost_app,
                        event_category,
                        event_timestamp_utc_ns,
                        event_timestamp_utc_iso,
                        aggregated_fg_duration_sec,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        u.android_user_profile_id,
                        str(u.telemetry_source.value if hasattr(u.telemetry_source, "value") else u.telemetry_source),
                        u.source_vfs_file_id,
                        u.granularity_level,
                        u.package_name,
                        u.activity_or_service_class,
                        u.is_uninstalled_ghost_app,
                        str(u.event_category.value if hasattr(u.event_category, "value") else u.event_category),
                        u.event_timestamp_utc_ns,
                        u.event_timestamp_utc_iso,
                        u.aggregated_fg_duration_sec,
                        str(u.forensic_group.value if hasattr(u.forensic_group, "value") else u.forensic_group),
                    ),
                )

        if appops_records:
            for a in appops_records:
                cur.execute(
                    """
                    INSERT INTO android_appops_and_privacy_sensor_audit (
                        source_subsystem,
                        source_vfs_file_id,
                        package_name,
                        linux_uid,
                        op_code_and_name,
                        process_uid_state,
                        access_outcome,
                        access_timestamp_utc_iso,
                        access_duration_seconds,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(a.source_subsystem.value if hasattr(a.source_subsystem, "value") else a.source_subsystem),
                        a.source_vfs_file_id,
                        a.package_name,
                        a.linux_uid,
                        a.op_code_and_name,
                        a.process_uid_state,
                        a.access_outcome,
                        a.access_timestamp_utc_iso,
                        a.access_duration_seconds,
                        str(a.forensic_group.value if hasattr(a.forensic_group, "value") else a.forensic_group),
                    ),
                )

        if health_network_records:
            for h in health_network_records:
                cur.execute(
                    """
                    INSERT INTO android_health_and_network_usage_ledger (
                        ledger_domain,
                        package_or_source_app,
                        metric_type,
                        primary_numeric_value,
                        secondary_detail_json,
                        window_start_utc_iso,
                        window_end_utc_iso,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(h.ledger_domain.value if hasattr(h.ledger_domain, "value") else h.ledger_domain),
                        h.package_or_source_app,
                        h.metric_type,
                        h.primary_numeric_value,
                        h.secondary_detail_json,
                        h.window_start_utc_iso,
                        h.window_end_utc_iso,
                        str(h.forensic_group.value if hasattr(h.forensic_group, "value") else h.forensic_group),
                    ),
                )

        conn.commit()
        conn.close()
