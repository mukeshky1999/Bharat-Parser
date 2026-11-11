"""
Sub-Engine 6.1: Unified iOS Behavioral Telemetry Master Engine.
Orchestrates ingestion and normalizes events across CoreDuet, Biome, Unified Logs, Health, and FSEvents.
Exports the normalized forensic timeline into ios_behavioral_telemetry_engine.sqlite.
Complies with Section 8 of Phase 6 Module 6.1 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import List, Optional

from src.core.enums import ForensicGroup
from src.ios_telemetry.models import (
    IOSTelemetryEventRecord,
    IOSHealthSampleRecord,
    IOSFSEventRecord,
)

logger = logging.getLogger(__name__)


class IOSTelemetryEngine:
    """Master export and coordination engine for iOS Behavioral Telemetry."""

    def init_database(self, db_path: str) -> None:
        """Initializes the SQLite schema with the 3 canonical tables."""
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Table 1: ios_behavioral_timeline_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ios_behavioral_timeline_ledger (
                ios_telemetry_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                telemetry_source_engine TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                device_locality TEXT NOT NULL,
                stream_or_subsystem_name TEXT NOT NULL,
                event_category TEXT NOT NULL,
                target_app_bundle_id TEXT,
                primary_state_or_value TEXT NOT NULL,
                unpacked_metadata_json TEXT,
                start_utc_ns INTEGER NOT NULL,
                start_utc_iso TEXT NOT NULL,
                end_utc_iso TEXT,
                duration_seconds REAL,
                recorded_tz_offset_sec INTEGER,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 2: ios_health_sensor_alibi_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ios_health_sensor_alibi_ledger (
                health_sample_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                sensor_metric_type TEXT NOT NULL,
                metric_value REAL NOT NULL,
                hardware_source_model TEXT NOT NULL,
                is_local_iphone_sensor INTEGER NOT NULL,
                was_manually_user_entered INTEGER DEFAULT 0,
                activity_start_utc_iso TEXT NOT NULL,
                activity_end_utc_iso TEXT NOT NULL,
                db_sync_committed_utc_iso TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Table 3: ios_fsevents_filesystem_audit
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ios_fsevents_filesystem_audit (
                fsevent_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                gzip_source_file_name TEXT NOT NULL,
                fsevent_format_version TEXT NOT NULL,
                monotonic_event_id INTEGER NOT NULL,
                target_file_path TEXT NOT NULL,
                apfs_inode_node_id INTEGER,
                decoded_flags_list TEXT NOT NULL,
                does_file_still_exist INTEGER NOT NULL,
                bracket_earliest_utc_iso TEXT,
                bracket_latest_utc_iso TEXT NOT NULL,
                forensic_group TEXT NOT NULL
            )
        """)

        # Create indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_start ON ios_behavioral_timeline_ledger(start_utc_ns)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_cat ON ios_behavioral_timeline_ledger(event_category)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_health_start ON ios_health_sensor_alibi_ledger(activity_start_utc_iso)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_fsevents_mono ON ios_fsevents_filesystem_audit(monotonic_event_id)")

        conn.commit()
        conn.close()

    def export_to_sqlite(
        self,
        telemetry_events: Optional[List[IOSTelemetryEventRecord]] = None,
        health_samples: Optional[List[IOSHealthSampleRecord]] = None,
        fsevents: Optional[List[IOSFSEventRecord]] = None,
        output_db_path: str = "./.workspace_tmp/ios_behavioral_telemetry_engine.sqlite",
    ) -> None:
        """Populates the 3 tables in the case database with extracted records."""
        out_path = Path(output_db_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        self.init_database(output_db_path)

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        if telemetry_events:
            for t in telemetry_events:
                cur.execute(
                    """
                    INSERT INTO ios_behavioral_timeline_ledger (
                        telemetry_source_engine,
                        source_vfs_file_id,
                        recovery_classification,
                        device_locality,
                        stream_or_subsystem_name,
                        event_category,
                        target_app_bundle_id,
                        primary_state_or_value,
                        unpacked_metadata_json,
                        start_utc_ns,
                        start_utc_iso,
                        end_utc_iso,
                        duration_seconds,
                        recorded_tz_offset_sec,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(t.telemetry_source_engine.value if hasattr(t.telemetry_source_engine, "value") else t.telemetry_source_engine),
                        t.source_vfs_file_id,
                        str(t.recovery_classification.value if hasattr(t.recovery_classification, "value") else t.recovery_classification),
                        t.device_locality,
                        t.stream_or_subsystem_name,
                        str(t.event_category.value if hasattr(t.event_category, "value") else t.event_category),
                        t.target_app_bundle_id,
                        t.primary_state_or_value,
                        t.unpacked_metadata_json,
                        t.start_utc_ns,
                        t.start_utc_iso,
                        t.end_utc_iso,
                        t.duration_seconds,
                        t.recorded_tz_offset_sec,
                        str(t.forensic_group.value if hasattr(t.forensic_group, "value") else t.forensic_group),
                    ),
                )

        if health_samples:
            for h in health_samples:
                cur.execute(
                    """
                    INSERT INTO ios_health_sensor_alibi_ledger (
                        source_vfs_file_id,
                        recovery_classification,
                        sensor_metric_type,
                        metric_value,
                        hardware_source_model,
                        is_local_iphone_sensor,
                        was_manually_user_entered,
                        activity_start_utc_iso,
                        activity_end_utc_iso,
                        db_sync_committed_utc_iso,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        h.source_vfs_file_id,
                        str(h.recovery_classification.value if hasattr(h.recovery_classification, "value") else h.recovery_classification),
                        str(h.sensor_metric_type.value if hasattr(h.sensor_metric_type, "value") else h.sensor_metric_type),
                        h.metric_value,
                        h.hardware_source_model,
                        h.is_local_iphone_sensor,
                        h.was_manually_user_entered,
                        h.activity_start_utc_iso,
                        h.activity_end_utc_iso,
                        h.db_sync_committed_utc_iso,
                        str(h.forensic_group.value if hasattr(h.forensic_group, "value") else h.forensic_group),
                    ),
                )

        if fsevents:
            for f in fsevents:
                cur.execute(
                    """
                    INSERT INTO ios_fsevents_filesystem_audit (
                        gzip_source_file_name,
                        fsevent_format_version,
                        monotonic_event_id,
                        target_file_path,
                        apfs_inode_node_id,
                        decoded_flags_list,
                        does_file_still_exist,
                        bracket_earliest_utc_iso,
                        bracket_latest_utc_iso,
                        forensic_group
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.gzip_source_file_name,
                        f.fsevent_format_version,
                        f.monotonic_event_id,
                        f.target_file_path,
                        f.apfs_inode_node_id,
                        f.decoded_flags_list,
                        f.does_file_still_exist,
                        f.bracket_earliest_utc_iso,
                        f.bracket_latest_utc_iso,
                        str(f.forensic_group.value if hasattr(f.forensic_group, "value") else f.forensic_group),
                    ),
                )

        conn.commit()
        conn.close()
