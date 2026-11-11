"""
Sub-Engine 6.1D: Apple Health (healthdb_secure.sqlite) Sensor & Alibi Provenance Engine.
Executes the mandatory 6-table hardware provenance join:
samples -> objects -> data_provenances -> source_devices & sources -> quantity_samples.
Strictly separates iPhone internal coprocessor steps from Apple Watch / external synced steps.
Complies with Section 6 of Phase 6 Module 6.1 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import Dict, List, Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.ios_telemetry.models import (
    HealthSensorMetricType,
    IOSHealthSampleRecord,
    cocoa_to_utc_iso,
)

logger = logging.getLogger(__name__)


class HealthDecoder:
    """Decoder for Apple Health healthdb_secure.sqlite databases."""

    DATA_TYPE_METRIC_MAP: Dict[int, HealthSensorMetricType] = {
        7: HealthSensorMetricType.STEP_COUNT,
        8: HealthSensorMetricType.DISTANCE_WALK_RUN_METERS,
        12: HealthSensorMetricType.FLIGHTS_CLIMBED,
        5: HealthSensorMetricType.HEART_RATE_BPM,
        63: HealthSensorMetricType.SLEEP_STAGE,
        9: HealthSensorMetricType.ACTIVE_ENERGY,
        10: HealthSensorMetricType.ACTIVE_ENERGY,
    }

    def decode_health_database(
        self,
        db_path: str,
        source_vfs_file_id: int = 804,
    ) -> List[IOSHealthSampleRecord]:
        """Executes the 6-table join across samples, objects, data_provenances, source_devices, sources, and quantity_samples."""
        records: List[IOSHealthSampleRecord] = []
        if not os.path.exists(db_path):
            return records

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            required_tables = {"samples", "objects", "data_provenances", "source_devices", "sources"}
            if not required_tables.issubset(tables):
                conn.close()
                return records

            has_quantity = "quantity_samples" in tables

            query = """
                SELECT
                    s.data_id,
                    s.data_type,
                    s.start_date,
                    s.end_date,
                    o.creation_date,
                    sd.hardware,
                    sd.name,
                    src.bundle_identifier
            """
            if has_quantity:
                query += ", qs.quantity"
            else:
                query += ", NULL"

            query += """
                FROM samples s
                JOIN objects o ON s.data_id = o.data_id
                JOIN data_provenances dp ON o.provenance = dp.ROWID
                JOIN source_devices sd ON dp.device_id = sd.ROWID
                JOIN sources src ON dp.source_id = src.ROWID
            """
            if has_quantity:
                query += " LEFT JOIN quantity_samples qs ON s.data_id = qs.data_id "

            cur.execute(query)
            rows = cur.fetchall()

            for row in rows:
                (
                    data_id, data_type, start_date, end_date,
                    creation_date, hardware, device_name,
                    bundle_id, quantity
                ) = row

                # Metric classification
                metric_type = self.DATA_TYPE_METRIC_MAP.get(int(data_type), HealthSensorMetricType.STEP_COUNT)

                # Hardware provenance
                hw_model = str(hardware or device_name or "Unknown")
                is_local = 1 if "iphone" in hw_model.lower() else 0

                val = float(quantity) if quantity is not None else 0.0

                s_cocoa = float(start_date) if start_date else 0.0
                e_cocoa = float(end_date) if end_date else s_cocoa
                c_cocoa = float(creation_date) if creation_date else s_cocoa

                start_iso = cocoa_to_utc_iso(s_cocoa)
                end_iso = cocoa_to_utc_iso(e_cocoa)
                committed_iso = cocoa_to_utc_iso(c_cocoa)

                rec = IOSHealthSampleRecord(
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    sensor_metric_type=metric_type,
                    metric_value=val,
                    hardware_source_model=hw_model,
                    is_local_iphone_sensor=is_local,
                    was_manually_user_entered=0,
                    activity_start_utc_iso=start_iso,
                    activity_end_utc_iso=end_iso,
                    db_sync_committed_utc_iso=committed_iso,
                    forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                )
                records.append(rec)

            conn.close()
        except Exception as exc:
            logger.debug("Failed decoding health database %s: %s", db_path, exc)

        return records
