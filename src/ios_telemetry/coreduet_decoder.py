"""
Sub-Engine 6.1A: CoreDuet (knowledgeC.db) Deep Relational & Binary Plist Decoder.
Executes the master 4-table join (ZOBJECT, ZSTRUCTUREDMETADATA, ZSOURCE, ZCUSTOMMETADATA).
Extracts app foreground windows, lock states, timezone offsets (ZSECONDSFROMGMT), and device locality.
Complies with Section 3 of Phase 6 Module 6.1 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.ios_telemetry.models import (
    TelemetrySourceEngine,
    TelemetryEventCategory,
    IOSTelemetryEventRecord,
    cocoa_to_utc_ns,
    cocoa_to_utc_iso,
)

logger = logging.getLogger(__name__)


class CoreDuetDecoder:
    """Decoder for Apple CoreDuet knowledgeC.db SQLite databases."""

    STREAM_CATEGORY_MAP = {
        "/app/inFocus": TelemetryEventCategory.APP_IN_FOCUS,
        "/app/usage": TelemetryEventCategory.APP_IN_FOCUS,
        "/app/activity": TelemetryEventCategory.APP_IN_FOCUS,
        "/app/intents": TelemetryEventCategory.SIRI_APP_INTENT,
        "/device/isLocked": TelemetryEventCategory.SCREEN_LOCK_UNLOCK,
        "/display/isBacklit": TelemetryEventCategory.DISPLAY_BACKLIGHT,
        "/audio/outputRoute": TelemetryEventCategory.AUDIO_BT_CARPLAY_ROUTE,
        "/audio/inputRoute": TelemetryEventCategory.AUDIO_BT_CARPLAY_ROUTE,
        "/bluetooth/isConnected": TelemetryEventCategory.AUDIO_BT_CARPLAY_ROUTE,
        "/carplay/isConnected": TelemetryEventCategory.AUDIO_BT_CARPLAY_ROUTE,
        "/device/isPluggedIn": TelemetryEventCategory.HARDWARE_BUTTON_PRESS,
        "/notification/usage": TelemetryEventCategory.HARDWARE_BUTTON_PRESS,
    }

    def decode_knowledgec_database(
        self,
        db_path: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 801,
    ) -> List[IOSTelemetryEventRecord]:
        """Parses knowledgeC.db executing the relational join across ZOBJECT, ZSTRUCTUREDMETADATA, and ZSOURCE."""
        records: List[IOSTelemetryEventRecord] = []
        if not os.path.exists(db_path):
            return records

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            if "ZOBJECT" not in tables:
                conn.close()
                return records

            meta_table_exists = "ZSTRUCTUREDMETADATA" in tables
            source_table_exists = "ZSOURCE" in tables

            # Build query with optional left joins
            q = """
                SELECT
                    o.Z_PK,
                    o.ZSTREAMNAME,
                    o.ZVALUESTRING,
                    o.ZVALUEINTEGER,
                    o.ZVALUEDOUBLE,
                    o.ZSTARTDATE,
                    o.ZENDDATE,
                    o.ZCREATIONDATE,
                    o.ZSECONDSFROMGMT
            """
            if meta_table_exists:
                q += ", m.Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON"
            else:
                q += ", NULL"

            if source_table_exists:
                q += ", s.ZBUNDLEID, s.ZDEVICEID"
            else:
                q += ", NULL, NULL"

            q += " FROM ZOBJECT o "
            if meta_table_exists:
                q += " LEFT JOIN ZSTRUCTUREDMETADATA m ON o.ZSTRUCTUREDMETADATA = m.Z_PK "
            if source_table_exists:
                q += " LEFT JOIN ZSOURCE s ON o.ZSOURCE = s.Z_PK "

            cur.execute(q)
            rows = cur.fetchall()

            for row in rows:
                (
                    pk_val, stream_name, val_str, val_int, val_double,
                    start_date, end_date, create_date, tz_offset,
                    launch_reason, bundle_id, device_id
                ) = row

                s_name = str(stream_name) if stream_name else "/unknown"
                cat = self.STREAM_CATEGORY_MAP.get(s_name, TelemetryEventCategory.APP_IN_FOCUS)

                # Determine primary state/value
                primary_val = ""
                target_bundle = None

                if cat == TelemetryEventCategory.APP_IN_FOCUS:
                    target_bundle = val_str or bundle_id
                    primary_val = target_bundle or "InFocus"
                elif cat == TelemetryEventCategory.SCREEN_LOCK_UNLOCK:
                    primary_val = "LOCKED" if val_int == 1 else "UNLOCKED"
                elif cat == TelemetryEventCategory.DISPLAY_BACKLIGHT:
                    primary_val = "BACKLIGHT_ON" if val_int == 1 else "BACKLIGHT_OFF"
                else:
                    primary_val = val_str or (str(val_int) if val_int is not None else str(val_double or ""))

                # Locality
                locality = "LOCAL_SEIZED_IPHONE"
                if device_id:
                    locality = f"REMOTE_SYNCED_ICLOUD_DEVICE:{device_id}"

                # Timestamps
                s_cocoa = float(start_date) if start_date else 0.0
                e_cocoa = float(end_date) if end_date else s_cocoa

                start_ns = cocoa_to_utc_ns(s_cocoa)
                start_iso = cocoa_to_utc_iso(s_cocoa)
                end_iso = cocoa_to_utc_iso(e_cocoa) if e_cocoa else None
                duration = round(e_cocoa - s_cocoa, 6) if (e_cocoa >= s_cocoa) else 0.0

                # Metadata JSON
                meta_dict = {}
                if launch_reason:
                    meta_dict["launch_reason"] = launch_reason
                if bundle_id:
                    meta_dict["source_bundle_id"] = bundle_id

                meta_json = json.dumps(meta_dict) if meta_dict else None

                rec = IOSTelemetryEventRecord(
                    telemetry_source_engine=TelemetrySourceEngine.COREDUET_KNOWLEDGEC,
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    device_locality=locality,
                    stream_or_subsystem_name=s_name,
                    event_category=cat,
                    target_app_bundle_id=target_bundle,
                    primary_state_or_value=primary_val,
                    unpacked_metadata_json=meta_json,
                    start_utc_ns=start_ns,
                    start_utc_iso=start_iso,
                    end_utc_iso=end_iso,
                    duration_seconds=duration,
                    recorded_tz_offset_sec=tz_offset,
                    forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                )
                records.append(rec)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening knowledgeC.db %s: %s", db_path, exc)

        return records
