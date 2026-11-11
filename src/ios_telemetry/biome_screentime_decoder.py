"""
Sub-Engine 6.1B: Apple Biome Streams (SEGB v1/v2) and Screen Time (RMAdminStore) Decoder.
Decodes Apple Biome streams (Device.Torch, App.InFocus, Device.Orientation, Text.InputSession, Location.Semantic)
and Screen Time databases (RMAdminStore-Local.sqlite, RMAdminStore-Cloud.sqlite).
Complies with Section 4 of Phase 6 Module 6.1 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

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
    PhysicalOrientation,
    IOSTelemetryEventRecord,
    cocoa_to_utc_ns,
    cocoa_to_utc_iso,
)

logger = logging.getLogger(__name__)


class BiomeScreenTimeDecoder:
    """Decoder for Apple Biome streams and Screen Time usage databases."""

    STREAM_CATEGORY_MAP: Dict[str, TelemetryEventCategory] = {
        "Device.Torch": TelemetryEventCategory.TORCH_FLASHLIGHT,
        "App.InFocus": TelemetryEventCategory.APP_IN_FOCUS,
        "Device.Orientation": TelemetryEventCategory.PHYSICAL_SENSOR_ORIENTATION,
        "Device.ScreenLocked": TelemetryEventCategory.SCREEN_LOCK_UNLOCK,
        "Device.Display.Backlight": TelemetryEventCategory.DISPLAY_BACKLIGHT,
        "Text.InputSession": TelemetryEventCategory.KEYBOARD_TYPING_SESSION,
        "App.Intent": TelemetryEventCategory.SIRI_APP_INTENT,
        "Location.Semantic": TelemetryEventCategory.APP_IN_FOCUS,
        "CarPlay.Connected": TelemetryEventCategory.AUDIO_BT_CARPLAY_ROUTE,
        "Audio.Route": TelemetryEventCategory.AUDIO_BT_CARPLAY_ROUTE,
    }

    def parse_biome_events(
        self,
        raw_biome_records: List[Dict[str, Any]],
        app_instance_id: int = 1,
        source_vfs_file_id: int = 802,
    ) -> List[IOSTelemetryEventRecord]:
        """Parses extracted Biome stream event dictionaries into normalized IOSTelemetryEventRecord objects."""
        records: List[IOSTelemetryEventRecord] = []

        for item in raw_biome_records:
            stream_name = str(item.get("stream_name", "Unknown.Stream"))
            cat = self.STREAM_CATEGORY_MAP.get(stream_name, TelemetryEventCategory.APP_IN_FOCUS)

            # Determine primary state/value
            state_val = str(item.get("state", ""))
            starting = item.get("starting")
            bundle_id = item.get("bundleID") or item.get("bundle_id") or item.get("target_app")

            primary_value = ""
            if cat == TelemetryEventCategory.TORCH_FLASHLIGHT:
                if state_val in ("1", "ON", "True", "true") or starting == 1:
                    primary_value = "TORCH_ON"
                else:
                    primary_value = "TORCH_OFF"
            elif cat == TelemetryEventCategory.APP_IN_FOCUS:
                if starting == 1 or state_val in ("1", "foreground"):
                    primary_value = bundle_id or "InFocus"
                elif starting == 0 or state_val in ("0", "background"):
                    primary_value = f"{bundle_id or 'App'}:Backgrounded"
                else:
                    primary_value = bundle_id or "InFocus"
            elif cat == TelemetryEventCategory.SCREEN_LOCK_UNLOCK:
                primary_value = "LOCKED" if state_val in ("1", "locked") else "UNLOCKED"
            elif cat == TelemetryEventCategory.DISPLAY_BACKLIGHT:
                primary_value = "BACKLIGHT_ON" if state_val in ("1", "on") else "BACKLIGHT_OFF"
            elif cat == TelemetryEventCategory.KEYBOARD_TYPING_SESSION:
                primary_value = f"TypingSession:{bundle_id or 'Unknown'}"
            else:
                primary_value = state_val or bundle_id or stream_name

            # Timestamp parsing
            timestamp_cocoa = item.get("timestamp_cocoa")
            timestamp_ns = item.get("timestamp_ns")
            timestamp_iso = item.get("timestamp_iso")

            if timestamp_cocoa is not None:
                start_ns = cocoa_to_utc_ns(float(timestamp_cocoa))
                start_iso = cocoa_to_utc_iso(float(timestamp_cocoa))
            elif timestamp_ns is not None:
                start_ns = int(timestamp_ns)
                sec = start_ns // 1_000_000_000
                us = (start_ns % 1_000_000_000) // 1_000
                dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)
                start_iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            elif timestamp_iso is not None:
                start_iso = str(timestamp_iso)
                dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
                start_ns = int(dt.timestamp() * 1_000_000_000)
            else:
                start_ns = 0
                start_iso = "1970-01-01T00:00:00.000000Z"

            end_iso = item.get("end_iso")
            duration = item.get("duration_seconds")
            if duration is not None:
                duration = float(duration)

            metadata_dict = {
                k: v for k, v in item.items()
                if k not in ("stream_name", "state", "starting", "bundleID", "bundle_id",
                             "timestamp_cocoa", "timestamp_ns", "timestamp_iso", "end_iso", "duration_seconds")
            }
            meta_json = json.dumps(metadata_dict) if metadata_dict else None

            rec = IOSTelemetryEventRecord(
                telemetry_source_engine=TelemetrySourceEngine.APPLE_BIOME_SEGB,
                source_vfs_file_id=source_vfs_file_id,
                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                device_locality="LOCAL_SEIZED_IPHONE",
                stream_or_subsystem_name=stream_name,
                event_category=cat,
                target_app_bundle_id=str(bundle_id) if bundle_id else None,
                primary_state_or_value=primary_value,
                unpacked_metadata_json=meta_json,
                start_utc_ns=start_ns,
                start_utc_iso=start_iso,
                end_utc_iso=end_iso,
                duration_seconds=duration,
                recorded_tz_offset_sec=item.get("tz_offset_sec"),
                forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
            )
            records.append(rec)

        return records

    def decode_screentime_database(
        self,
        db_path: str,
        app_instance_id: int = 1,
        source_vfs_file_id: int = 806,
    ) -> List[IOSTelemetryEventRecord]:
        """Parses Apple Screen Time RMAdminStore SQLite database."""
        records: List[IOSTelemetryEventRecord] = []
        if not os.path.exists(db_path):
            return records

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {r[0] for r in cur.fetchall()}

            if "ZUSAGETIMEDITEM" not in tables or "ZUSAGEBLOCK" not in tables:
                conn.close()
                return records

            query = """
                SELECT
                    t.Z_PK,
                    t.ZBUNDLEIDENTIFIER,
                    t.ZTOTALTIMEINSECONDS,
                    b.ZSTARTDATE,
                    b.ZENDDATE,
                    b.ZFIRSTPICKUPDATE,
                    d.ZNAME,
                    d.ZIDENTIFIER
                FROM ZUSAGETIMEDITEM t
                LEFT JOIN ZUSAGEBLOCK b ON t.ZBLOCK = b.Z_PK
                LEFT JOIN ZCOREUSER u ON b.ZUSER = u.Z_PK
                LEFT JOIN ZCOREDEVICE d ON b.ZDEVICE = d.Z_PK
            """
            cur.execute(query)
            rows = cur.fetchall()

            for row in rows:
                (
                    pk_val, bundle_id, total_seconds, start_cocoa, end_cocoa,
                    first_pickup_cocoa, device_name, device_uuid
                ) = row

                locality = "LOCAL_SEIZED_IPHONE"
                if device_uuid:
                    locality = f"REMOTE_SYNCED_ICLOUD_DEVICE:{device_uuid}"

                s_cocoa = float(start_cocoa) if start_cocoa else 0.0
                e_cocoa = float(end_cocoa) if end_cocoa else s_cocoa

                start_ns = cocoa_to_utc_ns(s_cocoa)
                start_iso = cocoa_to_utc_iso(s_cocoa)
                end_iso = cocoa_to_utc_iso(e_cocoa)

                duration = float(total_seconds) if total_seconds else (e_cocoa - s_cocoa)

                meta = {
                    "screentime_pk": pk_val,
                    "first_pickup_cocoa": first_pickup_cocoa,
                    "device_name": device_name,
                }

                rec = IOSTelemetryEventRecord(
                    telemetry_source_engine=TelemetrySourceEngine.SCREENTIME_RMADMIN,
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    device_locality=locality,
                    stream_or_subsystem_name="ScreenTime.UsageTimedItem",
                    event_category=TelemetryEventCategory.APP_IN_FOCUS,
                    target_app_bundle_id=str(bundle_id) if bundle_id else None,
                    primary_state_or_value=str(bundle_id or "AppUsage"),
                    unpacked_metadata_json=json.dumps(meta),
                    start_utc_ns=start_ns,
                    start_utc_iso=start_iso,
                    end_utc_iso=end_iso,
                    duration_seconds=round(duration, 4),
                    forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                )
                records.append(rec)

            conn.close()
        except Exception as exc:
            logger.debug("Failed opening ScreenTime database %s: %s", db_path, exc)

        return records
