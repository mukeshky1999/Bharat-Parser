"""
Sub-Engine 6.1C: Apple Unified Logs (.tracev3) & Physical vs Display UI Orientation Decoder.
Processes unified log streams and separates hardware physical orientation (CMDeviceOrientation)
from SpringBoard display UI orientation (UIInterfaceOrientation).
Complies with Section 5 of Phase 6 Module 6.1 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import json
import logging
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
)

logger = logging.getLogger(__name__)


class UnifiedLogsOrientationDecoder:
    """Decoder for Apple Unified Logs and orientation classification."""

    PHYSICAL_ORIENTATION_NAMES = {
        1: "Portrait (1)",
        2: "PortraitUpsideDown (2)",
        3: "LandscapeLeft (3)",
        4: "LandscapeRight (4)",
        5: "FaceUp (5)",
        6: "FaceDown (6)",
    }

    UI_ORIENTATION_NAMES = {
        1: "UI_Portrait (1)",
        2: "UI_PortraitUpsideDown (2)",
        3: "UI_LandscapeLeft (3)",
        4: "UI_LandscapeRight (4)",
    }

    def decode_orientation_events(
        self,
        events: List[Dict[str, Any]],
        app_instance_id: int = 1,
        source_vfs_file_id: int = 803,
    ) -> List[IOSTelemetryEventRecord]:
        """Classifies orientation and unified log events into physical sensor vs. UI display orientation."""
        records: List[IOSTelemetryEventRecord] = []

        for evt in events:
            subsystem = str(evt.get("subsystem", "com.apple.BackBoard"))
            category = str(evt.get("category", "Orientation"))
            evt_type = str(evt.get("type", "")).upper()
            code = int(evt.get("orientation_code", 0))
            screen_locked = evt.get("screen_locked")

            # Determine whether physical sensor or display UI
            is_physical = (
                evt_type == "PHYSICAL_SENSOR"
                or "BACKBOARD" in subsystem.upper()
                or ("SPRINGBOARD" not in subsystem.upper() and evt_type != "DISPLAY_UI")
            )

            if is_physical and evt_type != "DISPLAY_UI":
                cat = TelemetryEventCategory.PHYSICAL_SENSOR_ORIENTATION
                state_str = self.PHYSICAL_ORIENTATION_NAMES.get(code, f"PhysicalOrientation ({code})")
            else:
                cat = TelemetryEventCategory.DISPLAY_UI_ORIENTATION
                state_str = self.UI_ORIENTATION_NAMES.get(code, f"UIOrientation ({code})")

            # Timestamps
            timestamp_ns = evt.get("timestamp_ns")
            timestamp_iso = evt.get("timestamp_iso")

            if timestamp_ns is not None:
                ns_val = int(timestamp_ns)
                sec = ns_val // 1_000_000_000
                us = (ns_val % 1_000_000_000) // 1_000
                dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)
                iso_val = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            elif timestamp_iso is not None:
                iso_val = str(timestamp_iso)
                dt = datetime.fromisoformat(iso_val.replace("Z", "+00:00"))
                ns_val = int(dt.timestamp() * 1_000_000_000)
            else:
                ns_val = 0
                iso_val = "1970-01-01T00:00:00.000000Z"

            meta = {
                "subsystem": subsystem,
                "category": category,
                "raw_orientation_code": code,
                "screen_locked": screen_locked,
            }

            rec = IOSTelemetryEventRecord(
                telemetry_source_engine=TelemetrySourceEngine.UNIFIED_LOG_TRACEV3,
                source_vfs_file_id=source_vfs_file_id,
                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                device_locality="LOCAL_SEIZED_IPHONE",
                stream_or_subsystem_name=f"{subsystem}:{category}",
                event_category=cat,
                target_app_bundle_id=evt.get("target_app"),
                primary_state_or_value=state_str,
                unpacked_metadata_json=json.dumps(meta),
                start_utc_ns=ns_val,
                start_utc_iso=iso_val,
                forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
            )
            records.append(rec)

        return records
