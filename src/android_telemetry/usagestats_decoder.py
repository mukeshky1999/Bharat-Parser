"""
Sub-Engine 6.2A: Android UsageStats Binary Protobuf & XML Decoder.
Parses IntervalStatsProto across daily/, weekly/, monthly/, and yearly/ directories.
Resolves 1-based StringPool indices and computes relative time offsets from file_base_time_ms.
Complies with Section 3 of Phase 6 Module 6.2 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import ForensicGroup
from src.android_telemetry.models import (
    TelemetrySource,
    AndroidEventCategory,
    AndroidUsageEventRecord,
    unix_ms_to_utc_iso,
    unix_ms_to_utc_ns,
)

logger = logging.getLogger(__name__)


def _decode_varint(buffer: bytes, pos: int) -> Tuple[int, int]:
    """Decodes an unsigned LEB128 varint from buffer starting at pos. Returns (value, bytes_read)."""
    res = 0
    shift = 0
    start = pos
    buf_len = len(buffer)
    while pos < buf_len:
        b = buffer[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, pos - start
        shift += 7
        if shift >= 70:
            break
    return res, pos - start


class UsageStatsDecoder:
    """Decoder for Android UsageStats binary protobuf and XML files."""

    EVENT_TYPE_MAP: Dict[int, AndroidEventCategory] = {
        1: AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND,
        2: AndroidEventCategory.ACTIVITY_PAUSED_BACKGROUND,
        5: AndroidEventCategory.SCREEN_ROTATION_CONFIG,
        7: AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND,
        8: AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND,
        10: AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND,
        12: AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND,
        15: AndroidEventCategory.SCREEN_ON_INTERACTIVE,
        16: AndroidEventCategory.SCREEN_OFF_DARK,
        17: AndroidEventCategory.KEYGUARD_LOCKED,
        18: AndroidEventCategory.KEYGUARD_UNLOCKED,
        19: AndroidEventCategory.FOREGROUND_SERVICE_START,
        20: AndroidEventCategory.FOREGROUND_SERVICE_STOP,
        23: AndroidEventCategory.ACTIVITY_PAUSED_BACKGROUND,
        26: AndroidEventCategory.DEVICE_SHUTDOWN,
        27: AndroidEventCategory.DEVICE_STARTUP,
    }

    def decode_usagestats_file(
        self,
        file_path: str,
        android_user_profile_id: int = 0,
        source_vfs_file_id: int = 901,
        known_installed_packages: Optional[List[str]] = None,
    ) -> List[AndroidUsageEventRecord]:
        """Parses a UsageStats file (binary protobuf or XML) and returns normalized records."""
        records: List[AndroidUsageEventRecord] = []
        if not os.path.exists(file_path):
            return records

        p = Path(file_path)
        stem = p.stem
        try:
            file_base_time_ms = int(stem)
        except ValueError:
            file_base_time_ms = 0

        is_daily = "daily" in p.parts or "daily" in file_path.lower()
        granularity = "GRANULAR_MILLISECOND_EVENT" if is_daily else "AGGREGATED_INTERVAL_SUMMARY"
        source_enum = (
            TelemetrySource.USAGESTATS_DAILY_EVENTLOG
            if is_daily
            else TelemetrySource.USAGESTATS_AGGREGATE_ROLLUP
        )

        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return records

        # Check if plain text XML
        if data.lstrip().startswith(b"<"):
            return self._decode_xml(
                data,
                file_base_time_ms,
                android_user_profile_id,
                source_vfs_file_id,
                granularity,
                source_enum,
                known_installed_packages,
            )

        # Parse binary IntervalStatsProto
        return self._decode_interval_stats_proto(
            data,
            file_base_time_ms,
            android_user_profile_id,
            source_vfs_file_id,
            granularity,
            source_enum,
            known_installed_packages,
        )

    def _decode_interval_stats_proto(
        self,
        data: bytes,
        file_base_time_ms: int,
        android_user_profile_id: int,
        source_vfs_file_id: int,
        granularity: str,
        source_enum: TelemetrySource,
        known_installed_packages: Optional[List[str]],
    ) -> List[AndroidUsageEventRecord]:
        """Decodes raw binary IntervalStatsProto wire format."""
        records: List[AndroidUsageEventRecord] = []
        stringpool: List[str] = []
        event_protos: List[bytes] = []
        package_protos: List[bytes] = []

        pos = 0
        data_len = len(data)

        # Walk root message fields
        while pos < data_len:
            tag, tag_len = _decode_varint(data, pos)
            if tag_len <= 0:
                break
            pos += tag_len
            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 0:  # Varint
                val, v_len = _decode_varint(data, pos)
                pos += v_len
            elif wire_type == 1:  # 64-bit
                pos += 8
            elif wire_type == 2:  # Length-delimited
                length, l_len = _decode_varint(data, pos)
                pos += l_len
                sub_bytes = data[pos : pos + length]
                pos += length

                if field_num == 2:
                    # StringPool message: decode repeated string fields inside
                    stringpool = self._decode_stringpool(sub_bytes)
                elif field_num == 22:
                    # EventProto (in daily/ files)
                    event_protos.append(sub_bytes)
                elif field_num == 20:
                    # UsageStatsProto (packages)
                    package_protos.append(sub_bytes)
            elif wire_type == 5:  # 32-bit
                pos += 4
            else:
                break

        # Process granular events (from daily/ event_log)
        for ep_bytes in event_protos:
            ev_rec = self._parse_event_proto(
                ep_bytes,
                stringpool,
                file_base_time_ms,
                android_user_profile_id,
                source_vfs_file_id,
                granularity,
                source_enum,
                known_installed_packages,
            )
            if ev_rec:
                records.append(ev_rec)

        # Process package summaries (from weekly/monthly/yearly or daily package rollups)
        if not records and package_protos:
            for pkg_bytes in package_protos:
                pkg_rec = self._parse_package_proto(
                    pkg_bytes,
                    stringpool,
                    file_base_time_ms,
                    android_user_profile_id,
                    source_vfs_file_id,
                    granularity,
                    source_enum,
                    known_installed_packages,
                )
                if pkg_rec:
                    records.append(pkg_rec)

        return records

    def _decode_stringpool(self, sp_bytes: bytes) -> List[str]:
        """Decodes StringPool message containing repeated strings (Field 1 or Field 2)."""
        pool: List[str] = []
        pos = 0
        buf_len = len(sp_bytes)

        while pos < buf_len:
            tag, tag_len = _decode_varint(sp_bytes, pos)
            if tag_len <= 0:
                break
            pos += tag_len
            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 0:
                val, v_len = _decode_varint(sp_bytes, pos)
                pos += v_len
            elif wire_type == 1:
                pos += 8
            elif wire_type == 2:
                length, l_len = _decode_varint(sp_bytes, pos)
                pos += l_len
                s_bytes = sp_bytes[pos : pos + length]
                pos += length
                try:
                    s_text = s_bytes.decode("utf-8")
                    pool.append(s_text)
                except Exception:
                    pool.append(s_bytes.hex())
            elif wire_type == 5:
                pos += 4
            else:
                break

        return pool

    def _resolve_string(self, idx: Optional[int], direct_str: Optional[str], pool: List[str]) -> str:
        """Resolves 1-based stringpool index or direct string."""
        if direct_str:
            return direct_str
        if idx is not None and 1 <= idx <= len(pool):
            return pool[idx - 1]
        return "Unknown"

    def _parse_event_proto(
        self,
        ep_bytes: bytes,
        stringpool: List[str],
        file_base_time_ms: int,
        android_user_profile_id: int,
        source_vfs_file_id: int,
        granularity: str,
        source_enum: TelemetrySource,
        known_installed_packages: Optional[List[str]],
    ) -> Optional[AndroidUsageEventRecord]:
        """Parses individual EventProto message."""
        pos = 0
        buf_len = len(ep_bytes)

        package_index: Optional[int] = None
        class_index: Optional[int] = None
        package_str: Optional[str] = None
        class_str: Optional[str] = None
        time_offset_ms: int = 0
        event_type: int = 1

        while pos < buf_len:
            tag, tag_len = _decode_varint(ep_bytes, pos)
            if tag_len <= 0:
                break
            pos += tag_len
            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 0:  # Varint
                val, v_len = _decode_varint(ep_bytes, pos)
                pos += v_len
                if field_num == 1:
                    package_index = val
                elif field_num == 2:
                    class_index = val
                elif field_num == 3:
                    time_offset_ms = val
                elif field_num == 4:
                    event_type = val
            elif wire_type == 2:  # Length-delimited string
                length, l_len = _decode_varint(ep_bytes, pos)
                pos += l_len
                sub = ep_bytes[pos : pos + length]
                pos += length
                if field_num == 1:
                    package_str = sub.decode("utf-8", errors="replace")
                elif field_num == 2:
                    class_str = sub.decode("utf-8", errors="replace")
            elif wire_type == 1:
                pos += 8
            elif wire_type == 5:
                pos += 4
            else:
                break

        pkg_name = self._resolve_string(package_index, package_str, stringpool)
        cls_name = self._resolve_string(class_index, class_str, stringpool) if (class_index or class_str) else None

        # Compute absolute millisecond timestamp
        if time_offset_ms < 1_000_000_000_000:
            abs_time_ms = file_base_time_ms + time_offset_ms
        else:
            abs_time_ms = time_offset_ms

        time_ns = unix_ms_to_utc_ns(abs_time_ms)
        time_iso = unix_ms_to_utc_iso(abs_time_ms)

        category = self.EVENT_TYPE_MAP.get(event_type, AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND)

        is_ghost = 0
        if known_installed_packages is not None and pkg_name not in known_installed_packages:
            is_ghost = 1

        return AndroidUsageEventRecord(
            android_user_profile_id=android_user_profile_id,
            telemetry_source=source_enum,
            source_vfs_file_id=source_vfs_file_id,
            granularity_level=granularity,
            package_name=pkg_name,
            activity_or_service_class=cls_name,
            is_uninstalled_ghost_app=is_ghost,
            event_category=category,
            event_timestamp_utc_ns=time_ns,
            event_timestamp_utc_iso=time_iso,
            forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
        )

    def _parse_package_proto(
        self,
        pkg_bytes: bytes,
        stringpool: List[str],
        file_base_time_ms: int,
        android_user_profile_id: int,
        source_vfs_file_id: int,
        granularity: str,
        source_enum: TelemetrySource,
        known_installed_packages: Optional[List[str]],
    ) -> Optional[AndroidUsageEventRecord]:
        """Parses individual UsageStatsProto package summary message."""
        pos = 0
        buf_len = len(pkg_bytes)

        package_index: Optional[int] = None
        package_str: Optional[str] = None
        last_time_active_offset: int = 0
        total_time_active_ms: int = 0

        while pos < buf_len:
            tag, tag_len = _decode_varint(pkg_bytes, pos)
            if tag_len <= 0:
                break
            pos += tag_len
            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 0:
                val, v_len = _decode_varint(pkg_bytes, pos)
                pos += v_len
                if field_num == 1:
                    package_index = val
                elif field_num == 2:
                    last_time_active_offset = val
                elif field_num == 3:
                    total_time_active_ms = val
            elif wire_type == 2:
                length, l_len = _decode_varint(pkg_bytes, pos)
                pos += l_len
                sub = pkg_bytes[pos : pos + length]
                pos += length
                if field_num == 1:
                    package_str = sub.decode("utf-8", errors="replace")
            elif wire_type == 1:
                pos += 8
            elif wire_type == 5:
                pos += 4
            else:
                break

        pkg_name = self._resolve_string(package_index, package_str, stringpool)

        if last_time_active_offset < 1_000_000_000_000:
            abs_time_ms = file_base_time_ms + last_time_active_offset
        else:
            abs_time_ms = last_time_active_offset

        time_ns = unix_ms_to_utc_ns(abs_time_ms)
        time_iso = unix_ms_to_utc_iso(abs_time_ms)

        is_ghost = 0
        if known_installed_packages is not None and pkg_name not in known_installed_packages:
            is_ghost = 1

        duration_sec = round(total_time_active_ms / 1000.0, 3) if total_time_active_ms else None

        return AndroidUsageEventRecord(
            android_user_profile_id=android_user_profile_id,
            telemetry_source=source_enum,
            source_vfs_file_id=source_vfs_file_id,
            granularity_level=granularity,
            package_name=pkg_name,
            activity_or_service_class=None,
            is_uninstalled_ghost_app=is_ghost,
            event_category=AndroidEventCategory.AGGREGATED_USAGE_WINDOW,
            event_timestamp_utc_ns=time_ns,
            event_timestamp_utc_iso=time_iso,
            aggregated_fg_duration_sec=duration_sec,
            forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
        )

    def _decode_xml(
        self,
        xml_data: bytes,
        file_base_time_ms: int,
        android_user_profile_id: int,
        source_vfs_file_id: int,
        granularity: str,
        source_enum: TelemetrySource,
        known_installed_packages: Optional[List[str]],
    ) -> List[AndroidUsageEventRecord]:
        """Parses legacy XML UsageStats files."""
        records: List[AndroidUsageEventRecord] = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_data)

            for ev in root.findall(".//event"):
                pkg_name = ev.get("package", "Unknown")
                cls_name = ev.get("class")
                time_val = int(ev.get("time", 0))
                ev_type = int(ev.get("type", 1))

                if time_val < 1_000_000_000_000:
                    abs_time_ms = file_base_time_ms + time_val
                else:
                    abs_time_ms = time_val

                time_ns = unix_ms_to_utc_ns(abs_time_ms)
                time_iso = unix_ms_to_utc_iso(abs_time_ms)
                cat = self.EVENT_TYPE_MAP.get(ev_type, AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND)

                is_ghost = 1 if (known_installed_packages and pkg_name not in known_installed_packages) else 0

                records.append(
                    AndroidUsageEventRecord(
                        android_user_profile_id=android_user_profile_id,
                        telemetry_source=source_enum,
                        source_vfs_file_id=source_vfs_file_id,
                        granularity_level=granularity,
                        package_name=pkg_name,
                        activity_or_service_class=cls_name,
                        is_uninstalled_ghost_app=is_ghost,
                        event_category=cat,
                        event_timestamp_utc_ns=time_ns,
                        event_timestamp_utc_iso=time_iso,
                        forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
                    )
                )
        except Exception as exc:
            logger.debug("Failed parsing legacy XML UsageStats: %s", exc)

        return records
