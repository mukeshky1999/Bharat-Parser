"""
Sub-Engine 6.1E: APFS File System Events (/.fseventsd/) Binary 1SLG/2SLG Parser & Timestamp Bracketing.
Decompresses gzipped 1SLG/2SLG pages, parses 32-bit flags and 64-bit node IDs,
and executes monotonic event_id timestamp bracketing for deleted files.
Complies with Section 7 of Phase 6 Module 6.1 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import gzip
import logging
import os
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.ios_telemetry.models import (
    IOSFSEventRecord,
    decode_fsevent_flags,
)

logger = logging.getLogger(__name__)


class FSEventsDecoder:
    """Decoder for APFS FSEvents binary records (1SLG and 2SLG)."""

    def decode_fsevents_file(
        self,
        gz_path: str,
        existing_file_anchors: Optional[Dict[str, Dict[str, Any]]] = None,
        source_vfs_file_id: int = 805,
    ) -> List[IOSFSEventRecord]:
        """Parses a gzipped /.fseventsd/ file and computes monotonic timestamp bracketing windows."""
        if existing_file_anchors is None:
            existing_file_anchors = {}

        file_name = Path(gz_path).name
        raw_events: List[Dict[str, Any]] = []

        if not os.path.exists(gz_path):
            return []

        # Get container mtime as fallback bracket
        try:
            mtime_sec = os.path.getmtime(gz_path)
            dt_mtime = datetime.fromtimestamp(mtime_sec, tz=timezone.utc)
            container_mtime_iso = dt_mtime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except Exception:
            container_mtime_iso = "1970-01-01T00:00:00.000000Z"

        # Decompress gzip stream
        try:
            with gzip.open(gz_path, "rb") as f_gz:
                data = f_gz.read()
        except Exception as exc:
            logger.debug("Failed decompressing FSEvents gzip %s: %s", gz_path, exc)
            return []

        offset = 0
        data_len = len(data)

        while offset + 12 <= data_len:
            magic = data[offset : offset + 4]
            if magic not in (b"1SLG", b"2SLG"):
                next_slg = data.find(b"SLG", offset + 1)
                if next_slg > 0 and data[next_slg - 1 : next_slg + 3] in (b"1SLG", b"2SLG"):
                    offset = next_slg - 1
                    continue
                break

            format_version = magic.decode("ascii", errors="replace")
            version, page_size = struct.unpack("<II", data[offset + 4 : offset + 12])

            if page_size < 12 or offset + page_size > data_len:
                page_data = data[offset:]
                page_len = len(page_data)
            else:
                page_data = data[offset : offset + page_size]
                page_len = page_size

            p_pos = 12
            while p_pos < page_len:
                null_pos = page_data.find(b"\x00", p_pos)
                if null_pos == -1:
                    break

                path_bytes = page_data[p_pos:null_pos]
                target_path = path_bytes.decode("utf-8", errors="replace")
                p_pos = null_pos + 1

                if magic == b"2SLG":
                    if p_pos + 20 > page_len:
                        break
                    event_id, flags, node_id = struct.unpack("<QIQ", page_data[p_pos : p_pos + 20])
                    p_pos += 20
                else:
                    if p_pos + 12 > page_len:
                        break
                    event_id, flags = struct.unpack("<QI", page_data[p_pos : p_pos + 12])
                    node_id = None
                    p_pos += 12

                flags_str = decode_fsevent_flags(flags)
                is_removed = bool(flags & 0x00000002)

                exists = 0
                anchor_time = None
                if target_path in existing_file_anchors and not is_removed:
                    info = existing_file_anchors[target_path]
                    if info.get("exists", 0) == 1:
                        exists = 1
                        anchor_time = info.get("btime_iso")

                raw_events.append({
                    "format_version": format_version,
                    "event_id": event_id,
                    "path": target_path,
                    "node_id": node_id,
                    "flags": flags,
                    "flags_str": flags_str,
                    "exists": exists,
                    "anchor_time": anchor_time,
                })

            offset += page_len

        # Sort all raw events chronologically by monotonic event_id
        raw_events.sort(key=lambda x: x["event_id"])

        # Execute Monotonic Timestamp Bracketing
        records: List[IOSFSEventRecord] = []
        n_events = len(raw_events)

        for i, ev in enumerate(raw_events):
            event_id = ev["event_id"]
            target_path = ev["path"]
            node_id = ev["node_id"]
            flags_str = ev["flags_str"]
            exists = ev["exists"]
            anchor_time = ev["anchor_time"]

            if exists == 1 and anchor_time:
                earliest_iso = anchor_time
                latest_iso = anchor_time
            else:
                # Search backward for nearest preceding anchored event
                earliest_iso = None
                for prev_i in range(i - 1, -1, -1):
                    prev_ev = raw_events[prev_i]
                    if prev_ev["anchor_time"] is not None:
                        earliest_iso = prev_ev["anchor_time"]
                        break

                # Search forward for nearest succeeding anchored event
                latest_iso = None
                for next_i in range(i + 1, n_events):
                    next_ev = raw_events[next_i]
                    if next_ev["anchor_time"] is not None:
                        latest_iso = next_ev["anchor_time"]
                        break

                if latest_iso is None:
                    latest_iso = container_mtime_iso

            rec = IOSFSEventRecord(
                gzip_source_file_name=file_name,
                fsevent_format_version=ev["format_version"],
                monotonic_event_id=event_id,
                target_file_path=target_path,
                apfs_inode_node_id=node_id,
                decoded_flags_list=flags_str,
                does_file_still_exist=exists,
                bracket_earliest_utc_iso=earliest_iso,
                bracket_latest_utc_iso=latest_iso,
                forensic_group=ForensicGroup.G15_OS_BEHAVIORAL_TELEMETRY,
            )
            records.append(rec)

        return records
