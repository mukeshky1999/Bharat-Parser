"""
Apple Biome SEGB v1 and v2 Binary Stream Decoder.
Adheres strictly to Specification Section 5 (Sub-Engine 2.3C) and AGENTS.md Forensic Invariants.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional

from src.core.enums import ResidualConfidence
from src.nonsqlite.models import BiomeSEGBRecord, SEGBVersion
from src.nonsqlite.protobuf import decode_raw_protobuf


def _extract_event_utc(d: Any) -> Optional[str]:
    """Recursively searches a decoded dictionary for inferred UTC timestamps."""
    if isinstance(d, dict):
        for k in ("_inferred_cocoa_utc", "_inferred_unix_utc"):
            if k in d:
                return str(d[k])
        for v in d.values():
            res = _extract_event_utc(v)
            if res is not None:
                return res
    elif isinstance(d, list):
        for item in d:
            res = _extract_event_utc(item)
            if res is not None:
                return res
    return None


class SEGBDecoder:
    """
    Decodes Apple Biome SEGB (v1 & v2) binary telemetry streams.
    Handles forward record iteration (v1) and reverse trailer walk from EOF (v2),
    recovering active, intact deleted, and zeroed payload records with surviving Cocoa timestamps.
    """

    def decode_segb_file(
        self,
        file_path: Path | str,
        stream_name: str = "Unknown",
        device_locality: Optional[str] = None,
        kv_store_id: int = 1,
    ) -> List[BiomeSEGBRecord]:
        """
        Reads a SEGB file from disk and parses all contained records.
        """
        p = Path(file_path)
        with open(p, "rb") as f:
            data = f.read()

        # Infer stream name from parent folder structure if not provided
        if stream_name == "Unknown":
            parts = p.parts
            if len(parts) >= 2:
                # e.g., .../App.InFocus/local/0000000000000001
                if parts[-2] in ("local", "public", "restricted"):
                    stream_name = parts[-3] if len(parts) >= 3 else parts[-2]
                else:
                    stream_name = parts[-2]

        # Infer device locality (LOCAL_DEVICE vs REMOTE_SYNCED_DEVICE:<UUID>)
        if device_locality is None:
            path_str = str(p).replace("\\", "/")
            if "/remote/" in path_str:
                remote_part = path_str.split("/remote/", 1)[1]
                uuid_segment = remote_part.split("/", 1)[0]
                device_locality = f"REMOTE_SYNCED_DEVICE:{uuid_segment}"
            else:
                device_locality = "LOCAL_DEVICE"

        return self.decode_segb_bytes(
            data=data,
            stream_name=stream_name,
            device_locality=device_locality,
            kv_store_id=kv_store_id,
        )

    def decode_segb_bytes(
        self,
        data: bytes,
        stream_name: str = "Unknown",
        device_locality: str = "LOCAL_DEVICE",
        kv_store_id: int = 1,
    ) -> List[BiomeSEGBRecord]:
        """
        Parses raw SEGB bytes, auto-detecting v1 (iOS 14-16) vs v2 (iOS 17-26).
        """
        if len(data) < 32:
            return []

        # Version detection:
        # SEGB v2: Bytes 0..3 == b"SEGB"
        # SEGB v1: Bytes 52..56 == b"SEGB"
        if data[:4] == b"SEGB":
            return self._decode_segb_v2(
                data=data,
                stream_name=stream_name,
                device_locality=device_locality,
                kv_store_id=kv_store_id,
            )
        elif len(data) >= 56 and data[52:56] == b"SEGB":
            return self._decode_segb_v1(
                data=data,
                stream_name=stream_name,
                device_locality=device_locality,
                kv_store_id=kv_store_id,
            )

        return []

    def _decode_segb_v2(
        self,
        data: bytes,
        stream_name: str,
        device_locality: str,
        kv_store_id: int,
    ) -> List[BiomeSEGBRecord]:
        """
        Decodes iOS 17-26 SEGB v2 stream:
        Payloads written forward from offset 32; 16-byte trailers written backward from EOF.
        """
        file_size = len(data)
        trailer_pos = file_size - 16
        previous_record_end_rel = 0
        records: List[BiomeSEGBRecord] = []

        while trailer_pos >= 32:
            try:
                record_end_rel, record_state, cocoa_ts = struct.unpack_from(
                    "<IId", data, trailer_pos
                )
            except Exception:
                break

            # Boundary Stop Conditions:
            # 1. State must be in (1=Written, 3=Deleted, 4=Pruned)
            # 2. record_end_rel >= previous_record_end_rel
            # 3. 32 + record_end_rel <= trailer_pos
            # 4. Cocoa timestamp within valid range 2013-2039 (~400M to 1.2B)
            if record_state not in (1, 3, 4):
                break
            if record_end_rel < previous_record_end_rel:
                break
            if 32 + record_end_rel > trailer_pos:
                break
            if not (400000000.0 <= cocoa_ts <= 1200000000.0):
                break

            payload_start_abs = 32 + previous_record_end_rel
            payload_end_abs = 32 + record_end_rel

            if payload_start_abs > payload_end_abs or payload_end_abs > file_size:
                break

            raw_payload = data[payload_start_abs:payload_end_abs]

            # Convert Apple Cocoa timestamp to UTC ISO-8601 (Unix = Cocoa + 978307200)
            unix_ts = cocoa_ts + 978307200.0
            dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
            write_utc_iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            # Check if payload was zeroed out (state 3/4 deletion zeroing)
            is_zeroed = (len(raw_payload) == 0) or all(b == 0 for b in raw_payload)

            if is_zeroed:
                # PARTIAL_RECORD: Zeroed SEGB Payload — Write Timestamp Survived
                rec = BiomeSEGBRecord(
                    kv_store_id=kv_store_id,
                    biome_stream_name=stream_name,
                    segb_version=SEGBVersion.SEGB_V2.value,
                    device_locality=device_locality,
                    segb_record_state=record_state,
                    recovery_classification=ResidualConfidence.PARTIAL_RECORD,
                    segb_write_cocoa_raw=cocoa_ts,
                    segb_write_utc_iso=write_utc_iso,
                    payload_event_utc_iso=None,
                    decoded_protobuf_json=None,
                    payload_byte_offset=payload_start_abs,
                )
            else:
                pb_dict, is_valid_pb = decode_raw_protobuf(raw_payload)
                pb_json = json.dumps(pb_dict, indent=2) if is_valid_pb else raw_payload.hex()
                event_utc = _extract_event_utc(pb_dict) if is_valid_pb else None

                if record_state == 1:
                    classification = ResidualConfidence.ORIGINAL_RECORD
                else:
                    classification = ResidualConfidence.RESIDUAL_RECORD

                rec = BiomeSEGBRecord(
                    kv_store_id=kv_store_id,
                    biome_stream_name=stream_name,
                    segb_version=SEGBVersion.SEGB_V2.value,
                    device_locality=device_locality,
                    segb_record_state=record_state,
                    recovery_classification=classification,
                    segb_write_cocoa_raw=cocoa_ts,
                    segb_write_utc_iso=write_utc_iso,
                    payload_event_utc_iso=event_utc or write_utc_iso,
                    decoded_protobuf_json=pb_json,
                    payload_byte_offset=payload_start_abs,
                )

            records.append(rec)
            previous_record_end_rel = (record_end_rel + 3) & ~3
            trailer_pos -= 16

        return records

    def _decode_segb_v1(
        self,
        data: bytes,
        stream_name: str,
        device_locality: str,
        kv_store_id: int,
    ) -> List[BiomeSEGBRecord]:
        """
        Decodes iOS 14-16 SEGB v1 stream:
        64-byte file header, followed by forward record loop (32-byte header + 8-byte aligned payload).
        """
        file_size = len(data)
        pos = 64
        records: List[BiomeSEGBRecord] = []

        while pos + 32 <= file_size:
            try:
                payload_len, record_state = struct.unpack_from("<II", data, pos)
                cocoa_ts1, cocoa_ts2 = struct.unpack_from("<dd", data, pos + 8)
            except Exception:
                break

            if payload_len == 0:
                if all(b == 0 for b in data[pos:]):
                    break
                pos += 32
                continue

            payload_start_abs = pos + 32
            payload_end_abs = payload_start_abs + payload_len

            if payload_end_abs > file_size:
                break

            raw_payload = data[payload_start_abs:payload_end_abs]

            # Convert Cocoa timestamp to UTC ISO-8601
            unix_ts = cocoa_ts1 + 978307200.0
            dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
            write_utc_iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            is_zeroed = (len(raw_payload) == 0) or all(b == 0 for b in raw_payload)

            if is_zeroed:
                rec = BiomeSEGBRecord(
                    kv_store_id=kv_store_id,
                    biome_stream_name=stream_name,
                    segb_version=SEGBVersion.SEGB_V1.value,
                    device_locality=device_locality,
                    segb_record_state=record_state,
                    recovery_classification=ResidualConfidence.PARTIAL_RECORD,
                    segb_write_cocoa_raw=cocoa_ts1,
                    segb_write_utc_iso=write_utc_iso,
                    payload_event_utc_iso=None,
                    decoded_protobuf_json=None,
                    payload_byte_offset=payload_start_abs,
                )
            else:
                pb_dict, is_valid_pb = decode_raw_protobuf(raw_payload)
                pb_json = json.dumps(pb_dict, indent=2) if is_valid_pb else raw_payload.hex()
                event_utc = _extract_event_utc(pb_dict) if is_valid_pb else None

                if record_state == 1:
                    classification = ResidualConfidence.ORIGINAL_RECORD
                else:
                    classification = ResidualConfidence.RESIDUAL_RECORD

                rec = BiomeSEGBRecord(
                    kv_store_id=kv_store_id,
                    biome_stream_name=stream_name,
                    segb_version=SEGBVersion.SEGB_V1.value,
                    device_locality=device_locality,
                    segb_record_state=record_state,
                    recovery_classification=classification,
                    segb_write_cocoa_raw=cocoa_ts1,
                    segb_write_utc_iso=write_utc_iso,
                    payload_event_utc_iso=event_utc or write_utc_iso,
                    decoded_protobuf_json=pb_json,
                    payload_byte_offset=payload_start_abs,
                )

            records.append(rec)
            padded_len = ((payload_len + 7) // 8) * 8
            pos = pos + 32 + padded_len

        return records
