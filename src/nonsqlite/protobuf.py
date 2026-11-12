"""
Schema-Less Raw Wire-Format Protocol Buffers Decoder.
Adheres strictly to Specification Section 6 (Sub-Engine 2.3D).
"""

import json
import struct
from typing import Any, Dict, Tuple

from src.core.timestamps import ForensicTimestamp
from src.nonsqlite.varint import decode_le_varint, decode_zigzag_64


MAX_NESTING_DEPTH = 24


def decode_raw_protobuf(pb_buf: bytes, _depth: int = 0) -> Tuple[Dict[str, Any], bool]:
    """
    Recursively decodes a raw Protocol Buffers byte slice without .proto schema definitions.
    Returns `(decoded_dict, is_valid_protobuf)`.
    """
    if not pb_buf:
        return {}, True
    if _depth > MAX_NESTING_DEPTH:  # hostile or random data nests without end: stop instead of recursing to a crash
        return {}, False

    pos = 0
    buf_len = len(pb_buf)
    fields_dict: Dict[str, Any] = {}

    while pos < buf_len:
        try:
            tag, tag_len = decode_le_varint(pb_buf, pos)
        except Exception:
            return {}, False

        if tag_len <= 0:
            return {}, False

        pos += tag_len
        field_number = tag >> 3
        wire_type = tag & 0x07

        # Strict Protobuf sanity filter:
        # If field_number == 0 and we already decoded fields and all remaining bytes are 0x00:
        # This is trailing alignment padding, not a corrupted field.
        if field_number == 0:
            if len(fields_dict) > 0 and all(b == 0 for b in pb_buf[pos - tag_len:]):
                break
            return {}, False

        # Field number must be > 0 and <= 500,000; wire_type in (0, 1, 2, 5)
        if field_number > 500000 or wire_type not in (0, 1, 2, 5):
            return {}, False

        field_key = f"field_{field_number}"

        # ----------------------------------------------------------------------
        # Wire Type 0: Varint (bool, int32, int64, uint32, uint64, sint32, sint64)
        # ----------------------------------------------------------------------
        if wire_type == 0:
            try:
                val, val_len = decode_le_varint(pb_buf, pos)
            except Exception:
                return {}, False
            pos += val_len

            field_info: Dict[str, Any] = {
                "wire_type": 0,
                "value": val,
                "zigzag_signed": decode_zigzag_64(val),
            }

            # Check if value matches Unix timestamp range (2001 - 2049)
            if 1000000000 <= val <= 2500000000:
                try:
                    ft = ForensicTimestamp.from_unix_seconds(val)
                    field_info["_inferred_unix_utc"] = ft.utc_iso8601
                except Exception as ex_ts:
                    field_info["_ts_err"] = str(ex_ts)
            elif 1000000000000 <= val <= 2500000000000:
                try:
                    ft = ForensicTimestamp.from_unix_milliseconds(val)
                    field_info["_inferred_unix_utc"] = ft.utc_iso8601
                except Exception as ex_ts:
                    field_info["_ts_err"] = str(ex_ts)

            fields_dict[field_key] = field_info

        # ----------------------------------------------------------------------
        # Wire Type 1: 64-Bit Fixed (fixed64, sfixed64, double)
        # ----------------------------------------------------------------------
        elif wire_type == 1:
            if pos + 8 > buf_len:
                return {}, False

            u64 = struct.unpack("<Q", pb_buf[pos:pos + 8])[0]
            f64 = struct.unpack("<d", pb_buf[pos:pos + 8])[0]
            pos += 8

            field_info = {
                "wire_type": 1,
                "uint64": u64,
                "float64": f64,
            }

            # Automatic Cocoa / Unix float timestamp check
            # Apple Cocoa timestamp (seconds since 2001): 400M to 1.2B (2013-2039)
            if 400000000.0 <= f64 <= 1200000000.0:
                try:
                    ft = ForensicTimestamp.from_cocoa_seconds(f64)
                    field_info["_inferred_cocoa_utc"] = ft.utc_iso8601
                except Exception as ex_cocoa:
                    field_info["_ts_err"] = str(ex_cocoa)
            # POSIX Unix timestamp float: 1.4B to 2.5B (2014-2049)
            elif 1400000000.0 <= f64 <= 2500000000.0:
                try:
                    ft = ForensicTimestamp.from_unix_seconds(f64)
                    field_info["_inferred_unix_utc"] = ft.utc_iso8601
                except Exception as ex_unix:
                    field_info["_ts_err"] = str(ex_unix)

            fields_dict[field_key] = field_info

        # ----------------------------------------------------------------------
        # Wire Type 2: Length-Delimited (string, bytes, embedded messages)
        # ----------------------------------------------------------------------
        elif wire_type == 2:
            try:
                sub_len, sub_len_bytes = decode_le_varint(pb_buf, pos)
            except Exception:
                return {}, False
            pos += sub_len_bytes

            if pos + sub_len > buf_len:
                return {}, False

            sub_slice = pb_buf[pos:pos + sub_len]
            pos += sub_len

            field_info = {"wire_type": 2}

            # 3-Way Disambiguation Cascade:
            # Check 1: Nested Protobuf Object?
            if sub_len > 0:
                nested_dict, is_nested_valid = decode_raw_protobuf(sub_slice, _depth + 1)
                if is_nested_valid and len(nested_dict) > 0:
                    field_info["nested_object"] = nested_dict
                    # Printable text can also parse as a message by chance: keep both readings, do not choose silently.
                    try:
                        as_text = sub_slice.decode("utf-8")
                        if as_text and sum(1 for c in as_text if c.isprintable() or c in "\r\n\t") / len(as_text) >= 0.90:
                            field_info["value"] = as_text
                            field_info["ambiguous_text_or_message"] = True
                    except UnicodeDecodeError:
                        field_info["text_reading"] = "not valid UTF-8"
                    fields_dict[field_key] = field_info
                    continue

            # Check 2: Printable UTF-8 string?
            try:
                text_str = sub_slice.decode("utf-8")
                printable_count = sum(1 for c in text_str if c.isprintable() or c in "\r\n\t")
                if len(text_str) > 0 and (printable_count / len(text_str)) >= 0.90:
                    field_info["value"] = text_str
                    fields_dict[field_key] = field_info
                    continue
            except Exception:
                text_str = None

            # Check 3: Raw Byte Array
            field_info["value_hex"] = sub_slice.hex()
            fields_dict[field_key] = field_info

        # ----------------------------------------------------------------------
        # Wire Type 5: 32-Bit Fixed (fixed32, sfixed32, float)
        # ----------------------------------------------------------------------
        elif wire_type == 5:
            if pos + 4 > buf_len:
                return {}, False

            u32 = struct.unpack("<I", pb_buf[pos:pos + 4])[0]
            f32 = struct.unpack("<f", pb_buf[pos:pos + 4])[0]
            pos += 4

            fields_dict[field_key] = {
                "wire_type": 5,
                "uint32": u32,
                "float32": f32,
            }

    return fields_dict, True
