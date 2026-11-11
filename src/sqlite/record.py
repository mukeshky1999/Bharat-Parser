"""
SQLite Record Header and Serial-Type Decoder.
Adheres strictly to Specification Section 5.3.
"""

import struct
from typing import Any, List, Tuple

from src.sqlite.varint import decode_varint


def decode_serial_type(
    serial_type: int,
    data: bytes,
    offset: int,
    text_encoding: str = "UTF-8"
) -> Tuple[Any, int]:
    """
    Decodes a single column value from `data` at `offset` according to SQLite `serial_type`.
    Returns `(decoded_value, bytes_consumed)`.
    """
    if serial_type == 0:
        return None, 0
    elif serial_type == 1:
        # 1-byte signed integer
        if offset >= len(data):
            return 0, 0
        val = struct.unpack(">b", data[offset:offset + 1])[0]
        return val, 1
    elif serial_type == 2:
        # 2-byte big-endian signed integer
        if offset + 2 > len(data):
            return 0, 0
        val = struct.unpack(">h", data[offset:offset + 2])[0]
        return val, 2
    elif serial_type == 3:
        # 3-byte big-endian signed integer (sign-extend bit 23)
        if offset + 3 > len(data):
            return 0, 0
        raw = struct.unpack(">I", b"\x00" + data[offset:offset + 3])[0]
        if raw & 0x800000:
            raw -= 0x1000000
        return raw, 3
    elif serial_type == 4:
        # 4-byte big-endian signed integer
        if offset + 4 > len(data):
            return 0, 0
        val = struct.unpack(">i", data[offset:offset + 4])[0]
        return val, 4
    elif serial_type == 5:
        # 6-byte big-endian signed integer (sign-extend bit 47)
        if offset + 6 > len(data):
            return 0, 0
        raw = struct.unpack(">Q", b"\x00\x00" + data[offset:offset + 6])[0]
        if raw & 0x800000000000:
            raw -= 0x1000000000000
        return raw, 6
    elif serial_type == 6:
        # 8-byte big-endian signed integer
        if offset + 8 > len(data):
            return 0, 0
        val = struct.unpack(">q", data[offset:offset + 8])[0]
        return val, 8
    elif serial_type == 7:
        # 8-byte IEEE 754 floating point
        if offset + 8 > len(data):
            return 0.0, 0
        val = struct.unpack(">d", data[offset:offset + 8])[0]
        return val, 8
    elif serial_type == 8:
        # Integer constant 0
        return 0, 0
    elif serial_type == 9:
        # Integer constant 1
        return 1, 0
    elif serial_type in (10, 11):
        # Reserved for internal use
        return None, 0
    elif serial_type >= 12 and (serial_type % 2 == 0):
        # BLOB of length (serial_type - 12) // 2
        length = (serial_type - 12) // 2
        slice_end = min(offset + length, len(data))
        return data[offset:slice_end], length
    elif serial_type >= 13 and (serial_type % 2 == 1):
        # TEXT of length (serial_type - 13) // 2
        length = (serial_type - 13) // 2
        slice_end = min(offset + length, len(data))
        raw_text = data[offset:slice_end]
        py_encoding = "utf-8"
        if text_encoding.upper() == "UTF-16LE":
            py_encoding = "utf-16le"
        elif text_encoding.upper() == "UTF-16BE":
            py_encoding = "utf-16be"
        try:
            val = raw_text.decode(py_encoding, errors="replace")
        except Exception:
            val = raw_text.decode("utf-8", errors="replace")
        return val, length
    return None, 0


def extract_serial_types(payload: bytes, pos: int = 0) -> Tuple[int, List[int]]:
    """
    Parses the record header from payload at `pos`.
    Returns `(header_size, serial_types_list)`.
    """
    if pos >= len(payload):
        return 0, []

    header_size, varint_len = decode_varint(payload, pos)
    if header_size <= 0 or header_size > len(payload) - pos:
        return 0, []

    serial_types = []
    cursor = pos + varint_len
    header_end = pos + header_size

    while cursor < header_end:
        st, st_len = decode_varint(payload, cursor)
        if st_len <= 0:
            break
        serial_types.append(st)
        cursor += st_len

    return header_size, serial_types


def decode_record(
    payload: bytes,
    text_encoding: str = "UTF-8",
    pos: int = 0
) -> List[Any]:
    """
    Decodes an entire SQLite record payload into a list of column values.
    """
    header_size, serial_types = extract_serial_types(payload, pos)
    if header_size == 0:
        return []

    values = []
    data_cursor = pos + header_size
    data_len = len(payload)

    for st in serial_types:
        val, consumed = decode_serial_type(st, payload, data_cursor, text_encoding)
        values.append(val)
        data_cursor += consumed
        if data_cursor > data_len:
            break

    return values
