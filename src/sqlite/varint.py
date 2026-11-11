"""
SQLite 9-Byte Varint Encoder and Decoder.
Adheres strictly to Specification Section 5.1 and Section 2 Mistake 3.
"""

from typing import Tuple


def decode_varint(buf: bytes, pos: int = 0) -> Tuple[int, int]:
    """
    Decodes a SQLite variable-length integer (varint) starting at offset `pos`.

    SQLite varints are between 1 and 9 bytes long:
    - Bytes 1 through 8 contribute 7 bits each (b & 0x7F).
    - The 9th byte contributes all 8 bits (b & 0xFF) and has no continuation bit.
    - Values are interpreted as 64-bit signed integers.
    """
    buf_len = len(buf)
    if pos < 0 or pos >= buf_len:
        raise ValueError(f"Varint decode offset {pos} exceeds buffer length {buf_len}")

    result = 0
    # Process up to the first 8 bytes
    limit = min(8, buf_len - pos)
    for i in range(limit):
        b = buf[pos + i]
        result = (result << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            # Reached end of varint within bytes 1-8
            if result >= (1 << 63):
                return result - (1 << 64), i + 1
            return result, i + 1

    # If 8 bytes had MSB=1, check if 9th byte exists
    if buf_len - pos > 8:
        b = buf[pos + 8]
        # 9th byte contributes all 8 bits
        result = (result << 8) | (b & 0xFF)
        if result >= (1 << 63):
            return result - (1 << 64), 9
        return result, 9

    # Truncated varint at end of buffer
    if result >= (1 << 63):
        return result - (1 << 64), limit
    return result, limit


def encode_varint(val: int) -> bytes:
    """
    Encodes a 64-bit signed integer into SQLite variable-length integer format.
    """
    # Convert negative integer to 64-bit unsigned representation
    if val < 0:
        val = (1 << 64) + val

    if val <= 0x7F:
        return bytes([val])

    # Values that fit within 1-8 bytes (up to 56 bits)
    # Collect 7-bit groups from least significant to most significant
    parts = []
    if val > 0x00FFFFFFFFFFFFFF:
        # Requires 9 bytes: the lowest 8 bits go into the 9th byte
        parts.append(val & 0xFF)
        val >>= 8
        while val > 0 or len(parts) < 9:
            parts.append((val & 0x7F) | 0x80)
            val >>= 7
        parts.reverse()
        return bytes(parts)

    # 2 to 8 bytes
    parts.append(val & 0x7F)
    val >>= 7
    while val > 0:
        parts.append((val & 0x7F) | 0x80)
        val >>= 7
    parts.reverse()
    return bytes(parts)
