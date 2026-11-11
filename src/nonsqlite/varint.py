"""
Little-Endian Base-128 Varint and ZigZag Encoders/Decoders.
Adheres strictly to Specification Section 3.2.
"""

from typing import Tuple


def decode_le_varint(buf: bytes, pos: int = 0) -> Tuple[int, int]:
    """
    Decodes an unsigned 64-bit Little-Endian Base-128 Varint from `buf` at `pos`.
    Returns `(value, bytes_consumed)`.
    """
    buf_len = len(buf)
    if pos >= buf_len:
        raise ValueError(f"Varint position {pos} out of range for buffer length {buf_len}")

    result = 0
    shift = 0
    limit = min(10, buf_len - pos)

    for i in range(limit):
        b = buf[pos + i]
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, i + 1
        shift += 7

    return result, limit


def encode_le_varint(val: int) -> bytes:
    """Encodes an unsigned integer into Little-Endian Base-128 Varint bytes."""
    if val < 0:
        val = (1 << 64) + val

    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val)
    return bytes(out)


def decode_zigzag_64(n: int) -> int:
    """Decodes an unsigned integer into a signed 64-bit integer using ZigZag decoding."""
    return (n >> 1) ^ (-(n & 1))


def encode_zigzag_64(n: int) -> int:
    """Encodes a signed 64-bit integer into an unsigned integer using ZigZag encoding."""
    return (n << 1) ^ (n >> 63)
