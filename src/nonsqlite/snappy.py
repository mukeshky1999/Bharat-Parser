"""
Pure-Python Google Snappy Block Decompressor.
Adheres strictly to LevelDB Snappy Framing (Specification Section 4.3).
100% offline, native execution with zero external dependencies.
"""

import struct


def snappy_decompress(data: bytes) -> bytes:
    """
    Decompresses raw Google Snappy compressed bytes without frame headers.
    """
    if not data:
        return b""

    pos = 0
    data_len = len(data)

    # 1. Read Little-Endian Varint uncompressed length
    uncompressed_len = 0
    shift = 0
    while pos < data_len:
        b = data[pos]
        pos += 1
        uncompressed_len |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7

    out = bytearray()

    # 2. Process element tags
    while pos < data_len and len(out) < uncompressed_len:
        b = data[pos]
        pos += 1
        tag = b & 0x03

        if tag == 0:
            # Literal
            length_tag = (b >> 2) & 0x3F
            if length_tag < 60:
                length = length_tag + 1
            elif length_tag == 60:
                if pos >= data_len:
                    break
                length = data[pos] + 1
                pos += 1
            elif length_tag == 61:
                if pos + 2 > data_len:
                    break
                length = struct.unpack("<H", data[pos:pos + 2])[0] + 1
                pos += 2
            elif length_tag == 62:
                if pos + 3 > data_len:
                    break
                length = struct.unpack("<I", data[pos:pos + 3] + b"\x00")[0] + 1
                pos += 3
            else:  # 63
                if pos + 4 > data_len:
                    break
                length = struct.unpack("<I", data[pos:pos + 4])[0] + 1
                pos += 4

            chunk = data[pos:pos + length]
            out.extend(chunk)
            pos += length

        elif tag == 1:
            # Copy with 1-byte offset
            length = ((b >> 2) & 0x07) + 4
            offset_hi = (b >> 5) & 0x07
            if pos >= data_len:
                break
            offset_lo = data[pos]
            pos += 1
            offset = (offset_hi << 8) | offset_lo

            if offset == 0 or offset > len(out):
                raise ValueError('Snappy copy offset outside decoded data')
            for _ in range(length):
                out.append(out[len(out) - offset])

        elif tag == 2:
            # Copy with 2-byte offset
            length = (b >> 2) + 1
            if pos + 2 > data_len:
                break
            offset = struct.unpack("<H", data[pos:pos + 2])[0]
            pos += 2

            if offset == 0 or offset > len(out):
                raise ValueError('Snappy copy offset outside decoded data')
            for _ in range(length):
                out.append(out[len(out) - offset])

        else:
            # Copy with 4-byte offset
            length = (b >> 2) + 1
            if pos + 4 > data_len:
                break
            offset = struct.unpack("<I", data[pos:pos + 4])[0]
            pos += 4

            if offset == 0 or offset > len(out):
                raise ValueError('Snappy copy offset outside decoded data')
            for _ in range(length):
                out.append(out[len(out) - offset])

    if len(out) != uncompressed_len:
        # Corrupt or truncated stream: do not hand back a short buffer as if it were the whole block (review R-16).
        raise ValueError(f"Snappy output {len(out)} bytes, header declared {uncompressed_len}")
    return bytes(out)


# Alias
snappy_decompress_raw = snappy_decompress
