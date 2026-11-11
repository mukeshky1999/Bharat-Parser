"""
Chromium and iOS WebKit Local Storage Decoders.
Adheres strictly to Specification Section 2 (Mistake 6) and Section 7.2.
"""

from typing import Union


def decode_chromium_localstorage_value(val_bytes: Union[bytes, bytearray]) -> str:
    """
    Decodes Chromium Local Storage byte values handling the mandatory 1-byte encoding prefix:
    - 0x00: UTF-16LE (used for unicode strings, e.g. currency symbols and Indic text).
    - 0x01: UTF-8 / Latin-1 (used for standard ASCII strings).
    """
    if not val_bytes:
        return ""

    raw = bytes(val_bytes)
    prefix = raw[0]
    payload = raw[1:]

    if prefix == 0x00:
        # UTF-16LE
        if len(payload) % 2 != 0:
            payload = payload[:-1]
        try:
            return payload.decode("utf-16le")
        except Exception:
            return payload.decode("utf-8", errors="replace")

    elif prefix == 0x01:
        # UTF-8 / Latin-1
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload.decode("latin-1", errors="replace")

    # Fallback if no 1-byte prefix was present
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("utf-16le")
        except Exception:
            return raw.decode("latin-1", errors="replace")


def decode_ios_localstorage_blob(blob: Union[bytes, bytearray]) -> str:
    """
    Decodes iOS WebKit *.localstorage ItemTable value BLOBs (stored in UTF-16LE).
    """
    if not blob:
        return ""

    raw = bytes(blob)
    try:
        return raw.decode("utf-16le")
    except Exception:
        return raw.decode("utf-8", errors="replace")
