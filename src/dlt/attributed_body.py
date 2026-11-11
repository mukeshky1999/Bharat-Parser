"""
Sub-Engine 3.4A: iOS attributedBody typedstream Unpacker.
Extracts clean UTF-8 message text from iOS 16–26 sms.db message.attributedBody BLOBs
when the message.text column is NULL or empty.
Adheres strictly to AGENTS.md Forensic Invariants and Section 3.2 of Module 3.4 Spec.
"""

import struct
from typing import Optional


class IOSAttributedBodyUnpacker:
    """Unpacks Apple NSArchiver / typedstream NSAttributedString blobs without macOS dependencies."""

    NSSTRING_MARKER = b"NSString"
    TYPEDSTREAM_CLASS_SEQ = b"\x01\x94\x84\x01\x2b"

    def unpack(self, raw_bytes: Optional[bytes]) -> Optional[str]:
        """
        Locates the NSString byte token and extracts the length-prefixed UTF-8 text.
        """
        if not raw_bytes or len(raw_bytes) < 16:
            return None

        # Step 1: Locate ASCII byte sequence "NSString"
        pos = raw_bytes.find(self.NSSTRING_MARKER)
        if pos == -1:
            return None

        # Step 2: Advance past NSString and marker sequence
        after_nsstring = pos + len(self.NSSTRING_MARKER)
        marker_pos = raw_bytes.find(self.TYPEDSTREAM_CLASS_SEQ, after_nsstring)

        if marker_pos != -1:
            len_offset = marker_pos + len(self.TYPEDSTREAM_CLASS_SEQ)
        else:
            # Fallback: scan for 0x2B UTF-8 string indicator
            plus_pos = raw_bytes.find(b"\x2b", after_nsstring)
            if plus_pos != -1 and plus_pos + 1 < len(raw_bytes):
                len_offset = plus_pos + 1
            else:
                len_offset = after_nsstring + 5

        if len_offset >= len(raw_bytes):
            return None

        # Step 3: Read string byte length L
        length_indicator = raw_bytes[len_offset]
        text_start = len_offset + 1
        text_len = 0

        if length_indicator < 0x80:
            # Single-byte length (1 to 127)
            text_len = int(length_indicator)
            text_start = len_offset + 1
        elif length_indicator == 0x81:
            # uint16_le (next 2 bytes)
            if len_offset + 3 <= len(raw_bytes):
                text_len = struct.unpack("<H", raw_bytes[len_offset + 1 : len_offset + 3])[0]
                text_start = len_offset + 3
            else:
                return None
        elif length_indicator in (0x82, 0x83):
            # 3-byte / uint24 length
            if len_offset + 4 <= len(raw_bytes):
                text_len = int.from_bytes(raw_bytes[len_offset + 1 : len_offset + 4], byteorder="little")
                text_start = len_offset + 4
            else:
                return None
        elif length_indicator == 0x84:
            # uint32_le (next 4 bytes)
            if len_offset + 5 <= len(raw_bytes):
                text_len = struct.unpack("<I", raw_bytes[len_offset + 1 : len_offset + 5])[0]
                text_start = len_offset + 5
            else:
                return None
        else:
            text_len = int(length_indicator)
            text_start = len_offset + 1

        if text_len <= 0 or text_start + text_len > len(raw_bytes):
            # Fallback: slice remaining bytes until next null or end
            remaining = raw_bytes[text_start:]
            cleaned = remaining.split(b"\x86")[0].split(b"\x00")[0]
            if cleaned:
                return cleaned.decode("utf-8", errors="replace").strip()
            return None

        # Step 4: Decode L bytes as UTF-8
        extracted_bytes = raw_bytes[text_start : text_start + text_len]
        decoded_text = extracted_bytes.decode("utf-8", errors="replace").strip()

        return decoded_text if decoded_text else None
