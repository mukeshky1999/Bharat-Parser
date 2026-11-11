"""
Sub-Engine 5.2B: Telegram MTProto Type Language (TL) Binary Stream Deserializer.
Implements 4-byte aligned little-endian primitive readers, bitmask flag-controlled
deserialization for TL_user and TL_message, and a resilient 4-byte aligned scanner.
Complies with Section 4 of Phase 5 Module 5.2 Specification.
"""

import logging
import math
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TLStreamReader:
    """Little-endian binary stream reader aligning on 4-byte boundaries."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.length = len(data)
        self.cursor = 0

    def remaining(self) -> int:
        """Returns the number of unconsumed bytes."""
        return max(0, self.length - self.cursor)

    def read_int32(self) -> int:
        """Reads a 32-bit signed little-endian integer."""
        if self.cursor + 4 > self.length:
            return 0
        val = struct.unpack_from("<i", self.data, self.cursor)[0]
        self.cursor += 4
        return val

    def read_uint32(self) -> int:
        """Reads a 32-bit unsigned little-endian integer."""
        if self.cursor + 4 > self.length:
            return 0
        val = struct.unpack_from("<I", self.data, self.cursor)[0]
        self.cursor += 4
        return val

    def read_int64(self) -> int:
        """Reads a 64-bit signed little-endian integer."""
        if self.cursor + 8 > self.length:
            return 0
        val = struct.unpack_from("<q", self.data, self.cursor)[0]
        self.cursor += 8
        return val

    def read_uint64(self) -> int:
        """Reads a 64-bit unsigned little-endian integer."""
        if self.cursor + 8 > self.length:
            return 0
        val = struct.unpack_from("<Q", self.data, self.cursor)[0]
        self.cursor += 8
        return val

    def read_double(self) -> float:
        """Reads an IEEE 754 64-bit little-endian float."""
        if self.cursor + 8 > self.length:
            return 0.0
        val = struct.unpack_from("<d", self.data, self.cursor)[0]
        self.cursor += 8
        return val

    def read_tl_bytes(self) -> bytes:
        """
        Reads a 4-byte aligned length-prefixed byte array according to Section 4.1:
        - If first byte < 254: 1 length byte + L bytes, padded to 4-byte boundary.
        - If first byte == 254: 1 byte (0xFE) + 3 length bytes (24-bit LE) + L bytes, padded.
        """
        if self.cursor >= self.length:
            return b""

        first_byte = self.data[self.cursor]
        if first_byte < 254:
            str_len = first_byte
            start = self.cursor + 1
            end = start + str_len
            total_unpadded = 1 + str_len
            bytes_to_advance = math.ceil(total_unpadded / 4.0) * 4
            self.cursor += int(bytes_to_advance)
            if start <= self.length:
                return self.data[start:min(end, self.length)]
            return b""
        elif first_byte == 254:
            if self.cursor + 4 > self.length:
                self.cursor = self.length
                return b""
            str_len = (
                self.data[self.cursor + 1]
                | (self.data[self.cursor + 2] << 8)
                | (self.data[self.cursor + 3] << 16)
            )
            start = self.cursor + 4
            end = start + str_len
            total_unpadded = 4 + str_len
            bytes_to_advance = math.ceil(total_unpadded / 4.0) * 4
            self.cursor += int(bytes_to_advance)
            if start <= self.length:
                return self.data[start:min(end, self.length)]
            return b""
        else:
            self.cursor += 4
            return b""

    def read_tl_string(self) -> str:
        """Reads a 4-byte aligned length-prefixed UTF-8 string."""
        raw = self.read_tl_bytes()
        return raw.decode("utf-8", errors="replace")

    def read_tl_peer(self) -> Optional[Tuple[str, int]]:
        """
        Reads a TL_Peer object:
        - peerUser (0x595c107c or 0x9db1bc6d) -> ("user", id)
        - peerChat (0xbad0744e) -> ("chat", id)
        - peerChannel (0x179be863 or 0xa2a5d43e) -> ("channel", id)
        """
        if self.remaining() < 8:
            return None
        peer_const = self.read_uint32()
        # Read either 64-bit or 32-bit ID depending on remaining bytes
        if self.remaining() >= 8:
            peer_id = self.read_int64()
        else:
            peer_id = self.read_int32()

        if peer_const in (0x595C107C, 0x9DB1BC6D):
            return ("user", peer_id)
        elif peer_const in (0xBAD0744E,):
            return ("chat", peer_id)
        elif peer_const in (0x179BE863, 0xA2A5D43E):
            return ("channel", peer_id)
        return ("peer", peer_id)


def decode_tl_user(blob: bytes) -> Dict[str, Any]:
    """
    Deserializes a TL_user binary BLOB from users.data.
    Extracts user_id, first_name, last_name, username, and MSISDN phone number.
    """
    res: Dict[str, Any] = {
        "user_id": None,
        "first_name": None,
        "last_name": None,
        "username": None,
        "phone": None,
        "is_self": False,
        "is_contact": False,
        "is_bot": False,
        "is_scam": False,
        "is_fake": False,
        "is_premium": False,
    }

    if not blob or len(blob) < 8:
        return res

    reader = TLStreamReader(blob)
    constructor_id = reader.read_uint32()
    flags = reader.read_uint32()

    # User ID: int64 in modern layers, int32 in legacy
    if reader.remaining() >= 8:
        user_id = reader.read_int64()
    else:
        user_id = reader.read_int32()
    res["user_id"] = user_id

    # Optional fields governed by bitmask flags
    if flags & (1 << 0):
        _ = reader.read_int64()  # access_hash

    if flags & (1 << 1):
        res["first_name"] = reader.read_tl_string()

    if flags & (1 << 2):
        res["last_name"] = reader.read_tl_string()

    if flags & (1 << 3):
        res["username"] = reader.read_tl_string()

    if flags & (1 << 4):
        res["phone"] = reader.read_tl_string()

    res["is_self"] = bool(flags & (1 << 10))
    res["is_contact"] = bool(flags & (1 << 11))
    res["is_bot"] = bool(flags & (1 << 14))
    res["is_scam"] = bool(flags & (1 << 24))
    res["is_fake"] = bool(flags & (1 << 26))
    res["is_premium"] = bool(flags & (1 << 28))

    # Resilient fallback: If phone or username is still missing, scan 4-byte boundaries
    if not res["phone"] or not res["username"]:
        strings = _scan_aligned_strings(blob)
        for s in strings:
            clean = s.strip()
            if not res["phone"] and clean.isdigit() and len(clean) in (10, 11, 12, 13, 14, 15):
                res["phone"] = clean
            elif not res["username"] and len(clean) >= 4 and clean.replace("_", "").isalnum() and not clean.isdigit():
                if clean not in (res["first_name"], res["last_name"]):
                    res["username"] = clean

    return res


def decode_tl_message(blob: bytes) -> Dict[str, Any]:
    """
    Deserializes a TL_message binary BLOB from messages_v2.data.
    Extracts msg_id, from_id, peer_id, message_text, edit_date, and media attributes.
    """
    res: Dict[str, Any] = {
        "msg_id": None,
        "from_id": None,
        "peer_id": None,
        "date": None,
        "message_text": None,
        "edit_date": None,
        "forward_from": None,
        "reply_to_msg_id": None,
        "media_metadata": None,
        "inline_buttons": None,
    }

    if not blob or len(blob) < 8:
        return res

    reader = TLStreamReader(blob)
    constructor_id = reader.read_uint32()
    flags = reader.read_uint32()
    msg_id = reader.read_int32()
    res["msg_id"] = msg_id

    # Optional from_id (Bit 8)
    if flags & (1 << 8):
        peer = reader.read_tl_peer()
        if peer:
            res["from_id"] = peer[1]

    # Destination peer_id
    peer_dest = reader.read_tl_peer()
    if peer_dest:
        res["peer_id"] = peer_dest[1]

    # Optional forward header (Bit 2)
    if flags & (1 << 2):
        if reader.remaining() >= 8:
            _ = reader.read_uint32()  # fwd constructor
            _ = reader.read_uint32()  # fwd flags
            fwd_peer = reader.read_tl_peer()
            fwd_date = reader.read_int32()
            res["forward_from"] = {
                "fwd_peer_id": fwd_peer[1] if fwd_peer else None,
                "fwd_date": fwd_date,
            }

    # Optional via_bot_id (Bit 11)
    if flags & (1 << 11):
        _ = reader.read_int64()

    # Optional reply_to (Bit 3)
    if flags & (1 << 3):
        res["reply_to_msg_id"] = reader.read_int32()

    # Message Date
    res["date"] = reader.read_int32()

    # Message Text
    if reader.remaining() > 0:
        res["message_text"] = reader.read_tl_string()

    # Optional Media (Bit 9)
    if flags & (1 << 9):
        media_const = reader.read_uint32()
        res["media_metadata"] = {"media_constructor": hex(media_const)}

    # Optional Reply Markup (Bit 6)
    if flags & (1 << 6):
        markup_const = reader.read_uint32()
        res["inline_buttons"] = {"markup_constructor": hex(markup_const)}

    # Optional Edit Date (Bit 15)
    if flags & (1 << 15):
        res["edit_date"] = reader.read_int32()

    # Resilient fallback: If message_text is empty, scan for strings in blob
    if not res["message_text"]:
        strings = _scan_aligned_strings(blob)
        if strings:
            # Pick longest string as message text candidate
            res["message_text"] = max(strings, key=len)

    return res


def _scan_aligned_strings(blob: bytes) -> List[str]:
    """Scans 4-byte boundaries for valid UTF-8 length-prefixed strings."""
    found: List[str] = []
    pos = 0
    length = len(blob)

    while pos < length - 4:
        first = blob[pos]
        if 0 < first < 254:
            str_len = first
            start = pos + 1
            end = start + str_len
            total_unpadded = 1 + str_len
            advance = math.ceil(total_unpadded / 4.0) * 4
            if end <= length:
                cand = blob[start:end]
                try:
                    decoded = cand.decode("utf-8")
                    if decoded and any(ch.isalnum() for ch in decoded):
                        found.append(decoded)
                        pos += int(advance)
                        continue
                except UnicodeDecodeError as exc:
                    logger.debug("Non-utf8 candidate skipped at pos %d: %s", pos, exc)
        pos += 4

    return found
