"""
Android Binary XML (ABX) Decoder.
Phase 1, Module 1.3, Section 4.1: Decodes Android 12–17 BinaryXmlSerializer streams into standard ElementTree.
"""

import base64
import logging
import struct
import xml.etree.ElementTree as ET
from typing import Union, List, Any

logger = logging.getLogger(__name__)

ABX_MAGIC = b"abx\x00"
XML_HEADER_MAGIC = b"<?xm"


class AndroidBinaryXmlDecoder:
    """Decodes both proprietary Android Binary XML (ABX) and standard UTF-8 XML trees."""

    def decode(self, data: Union[bytes, str]) -> ET.Element:
        """Parses binary ABX or plain UTF-8 XML bytes into an ElementTree.Element root."""
        if isinstance(data, str):
            raw_bytes = data.encode("utf-8")
        else:
            raw_bytes = data

        if raw_bytes.startswith(XML_HEADER_MAGIC) or raw_bytes.lstrip().startswith(b"<"):
            return ET.fromstring(raw_bytes)

        if not raw_bytes.startswith(ABX_MAGIC):
            # Fallback to standard XML parsing attempt
            return ET.fromstring(raw_bytes)

        return self._decode_abx_stream(raw_bytes)

    def _decode_abx_stream(self, data: bytes) -> ET.Element:
        pos = 4
        total_len = len(data)
        interned_strings: List[str] = []
        stack: List[ET.Element] = []
        root: Union[ET.Element, None] = None

        def read_string_typed(dtype: int) -> str:
            nonlocal pos
            if dtype == 1:  # TYPE_NULL
                return ""
            elif dtype == 2:  # TYPE_STRING
                str_len = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                val_str = data[pos:pos + str_len].decode("utf-8", errors="replace")
                pos += str_len
                return val_str
            elif dtype == 3:  # TYPE_STRING_INTERNED
                idx = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                if idx == 0xFFFF:
                    str_len = struct.unpack_from(">H", data, pos)[0]
                    pos += 2
                    val_str = data[pos:pos + str_len].decode("utf-8", errors="replace")
                    pos += str_len
                    interned_strings.append(val_str)
                    return val_str
                else:
                    if idx < len(interned_strings):
                        return interned_strings[idx]
                    return ""
            elif dtype == 4:  # TYPE_BYTES_HEX
                byte_len = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                raw = data[pos:pos + byte_len]
                pos += byte_len
                return raw.hex()
            elif dtype == 5:  # TYPE_BYTES_BASE64
                byte_len = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                raw = data[pos:pos + byte_len]
                pos += byte_len
                return base64.b64encode(raw).decode("ascii")
            elif dtype == 6:  # TYPE_INT
                val_i = struct.unpack_from(">i", data, pos)[0]
                pos += 4
                return str(val_i)
            elif dtype == 7:  # TYPE_INT_HEX
                val_u = struct.unpack_from(">I", data, pos)[0]
                pos += 4
                return f"0x{val_u:x}"
            elif dtype == 8:  # TYPE_LONG
                val_q = struct.unpack_from(">q", data, pos)[0]
                pos += 8
                return str(val_q)
            elif dtype == 9:  # TYPE_LONG_HEX
                val_uq = struct.unpack_from(">Q", data, pos)[0]
                pos += 8
                return f"0x{val_uq:x}"
            elif dtype == 10:  # TYPE_FLOAT
                val_f = struct.unpack_from(">f", data, pos)[0]
                pos += 4
                return str(val_f)
            elif dtype == 11:  # TYPE_DOUBLE
                val_d = struct.unpack_from(">d", data, pos)[0]
                pos += 8
                return str(val_d)
            elif dtype == 12:  # TYPE_BOOLEAN_TRUE
                return "true"
            elif dtype == 13:  # TYPE_BOOLEAN_FALSE
                return "false"
            else:
                return ""

        while pos < total_len:
            header_byte = data[pos]
            pos += 1
            cmd = header_byte & 0x0F
            dtype = (header_byte & 0xF0) >> 4

            if cmd == 0:  # START_DOCUMENT
                continue
            elif cmd == 1:  # END_DOCUMENT
                break
            elif cmd == 2:  # START_TAG
                tag_name = read_string_typed(dtype)
                el = ET.Element(tag_name)
                if stack:
                    stack[-1].append(el)
                if root is None:
                    root = el
                stack.append(el)

            elif cmd == 3:  # END_TAG
                # Read tag name
                _ = read_string_typed(dtype)
                if stack:
                    stack.pop()

            elif cmd == 4:  # TEXT
                text_content = read_string_typed(dtype)
                if stack:
                    stack[-1].text = (stack[-1].text or "") + text_content

            elif cmd == 15:  # ATTRIBUTE
                # In standard ABX, attribute command byte contains data type of the attribute value in high nibble.
                # First read attribute name as a string (length + bytes):
                attr_name_len = struct.unpack_from(">H", data, pos)[0]
                pos += 2
                attr_name = data[pos:pos + attr_name_len].decode("utf-8", errors="replace")
                pos += attr_name_len

                # Read attribute value based on dtype:
                attr_val = read_string_typed(dtype)
                if stack:
                    stack[-1].attrib[attr_name] = attr_val

        if root is None:
            return ET.Element("empty")
        return root
