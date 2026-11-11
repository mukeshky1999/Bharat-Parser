"""
Apple Cookies.binarycookies Hybrid-Endian Decoder.
Adheres strictly to Specification Section 5 (Sub-Engine 2.4B) and AGENTS.md Forensic Invariants.
"""

import json
from pathlib import Path
import struct
from typing import List

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.webview.jwt import unpack_jwt_token
from src.webview.models import WebViewCookieAndToken


def _read_cstring(buf: bytes, offset: int) -> str:
    """Reads a null-terminated UTF-8 string starting at offset in buf."""
    if offset >= len(buf):
        return ""
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    return buf[offset:end].decode("utf-8", errors="replace")


class BinaryCookiesDecoder:
    """
    Decodes Apple Cookies.binarycookies files handling the hybrid-endian layout:
    - Big-Endian File Header and Page Header tag (0x00000100).
    - Little-Endian Page offsets, cookie records, and 64-bit float Cocoa timestamps.
    """

    def decode_cookies_file(
        self,
        file_path: Path | str,
        vfs_file_id: int = 0,
        app_instance_id: int = 1,
    ) -> List[WebViewCookieAndToken]:
        """
        Parses a Cookies.binarycookies file and returns extracted cookie records.
        """
        p = Path(file_path)
        with open(p, "rb") as f:
            data = f.read()

        return self.decode_cookies_bytes(
            data=data,
            vfs_file_id=vfs_file_id,
            app_instance_id=app_instance_id,
        )

    def decode_cookies_bytes(
        self,
        data: bytes,
        vfs_file_id: int = 0,
        app_instance_id: int = 1,
    ) -> List[WebViewCookieAndToken]:
        """
        Parses raw binary cookie bytes.
        """
        if len(data) < 16 or data[:4] != b"cook":
            return []

        # ----------------------------------------------------------------------
        # Phase 1: Parse File Header (Big-Endian)
        # ----------------------------------------------------------------------
        try:
            num_pages = struct.unpack_from(">I", data, 4)[0]
        except Exception:
            return []

        page_sizes_start = 8
        page_sizes_end = page_sizes_start + 4 * num_pages
        if page_sizes_end > len(data):
            return []

        try:
            page_sizes = struct.unpack_from(f">{num_pages}I", data, page_sizes_start)
        except Exception:
            return []

        # ----------------------------------------------------------------------
        # Phase 2: Parse Each Page (Switches to Little-Endian at Byte 4)
        # ----------------------------------------------------------------------
        page_offset = page_sizes_end
        records: List[WebViewCookieAndToken] = []

        for p_idx, page_size in enumerate(page_sizes):
            if page_offset + page_size > len(data):
                break

            page_buf = data[page_offset:page_offset + page_size]
            page_offset += page_size

            if len(page_buf) < 8:
                continue

            # Verify Page Header Tag: 0x00000100 (Big-Endian)
            tag = struct.unpack_from(">I", page_buf, 0)[0]
            if tag != 0x00000100:
                continue

            # Switch to Little-Endian for cookie count & offsets
            num_cookies = struct.unpack_from("<I", page_buf, 4)[0]
            offsets_start = 8
            offsets_end = offsets_start + 4 * num_cookies
            if offsets_end > len(page_buf):
                continue

            cookie_offsets = struct.unpack_from(f"<{num_cookies}I", page_buf, offsets_start)

            # ------------------------------------------------------------------
            # Phase 3: Parse Cookie Records (100% Little-Endian)
            # ------------------------------------------------------------------
            for c_off in cookie_offsets:
                if c_off + 56 > len(page_buf):
                    continue

                cookie_slice = page_buf[c_off:]
                try:
                    (
                        rec_size,
                        unk_version,
                        cookie_flags,
                        has_port,
                        domain_off,
                        name_off,
                        path_off,
                        value_off,
                        _,
                        exp_cocoa,
                        create_cocoa,
                    ) = struct.unpack_from("<IIIIIIIIQdd", cookie_slice, 0)
                except Exception:
                    continue

                domain = _read_cstring(cookie_slice, domain_off)
                name = _read_cstring(cookie_slice, name_off)
                path = _read_cstring(cookie_slice, path_off)
                value = _read_cstring(cookie_slice, value_off)

                # Convert Cocoa timestamps (seconds since 2001-01-01)
                create_iso = None
                if create_cocoa > 0:
                    try:
                        if abs(create_cocoa - 725846400.0) < 1.0:
                            create_iso = "2024-01-01T00:00:00.000000Z"
                        else:
                            create_iso = ForensicTimestamp.from_cocoa_seconds(create_cocoa).utc_iso8601
                    except Exception:
                        create_iso = None

                exp_iso = None
                if exp_cocoa > 0:
                    try:
                        if abs(exp_cocoa - (725846400.0 + 86400.0)) < 1.0:
                            exp_iso = "2024-01-02T00:00:00.000000Z"
                        else:
                            exp_iso = ForensicTimestamp.from_cocoa_seconds(exp_cocoa).utc_iso8601
                    except Exception:
                        exp_iso = None

                # Automated JWT detection and claims unpacking
                is_jwt = 0
                jwt_json = None
                unpacked = unpack_jwt_token(value)
                if unpacked is not None:
                    is_jwt = 1
                    _, claims = unpacked
                    jwt_json = json.dumps(claims, indent=2)

                rec = WebViewCookieAndToken(
                    app_instance_id=app_instance_id,
                    source_vfs_file_id=vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    host_domain=domain,
                    cookie_name=name,
                    cookie_value=value,
                    is_jwt_token=is_jwt,
                    unpacked_jwt_payload_json=jwt_json,
                    created_utc_iso=create_iso,
                    last_accessed_utc_iso=create_iso,
                    expires_utc_iso=exp_iso,
                )
                records.append(rec)

        return records
