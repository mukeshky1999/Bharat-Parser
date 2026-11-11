"""
Chromium Simple Cache (*_0, *_1, *_s) Binary Parser.
Adheres strictly to Specification Section 4 (Sub-Engine 2.4A) and AGENTS.md Forensic Invariants.
"""

import gzip
import hashlib
import json
from pathlib import Path
import struct
from typing import Dict, Optional, Tuple
import zlib

import brotli
import zstandard as zstd

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.webview.models import WebViewHTTPCacheRecord

SIMPLE_CACHE_MAGIC_INITIAL = 0xfcfb6d1ba7725c30
SIMPLE_CACHE_MAGIC_FINAL = 0xf4fa6f45970d41d8


class ChromiumSimpleCacheParser:
    """
    Parses Chromium SimpleEntryFormat v5 cache files (*_0) from both file ends:
    - Offset 0: SimpleFileHeader (magic 0xfcfb6d1ba7725c30) + URL key.
    - End-of-file: Stream 0 (HttpResponseInfo pickle + WebKit us timestamps) + Stream 1 (HTTP Body).
    """

    def parse_cache_file(
        self,
        file_path: Path | str,
        vfs_file_id: int = 0,
        wv_sandbox_id: int = 1,
        app_instance_id: int = 1,
    ) -> Optional[WebViewHTTPCacheRecord]:
        """
        Parses a *_0 Simple Cache file and returns a decoded WebViewHTTPCacheRecord.
        """
        p = Path(file_path)
        with open(p, "rb") as f:
            data = f.read()

        file_len = len(data)
        if file_len < 48:
            return None

        # ----------------------------------------------------------------------
        # Phase 1: SimpleFileHeader at Byte 0 (24 bytes)
        # ----------------------------------------------------------------------
        try:
            init_magic, version, key_len, key_hash, _ = struct.unpack_from("<QIIII", data, 0)
        except Exception:
            return None

        if init_magic != SIMPLE_CACHE_MAGIC_INITIAL:
            return None

        key_start = 24
        key_end = 24 + key_len
        if key_end > file_len:
            return None

        raw_key = data[key_start:key_end].decode("utf-8", errors="replace")

        # Parse request_url and initiator_top_origin from Modern Chromium Isolation Key
        # Format: "1/0/_dk_<domain> <initiator> <url>" or just "<url>"
        parts = raw_key.strip().split()
        if len(parts) >= 2:
            request_url = parts[-1]
            initiator_origin: Optional[str] = None
            for part in parts[:-1]:
                if "_dk_" in part:
                    initiator_origin = part.split("_dk_", 1)[1]
                    break
            if initiator_origin is None and len(parts) >= 2:
                initiator_origin = parts[0]
        else:
            request_url = raw_key.strip()
            initiator_origin = None

        # ----------------------------------------------------------------------
        # Phase 2: Stream 0 (HTTP Headers Pickle) - Read Backward from EOF
        # ----------------------------------------------------------------------
        if file_len < 24:
            return None

        eof_0_pos = file_len - 24
        try:
            magic_0, flags_0, crc_0, s0_size, _ = struct.unpack_from("<QIIII", data, eof_0_pos)
        except Exception:
            return None

        if magic_0 != SIMPLE_CACHE_MAGIC_FINAL:
            return None

        sha256_len = 32 if (flags_0 & 2) != 0 else 0
        s0_end = eof_0_pos - sha256_len
        s0_start = s0_end - s0_size

        if s0_start < key_end or s0_end > file_len:
            return None

        s0_bytes = data[s0_start:s0_end]

        # Decode HttpResponseInfo Pickle
        http_status_code: Optional[int] = None
        content_type_mime: Optional[str] = None
        content_encoding: Optional[str] = None
        req_utc_iso: Optional[str] = None
        resp_utc_iso: Optional[str] = None
        headers_dict: Dict[str, str] = {}

        if len(s0_bytes) >= 28:
            try:
                p_size, p_flags, req_us, resp_us, h_len = struct.unpack_from("<IIqqI", s0_bytes, 0)
                if req_us > 0:
                    req_utc_iso = ForensicTimestamp.from_webkit_filetime_microseconds(req_us).utc_iso8601
                if resp_us > 0:
                    resp_utc_iso = ForensicTimestamp.from_webkit_filetime_microseconds(resp_us).utc_iso8601

                raw_headers = s0_bytes[28:28 + h_len]
                header_lines = raw_headers.split(b"\x00")

                if header_lines:
                    status_line = header_lines[0].decode("latin-1", errors="replace")
                    status_parts = status_line.split()
                    if len(status_parts) >= 2:
                        try:
                            http_status_code = int(status_parts[1])
                        except ValueError:
                            http_status_code = None

                    for line in header_lines[1:]:
                        if not line:
                            continue
                        line_str = line.decode("latin-1", errors="replace")
                        if ":" in line_str:
                            k, v = line_str.split(":", 1)
                            k_clean = k.strip().lower()
                            v_clean = v.strip()
                            headers_dict[k_clean] = v_clean
                            if k_clean == "content-type":
                                content_type_mime = v_clean.split(";")[0].strip()
                            elif k_clean == "content-encoding":
                                content_encoding = v_clean.strip().lower()
            except Exception as ex_pickle:
                headers_dict["_pickle_error"] = str(ex_pickle)

        # ----------------------------------------------------------------------
        # Phase 3: Stream 1 (HTTP Response Body)
        # ----------------------------------------------------------------------
        s1_bytes = b""
        eof_1_pos = s0_start - 24

        if eof_1_pos >= key_end:
            try:
                magic_1, flags_1, crc_1, s1_size, _ = struct.unpack_from("<QIIII", data, eof_1_pos)
                if magic_1 == SIMPLE_CACHE_MAGIC_FINAL and s1_size > 0:
                    s1_start = key_end
                    s1_end = s1_start + s1_size
                    if s1_end <= eof_1_pos:
                        s1_bytes = data[s1_start:s1_end]
            except Exception:
                s1_bytes = b""

        # Companion *_1 file check if s1_bytes is empty
        if not s1_bytes:
            companion_path = p.with_name(p.stem[:-1] + "1")
            if companion_path.exists():
                with open(companion_path, "rb") as cf:
                    cdata = cf.read()
                if len(cdata) >= 48:
                    try:
                        c_magic, _, c_klen, _, _ = struct.unpack_from("<QIIII", cdata, 0)
                        if c_magic == SIMPLE_CACHE_MAGIC_INITIAL:
                            s1_bytes = cdata[24 + c_klen:-24]
                    except Exception:
                        s1_bytes = b""

        # Decompress HTTP Body
        decompressed_bytes = s1_bytes
        if s1_bytes:
            if content_encoding == "br":
                try:
                    decompressed_bytes = brotli.decompress(s1_bytes)
                except Exception:
                    decompressed_bytes = s1_bytes
            elif content_encoding == "gzip" or (len(s1_bytes) >= 3 and s1_bytes[:3] == b"\x1f\x8b\x08"):
                try:
                    decompressed_bytes = gzip.decompress(s1_bytes)
                    if content_encoding is None:
                        content_encoding = "gzip"
                except Exception:
                    decompressed_bytes = s1_bytes
            elif content_encoding == "deflate":
                try:
                    decompressed_bytes = zlib.decompress(s1_bytes)
                except Exception:
                    decompressed_bytes = s1_bytes
            elif content_encoding == "zstd" or (len(s1_bytes) >= 4 and s1_bytes[:4] == b"\x28\xb5\x2f\xfd"):
                try:
                    dctx = zstd.ZstdDecompressor()
                    decompressed_bytes = dctx.decompress(s1_bytes)
                    if content_encoding is None:
                        content_encoding = "zstd"
                except Exception:
                    decompressed_bytes = s1_bytes

        decompressed_text = None
        body_sha256 = None
        if decompressed_bytes:
            body_sha256 = hashlib.sha256(decompressed_bytes).hexdigest()
            try:
                decompressed_text = decompressed_bytes.decode("utf-8")
            except UnicodeDecodeError:
                decompressed_text = decompressed_bytes.decode("latin-1", errors="replace")

        return WebViewHTTPCacheRecord(
            wv_sandbox_id=wv_sandbox_id,
            app_instance_id=app_instance_id,
            source_vfs_file_id=vfs_file_id,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            request_url=request_url,
            initiator_top_origin=initiator_origin,
            http_status_code=http_status_code,
            content_type_mime=content_type_mime,
            original_content_encoding=content_encoding or "identity",
            request_time_utc_iso=req_utc_iso,
            response_time_utc_iso=resp_utc_iso,
            response_headers_json=json.dumps(headers_dict, indent=2) if headers_dict else None,
            decompressed_body_text=decompressed_text,
            body_sha256=body_sha256,
        )
