"""
iOS Cache.db (NSURLCache) SQLite & fsCachedData/<UUID> External Payload Correlator.
Adheres strictly to Specification Section 6 (Sub-Engine 2.4C) and AGENTS.md Forensic Invariants.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import plistlib
import sqlite3
from typing import Dict, List, Optional, Set

from src.core.enums import ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.webview.models import WebViewHTTPCacheRecord


def _infer_mime(data: bytes) -> str:
    """Infers MIME type from magic bytes or textual structure."""
    if not data:
        return "application/octet-stream"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif"
    if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
        return "image/webp"
    stripped = data[:64].strip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return "application/json"
    if stripped.startswith(b"<!DOCTYPE html") or stripped.startswith(b"<html"):
        return "text/html"
    return "application/octet-stream"


class NSURLCacheCorrelator:
    """
    Correlates Apple NSURLCache Cache.db SQLite databases with external
    fsCachedData/<UUID> file payloads, and sweeps unreferenced orphan files.
    """

    def correlate_cache_directory(
        self,
        caches_root: Path | str,
        vfs_file_id: int = 0,
        wv_sandbox_id: int = 1,
        app_instance_id: int = 1,
    ) -> List[WebViewHTTPCacheRecord]:
        """
        Processes Cache.db and fsCachedData/ within an iOS application cache directory.
        """
        root = Path(caches_root)
        db_path = root / "Cache.db" if (root / "Cache.db").exists() else root
        fs_data_dir = root / "fsCachedData" if (root / "fsCachedData").exists() else root.parent / "fsCachedData"

        records: List[WebViewHTTPCacheRecord] = []
        referenced_uuids: Set[str] = set()

        if db_path.is_file():
            con = sqlite3.connect(db_path)
            cur = con.cursor()

            try:
                cur.execute(
                    """
                    SELECT
                        r.entry_ID,
                        r.request_key,
                        r.time_stamp,
                        b.response_object,
                        d.isDataOnFS,
                        d.receiver_data
                    FROM cfurl_cache_response r
                    LEFT JOIN cfurl_cache_blob_data b ON r.entry_ID = b.entry_ID
                    LEFT JOIN cfurl_cache_receiver_data d ON r.entry_ID = d.entry_ID;
                    """
                )
                rows = cur.fetchall()

                for row in rows:
                    entry_id, req_key, ts_val, bplist_bytes, is_fs, recv_data = row
                    request_url = req_key or ""

                    # Timestamp conversion
                    resp_time_iso: Optional[str] = None
                    if ts_val is not None:
                        try:
                            # Auto-detect Cocoa vs Unix epoch
                            if ts_val > 1000000000.0:
                                resp_time_iso = ForensicTimestamp.from_unix_seconds(ts_val).utc_iso8601
                            elif ts_val > 400000000.0:
                                resp_time_iso = ForensicTimestamp.from_cocoa_seconds(ts_val).utc_iso8601
                            else:
                                dt = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
                                resp_time_iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                        except Exception as ex_ts:
                            resp_time_iso = str(ex_ts)

                    # Extract HTTP response headers from bplist00 if available
                    headers_json: Optional[str] = None
                    if bplist_bytes and isinstance(bplist_bytes, (bytes, bytearray)):
                        try:
                            parsed_plist = plistlib.loads(bytes(bplist_bytes))
                            if isinstance(parsed_plist, dict):
                                headers_json = json.dumps(parsed_plist, indent=2, default=str)
                        except Exception as ex_pl:
                            headers_json = json.dumps({"_plist_error": str(ex_pl)})

                    # Resolve response body
                    body_bytes = b""
                    if is_fs == 1 and recv_data:
                        uuid_str = (
                            recv_data.decode("ascii", errors="replace").strip()
                            if isinstance(recv_data, (bytes, bytearray))
                            else str(recv_data).strip()
                        )
                        referenced_uuids.add(uuid_str)
                        external_file = fs_data_dir / uuid_str
                        if external_file.exists():
                            with open(external_file, "rb") as ef:
                                body_bytes = ef.read()
                    elif recv_data and isinstance(recv_data, (bytes, bytearray)):
                        body_bytes = bytes(recv_data)

                    body_sha = hashlib.sha256(body_bytes).hexdigest() if body_bytes else None
                    body_text = None
                    if body_bytes:
                        try:
                            body_text = body_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            body_text = body_bytes.decode("latin-1", errors="replace")

                    mime_type = _infer_mime(body_bytes)

                    rec = WebViewHTTPCacheRecord(
                        wv_sandbox_id=wv_sandbox_id,
                        app_instance_id=app_instance_id,
                        source_vfs_file_id=vfs_file_id,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        request_url=request_url,
                        initiator_top_origin=None,
                        http_status_code=200,
                        content_type_mime=mime_type,
                        original_content_encoding="identity",
                        request_time_utc_iso=resp_time_iso,
                        response_time_utc_iso=resp_time_iso,
                        response_headers_json=headers_json,
                        decompressed_body_text=body_text,
                        body_sha256=body_sha,
                    )
                    records.append(rec)

            finally:
                con.close()

        # ----------------------------------------------------------------------
        # Orphaned fsCachedData/ Sweeper
        # ----------------------------------------------------------------------
        if fs_data_dir.is_dir():
            for orphan_file in fs_data_dir.iterdir():
                if not orphan_file.is_file():
                    continue
                if orphan_file.name in referenced_uuids:
                    continue

                # Orphaned payload discovered!
                with open(orphan_file, "rb") as of:
                    orphan_bytes = of.read()

                orphan_sha = hashlib.sha256(orphan_bytes).hexdigest() if orphan_bytes else None
                orphan_text = None
                if orphan_bytes:
                    try:
                        orphan_text = orphan_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        orphan_text = orphan_bytes.decode("latin-1", errors="replace")

                stat = orphan_file.stat()
                mtime_dt = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                mtime_iso = mtime_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                mime_type = _infer_mime(orphan_bytes)

                orphan_rec = WebViewHTTPCacheRecord(
                    wv_sandbox_id=wv_sandbox_id,
                    app_instance_id=app_instance_id,
                    source_vfs_file_id=vfs_file_id,
                    recovery_classification=ResidualConfidence.RESIDUAL_RECORD,
                    request_url=f"orphaned://fsCachedData/{orphan_file.name}",
                    initiator_top_origin=None,
                    http_status_code=None,
                    content_type_mime=mime_type,
                    original_content_encoding="identity",
                    request_time_utc_iso=mtime_iso,
                    response_time_utc_iso=mtime_iso,
                    response_headers_json=None,
                    decompressed_body_text=orphan_text,
                    body_sha256=orphan_sha,
                )
                records.append(orphan_rec)

        return records
