"""
Universal Embedded WebView Crawler & Forensic Master Ledger Engine.
Discovers and extracts Android app_webview and iOS WKWebView / NSURLCache sandboxes
and exports to webview_forensic_engine.sqlite.
Adheres strictly to Specification Section 3, Section 7, Section 8, and AGENTS.md Forensic Invariants.
"""

from pathlib import Path
import sqlite3
from typing import Any, List, Optional, Tuple

from src.core.enums import ResidualConfidence
from src.webview.binarycookies import BinaryCookiesDecoder
from src.webview.jwt import extract_jwt_claims_json, unpack_jwt_token
from src.webview.localstorage import decode_chromium_localstorage_value
from src.webview.models import (
    StorageCategory,
    WebViewAutofillAndStorage,
    WebViewCookieAndToken,
    WebViewEngineType,
    WebViewHTTPCacheRecord,
    WebViewSandboxInventory,
)
from src.webview.nsurlcache import NSURLCacheCorrelator
from src.webview.simplecache import ChromiumSimpleCacheParser


def _enum_val(val: Any) -> str:
    """Extracts raw string representation from enum or string."""
    if hasattr(val, "value"):
        return str(val.value)
    return str(val) if val is not None else ""


class WebViewForensicEngine:
    """
    Coordinates discovery, parsing, and ledger persistence for embedded WebView artifacts
    across Android Chromium WebView and iOS WKWebView / NSURLCache.
    """

    def __init__(self) -> None:
        self.simple_cache_parser = ChromiumSimpleCacheParser()
        self.binary_cookies_decoder = BinaryCookiesDecoder()
        self.nsurlcache_correlator = NSURLCacheCorrelator()

    def crawl_directory(
        self,
        root_dir: Path | str,
        app_instance_id: int = 1,
        os_platform: str = "ANDROID",
        vfs_file_id: int = 0,
    ) -> Tuple[
        WebViewSandboxInventory,
        List[WebViewHTTPCacheRecord],
        List[WebViewCookieAndToken],
        List[WebViewAutofillAndStorage],
    ]:
        """
        Crawls a directory for WebView artifacts (Cache_Data/*_0, Cookies.binarycookies, Cache.db, Web Data).
        """
        root = Path(root_dir)
        cache_records: List[WebViewHTTPCacheRecord] = []
        cookies: List[WebViewCookieAndToken] = []
        storage_records: List[WebViewAutofillAndStorage] = []

        engine_type = (
            WebViewEngineType.ANDROID_CHROMIUM_WEBVIEW.value
            if os_platform.upper() == "ANDROID"
            else WebViewEngineType.IOS_WKWEBVIEW.value
        )

        jwt_count = 0

        # 1. Chromium Simple Cache search (*_0)
        for cache_f in root.glob("**/*_0"):
            if cache_f.is_file():
                rec = self.simple_cache_parser.parse_cache_file(
                    cache_f,
                    vfs_file_id=vfs_file_id,
                    wv_sandbox_id=1,
                    app_instance_id=app_instance_id,
                )
                if rec is not None:
                    cache_records.append(rec)
                    if rec.decompressed_body_text and unpack_jwt_token(rec.decompressed_body_text):
                        jwt_count += 1

        # 2. Apple Cookies.binarycookies search
        for c_file in root.glob("**/Cookies.binarycookies"):
            if c_file.is_file():
                cookie_list = self.binary_cookies_decoder.decode_cookies_file(
                    c_file,
                    vfs_file_id=vfs_file_id,
                    app_instance_id=app_instance_id,
                )
                cookies.extend(cookie_list)
                jwt_count += sum(1 for c in cookie_list if c.is_jwt_token == 1)

        # 3. iOS Cache.db search
        for cdb in root.glob("**/Cache.db"):
            if cdb.is_file():
                ns_recs = self.nsurlcache_correlator.correlate_cache_directory(
                    cdb.parent,
                    vfs_file_id=vfs_file_id,
                    wv_sandbox_id=1,
                    app_instance_id=app_instance_id,
                )
                cache_records.extend(ns_recs)
                for r in ns_recs:
                    if r.decompressed_body_text and unpack_jwt_token(r.decompressed_body_text):
                        jwt_count += 1

        # 4. Web Data autofill extraction
        for wd in root.glob("**/Web Data"):
            if wd.is_file():
                con = sqlite3.connect(wd)
                cur = con.cursor()
                try:
                    cur.execute("SELECT name, value, date_created, date_last_used FROM autofill;")
                    for name_str, val_str, d_create, d_used in cur.fetchall():
                        jwt_claims = extract_jwt_claims_json(val_str or "")
                        if jwt_claims:
                            jwt_count += 1

                        storage_records.append(
                            WebViewAutofillAndStorage(
                                app_instance_id=app_instance_id,
                                source_vfs_file_id=vfs_file_id,
                                storage_category=StorageCategory.FORM_AUTOFILL.value,
                                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                                field_or_key_name=str(name_str),
                                web_origin_or_domain=None,
                                decoded_value_text=str(val_str),
                                unpacked_jwt_payload_json=jwt_claims,
                                first_recorded_utc_iso=str(d_create) if d_create else None,
                                last_used_utc_iso=str(d_used) if d_used else None,
                            )
                        )
                except Exception as ex_wd:
                    storage_records.append(
                        WebViewAutofillAndStorage(
                            app_instance_id=app_instance_id,
                            source_vfs_file_id=vfs_file_id,
                            storage_category=StorageCategory.FORM_AUTOFILL.value,
                            recovery_classification=ResidualConfidence.PARTIAL_RECORD,
                            field_or_key_name="_error",
                            web_origin_or_domain=None,
                            decoded_value_text=str(ex_wd),
                        )
                    )
                finally:
                    con.close()

        inv = WebViewSandboxInventory(
            app_instance_id=app_instance_id,
            os_platform=os_platform.upper(),
            webview_engine_type=engine_type,
            canonical_root_path=str(root),
            cookies_extracted_count=len(cookies),
            http_cache_entries_count=len(cache_records),
            local_storage_keys_count=len(storage_records),
            jwt_tokens_unpacked_count=jwt_count,
        )

        return inv, cache_records, cookies, storage_records

    def export_to_ledger(
        self,
        inventories: List[WebViewSandboxInventory],
        cache_records: List[WebViewHTTPCacheRecord],
        cookies: List[WebViewCookieAndToken],
        storage_records: List[WebViewAutofillAndStorage],
        ledger_path: Path | str,
    ) -> None:
        """
        Commits all extracted WebView artifacts into webview_forensic_engine.sqlite.
        """
        p = Path(ledger_path)
        p.parent.mkdir(parents=True, exist_ok=True)

        con = sqlite3.connect(p)
        cur = con.cursor()

        try:
            cur.execute("PRAGMA foreign_keys = ON;")

            # 1. Table: webview_sandbox_inventory
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS webview_sandbox_inventory (
                    wv_sandbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    os_platform TEXT NOT NULL,
                    webview_engine_type TEXT NOT NULL,
                    canonical_root_path TEXT NOT NULL,
                    cookies_extracted_count INTEGER DEFAULT 0,
                    http_cache_entries_count INTEGER DEFAULT 0,
                    local_storage_keys_count INTEGER DEFAULT 0,
                    jwt_tokens_unpacked_count INTEGER DEFAULT 0
                );
                """
            )

            # 2. Table: webview_http_cache_records
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS webview_http_cache_records (
                    cache_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    wv_sandbox_id INTEGER NOT NULL,
                    app_instance_id INTEGER NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    request_url TEXT NOT NULL,
                    initiator_top_origin TEXT,
                    http_status_code INTEGER,
                    content_type_mime TEXT,
                    original_content_encoding TEXT,
                    request_time_utc_iso TEXT,
                    response_time_utc_iso TEXT,
                    response_headers_json TEXT,
                    decompressed_body_text TEXT,
                    body_sha256 TEXT,
                    FOREIGN KEY (wv_sandbox_id) REFERENCES webview_sandbox_inventory(wv_sandbox_id)
                );
                """
            )

            # 3. Table: webview_cookies_and_tokens
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS webview_cookies_and_tokens (
                    cookie_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    host_domain TEXT NOT NULL,
                    cookie_name TEXT NOT NULL,
                    cookie_value TEXT,
                    is_jwt_token INTEGER DEFAULT 0,
                    unpacked_jwt_payload_json TEXT,
                    created_utc_iso TEXT,
                    last_accessed_utc_iso TEXT,
                    expires_utc_iso TEXT
                );
                """
            )

            # 4. Table: webview_autofill_and_storage
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS webview_autofill_and_storage (
                    storage_row_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_instance_id INTEGER NOT NULL,
                    source_vfs_file_id INTEGER NOT NULL,
                    storage_category TEXT NOT NULL,
                    recovery_classification TEXT NOT NULL,
                    web_origin_or_domain TEXT,
                    field_or_key_name TEXT NOT NULL,
                    decoded_value_text TEXT,
                    unpacked_jwt_payload_json TEXT,
                    first_recorded_utc_iso TEXT,
                    last_used_utc_iso TEXT
                );
                """
            )

            # Performance indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_wv_cache_url ON webview_http_cache_records(request_url);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_wv_cookies_dom ON webview_cookies_and_tokens(host_domain);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_wv_storage_app ON webview_autofill_and_storage(app_instance_id);")

            # Insert inventories
            for inv in inventories:
                if inv.wv_sandbox_id is not None:
                    cur.execute(
                        """
                        INSERT INTO webview_sandbox_inventory (
                            wv_sandbox_id, app_instance_id, os_platform, webview_engine_type,
                            canonical_root_path, cookies_extracted_count, http_cache_entries_count,
                            local_storage_keys_count, jwt_tokens_unpacked_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            inv.wv_sandbox_id,
                            inv.app_instance_id,
                            inv.os_platform,
                            _enum_val(inv.webview_engine_type),
                            inv.canonical_root_path,
                            inv.cookies_extracted_count,
                            inv.http_cache_entries_count,
                            inv.local_storage_keys_count,
                            inv.jwt_tokens_unpacked_count,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO webview_sandbox_inventory (
                            app_instance_id, os_platform, webview_engine_type,
                            canonical_root_path, cookies_extracted_count, http_cache_entries_count,
                            local_storage_keys_count, jwt_tokens_unpacked_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            inv.app_instance_id,
                            inv.os_platform,
                            _enum_val(inv.webview_engine_type),
                            inv.canonical_root_path,
                            inv.cookies_extracted_count,
                            inv.http_cache_entries_count,
                            inv.local_storage_keys_count,
                            inv.jwt_tokens_unpacked_count,
                        ),
                    )
                    inv.wv_sandbox_id = cur.lastrowid

            # Insert cache records
            for cr in cache_records:
                cur.execute(
                    """
                    INSERT INTO webview_http_cache_records (
                        wv_sandbox_id, app_instance_id, source_vfs_file_id,
                        recovery_classification, request_url, initiator_top_origin,
                        http_status_code, content_type_mime, original_content_encoding,
                        request_time_utc_iso, response_time_utc_iso, response_headers_json,
                        decompressed_body_text, body_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        cr.wv_sandbox_id,
                        cr.app_instance_id,
                        cr.source_vfs_file_id,
                        _enum_val(cr.recovery_classification),
                        cr.request_url,
                        cr.initiator_top_origin,
                        cr.http_status_code,
                        cr.content_type_mime,
                        cr.original_content_encoding,
                        cr.request_time_utc_iso,
                        cr.response_time_utc_iso,
                        cr.response_headers_json,
                        cr.decompressed_body_text,
                        cr.body_sha256,
                    ),
                )
                cr.cache_record_uid = cur.lastrowid

            # Insert cookies
            for ck in cookies:
                cur.execute(
                    """
                    INSERT INTO webview_cookies_and_tokens (
                        app_instance_id, source_vfs_file_id, recovery_classification,
                        host_domain, cookie_name, cookie_value, is_jwt_token,
                        unpacked_jwt_payload_json, created_utc_iso, last_accessed_utc_iso,
                        expires_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        ck.app_instance_id,
                        ck.source_vfs_file_id,
                        _enum_val(ck.recovery_classification),
                        ck.host_domain,
                        ck.cookie_name,
                        ck.cookie_value,
                        ck.is_jwt_token,
                        ck.unpacked_jwt_payload_json,
                        ck.created_utc_iso,
                        ck.last_accessed_utc_iso,
                        ck.expires_utc_iso,
                    ),
                )
                ck.cookie_uid = cur.lastrowid

            # Insert storage records
            for sr in storage_records:
                cur.execute(
                    """
                    INSERT INTO webview_autofill_and_storage (
                        app_instance_id, source_vfs_file_id, storage_category,
                        recovery_classification, web_origin_or_domain, field_or_key_name,
                        decoded_value_text, unpacked_jwt_payload_json, first_recorded_utc_iso,
                        last_used_utc_iso
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        sr.app_instance_id,
                        sr.source_vfs_file_id,
                        _enum_val(sr.storage_category),
                        _enum_val(sr.recovery_classification),
                        sr.web_origin_or_domain,
                        sr.field_or_key_name,
                        sr.decoded_value_text,
                        sr.unpacked_jwt_payload_json,
                        sr.first_recorded_utc_iso,
                        sr.last_used_utc_iso,
                    ),
                )
                sr.storage_row_uid = cur.lastrowid

            con.commit()
        finally:
            con.close()
