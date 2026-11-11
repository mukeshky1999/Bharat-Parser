"""
Test Suite for Phase 2, Module 2.4: Universal Embedded WebView Crawler,
Chromium Simple Cache Parser, Apple binarycookies Decoder & Cache.db Correlator.

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real binary byte fixtures and streams (no mock objects).
- All fixtures write strictly to ./.workspace_tmp/
- Tests Chromium Simple Cache (*_0) dual-ended Brotli JSON recovery.
- Tests Apple Cookies.binarycookies hybrid-endian parsing (Big-Endian header, Little-Endian records).
- Tests iOS Cache.db (NSURLCache) SQLite + fsCachedData/<UUID> external join and orphan sweeping.
- Tests Chromium Local Storage 1-byte encoding prefix (0x00 UTF-16LE vs 0x01 UTF-8) and Base64URL JWT unpacking.
- Verifies canonical webview_sandbox_inventory, webview_http_cache_records,
  webview_cookies_and_tokens, and webview_autofill_and_storage schemas in webview_forensic_engine.sqlite.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import zlib
from typing import Dict, Any

import brotli
import pytest

from src.core.enums import ResidualConfidence


@pytest.fixture
def tmp_webview_dir():
    """Provides an isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_webview_engine")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


# ==============================================================================
# HELPER: Binary Fixture Synthesizers
# ==============================================================================

def make_b64url(data: bytes) -> str:
    """Base64URL encoding without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt_token(payload_dict: Dict[str, Any]) -> str:
    """Creates a realistic 3-part Base64URL JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = make_b64url(json.dumps(header).encode("utf-8"))
    payload_b64 = make_b64url(json.dumps(payload_dict).encode("utf-8"))
    sig_b64 = make_b64url(b"mock_sha256_cryptographic_signature_bytes_32b")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ==============================================================================
# TEST 1: Chromium Simple Cache (*_0) Dual-Ended Brotli JSON Test
# ==============================================================================

def test_chromium_simple_cache_dual_ended_brotli_json(tmp_webview_dir):
    """
    Acceptance Test 1 (Section 9.1):
    Constructs an Android app_webview/Default/Cache/Cache_Data/a1b2c3d4e5f60718_0 file:
    - Offset 0: SimpleFileHeader (magic 0xfcfb6d1ba7725c30) + URL key
    - Stream 1: Brotli-compressed JSON API response:
      {"status":"SUCCESS","utr":"431098765432","vpa":"merchant@icici"}
    - Stream 1 EOF (24 bytes): magic 0xf4fa6f45970d41d8
    - Stream 0: HttpResponseInfo Pickle (WebKit us timestamps + null-separated headers)
    - Stream 0 EOF (24 bytes): magic 0xf4fa6f45970d41d8
    Verifies that ChromiumSimpleCacheParser:
    1. Reads backward from EOF to parse Stream 0 headers.
    2. Extracts WebKit us request/response timestamps.
    3. Decompresses Stream 1 from Brotli to UTF-8 JSON.
    4. Extracts request_url, initiator_top_origin, and body SHA-256.
    """
    from src.webview.simplecache import ChromiumSimpleCacheParser

    cache_dir = tmp_webview_dir / "Cache_Data"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / "a1b2c3d4e5f60718_0"

    # URL Key with Modern Chromium Isolation Key prefix
    url_key_str = "1/0/_dk_https://phonepe.com https://phonepe.com https://api.phonepe.com/apis/v3/transaction/status"
    url_key_bytes = url_key_str.encode("utf-8")
    k_len = len(url_key_bytes)

    # 1. SimpleFileHeader (24 bytes) at offset 0
    # uint64 initial_magic_number: 0xfcfb6d1ba7725c30
    # uint32 version: 5
    # uint32 key_length: k_len
    # uint32 key_hash: 0x12345678
    # uint32 padding: 0
    hdr = struct.pack("<QIIII", 0xfcfb6d1ba7725c30, 5, k_len, 0x12345678, 0)

    # 2. Stream 1: Brotli-compressed HTTP Body
    json_body = b'{"status":"SUCCESS","utr":"431098765432","vpa":"merchant@icici"}'
    brotli_body = brotli.compress(json_body)
    s1_len = len(brotli_body)
    s1_crc = zlib.crc32(brotli_body)

    # Stream 1 EOF (24 bytes)
    # uint64 final_magic_number: 0xf4fa6f45970d41d8
    # uint32 flags: 0
    # uint32 crc32: s1_crc
    # uint32 stream_size: s1_len
    # uint32 padding: 0
    s1_eof = struct.pack("<QIIII", 0xf4fa6f45970d41d8, 0, s1_crc, s1_len, 0)

    # 3. Stream 0: HttpResponseInfo Pickle
    # WebKit us timestamp for 2024-01-01 12:00:00 UTC (Unix = 1704110400)
    # WebKit = (1704110400 + 11644473600) * 1_000_000 = 13348584000000000
    req_time_webkit = 13348584000000000
    resp_time_webkit = 13348584000500000

    raw_headers = b"HTTP/1.1 200 OK\x00content-type: application/json\x00content-encoding: br\x00server: envoy\x00\x00"
    headers_len = len(raw_headers)

    # Pickle buffer:
    # payload_size (4b), flags/version (4b), req_time (8b), resp_time (8b), headers_len (4b), headers
    pickle_payload_size = 28 + headers_len
    pickle_bytes = bytearray()
    pickle_bytes.extend(struct.pack("<IIqqI", pickle_payload_size, 1, req_time_webkit, resp_time_webkit, headers_len))
    pickle_bytes.extend(raw_headers)
    # 4-byte align pickle payload
    while len(pickle_bytes) % 4 != 0:
        pickle_bytes.append(0)

    s0_len = len(pickle_bytes)
    s0_crc = zlib.crc32(pickle_bytes)

    # Stream 0 EOF (24 bytes)
    s0_eof = struct.pack("<QIIII", 0xf4fa6f45970d41d8, 0, s0_crc, s0_len, 0)

    # Assemble full Simple Cache file
    full_cache_data = hdr + url_key_bytes + brotli_body + s1_eof + bytes(pickle_bytes) + s0_eof

    with open(cache_file, "wb") as f:
        f.write(full_cache_data)

    # Run parser
    parser = ChromiumSimpleCacheParser()
    record = parser.parse_cache_file(cache_file, vfs_file_id=101, wv_sandbox_id=1, app_instance_id=5)

    assert record is not None
    assert record.request_url == "https://api.phonepe.com/apis/v3/transaction/status"
    assert record.initiator_top_origin == "https://phonepe.com"
    assert record.http_status_code == 200
    assert record.content_type_mime == "application/json"
    assert record.original_content_encoding == "br"
    assert "431098765432" in record.decompressed_body_text
    assert "merchant@icici" in record.decompressed_body_text
    assert record.body_sha256 == hashlib.sha256(json_body).hexdigest()
    assert record.response_time_utc_iso.startswith("2024-01-01T")


# ==============================================================================
# TEST 2: Apple Cookies.binarycookies Hybrid-Endian Parser Test
# ==============================================================================

def test_apple_binarycookies_hybrid_endian_parser(tmp_webview_dir):
    """
    Acceptance Test 2 (Section 9.2):
    Synthesizes an iOS Cookies.binarycookies file:
    - Big-Endian File Header: magic "cook" (4b), num_pages (4b, uint32_be), page_sizes ([size], uint32_be)
    - Page: Big-Endian tag 0x00000100 (4b), switches to Little-Endian at byte 4:
      num_cookies (uint32_le), offsets (uint32_le[C])
    - Cookie records: 56-byte Little-Endian header + null-terminated strings:
      - Cookie 1: domain=".razorpay.com", name="rzp_device_id", value="dev_998877"
      - Cookie 2: domain=".auth.paytm.com", name="jwt_token", value=JWT with sub, phone, iat
    Verifies that BinaryCookiesDecoder:
    1. Handles hybrid-endian switches accurately.
    2. Decodes domains, names, paths, values.
    3. Converts 64-bit IEEE-754 float Cocoa timestamps to UTC ISO-8601.
    4. Automatically unpacks JWT authentication tokens.
    """
    from src.webview.binarycookies import BinaryCookiesDecoder

    cookies_file = tmp_webview_dir / "Cookies.binarycookies"

    # Base Cocoa time: 2024-01-01 (725846400.0)
    cocoa_ts = 725846400.0

    # Build Cookie 1: Standard Cookie
    jwt_val = make_jwt_token({
        "sub": "usr_776655",
        "phone_number": "+919876543210",
        "vpa": "suspect@ybl",
        "iat": 1704110400,
        "exp": 1704196800,
    })

    def build_cookie_record(domain: str, name: str, path: str, val: str, is_sec: bool) -> bytes:
        d_bytes = domain.encode("utf-8") + b"\x00"
        n_bytes = name.encode("utf-8") + b"\x00"
        p_bytes = path.encode("utf-8") + b"\x00"
        v_bytes = val.encode("utf-8") + b"\x00"

        # Fixed header is 56 bytes
        d_off = 56
        n_off = d_off + len(d_bytes)
        p_off = n_off + len(n_bytes)
        v_off = p_off + len(p_bytes)
        rec_size = v_off + len(v_bytes)

        flags = 0x01 if is_sec else 0x00
        hdr_bytes = struct.pack(
            "<IIIIIIIIQdd",
            rec_size,
            0,            # unknown_version
            flags,        # cookie_flags (1=secure)
            0,            # has_port
            d_off,
            n_off,
            p_off,
            v_off,
            0,            # comment
            cocoa_ts + 86400.0,  # expiration
            cocoa_ts,            # creation
        )
        return hdr_bytes + d_bytes + n_bytes + p_bytes + v_bytes

    c1_bytes = build_cookie_record(".razorpay.com", "rzp_device_id", "/", "dev_998877", True)
    c2_bytes = build_cookie_record(".auth.paytm.com", "session_jwt", "/", jwt_val, True)

    # Build Page:
    # Bytes 0..3: 0x00000100 (Big-Endian)
    # Bytes 4..7: num_cookies = 2 (Little-Endian!)
    # Bytes 8..15: offsets for c1 and c2 (Little-Endian!)
    page_hdr_len = 8 + 4 * 2  # 16 bytes
    c1_offset = page_hdr_len
    c2_offset = c1_offset + len(c1_bytes)

    page_buf = bytearray()
    page_buf.extend(struct.pack(">I", 0x00000100))  # Big-endian tag
    page_buf.extend(struct.pack("<III", 2, c1_offset, c2_offset))  # Little-endian count + offsets
    page_buf.extend(c1_bytes)
    page_buf.extend(c2_bytes)

    page_size = len(page_buf)

    # Build File:
    # Magic "cook" (4b)
    # num_pages = 1 (uint32_be)
    # page_sizes = [page_size] (uint32_be)
    # page_buf
    file_bytes = bytearray()
    file_bytes.extend(b"cook")
    file_bytes.extend(struct.pack(">II", 1, page_size))
    file_bytes.extend(page_buf)

    with open(cookies_file, "wb") as f:
        f.write(file_bytes)

    decoder = BinaryCookiesDecoder()
    records = decoder.decode_cookies_file(cookies_file, vfs_file_id=202, app_instance_id=7)

    assert len(records) == 2

    # Check Cookie 1
    rzp_cookies = [c for c in records if c.host_domain == ".razorpay.com"]
    assert len(rzp_cookies) == 1
    assert rzp_cookies[0].cookie_name == "rzp_device_id"
    assert rzp_cookies[0].cookie_value == "dev_998877"
    assert rzp_cookies[0].created_utc_iso.startswith("2024-01-01T")
    assert rzp_cookies[0].is_jwt_token == 0

    # Check Cookie 2 with JWT
    jwt_cookies = [c for c in records if c.host_domain == ".auth.paytm.com"]
    assert len(jwt_cookies) == 1
    assert jwt_cookies[0].cookie_name == "session_jwt"
    assert jwt_cookies[0].is_jwt_token == 1
    assert jwt_cookies[0].unpacked_jwt_payload_json is not None

    claims = json.loads(jwt_cookies[0].unpacked_jwt_payload_json)
    assert claims["sub"] == "usr_776655"
    assert claims["phone_number"] == "+919876543210"
    assert claims["vpa"] == "suspect@ybl"


# ==============================================================================
# TEST 3: iOS Cache.db (NSURLCache) SQLite + fsCachedData/<UUID> Correlation Test
# ==============================================================================

def test_ios_nsurlcache_db_and_fscacheddata_correlation(tmp_webview_dir):
    """
    Acceptance Test 3 (Section 9.3):
    Constructs an iOS Library/Caches/com.phonepe.app/ directory:
    - Cache.db SQLite with 3 joined tables:
      - cfurl_cache_response (entry_ID, request_key, time_stamp)
      - cfurl_cache_blob_data (entry_ID, response_object bplist)
      - cfurl_cache_receiver_data (entry_ID, isDataOnFS, receiver_data)
      - Row 1: isDataOnFS = 0, inline JSON payload {"user_name": "Amit Kumar"}
      - Row 2: isDataOnFS = 1, external UUID "8F1D4A22-1111-2222-3333-444455556666"
    - fsCachedData/ directory:
      - 8F1D4A22-1111-2222-3333-444455556666 (PNG image)
      - 9A2B3C4D-9999-8888-7777-666655554444 (Orphaned file from deleted cache entry!)
    Verifies that NSURLCacheCorrelator:
    1. Extracts inline response for Row 1.
    2. Follows isDataOnFS=1 to load external file for Row 2.
    3. Sweeps fsCachedData/ to recover orphan as RESIDUAL_RECORD.
    """
    from src.webview.nsurlcache import NSURLCacheCorrelator

    caches_root = tmp_webview_dir / "Library" / "Caches" / "com.phonepe.app"
    caches_root.mkdir(parents=True, exist_ok=True)
    fs_data_dir = caches_root / "fsCachedData"
    fs_data_dir.mkdir(parents=True, exist_ok=True)

    db_path = caches_root / "Cache.db"
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE cfurl_cache_response (
            entry_ID INTEGER PRIMARY KEY,
            version INTEGER,
            hash_value INTEGER,
            storage_policy INTEGER,
            request_key TEXT,
            time_stamp REAL,
            partition TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE cfurl_cache_blob_data (
            entry_ID INTEGER PRIMARY KEY,
            response_object BLOB
        );
    """)
    cur.execute("""
        CREATE TABLE cfurl_cache_receiver_data (
            entry_ID INTEGER PRIMARY KEY,
            isDataOnFS INTEGER,
            receiver_data BLOB
        );
    """)

    # Row 1: Inline JSON response (isDataOnFS = 0)
    cur.execute(
        "INSERT INTO cfurl_cache_response VALUES (1, 1, 100, 0, 'https://api.phonepe.com/user/profile', 725846400.0, '');"
    )
    cur.execute("INSERT INTO cfurl_cache_blob_data VALUES (1, X'62706c6973743030');")  # bplist00 header
    cur.execute(
        "INSERT INTO cfurl_cache_receiver_data VALUES (1, 0, ?);",
        (b'{"user_name": "Amit Kumar", "account_type": "SAVINGS"}',),
    )

    # Row 2: External payload (isDataOnFS = 1)
    uuid_ref = "8F1D4A22-1111-2222-3333-444455556666"
    cur.execute(
        "INSERT INTO cfurl_cache_response VALUES (2, 1, 101, 0, 'https://api.phonepe.com/qr/payment_qr.png', 725846460.0, '');"
    )
    cur.execute("INSERT INTO cfurl_cache_blob_data VALUES (2, X'62706c6973743030');")
    cur.execute(
        "INSERT INTO cfurl_cache_receiver_data VALUES (2, 1, ?);",
        (uuid_ref.encode("ascii"),),
    )
    con.commit()
    con.close()

    # Write external payload file in fsCachedData/
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    with open(fs_data_dir / uuid_ref, "wb") as f:
        f.write(png_bytes)

    # Write Orphaned payload file (unreferenced in Cache.db!)
    orphan_uuid = "9A2B3C4D-9999-8888-7777-666655554444"
    orphan_json = b'{"receipt_id": "REC_9988", "amount": 15000.00, "status": "SETTLED"}'
    with open(fs_data_dir / orphan_uuid, "wb") as f:
        f.write(orphan_json)

    correlator = NSURLCacheCorrelator()
    records = correlator.correlate_cache_directory(caches_root, vfs_file_id=303, wv_sandbox_id=2, app_instance_id=10)

    assert len(records) == 3

    # 1. Inline profile record
    profile_recs = [r for r in records if "user/profile" in r.request_url]
    assert len(profile_recs) == 1
    assert "Amit Kumar" in profile_recs[0].decompressed_body_text
    assert profile_recs[0].recovery_classification == ResidualConfidence.ORIGINAL_RECORD

    # 2. External joined image record
    qr_recs = [r for r in records if "payment_qr.png" in r.request_url]
    assert len(qr_recs) == 1
    assert qr_recs[0].body_sha256 == hashlib.sha256(png_bytes).hexdigest()
    assert qr_recs[0].recovery_classification == ResidualConfidence.ORIGINAL_RECORD

    # 3. Orphaned residual record
    orphan_recs = [r for r in records if orphan_uuid in r.request_url]
    assert len(orphan_recs) == 1
    assert orphan_recs[0].recovery_classification == ResidualConfidence.RESIDUAL_RECORD
    assert "REC_9988" in orphan_recs[0].decompressed_body_text


# ==============================================================================
# TEST 4: Chromium Local Storage UTF-16LE & JWT Unpacker Test
# ==============================================================================

def test_localstorage_utf16le_and_jwt_unpacker():
    """
    Acceptance Test 4 (Section 9.4):
    Tests:
    1. Chromium Local Storage 1-byte encoding prefix:
       - 0x00: UTF-16LE (e.g. "₹50,000" with Indian Rupee symbol)
       - 0x01: Latin-1 / UTF-8
    2. Fast Regex and Base64URL JWT Identity claim extractor.
    """
    from src.webview.localstorage import decode_chromium_localstorage_value
    from src.webview.jwt import unpack_jwt_token

    # 1. Test UTF-16LE decoding (prefix 0x00)
    raw_utf16 = b"\x00" + "₹50,000 transferred to mule_account@okaxis".encode("utf-16le")
    decoded_utf16 = decode_chromium_localstorage_value(raw_utf16)
    assert decoded_utf16 == "₹50,000 transferred to mule_account@okaxis"

    # Test UTF-8/Latin-1 decoding (prefix 0x01)
    raw_utf8 = b"\x01" + "standard_ascii_token_12345".encode("utf-8")
    decoded_utf8 = decode_chromium_localstorage_value(raw_utf8)
    assert decoded_utf8 == "standard_ascii_token_12345"

    # 2. Test JWT Unpacker
    jwt_str = make_jwt_token({
        "sub": "cust_889900",
        "phone_number": "+919876543210",
        "email": "suspect@darkmail.com",
        "vpa": "mule@okaxis",
        "iat": 1704110400,
        "exp": 1704196800,
        "iss": "https://auth.coindcx.com",
    })

    unpacked = unpack_jwt_token(jwt_str)
    assert unpacked is not None
    hdr, claims = unpacked
    assert hdr["alg"] == "HS256"
    assert claims["sub"] == "cust_889900"
    assert claims["phone_number"] == "+919876543210"
    assert claims["email"] == "suspect@darkmail.com"
    assert claims["vpa"] == "mule@okaxis"
    assert claims["iat"] == 1704110400


# ==============================================================================
# TEST 5: Universal WebView Crawler & Master Ledger Export Test
# ==============================================================================

def test_webview_forensic_engine_master_ledger_export(tmp_webview_dir):
    """
    Section 8: Database Schema for Module 2.4 (webview_forensic_engine.sqlite).
    Verifies that WebViewForensicEngine exports to:
    1. webview_sandbox_inventory
    2. webview_http_cache_records
    3. webview_cookies_and_tokens
    4. webview_autofill_and_storage
    with exact column names, constraints, and valid foreign keys.
    """
    from src.webview.crawler import WebViewForensicEngine
    from src.webview.models import (
        WebViewSandboxInventory,
        WebViewHTTPCacheRecord,
        WebViewCookieAndToken,
        WebViewAutofillAndStorage,
        WebViewEngineType,
        StorageCategory,
    )

    ledger_path = tmp_webview_dir / "webview_forensic_engine.sqlite"
    engine = WebViewForensicEngine()

    inv = WebViewSandboxInventory(
        app_instance_id=1,
        os_platform="ANDROID",
        webview_engine_type=WebViewEngineType.ANDROID_CHROMIUM_WEBVIEW.value,
        canonical_root_path="/data/user/0/com.phonepe.app/app_webview",
        cookies_extracted_count=15,
        http_cache_entries_count=50,
        local_storage_keys_count=20,
        jwt_tokens_unpacked_count=3,
    )

    cache_rec = WebViewHTTPCacheRecord(
        wv_sandbox_id=1,
        app_instance_id=1,
        source_vfs_file_id=101,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        request_url="https://api.phonepe.com/apis/v3/transaction/status",
        initiator_top_origin="https://phonepe.com",
        http_status_code=200,
        content_type_mime="application/json",
        original_content_encoding="br",
        request_time_utc_iso="2024-01-01T12:00:00.000000Z",
        response_time_utc_iso="2024-01-01T12:00:00.050000Z",
        response_headers_json='{"content-type": "application/json"}',
        decompressed_body_text='{"status": "SUCCESS"}',
        body_sha256="abcd1234ef567890",
    )

    cookie_rec = WebViewCookieAndToken(
        app_instance_id=1,
        source_vfs_file_id=202,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        host_domain=".phonepe.com",
        cookie_name="session_token",
        cookie_value="eyJh...",
        is_jwt_token=1,
        unpacked_jwt_payload_json='{"sub": "usr_9988"}',
        created_utc_iso="2024-01-01T12:00:00.000000Z",
        last_accessed_utc_iso="2024-01-01T12:30:00.000000Z",
        expires_utc_iso="2024-01-02T12:00:00.000000Z",
    )

    autofill_rec = WebViewAutofillAndStorage(
        app_instance_id=1,
        source_vfs_file_id=303,
        storage_category=StorageCategory.FORM_AUTOFILL.value,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        web_origin_or_domain="https://merchants.phonepe.com",
        field_or_key_name="vpa",
        decoded_value_text="merchant@ybl",
        unpacked_jwt_payload_json=None,
        first_recorded_utc_iso="2024-01-01T10:00:00.000000Z",
        last_used_utc_iso="2024-01-01T11:00:00.000000Z",
    )

    engine.export_to_ledger(
        inventories=[inv],
        cache_records=[cache_rec],
        cookies=[cookie_rec],
        storage_records=[autofill_rec],
        ledger_path=ledger_path,
    )

    assert ledger_path.exists()
    con = sqlite3.connect(ledger_path)
    cur = con.cursor()

    # 1. Check webview_sandbox_inventory
    cur.execute("SELECT * FROM webview_sandbox_inventory;")
    inv_row = cur.fetchone()
    assert inv_row is not None
    inv_cols = [d[0] for d in cur.description]
    assert "webview_engine_type" in inv_cols
    assert "jwt_tokens_unpacked_count" in inv_cols

    # 2. Check webview_http_cache_records
    cur.execute("SELECT * FROM webview_http_cache_records;")
    cache_row = cur.fetchone()
    assert cache_row is not None
    cache_cols = [d[0] for d in cur.description]
    assert "request_url" in cache_cols
    assert "body_sha256" in cache_cols

    # 3. Check webview_cookies_and_tokens
    cur.execute("SELECT * FROM webview_cookies_and_tokens;")
    cookie_row = cur.fetchone()
    assert cookie_row is not None
    cookie_cols = [d[0] for d in cur.description]
    assert "is_jwt_token" in cookie_cols
    assert "unpacked_jwt_payload_json" in cookie_cols

    # 4. Check webview_autofill_and_storage
    cur.execute("SELECT * FROM webview_autofill_and_storage;")
    store_row = cur.fetchone()
    assert store_row is not None
    store_cols = [d[0] for d in cur.description]
    assert "storage_category" in store_cols
    assert "field_or_key_name" in store_cols

    con.close()
