"""
Domain Models and Enums for Embedded WebView Forensics.
Adheres strictly to Specification Section 8 and AGENTS.md Forensic Invariants.
"""

from dataclasses import dataclass
from enum import Enum, unique
from typing import Optional

from src.core.enums import ResidualConfidence


@unique
class WebViewEngineType(str, Enum):
    """Classification of the embedded WebView engine."""
    ANDROID_CHROMIUM_WEBVIEW = "ANDROID_CHROMIUM_WEBVIEW"
    IOS_WKWEBVIEW = "IOS_WKWEBVIEW"
    IOS_NSURLCACHE = "IOS_NSURLCACHE"


@unique
class StorageCategory(str, Enum):
    """Classification of WebView storage mechanisms."""
    FORM_AUTOFILL = "FORM_AUTOFILL"
    LOCAL_STORAGE = "LOCAL_STORAGE"
    SESSION_STORAGE = "SESSION_STORAGE"
    INDEXED_DB = "INDEXED_DB"
    ITP_DOMAIN_OBSERVATION = "ITP_DOMAIN_OBSERVATION"


@dataclass(slots=True)
class WebViewSandboxInventory:
    """Discovered embedded WebView sandbox profile."""
    app_instance_id: int
    os_platform: str
    webview_engine_type: str
    canonical_root_path: str
    cookies_extracted_count: int = 0
    http_cache_entries_count: int = 0
    local_storage_keys_count: int = 0
    jwt_tokens_unpacked_count: int = 0
    wv_sandbox_id: Optional[int] = None


@dataclass(slots=True)
class WebViewHTTPCacheRecord:
    """Decoded HTTP cache entry from Simple Cache (*_0) or iOS Cache.db."""
    wv_sandbox_id: int
    app_instance_id: int
    source_vfs_file_id: int
    recovery_classification: ResidualConfidence
    request_url: str
    initiator_top_origin: Optional[str] = None
    http_status_code: Optional[int] = None
    content_type_mime: Optional[str] = None
    original_content_encoding: Optional[str] = None
    request_time_utc_iso: Optional[str] = None
    response_time_utc_iso: Optional[str] = None
    response_headers_json: Optional[str] = None
    decompressed_body_text: Optional[str] = None
    body_sha256: Optional[str] = None
    cache_record_uid: Optional[int] = None


@dataclass(slots=True)
class WebViewCookieAndToken:
    """Extracted cookie or unpacked JWT token."""
    app_instance_id: int
    source_vfs_file_id: int
    recovery_classification: ResidualConfidence
    host_domain: str
    cookie_name: str
    cookie_value: Optional[str] = None
    is_jwt_token: int = 0
    unpacked_jwt_payload_json: Optional[str] = None
    created_utc_iso: Optional[str] = None
    last_accessed_utc_iso: Optional[str] = None
    expires_utc_iso: Optional[str] = None
    cookie_uid: Optional[int] = None


@dataclass(slots=True)
class WebViewAutofillAndStorage:
    """Autofill form inputs, Local Storage, Session Storage, and IndexedDB records."""
    app_instance_id: int
    source_vfs_file_id: int
    storage_category: str
    recovery_classification: ResidualConfidence
    field_or_key_name: str
    web_origin_or_domain: Optional[str] = None
    decoded_value_text: Optional[str] = None
    unpacked_jwt_payload_json: Optional[str] = None
    first_recorded_utc_iso: Optional[str] = None
    last_used_utc_iso: Optional[str] = None
    storage_row_uid: Optional[int] = None
