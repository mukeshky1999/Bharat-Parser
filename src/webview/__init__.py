"""
Universal Embedded WebView Crawler & Forensic Decoders:
Chromium Simple Cache (*_0), Apple Cookies.binarycookies, iOS Cache.db (NSURLCache)
& fsCachedData correlation, Chromium/iOS Local Storage, and Base64URL JWT Identity Unpacker.
"""

from src.webview.binarycookies import BinaryCookiesDecoder
from src.webview.crawler import WebViewForensicEngine
from src.webview.jwt import extract_jwt_claims_json, unpack_jwt_token
from src.webview.localstorage import (
    decode_chromium_localstorage_value,
    decode_ios_localstorage_blob,
)
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

__all__ = [
    "WebViewEngineType",
    "StorageCategory",
    "WebViewSandboxInventory",
    "WebViewHTTPCacheRecord",
    "WebViewCookieAndToken",
    "WebViewAutofillAndStorage",
    "ChromiumSimpleCacheParser",
    "BinaryCookiesDecoder",
    "NSURLCacheCorrelator",
    "WebViewForensicEngine",
    "unpack_jwt_token",
    "extract_jwt_claims_json",
    "decode_chromium_localstorage_value",
    "decode_ios_localstorage_blob",
]
