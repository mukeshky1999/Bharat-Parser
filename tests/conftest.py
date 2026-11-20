"""
Bharat Forensic Suite — Unified Root Pytest Configuration and Fixtures.
Provides environment bootstrapping, test evidence discovery, and test helpers.
"""

import io
import os
import sqlite3
import struct
import sys
import zipfile
from pathlib import Path
import pytest

# Clean out any stale search paths
sys.path[:] = [p for p in sys.path if "OneDrive" not in p and "AcquireX" not in p]

# Ensure root directory is at the head of sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Support force_zip64 in ZipFile for generating real binary ZIP64 test archives
orig_zip_init = zipfile.ZipFile.__init__
orig_zip_write_end = zipfile.ZipFile._write_end_record


def patched_zip_init(self, *args, **kwargs):
    self._force_zip64 = kwargs.pop("force_zip64", False)
    orig_zip_init(self, *args, **kwargs)


def patched_zip_write_end(self):
    if getattr(self, "_force_zip64", False):
        orig_limit = getattr(zipfile, "ZIP_FILECOUNT_LIMIT", 65535)
        zipfile.ZIP_FILECOUNT_LIMIT = 0
        try:
            return orig_zip_write_end(self)
        finally:
            zipfile.ZIP_FILECOUNT_LIMIT = orig_limit
    return orig_zip_write_end(self)


zipfile.ZipFile.__init__ = patched_zip_init
zipfile.ZipFile._write_end_record = patched_zip_write_end


@pytest.fixture(scope="session")
def test_evidence_dir():
    """Returns path to the test evidence directory; skips when it is absent (not tracked in git)."""
    path = ROOT_DIR / "test_evidence"
    if not path.is_dir():
        pytest.skip("test_evidence/ not found; run scripts/generate_forensic_test_data.py")
    return path


@pytest.fixture(autouse=True)
def _allow_api_without_token(monkeypatch):
    """The API fails closed without BHARAT_API_TOKEN. Tests that do not exercise the token run with the explicit
    development opt-out; tests that set a token themselves still get the token check."""
    if not os.environ.get("BHARAT_API_TOKEN"):
        monkeypatch.setenv("BHARAT_API_ALLOW_NO_TOKEN", "1")
