"""
Acceptance Test Suite for Phase 10:
Codebase Remediation, Bilingual Hindi-English (hin+eng) OCR,
Hybrid Online/Offline Map Geocoder & Unified main.py Workstation Launcher.
"""

import io
import json
from pathlib import Path
import re
import threading
from unittest.mock import MagicMock, patch
import urllib.error
import zlib

import pytest

from main import run_self_test
from src.core.sqlite_manager import connect_forensic_sqlite
from src.geospatial_media_and_tamper.bilingual_ocr_engine import (
    BilingualOcrEngine,
    normalize_indic_text,
)
from src.geospatial_media_and_tamper.hybrid_map_geocoder import (
    HybridReverseGeocoder,
    INDIAN_GAZETTEER_HUBS,
)
from src.workstation_app.dashboard_server import ForensicDashboardHandler


def test_thread_safe_sqlite_concurrency(tmp_path):
    """
    Spawns 8 concurrent Python threads performing parallel reads and writes via
    connect_forensic_sqlite and asserts 0 OperationalError exceptions.
    """
    db_file = tmp_path / "concurrent_forensic.sqlite"
    init_conn = connect_forensic_sqlite(db_file)
    init_conn.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, worker_id INT, payload TEXT);")
    init_conn.commit()
    init_conn.close()

    exceptions: list[Exception] = []

    def worker_task(worker_id: int):
        try:
            conn = connect_forensic_sqlite(db_file, timeout=30.0)
            for i in range(15):
                conn.execute(
                    "INSERT INTO records (worker_id, payload) VALUES (?, ?);",
                    (worker_id, f"payload_{worker_id}_{i}"),
                )
                conn.commit()
                # Interleaved read
                rows = conn.execute("SELECT COUNT(*) AS cnt FROM records WHERE worker_id = ?;", (worker_id,)).fetchall()
                assert len(rows) > 0
            conn.close()
        except Exception as e:
            exceptions.append(e)

    threads = [threading.Thread(target=worker_task, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(exceptions) == 0, f"Concurrent SQLite operations failed with exceptions: {exceptions}"

    verify_conn = connect_forensic_sqlite(db_file, read_only=True)
    count_row = verify_conn.execute("SELECT COUNT(*) AS total FROM records;").fetchone()
    assert count_row["total"] == 8 * 15
    verify_conn.close()


def test_bilingual_hindi_english_ocr_and_devanagari_digits():
    """
    Tests Devanagari digit conversion to ASCII, forensic entity extraction
    for UPI receipts, PAN cards, and PNG embedded text metadata.
    """
    engine = BilingualOcrEngine()

    # 1. Hindi + English UPI Receipt with Devanagari digits
    upi_raw_text = (
        "भुगतान सफल! रु. ९५,००० यूपीआई संदर्भ: ६३१०१४८९२०११ "
        "IFSC: SBIN0001234 A/C: 9876543210"
    )
    res_upi = engine.extract_from_text(upi_raw_text)

    assert "95,000" in res_upi.normalized_ascii_text
    assert "631014892011" in res_upi.normalized_ascii_text
    assert "631014892011" in res_upi.extracted_utrs
    assert "SBIN0001234" in res_upi.extracted_ifscs
    assert 95000.0 in res_upi.extracted_amounts_inr
    assert res_upi.document_category == "UPI_BANK_RECEIPT"
    assert "DEVANAGARI" in res_upi.detected_scripts
    assert "LATIN" in res_upi.detected_scripts

    # 2. Hindi + English Income Tax PAN Card
    pan_raw_text = (
        "भारत सरकार GOVT OF INDIA\n"
        "आयकर विभाग INCOME TAX DEPARTMENT\n"
        "स्थायी खाता संख्या ABCDE1234F\n"
        "नाम / Name: RAJESH SHARMA\n"
        "पिता का नाम: VIKRAM SHARMA"
    )
    res_pan = engine.extract_from_text(pan_raw_text)

    assert "ABCDE1234F" in res_pan.extracted_pans
    assert res_pan.document_category == "INCOME_TAX_PAN"
    assert res_pan.confidence_score >= 0.90

    # 3. PNG Image with embedded UTF-8 metadata
    png_sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"\x08\x06\x00\x00\x00"
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data).to_bytes(4, "big")
    ihdr_chunk = len(ihdr_data).to_bytes(4, "big") + b"IHDR" + ihdr_data + ihdr_crc

    comment_body = "भुगतान सफल! रु. ५०००० यूपीआई संदर्भ: १२३४५६७८९०१२ IFSC: HDFC0001234"
    text_data = b"Comment\x00" + comment_body.encode("utf-8")
    text_crc = zlib.crc32(b"tEXt" + text_data).to_bytes(4, "big")
    text_chunk = len(text_data).to_bytes(4, "big") + b"tEXt" + text_data + text_crc

    iend_crc = zlib.crc32(b"IEND").to_bytes(4, "big")
    iend_chunk = (0).to_bytes(4, "big") + b"IEND" + iend_crc

    png_bytes = png_sig + ihdr_chunk + text_chunk + iend_chunk

    res_png = engine.extract_from_bytes(png_bytes)
    assert "123456789012" in res_png.extracted_utrs
    assert "HDFC0001234" in res_png.extracted_ifscs
    assert res_png.document_category == "UPI_BANK_RECEIPT"


def test_hybrid_online_and_offline_reverse_geocoder(tmp_path):
    """
    Tests offline Indian gazetteer proximity resolution, live Nominatim resolution with
    local SQLite cache hits, and network failure fallback.
    """
    cache_db = tmp_path / "test_geo_cache.sqlite"
    geocoder = HybridReverseGeocoder(cache_db_path=cache_db)

    # 1. Offline Mode with coordinates of Varanasi (25.3176, 82.9739)
    loc_offline = geocoder.resolve_location(25.3176, 82.9739, force_offline=True)
    assert not loc_offline.is_online_resolved
    assert loc_offline.resolution_source == "OFFLINE_LATLON_FALLBACK"
    assert "25.317600" in loc_offline.display_address
    assert "82.973900" in loc_offline.display_address
    assert "Varanasi" in loc_offline.display_address
    assert loc_offline.city_or_district == "Varanasi"
    assert loc_offline.state_name == "Uttar Pradesh"

    # 2. Online Mode with Mocked Nominatim HTTP response for Bengaluru
    bengaluru_json = {
        "display_name": "MG Road, Bengaluru, Karnataka, 560001, India",
        "address": {
            "city": "Bengaluru",
            "state": "Karnataka",
            "country": "India",
            "postcode": "560001",
        },
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(bengaluru_json).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        loc_online = geocoder.resolve_location(12.9716, 77.5946, force_offline=False)
        assert loc_online.is_online_resolved
        assert loc_online.resolution_source == "ONLINE_OSM_NOMINATIM"
        assert "MG Road, Bengaluru" in loc_online.display_address
        assert loc_online.city_or_district == "Bengaluru"
        assert loc_online.pincode == "560001"

    # Verify that a subsequent call hits LOCAL_SQLITE_CACHE without making an HTTP request
    loc_cached = geocoder.resolve_location(12.9716, 77.5946, force_offline=False)
    assert loc_cached.resolution_source == "LOCAL_SQLITE_CACHE"
    assert "Bengaluru" in loc_cached.display_address

    # 3. Network Failure Fallback (URLError)
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Network unreachable")):
        loc_fail = geocoder.resolve_location(26.9124, 75.7873, force_offline=False)
        assert not loc_fail.is_online_resolved
        assert loc_fail.resolution_source == "OFFLINE_LATLON_FALLBACK"
        assert "Jaipur" in loc_fail.display_address

    # Verify HTML Map generation
    html_map = geocoder.render_hybrid_map_html(
        markers=[{"lat": 25.3176, "lon": 82.9739, "label": "Varanasi Node"}]
    )
    assert "forensic-map-container" in html_map
    assert "tactical-grid-overlay" in html_map


def _dispatch_mock_request(method: str, path: str, body: dict = None) -> tuple[int, dict, str]:
    """Helper to dispatch HTTP requests directly to ForensicDashboardHandler in-memory."""
    class MockSocket:
        def __init__(self, data: bytes):
            self.r = io.BytesIO(data)
            self.w = io.BytesIO()

        def makefile(self, mode: str, bufsize: int = -1):
            if "r" in mode:
                return self.r
            return self.w

        def sendall(self, data):
            self.w.write(data)

    body_bytes = json.dumps(body).encode("utf-8") if body is not None else b""
    req_lines = [
        f"{method} {path} HTTP/1.1",
        "Host: 127.0.0.1",
        f"Content-Length: {len(body_bytes)}",
        "Content-Type: application/json",
        "",
        "",
    ]
    raw_req = "\r\n".join(req_lines).encode("utf-8") + body_bytes

    sock = MockSocket(raw_req)
    mock_server = MagicMock()
    handler = ForensicDashboardHandler(sock, ("127.0.0.1", 8765), mock_server)

    raw_resp = sock.w.getvalue().decode("utf-8", errors="replace")
    status_code = 200 if "200 OK" in raw_resp else (404 if "404" in raw_resp else 500)

    # Extract JSON or HTML payload
    parts = raw_resp.split("\r\n\r\n", 1)
    body_str = parts[1] if len(parts) > 1 else ""
    try:
        json_data = json.loads(body_str)
    except Exception:
        json_data = {}

    return status_code, json_data, body_str


def test_unified_main_and_workstation_api():
    """
    Runs self-test diagnostic from main.py and tests all API endpoints
    for HTTP 200 and schema validity using in-memory request processing.
    """
    # 1. Run CLI Self-Test diagnostic
    exit_code = run_self_test()
    assert exit_code == 0, "run_self_test() must exit with 0"

    # 2. Test GET /
    status, _, html_text = _dispatch_mock_request("GET", "/")
    assert status == 200
    assert "Bharat Analyzer" in html_text
    assert "3-Pane Hex" in html_text

    # 3. Test GET /api/status
    status, data, _ = _dispatch_mock_request("GET", "/api/status")
    assert status == 200
    assert data["status"] == "HEALTHY"
    assert data["active_modules_count"] >= 41

    # 4. Test GET /api/hex-demo
    status, hex_data, _ = _dispatch_mock_request("GET", "/api/hex-demo")
    assert status == 200
    assert "hex_view" in hex_data

    # 5. Test POST /api/chat-redline
    status, diff_data, _ = _dispatch_mock_request(
        "POST",
        "/api/chat-redline",
        {"original_text": "Bhai 50k send karo", "edited_text": "Bhai 150k hawala send karo"},
    )
    assert status == 200
    assert "<ins>" in diff_data["html_rendered_diff"]
    assert diff_data["insertions_count"] > 0

    # 6. Test GET /api/financial-sankey
    status, sankey_data, _ = _dispatch_mock_request("GET", "/api/financial-sankey")
    assert status == 200
    assert "<svg" in sankey_data["svg_markup"]

    # 7. Test POST /api/map/resolve
    status, map_data, _ = _dispatch_mock_request(
        "POST",
        "/api/map/resolve",
        {"lat": 25.3176, "lon": 82.9739, "force_offline": True},
    )
    assert status == 200
    assert map_data["city_or_district"] == "Varanasi"

    # 8. Test POST /api/ocr/analyze
    status, ocr_data, _ = _dispatch_mock_request(
        "POST",
        "/api/ocr/analyze",
        {"text": "भुगतान सफल! रु. ९५,००० यूपीआई संदर्भ: ६३१०१४८९२०११ IFSC: SBIN0001234"},
    )
    assert status == 200
    assert "631014892011" in ocr_data["extracted_utrs"]

    # 9. Test POST /api/bsa/generate
    status, bsa_data, _ = _dispatch_mock_request("POST", "/api/bsa/generate", {})
    assert status == 200
    assert "COURT MASTER COPY" in bsa_data["master_court_preview_html"]
    assert "DEFENSE DISCLOSURE COPY" in bsa_data["defense_redacted_preview_html"]


def test_zero_banned_words_audit_across_src_and_main():
    """
    Scans main.py and all Python files in src/ to verify that zero banned tokens
    (TODO, FIXME, pass as skeleton statement, NotImplemented, or the literal HTML hint word) exist.
    """
    banned_word_pattern = re.compile(r"\b(TODO|FIXME|NotImplemented|placeholder)\b", re.IGNORECASE)
    banned_pass_pattern = re.compile(r"^\s*pass\s*(#.*)?$")

    violations: list[str] = []

    # Check main.py
    main_path = Path("main.py")
    if main_path.exists():
        for i, line in enumerate(main_path.read_text(encoding="utf-8").splitlines(), 1):
            if banned_word_pattern.search(line) or banned_pass_pattern.search(line):
                violations.append(f"main.py:{i}: {line.strip()}")

    # Check all src files
    src_dir = Path("src")
    for py_file in src_dir.rglob("*.py"):
        lines = py_file.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines, 1):
            if banned_word_pattern.search(line) or banned_pass_pattern.search(line):
                violations.append(f"{py_file}:{i}: {line.strip()}")

    assert len(violations) == 0, f"Found {len(violations)} banned word violations in codebase:\n" + "\n".join(violations[:15])
