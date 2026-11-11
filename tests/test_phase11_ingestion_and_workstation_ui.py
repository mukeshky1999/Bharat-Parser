"""
Phase 11 Acceptance Test Suite: Real Evidence Ingestion, Dynamic Workstation UI,
Synchronized Hex Inspector, and Native Desktop Application Mode.
"""

import base64
import json
from pathlib import Path
import sqlite3
import sys
import zipfile

import pytest

from src.workstation_app.dashboard_server import build_desktop_app_args
from src.workstation_app.ingestion_pipeline import LiveForensicIngestEngine
from tests.test_phase10_remediation_ocr_map_app import _dispatch_mock_request


@pytest.fixture
def temp_evidence_dir(tmp_path: Path) -> Path:
    """Creates a temporary workspace directory for binary test fixtures."""
    ev_dir = tmp_path / "seized_evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    return ev_dir


def test_live_forensic_ingest_engine_sqlite(temp_evidence_dir: Path):
    """
    Tests live ingestion of a real SQLite database containing UPI transaction rows.
    Verifies Dual SHA-256 (Product A and Product B), table enumeration, and UTR extraction.
    """
    db_file = temp_evidence_dir / "tez_paisa_mule.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE upi_ledger (id INTEGER PRIMARY KEY, utr TEXT, amount REAL, vpa TEXT);")
    conn.execute("INSERT INTO upi_ledger (utr, amount, vpa) VALUES ('631014892011', 95000.0, 'rsharma@sbi');")
    conn.execute("INSERT INTO upi_ledger (utr, amount, vpa) VALUES ('631014892012', 47500.0, 'amit.kumar@icici');")
    conn.commit()
    conn.close()

    engine = LiveForensicIngestEngine()
    result = engine.ingest_local_path(db_file, "Seized Suspect Storage DB")

    assert result["success"] is True
    assert result["total_files"] == 1
    assert result["total_bytes"] > 0
    assert len(result["product_a_sha256"]) == 64
    assert len(result["product_b_sha256"]) == 64
    assert len(result["merkle_root"]) == 64
    assert result["discovered_sqlite_tables"] >= 1
    assert "631014892011" in result["extracted_utrs"]
    assert "631014892012" in result["extracted_utrs"]

    # Verify dynamic bootstrap for the newly created device profile
    new_dev_id = result["device_id"]
    boot_data = engine.get_device_bootstrap(new_dev_id)
    assert boot_data["case_metadata"]["active_device_id"] == new_dev_id
    assert boot_data["case_metadata"]["kpi_metrics"]["total_vfs_nodes"] == 1
    assert boot_data["case_metadata"]["dual_sha256"]["product_a_container"] == result["product_a_sha256"]


def test_live_forensic_ingest_archive_with_spoofing(temp_evidence_dir: Path):
    """
    Tests ingestion of an archive file (.zip) containing KYC text and an extension-spoofed file.
    Verifies that a file with SQLite header disguised as a .png is flagged with is_extension_spoofed=True.
    """
    zip_path = temp_evidence_dir / "seized_extraction.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("kyc_info.txt", "Name: Rajesh Sharma\nPAN: ABCDE1234F\nTRC20: TYk9q8WwJ3x4rZ5m1n8L2pQ9s7V64xLpAB")
        # Disguised SQLite file named as a PNG image
        fake_png_bytes = b"SQLite format 3\x00" + b"\x00" * 96
        zf.writestr("hidden_wallet.png", fake_png_bytes)

    engine = LiveForensicIngestEngine()
    result = engine.ingest_archive(zip_path, "Seized ZIP Archive Extraction")

    assert result["success"] is True
    assert result["total_files"] == 2
    assert result["spoofed_files_count"] == 1
    assert "ABCDE1234F" in result["extracted_pans"]
    assert "TYk9q8WwJ3x4rZ5m1n8L2pQ9s7V64xLpAB" in result["extracted_crypto_addrs"]

    # Check the specific ingested file record
    profile = engine.active_devices[result["device_id"]]
    spoofed_rec = next((r for r in profile.ingested_files if r.is_extension_spoofed), None)
    assert spoofed_rec is not None
    assert spoofed_rec.file_name == "hidden_wallet.png"
    assert spoofed_rec.inferred_type == "SQLITE_3_DATABASE"


def test_ingest_local_path_and_upload_api(temp_evidence_dir: Path):
    """
    Tests POST /api/ingest/local-path and POST /api/ingest/upload-file REST API endpoints.
    """
    # 1. Test POST /api/ingest/local-path
    test_db = temp_evidence_dir / "api_test.db"
    conn = sqlite3.connect(test_db)
    conn.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY, pan TEXT);")
    conn.execute("INSERT INTO accounts (pan) VALUES ('ABCDE9999Z');")
    conn.commit()
    conn.close()

    status, res_local, _ = _dispatch_mock_request(
        "POST",
        "/api/ingest/local-path",
        {"source_path": str(test_db), "case_name": "API Seized Handset DB"},
    )
    assert status == 200
    assert res_local["success"] is True
    assert "ABCDE9999Z" in res_local["extracted_pans"]
    assert len(res_local["product_a_sha256"]) == 64

    # 2. Test POST /api/ingest/upload-file via base64 stream
    raw_evidence = b"Confidential Mule Note | UTR: 631099887766 | PAN: BKRPK1234D"
    b64_evidence = base64.b64encode(raw_evidence).decode("utf-8")

    status, res_upload, _ = _dispatch_mock_request(
        "POST",
        "/api/ingest/upload-file",
        {
            "file_name": "mule_ledger.txt",
            "file_base64": b64_evidence,
            "case_name": "Streamed Upload File",
        },
    )
    assert status == 200
    assert res_upload["success"] is True
    assert "631099887766" in res_upload["extracted_utrs"]
    assert "BKRPK1234D" in res_upload["extracted_pans"]

    # 3. Test dynamic bootstrap retrieval for the uploaded device
    dev_id = res_upload["device_id"]
    status, boot_data, _ = _dispatch_mock_request("GET", f"/api/workspace/bootstrap?device_id={dev_id}")
    assert status == 200
    assert boot_data["case_metadata"]["active_device_id"] == dev_id
    assert boot_data["case_metadata"]["kpi_metrics"]["total_vfs_nodes"] == 1


def test_bookmarks_and_device_selection_api():
    """
    Tests GET /api/bookmarks, POST /api/bookmarks/toggle, and POST /api/case/select-device.
    """
    # 1. Toggle bookmark
    status, res_toggle, _ = _dispatch_mock_request(
        "POST",
        "/api/bookmarks/toggle",
        {
            "item_id": "TEST-EVT-01",
            "item_type": "TIMELINE_EVENT",
            "caption": "Critical UTR transfer event",
        },
    )
    assert status == 200
    assert res_toggle["success"] is True
    assert res_toggle["action"] in ("ADDED", "REMOVED")

    # 2. Query bookmarks list
    status, bmk_list, _ = _dispatch_mock_request("GET", "/api/bookmarks")
    assert status == 200
    assert isinstance(bmk_list["bookmarked_exhibits"], list)

    # 3. Select active device
    status, sel_res, _ = _dispatch_mock_request("POST", "/api/case/select-device", {"device_id": "DEV-01"})
    assert status == 200
    assert sel_res["success"] is True
    assert sel_res["selected_device_id"] == "DEV-01"


def test_hex_inspection_with_64_byte_stream():
    """
    Tests GET /api/timeline-hex and verifies that raw_hex_all (128 hex chars = 64 bytes)
    is returned for client-side Data Interpreter calculation.
    """
    status, hex_data, _ = _dispatch_mock_request("GET", "/api/timeline-hex?event_id=EVT-1001")
    assert status == 200
    assert "raw_hex_all" in hex_data
    assert len(hex_data["raw_hex_all"]) == 128
    assert "hex_rows" in hex_data
    assert len(hex_data["hex_rows"]) == 4
    assert hex_data["sqlite_page"] > 0
    assert "data_interpreter" in hex_data


def test_ocr_analyze_text_and_image():
    """
    Tests POST /api/ocr/analyze with both Hindi/English bilingual text and a 1x1 image stream.
    """
    # 1. Text analysis
    sample_text = "भुगतान सफल! रु. ९५,००० यूपीआई संदर्भ: ६३१०१४८९२०११ IFSC: SBIN0001234 A/C: 9876543210"
    status, text_res, _ = _dispatch_mock_request("POST", "/api/ocr/analyze", {"text": sample_text})
    assert status == 200
    assert "631014892011" in text_res["extracted_utrs"]
    assert "SBIN0001234" in text_res["extracted_ifscs"]
    assert 95000.0 in text_res["extracted_amounts_inr"]
    assert "DEVANAGARI" in text_res["detected_scripts"]

    # 2. Image stream analysis
    png_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
        b"\x1f\x15c4\x00\x00\x00\nIDATx\x9cc`\x00\x00\x00\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    b64_png = base64.b64encode(png_bytes).decode("utf-8")
    status, img_res, _ = _dispatch_mock_request(
        "POST", "/api/ocr/analyze", {"image_base64": b64_png, "file_name": "receipt_exhibit.png"}
    )
    assert status == 200
    assert img_res["engine_used"] in ("TESSERACT_HIN_ENG", "EASYOCR_HI_EN", "PURE_PYTHON_STREAM_SCANNER")


def test_keybroker_unlock_and_bsa_generate():
    """
    Tests POST /api/keybroker/unlock and POST /api/bsa/generate.
    """
    # 1. Test keybroker unlock with correct passphrase
    status, unlock_res, _ = _dispatch_mock_request(
        "POST", "/api/keybroker/unlock", {"vault_id": "VAULT-01", "candidate_pass": "Vikram@786"}
    )
    assert status == 200
    assert unlock_res["success"] is True
    assert unlock_res["status"] == "UNLOCKED_DECRYPTED"

    # 2. Test keybroker unlock with incorrect passphrase
    status, wrong_res, _ = _dispatch_mock_request(
        "POST", "/api/keybroker/unlock", {"vault_id": "VAULT-01", "candidate_pass": "WrongPass@123"}
    )
    assert status == 200
    assert wrong_res["success"] is False

    # 3. Test BSA Section 63 Statutory Certificate Generation
    status, bsa_res, _ = _dispatch_mock_request("POST", "/api/bsa/generate", {})
    assert status == 200
    assert "Section 63(4)(c)" in bsa_res["statutory_caption"]
    assert "Section 63(4)(c)" in bsa_res["master_court_preview_html"]
    assert "Bharatiya Sakshya Adhiniyam" in bsa_res["master_court_preview_html"]
    assert "DEFENSE DISCLOSURE COPY" in bsa_res["defense_redacted_preview_html"]
    assert "VICTIM_PROTECTED" in bsa_res["defense_redacted_preview_html"]


def test_static_assets_serving():
    """
    Tests serving of index.html, styles.css, and app.js with appropriate MIME types and content.
    """
    # 1. GET /
    status, _, html_str = _dispatch_mock_request("GET", "/")
    assert status == 200
    assert "BHARAT ANALYZER" in html_str
    assert "id=\"btn-open-ingest-modal\"" in html_str
    assert "id=\"ingest-modal\"" in html_str
    assert "id=\"ocr-image-dropzone\"" in html_str

    # 2. GET /static/styles.css
    status, _, css_str = _dispatch_mock_request("GET", "/static/styles.css")
    assert status == 200
    assert ".btn-ingest-trigger" in css_str
    assert ".modal-overlay" in css_str
    assert ".redline-ins" in css_str
    assert ".entropy-skyline-wrap" in css_str

    # 3. GET /static/app.js
    status, _, js_str = _dispatch_mock_request("GET", "/static/app.js")
    assert status == 200
    assert "initIngestModal" in js_str
    assert "initDeviceSwitcher" in js_str
    assert "updateDataInterpreterFromBuffer" in js_str


def test_desktop_app_args_builder(tmp_path: Path):
    """
    Verifies that build_desktop_app_args configures isolated --user-data-dir
    and correct Chromium flags to guarantee standalone native application window mode.
    """
    fake_browser = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    target_url = "http://127.0.0.1:8765"
    custom_profile = tmp_path / "test_browser_profile"

    args = build_desktop_app_args(fake_browser, target_url, custom_profile)

    assert args[0] == fake_browser
    assert f"--app={target_url}" in args
    assert f"--user-data-dir={custom_profile.resolve()}" in args
    assert "--window-size=1520,920" in args
    assert "--window-position=50,50" in args
    assert "--disable-extensions" in args
    assert "--disable-plugins" in args
    assert "--no-first-run" in args
    assert "--no-default-browser-check" in args
    assert "--enable-features=OverlayScrollbar" in args
    assert custom_profile.is_dir()


def test_ncrp_download_csv_route():
    """
    Tests GET /api/ncrp/download-csv endpoint.
    Verifies HTTP 200, Content-Disposition attachment, and Section 91 CrPC CSV payload with mule accounts.
    """
    status, _, csv_text = _dispatch_mock_request("GET", "/api/ncrp/download-csv")
    assert status == 200
    assert "Row ID,Account / Identifier,IFSC / Network,Holder Name,VPA / Address,Safeguard Status,Disputed Amount (INR),Action Directive" in csv_text
    assert "301928401928" in csv_text
    assert "9876543210" in csv_text
    assert "LOCKED_VICTIM_ACCOUNT" in csv_text
    assert "FREEZE_LIEN_IMMEDIATE" in csv_text
    assert "PROTECT_NO_FREEZE" in csv_text


def test_device_switching_hardware_profiles():
    """
    Tests dynamic bootstrap response across DEV-01 (Samsung Android 14) and DEV-02 (Apple iPhone 15 Pro).
    Verifies that hardware profiles, IMEIs, and device-specific timeline events update synchronously.
    """
    # 1. Device 01: Samsung S24 Ultra
    status1, boot1, _ = _dispatch_mock_request("GET", "/api/workspace/bootstrap?device_id=DEV-01")
    assert status1 == 200
    meta1 = boot1["case_metadata"]
    assert meta1["active_device_id"] == "DEV-01"
    assert "Samsung" in meta1["hardware_profile"]["device_model"]
    assert meta1["hardware_profile"]["imei_1"] == "864291060192837"
    assert meta1["dual_sha256"]["product_a_container"].startswith("e3b0c442")
    assert any(e["event_id"] == "EVT-1001" for e in boot1["timeline_events"])

    # 2. Device 02: Apple iPhone 15 Pro
    status2, boot2, _ = _dispatch_mock_request("GET", "/api/workspace/bootstrap?device_id=DEV-02")
    assert status2 == 200
    meta2 = boot2["case_metadata"]
    assert meta2["active_device_id"] == "DEV-02"
    assert "iPhone 15 Pro" in meta2["hardware_profile"]["device_model"]
    assert meta2["hardware_profile"]["imei_1"] == "354928104829104"
    assert meta2["dual_sha256"]["product_a_container"].startswith("4a5e1e53")
    assert any(e["event_id"] == "EVT-IOS-01" for e in boot2["timeline_events"])
    assert any(e["event_id"] == "EVT-IOS-02" for e in boot2["timeline_events"])


def test_all_18_forensic_groups_registry():
    """
    Verifies that /api/workspace/bootstrap exports all 18 canonical Forensic Groups
    (G01 to G18) with non-zero artifact counts, group codes, and descriptive labels.
    """
    status, boot, _ = _dispatch_mock_request("GET", "/api/workspace/bootstrap")
    assert status == 200
    groups = boot["forensic_groups_registry"]
    assert len(groups) == 18

    group_codes = [g["code"] for g in groups]
    for i in range(1, 19):
        expected_code = f"G{i:02d}"
        assert expected_code in group_codes, f"Missing canonical group code {expected_code}"

    for g in groups:
        assert len(g["name"]) > 0
        assert len(g["desc"]) > 0
        assert g["count"] > 0


def test_financial_ledger_transactions_and_sankey():
    """
    Verifies that /api/workspace/bootstrap exports the 5-stage audited financial laundering
    ledger transactions (Victim -> Mule 1 -> Mule 2 -> Crypto P2P -> TRC20 -> XMR) and the Sankey SVG.
    """
    status, boot, _ = _dispatch_mock_request("GET", "/api/workspace/bootstrap")
    assert status == 200
    assert "initial_sankey_svg" in boot
    assert "<svg" in boot["initial_sankey_svg"]

    txs = boot["financial_ledger_transactions"]
    assert len(txs) == 5
    assert any(t["tx_id"] == "TX-101" and t["utr"] == "631014892011" for t in txs)
    assert any(t["tx_id"] == "TX-103" and "Binance P2P" in t["credited_entity"] for t in txs)
    assert any(t["tx_id"] == "TX-104" and "TronLink" in t["credited_entity"] for t in txs)
    assert any(t["tx_id"] == "TX-105" and "FixedFloat" in t["credited_entity"] for t in txs)


def test_data_interpreter_timeline_hex_endpoint():
    """
    Verifies that /api/timeline-hex calculates and returns the 12+ format data interpreter fields
    including uint8, int8, uint16/32/64, float32/64, sqlite_varint, sleb128, and apple_cocoa_epoch.
    """
    status, hex_data, _ = _dispatch_mock_request("GET", "/api/timeline-hex?event_id=EVT-1001")
    assert status == 200
    assert "data_interpreter" in hex_data
    interp = hex_data["data_interpreter"]

    expected_keys = [
        "uint8", "int8", "uint16_le", "uint16_be", "int32_le", "uint32_le",
        "int64_le", "uint64_le", "sqlite_varint", "sleb128", "float32_le",
        "float64_le", "unix_epoch_sec", "unix_epoch_ms", "apple_cocoa_epoch",
        "hex_representation", "utf8_string",
    ]
    for k in expected_keys:
        assert k in interp, f"Missing data interpreter key: {k}"


def test_bookmarked_exhibits_in_bsa_generation():
    """
    Verifies that bookmarked artifacts dynamically flow into Section 63 BSA certificate generation.
    """
    status_toggle, res_toggle, _ = _dispatch_mock_request(
        "POST",
        "/api/bookmarks/toggle",
        {
            "item_id": "EX-AUDIT-BSA-01",
            "item_type": "TIMELINE_EVENT",
            "caption": "Paisa.db transfer record UTR 631014892011",
            "file_path": "/data/data/com.google.android.apps.nbu.paisa.user/databases/paisa.db",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    )
    assert status_toggle == 200
    assert res_toggle["success"] is True

    status_bsa, bsa_res, _ = _dispatch_mock_request("POST", "/api/bsa/generate", {})
    assert status_bsa == 200
    court_html = bsa_res["master_court_preview_html"]
    assert "Section 63(4)(c)" in court_html
    assert "e3b0c442" in court_html or "EX-AUDIT-BSA-01" in court_html or "Paisa.db" in court_html
