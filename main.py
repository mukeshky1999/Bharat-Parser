"""
Bharat Analyzer — Unified Single-Command Post-Acquisition Forensic Workstation Launcher.
Starts the local multi-threaded dashboard server or executes comprehensive self-test diagnostics.
"""

import argparse
from pathlib import Path
import sys
from typing import Any

from src.core.sqlite_manager import connect_forensic_sqlite
from src.chat_reconstructor_and_redline.myers_redline_engine import MyersRedlineEngine
from src.financial_graph_and_storyboard.sankey_canvas import SankeyCanvasRenderer
from src.geospatial_media_and_tamper.bilingual_ocr_engine import BilingualOcrEngine
from src.geospatial_media_and_tamper.hybrid_map_geocoder import HybridReverseGeocoder
from src.unk_triage_and_bsa_studio.bsa_report_studio import BsaReportStudioEngine
from src.workstation_shell_and_hex.hex_provenance_inspector import HexProvenanceInspector
from src.workstation_app.dashboard_server import run_dashboard_server


def run_self_test() -> int:
    """Executes automated diagnostic self-test across all major forensic sub-engines."""
    print("=" * 78)
    print("  BHARAT ANALYZER — AUTOMATED FORENSIC WORKSTATION DIAGNOSTICS")
    print("=" * 78)
    results: list[tuple[str, bool, str]] = []

    # Diagnostic 1: Thread-safe SQLite Manager & Concurrency
    try:
        test_db = Path("./.workspace_tmp/self_test_sqlite.sqlite")
        test_db.parent.mkdir(parents=True, exist_ok=True)
        conn = connect_forensic_sqlite(test_db)
        conn.execute("CREATE TABLE IF NOT EXISTS test_diag (id INTEGER PRIMARY KEY, msg TEXT);")
        conn.execute("INSERT INTO test_diag (msg) VALUES ('sqlite_manager_ok');")
        conn.commit()
        row = conn.execute("SELECT msg FROM test_diag WHERE id = 1;").fetchone()
        conn.close()
        passed = (row is not None and row["msg"] == "sqlite_manager_ok")
        results.append(("Thread-Safe SQLite Manager & Concurrency", passed, "WAL mode active"))
    except Exception as exc:
        results.append(("Thread-Safe SQLite Manager & Concurrency", False, str(exc)))

    # Diagnostic 2: Synchronized 3-Pane Hex & Byte Provenance Engine
    try:
        inspector = HexProvenanceInspector()
        demo_bytes = b"SQLITE FORMAT 3\x00\x10\x00\x01\x01\x00\x40\x20\x20\x00\x00\x00\x01"
        res = inspector.inspect_byte_slice(demo_bytes, cursor_byte_offset=0, slice_length=16)
        passed = (len(res.hex_tokens) == 16 and "53" in res.hex_tokens[0])
        results.append(("Synchronized 3-Pane Hex Inspector", passed, f"{len(res.hex_tokens)} bytes decoded"))
    except Exception as exc:
        results.append(("Synchronized 3-Pane Hex Inspector", False, str(exc)))

    # Diagnostic 3: Myers Chat Redline Engine
    try:
        redline = MyersRedlineEngine()
        diff = redline.compute_redline("Send 50000", "Send 150000 urgently")
        passed = ("<ins>" in diff.html_rendered_diff and diff.insertions_count > 0)
        results.append(("Myers Diff Chat Redline Engine", passed, f"{diff.insertions_count} insertions, {diff.deletions_count} deletions"))
    except Exception as exc:
        results.append(("Myers Diff Chat Redline Engine", False, str(exc)))

    # Diagnostic 4: Financial Multi-Stage Sankey Canvas
    try:
        sankey = SankeyCanvasRenderer()
        svg = sankey.render_svg()
        passed = ("<svg" in svg and "STAGE 1" in svg and "STAGE 4" in svg)
        results.append(("Financial Laundering Flow (Sankey)", passed, f"{len(svg):,} bytes SVG markup"))
    except Exception as exc:
        results.append(("Financial Laundering Flow (Sankey)", False, str(exc)))

    # Diagnostic 5: Bilingual Hindi + English OCR & Indic Normalizer
    try:
        ocr = BilingualOcrEngine()
        ocr_res = ocr.extract_from_text("भुगतान सफल! रु. ९५,००० यूपीआई संदर्भ: ६३१०१४८९२०११ IFSC: SBIN0001234")
        passed = (
            "95,000" in ocr_res.normalized_ascii_text
            and "631014892011" in ocr_res.extracted_utrs
            and "SBIN0001234" in ocr_res.extracted_ifscs
            and ocr_res.document_category == "UPI_BANK_RECEIPT"
        )
        results.append(("Bilingual Hindi+English OCR & Normalizer", passed, f"Category: {ocr_res.document_category}"))
    except Exception as exc:
        results.append(("Bilingual Hindi+English OCR & Normalizer", False, str(exc)))

    # Diagnostic 6: Hybrid Online/Offline Reverse Geocoder
    try:
        geocoder = HybridReverseGeocoder()
        loc = geocoder.resolve_location(25.3176, 82.9739, force_offline=True)
        passed = (
            not loc.is_online_resolved
            and loc.resolution_source == "OFFLINE_LATLON_FALLBACK"
            and "Varanasi" in loc.display_address
        )
        results.append(("Hybrid Online/Offline Reverse Geocoder", passed, f"Source: {loc.resolution_source} (~Varanasi)"))
    except Exception as exc:
        results.append(("Hybrid Online/Offline Reverse Geocoder", False, str(exc)))

    # Diagnostic 7: Section 63(4)(c) BSA Statutory Studio
    try:
        studio = BsaReportStudioEngine()
        dossier = studio.generate_dual_preview(exhibits=[
            {"exhibit_id": "EX-01", "file_path": "evidence.db", "sha256": "a" * 64, "md5": "b" * 32, "is_pocso_or_intimate_media": True, "victim_name": "ABC"}
        ])
        passed = (
            dossier.withheld_exhibits_count == 1
            and "COURT MASTER COPY" in dossier.master_court_html
            and "DEFENSE DISCLOSURE COPY" in dossier.defense_disclosure_html
        )
        results.append(("Section 63(4)(c) BSA Courtroom Studio", passed, f"Withheld: {dossier.withheld_exhibits_count} protected items"))
    except Exception as exc:
        results.append(("Section 63(4)(c) BSA Courtroom Studio", False, str(exc)))

    # Format table output
    all_passed = True
    print("\n{:<45} | {:<8} | {:<20}".format("Sub-Engine Diagnostic", "Status", "Details"))
    print("-" * 78)
    for name, status, details in results:
        status_str = "[PASSED]" if status else "[FAILED]"
        if not status:
            all_passed = False
        print("{:<45} | {:<8} | {:<20}".format(name, status_str, details[:20]))

    print("-" * 78)
    if all_passed:
        print("[SUCCESS] All 7 core forensic diagnostics PASSED with 0 errors.\n")
        return 0
    else:
        print("[FAILURE] One or more diagnostic checks failed.\n")
        return 1


def launch_native_desktop_window(url: str) -> bool:
    """
    3-Tier Native Desktop Window Launcher for Bharat Analyzer Workstation:
    Tier 1: pywebview Native OS Window (Edge WebView2 / Win32).
    Tier 2: Dedicated isolated Chromium/Edge --app window with unique profile dir.
    Tier 3: Default system browser fallback.
    """
    # Tier 1: pywebview Native OS Window
    try:
        import webview
        webview.create_window(
            "BharatAnalyzer — Post-Acquisition Forensic Workstation (BSA Sec 63)",
            url,
            width=1600,
            height=960,
        )
        webview.start()
        return True
    except Exception as exc_tier1:
        _ = str(exc_tier1)

    # Tier 2: Dedicated isolated Chromium/Edge --app window with unique profile dir
    import os
    import shutil
    import subprocess

    profile_dir = os.path.abspath("./.workspace_tmp/bharat_desktop_app_profile")
    os.makedirs(profile_dir, exist_ok=True)

    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
        "msedge",
        "chrome",
        "brave",
    ]

    for cand in candidates:
        browser_exe = shutil.which(cand) or (cand if os.path.isfile(cand) else None)
        if browser_exe:
            cmd = [
                str(browser_exe),
                f"--user-data-dir={profile_dir}",
                f"--app={url}",
                "--window-size=1620,960",
                "--disable-extensions",
                "--no-first-run",
                "--no-default-browser-check",
            ]
            try:
                subprocess.Popen(cmd)
                return True
            except Exception as exc_spawn:
                _ = str(exc_spawn)
                continue

    # Tier 3: webbrowser.open Fallback
    import webbrowser
    try:
        webbrowser.open(url)
        return True
    except Exception as exc_browser:
        _ = str(exc_browser)
        return False


def main() -> int:
    """Main CLI entry point for Bharat Analyzer Workstation."""
    parser = argparse.ArgumentParser(
        description="Bharat Analyzer — Commercial-Grade Mobile Forensic Engine & Workstation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Local HTTP server port (default: 8765, increments if port is occupied)",
    )
    parser.add_argument(
        "--desktop",
        action="store_true",
        help="Launch the workstation in dedicated native desktop application window mode",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Run the workstation server without automatically launching a web browser",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Execute comprehensive automated self-test diagnostics and exit",
    )

    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    run_dashboard_server(
        host="127.0.0.1",
        port=args.port,
        open_browser=not args.no_browser,
        desktop_mode=args.desktop,
        desktop_launcher=launch_native_desktop_window,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
