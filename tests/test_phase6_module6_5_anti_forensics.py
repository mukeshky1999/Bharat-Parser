"""
Test Suite: Phase 6, Module 6.5 — The Anti-Forensics, Tamper Detection, Root/Jailbreak,
Clock Manipulation, Mock GPS & Indian Banking Trojan/Overlay Audit Engine.
Covers:
  - Sub-Engine 6.5A: Magisk Root Policies, Zygisk Denylist & Repackaged Disguised Manager Unmasking.
  - Sub-Engine 6.5B: Monotonic ROWID Clock-Rollback ("Time-Travel") Inversion & True Bracketing.
  - Sub-Engine 6.5C: sqlite_sequence Tail Deletion Gaps & Evidence Wiping Detection.
  - Sub-Engine 6.5D: Location Spoofing, Mock GPS & Multi-Sensor Contradictions.
  - Sub-Engine 6.5E: Sideloaded APK Telegram-Bot C2 Unpacking, USSD *401* Hijacks & AnyDesk Traces.
Complies with Phase 6 Module 6.5 Specification and AGENTS.md Constitution.
"""

import json
import os
from pathlib import Path
import sqlite3
import zipfile
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.antiforensics.models import (
    IntegrityFindingCategory,
    TamperCategory,
    SpoofMethod,
    ThreatCategory,
    OSIntegrityAuditRecord,
    ClockTamperGapRecord,
    LocationSpoofContradictionRecord,
    MalwareThreatRecord,
    extract_telegram_c2,
    parse_ussd_forwarding,
    parse_anydesk_trace_events,
)
from src.antiforensics.integrity_auditor import OSIntegrityAuditor
from src.antiforensics.clock_gap_detector import ClockTamperGapDetector
from src.antiforensics.location_spoof_auditor import LocationSpoofAuditor
from src.antiforensics.malware_auditor import MalwareRemoteAccessAuditor
from src.antiforensics.engine import AntiForensicsEngine


# ---------------------------------------------------------------------------
# Test 1: Magisk denylist & Repackaged Hidden Manager Test
# ---------------------------------------------------------------------------

def test_magisk_denylist_and_repackaged_hidden_manager():
    """
    Test 1: Acceptance Test 1 from Spec Section 9.1.
    Verifies that Sub-Engine 6.5A parses /data/adb/magisk.db:
      1. Identifies root granted to UID 10210 (policy = 2).
      2. Detects root concealment from com.phonepe.app via Zygisk denylist.
      3. Unmasks com.hidden.random.pkg as the repackaged disguised Magisk Manager.
    """
    base_dir = Path("./.workspace_tmp/test_magisk_sandbox")
    adb_dir = base_dir / "data" / "adb"
    adb_dir.mkdir(parents=True, exist_ok=True)

    db_path = adb_dir / "magisk.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE policies (
            uid INTEGER PRIMARY KEY,
            package_name TEXT,
            policy INTEGER NOT NULL,
            until INTEGER,
            logging INTEGER,
            notification INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE denylist (
            package_name TEXT NOT NULL,
            process_name TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE strings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # 1. Root granted to UID 10210
    cur.execute("INSERT INTO policies VALUES (10210, 'com.termux', 2, 0, 1, 1)")
    # 2. Concealed from PhonePe
    cur.execute("INSERT INTO denylist VALUES ('com.phonepe.app', 'com.phonepe.app')")
    # 3. Hidden Magisk Manager app package
    cur.execute("INSERT INTO strings VALUES ('requester', 'com.hidden.random.pkg')")

    conn.commit()
    conn.close()

    auditor = OSIntegrityAuditor()
    records = auditor.audit_magisk_database(str(db_path), source_vfs_file_id=1201)

    assert len(records) == 3

    # Check root policy
    pol_rec = [r for r in records if r.finding_category == IntegrityFindingCategory.MAGISK_ROOT_POLICY][0]
    assert pol_rec.target_or_requester_pkg == "com.termux"
    assert "ROOT_ALLOWED" in pol_rec.policy_or_state

    # Check denylist
    deny_rec = [r for r in records if r.finding_category == IntegrityFindingCategory.MAGISK_ZYGISK_DENYLIST_HIDE][0]
    assert deny_rec.target_or_requester_pkg == "com.phonepe.app"
    assert "DENYLIST" in deny_rec.policy_or_state

    # Check unmasked repackaged manager
    mgr_rec = [r for r in records if r.finding_category == IntegrityFindingCategory.MAGISK_REPACKAGED_HIDDEN_APP][0]
    assert mgr_rec.target_or_requester_pkg == "com.hidden.random.pkg"
    assert "REPACKAGED_MAGISK_MANAGER" in mgr_rec.policy_or_state


# ---------------------------------------------------------------------------
# Test 2: Monotonic ROWID Clock-Rollback & sqlite_sequence Tail-Deletion
# ---------------------------------------------------------------------------

def test_monotonic_rowid_clock_rollback_and_sqlite_sequence_tail_deletion():
    """
    Test 2: Acceptance Test 2 from Spec Section 9.2.
    In mmssms.db:
      Row 500: Nov 5, 2026 14:00 UTC (1762351200000 ms)
      Row 501: Nov 1, 2026 09:00 UTC (1761987600000 ms — backdated by 4 days!)
      Row 502: Nov 5, 2026 14:10 UTC (1762351800000 ms)
      sqlite_sequence: ('sms', 525)
    Verifies that Sub-Engine 6.5B/C flags Row 501 as CLOCK_ROLLBACK_ROWID_INVERSION,
    brackets its true window between 14:00 and 14:10 on Nov 5,
    and proves that 525 - 502 = 23 tail SMS rows were deleted.
    """
    base_dir = Path("./.workspace_tmp/test_antiforensics_sandbox")
    dbs_dir = base_dir / "data" / "user" / "0" / "com.android.providers.telephony" / "databases"
    dbs_dir.mkdir(parents=True, exist_ok=True)

    db_path = dbs_dir / "mmssms.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT,
            date INTEGER NOT NULL,
            body TEXT
        )
    """)

    # Insert 3 sequential rows where row 501 is backdated
    cur.execute("INSERT INTO sms VALUES (500, '+919811001100', 1762351200000, 'Message 500')")
    cur.execute("INSERT INTO sms VALUES (501, '+919811001100', 1761987600000, 'Backdated Message 501')")
    cur.execute("INSERT INTO sms VALUES (502, '+919811001100', 1762351800000, 'Message 502')")

    # Sequence counter at 525 (23 rows deleted from tail)
    cur.execute("INSERT INTO sqlite_sequence VALUES ('sms', 525)")

    conn.commit()
    conn.close()

    detector = ClockTamperGapDetector()
    records = detector.audit_sqlite_database(
        db_path=str(db_path),
        table_name="sms",
        rowid_col="_id",
        date_col="date",
        source_vfs_file_id=1202,
    )

    assert len(records) == 2

    # 1. Clock rollback record
    rollback_rec = [r for r in records if r.tamper_category == TamperCategory.CLOCK_ROLLBACK_ROWID_INVERSION][0]
    assert rollback_rec.severity_level == "CRITICAL"
    assert "501" in rollback_rec.monotonic_anchor_detail
    assert "14:00" in str(rollback_rec.true_bracketed_window_utc)
    assert "14:10" in str(rollback_rec.true_bracketed_window_utc)

    # 2. Tail deletion record
    del_rec = [r for r in records if r.tamper_category == TamperCategory.SQLITE_SEQUENCE_TAIL_DELETION_GAP][0]
    assert del_rec.severity_level == "HIGH"
    assert "23 tail rows deleted" in del_rec.monotonic_anchor_detail


# ---------------------------------------------------------------------------
# Test 3: Sideloaded APK Telegram-Bot C2 Carver & *401* Call-Forwarding
# ---------------------------------------------------------------------------

def test_sideloaded_apk_telegram_bot_c2_and_call_forwarding():
    """
    Test 3: Acceptance Test 3 from Spec Section 9.3.
    Verifies that Sub-Engine 6.5E:
      1. Carves Telegram Bot Token '7182938475:AAH1234567890abcdefghijklmnopqrstuv'
         and chat_id '-100192837465' out of mock RTO_Challan.apk classes.dex.
      2. Detects Reliance Jio unconditional call-forwarding (*401*9876543210)
         in calllog.db and extracts hijacker destination phone '9876543210'.
    """
    base_dir = Path("./.workspace_tmp/test_malware_sandbox")
    base_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build real ZIP archive (APK) containing classes.dex with C2 string
    apk_path = base_dir / "RTO_Challan.apk"
    if apk_path.exists():
        apk_path.unlink()

    dex_payload = (
        b"\x64\x65\x78\x0a\x30\x33\x35\x00"  # DEX header magic
        + (b"\x00" * 32)
        + b"https://api.telegram.org/bot7182938475:AAH1234567890abcdefghijklmnopqrstuv/sendMessage?chat_id=-100192837465"
        + (b"\x00" * 32)
    )

    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("classes.dex", dex_payload)

    # 2. Build calllog.db with dialed USSD call forwarding
    calllog_dir = base_dir / "data" / "user" / "0" / "com.android.providers.contacts" / "databases"
    calllog_dir.mkdir(parents=True, exist_ok=True)

    calllog_path = calllog_dir / "calllog.db"
    if calllog_path.exists():
        calllog_path.unlink()

    conn = sqlite3.connect(calllog_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE calls (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT NOT NULL,
            date INTEGER NOT NULL,
            duration INTEGER NOT NULL,
            type INTEGER NOT NULL
        )
    """)
    cur.execute("INSERT INTO calls VALUES (1, '*401*9876543210', 1762351200000, 3, 2)")
    conn.commit()
    conn.close()

    auditor = MalwareRemoteAccessAuditor()

    # Audit APK
    apk_records = auditor.audit_apk_archive(str(apk_path), source_vfs_file_id=1203)
    assert len(apk_records) >= 1
    tg_rec = [r for r in apk_records if r.threat_category == ThreatCategory.EXTRACTED_TELEGRAM_BOT_C2_TOKEN][0]
    assert "7182938475:AAH1234567890abcdefghijklmnopqrstuv" in tg_rec.extracted_c2_or_remote_id
    assert "-100192837465" in tg_rec.extracted_c2_or_remote_id

    # Audit Call Forwarding
    call_records = auditor.audit_calllog_forwarding(str(calllog_path), source_vfs_file_id=1204)
    assert len(call_records) == 1
    ussd_rec = call_records[0]
    assert ussd_rec.threat_category == ThreatCategory.USSD_CALL_FORWARDING_HIJACK
    assert ussd_rec.extracted_c2_or_remote_id == "9876543210"
    assert "*401*" in ussd_rec.malicious_pkg_or_tool_name


# ---------------------------------------------------------------------------
# Test 4: AnyDesk ad_svc.trace Remote Session & UPI Overlap Test
# ---------------------------------------------------------------------------

def test_anydesk_trace_remote_session_and_upi_overlap():
    """
    Test 4: Acceptance Test 4 from Spec Section 9.4.
    Verifies that Sub-Engine 6.5E parses AnyDesk ad_svc.trace log:
      1. Extracts Remote AnyDesk ID '987654321' and session duration (14:00:10 to 14:08:45 UTC).
      2. Cross-references with a Phase 3 UPI transaction at 14:04:12 UTC,
         populating overlapped_financial_tx_uids.
    """
    base_dir = Path("./.workspace_tmp/test_malware_sandbox")
    anydesk_dir = base_dir / "data" / "user" / "0" / "com.anydesk.anydeskandroid" / "files"
    anydesk_dir.mkdir(parents=True, exist_ok=True)

    trace_file = anydesk_dir / "ad_svc.trace"
    trace_content = (
        "2026-11-05 14:00:10.120 info Logged in from 987654321 (198.51.100.42:54321)\n"
        "2026-11-05 14:04:00.000 info Clipboard synchronization active\n"
        "2026-11-05 14:08:45.000 info Session closed\n"
    )
    with open(trace_file, "w", encoding="utf-8") as f:
        f.write(trace_content)

    financial_transactions = [
        {
            "tx_uid": 301,
            "timestamp_iso": "2026-11-05T14:04:12.000000Z",
            "amount": 50000.0,
            "vpa": "fraudster@upi",
        }
    ]

    auditor = MalwareRemoteAccessAuditor()
    records = auditor.audit_anydesk_trace(
        trace_path=str(trace_file),
        financial_transactions=financial_transactions,
        source_vfs_file_id=1205,
    )

    assert len(records) == 1
    session = records[0]
    assert session.threat_category == ThreatCategory.ANYDESK_OR_REMOTE_DESKTOP_SESSION
    assert session.extracted_c2_or_remote_id == "987654321"
    assert "14:00:10" in str(session.session_start_or_install_utc)
    assert "14:08:45" in str(session.session_end_utc_iso)
    assert "[301]" in str(session.overlapped_financial_tx_uids)


# ---------------------------------------------------------------------------
# Test 5: Anti-Forensics Master SQLite Export Validation
# ---------------------------------------------------------------------------

def test_antiforensics_master_sqlite_export():
    """
    Test 5: Master Export Validation.
    Verifies that AntiForensicsEngine populates all four tables in
    antiforensics_tamper_and_malware_engine.sqlite.
    """
    export_db_path = Path("./.workspace_tmp/antiforensics_tamper_and_malware_engine.sqlite")
    if export_db_path.exists():
        export_db_path.unlink()

    sample_integrity = [
        OSIntegrityAuditRecord(
            finding_category=IntegrityFindingCategory.MAGISK_ROOT_POLICY,
            source_vfs_file_id=1201,
            target_or_requester_pkg="com.termux",
            policy_or_state="ROOT_ALLOWED (2)",
        )
    ]

    sample_tamper = [
        ClockTamperGapRecord(
            tamper_category=TamperCategory.CLOCK_ROLLBACK_ROWID_INVERSION,
            severity_level="CRITICAL",
            affected_app_or_database="mmssms.db (sms)",
            source_vfs_file_id=1202,
            monotonic_anchor_detail="ROWID 501 inverted by -4 days",
            courtroom_explanation_note="Suspect altered clock backward",
        )
    ]

    sample_spoof = [
        LocationSpoofContradictionRecord(
            detection_method=SpoofMethod.GPS_VS_CELL_WIFI_RADIO_CONTRADICTION,
            spoofer_package_or_tool="com.lexa.fakegps",
            claimed_gps_lat_lon="19.0760, 72.8777",
            contradicting_sensor_proof="Simultaneous serving 4G cell tower was in Varanasi (682 km away)",
            event_utc_iso="2026-11-05T14:00:00.000000Z",
        )
    ]

    sample_threats = [
        MalwareThreatRecord(
            threat_category=ThreatCategory.EXTRACTED_TELEGRAM_BOT_C2_TOKEN,
            malicious_pkg_or_tool_name="RTO_Challan.apk",
            extracted_c2_or_remote_id="bot7182938475:AAH1234567890abcdefghijklmnopqrstuv (chat_id: -100192837465)",
        )
    ]

    engine = AntiForensicsEngine()
    engine.export_to_sqlite(
        integrity_findings=sample_integrity,
        tamper_records=sample_tamper,
        spoof_records=sample_spoof,
        malware_threats=sample_threats,
        output_db_path=str(export_db_path),
    )

    assert export_db_path.exists()
    conn = sqlite3.connect(export_db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    assert "os_integrity_root_and_hook_audit" in tables
    assert "clock_tampering_and_deletion_gaps_ledger" in tables
    assert "location_spoofing_and_sensor_contradictions" in tables
    assert "malware_apk_c2_and_remote_access_ledger" in tables

    cur.execute("SELECT COUNT(*) FROM os_integrity_root_and_hook_audit")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM clock_tampering_and_deletion_gaps_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM location_spoofing_and_sensor_contradictions")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM malware_apk_c2_and_remote_access_ledger")
    assert cur.fetchone()[0] == 1

    conn.close()

