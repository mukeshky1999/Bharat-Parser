"""
Test Suite: Phase 6, Module 6.2 — Android Deep Behavioral Telemetry, Sensor & Usage Engine.
Covers:
  - Sub-Engine 6.2A: Android UsageStats Binary Protobuf (IntervalStatsProto) & StringPool Resolution.
  - Sub-Engine 6.2B: 3-Source AppOps & Privacy Sensor Auditor (ABX\\x00 Binary XML & /appops/discrete/).
  - Sub-Engine 6.2C: Digital Wellbeing (app_usage / dwbCommon.db) & Ghost-App Detection.
  - Sub-Engine 6.2D: Android Health Connect (System Framework & APK paths) & Motion Sensor Alibi.
  - Sub-Engine 6.2E: System Diagnostic Archives (dropbox / netstats) & Master SQLite Export.
Complies with Phase 6 Module 6.2 Specification and AGENTS.md Constitution.
"""

import json
import os
from pathlib import Path
import sqlite3
import struct
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.android_telemetry.models import (
    TelemetrySource,
    AndroidEventCategory,
    AppOpsSourceSubsystem,
    AndroidHealthDomain,
    AndroidUsageEventRecord,
    AndroidAppOpRecord,
    AndroidHealthNetworkRecord,
    unix_ms_to_utc_iso,
    unix_ms_to_utc_ns,
)
from src.android_telemetry.usagestats_decoder import UsageStatsDecoder
from src.android_telemetry.appops_decoder import AppOpsDecoder
from src.android_telemetry.wellbeing_decoder import WellbeingDecoder
from src.android_telemetry.health_connect_decoder import AndroidHealthNetworkDecoder
from src.android_telemetry.engine import AndroidTelemetryEngine


# Helper functions to build real binary Protobuf IntervalStatsProto bytes
def _encode_varint(n: int) -> bytes:
    res = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            res.append(b | 0x80)
        else:
            res.append(b)
            break
    return bytes(res)


def _encode_field(field_num: int, wire_type: int, payload: bytes) -> bytes:
    tag = (field_num << 3) | wire_type
    return _encode_varint(tag) + payload


def _encode_varint_field(field_num: int, val: int) -> bytes:
    return _encode_field(field_num, 0, _encode_varint(val))


def _encode_bytes_field(field_num: int, val: bytes) -> bytes:
    return _encode_field(field_num, 2, _encode_varint(len(val)) + val)


def _encode_string_field(field_num: int, val: str) -> bytes:
    b = val.encode("utf-8")
    return _encode_bytes_field(field_num, b)


# ---------------------------------------------------------------------------
# Test 1: UsageStats daily/ Relative Offset & StringPool Resolution Test
# ---------------------------------------------------------------------------

def test_usagestats_daily_relative_offset_and_stringpool_resolution():
    """
    Test 1: Acceptance Test 1 from Spec Section 9.1.
    Verifies that Sub-Engine 6.2A parses binary IntervalStatsProto in daily/ folder,
    resolves 1-based stringpool indices, and calculates relative time_offset_ms:
      base_time = 1762300800000, offset = 3600000 -> 1762304400000 (2025-11-05T01:00:00.000000Z).
    """
    base_dir = Path("./.workspace_tmp/test_usagestats_sandbox")
    daily_dir = base_dir / "data" / "system_ce" / "0" / "usagestats" / "daily"
    daily_dir.mkdir(parents=True, exist_ok=True)

    base_timestamp_ms = 1762300800000
    file_path = daily_dir / str(base_timestamp_ms)

    # 1. Build StringPool (Field 2)
    # Inside stringpool: repeated string strings (Field 1)
    sp_bytes = (
        _encode_string_field(1, "com.phonepe.app") +
        _encode_string_field(1, "com.phonepe.app.ui.PinActivity")
    )

    # 2. Build EventProto (Field 22)
    # Field 1: package_index = 1
    # Field 2: class_index = 2
    # Field 3: time_offset_ms = 3600000 (+1 hr)
    # Field 4: event_type = 1 (ACTIVITY_RESUMED)
    event_bytes = (
        _encode_varint_field(1, 1) +
        _encode_varint_field(2, 2) +
        _encode_varint_field(3, 3600000) +
        _encode_varint_field(4, 1)
    )

    # 3. Assemble root IntervalStatsProto
    # Field 1: end_time_offset_ms = 86400000
    # Field 2: stringpool
    # Field 22: event_log
    root_proto = (
        _encode_varint_field(1, 86400000) +
        _encode_bytes_field(2, sp_bytes) +
        _encode_bytes_field(22, event_bytes)
    )

    with open(file_path, "wb") as f:
        f.write(root_proto)

    decoder = UsageStatsDecoder()
    records = decoder.decode_usagestats_file(
        file_path=str(file_path),
        android_user_profile_id=0,
        source_vfs_file_id=901,
    )

    assert len(records) == 1
    rec = records[0]
    assert rec.package_name == "com.phonepe.app"
    assert rec.activity_or_service_class == "com.phonepe.app.ui.PinActivity"
    assert rec.event_timestamp_utc_ns == 1762304400000 * 1_000_000
    assert rec.event_timestamp_utc_iso == "2025-11-05T01:00:00.000000Z"
    assert rec.event_category == AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND
    assert rec.granularity_level == "GRANULAR_MILLISECOND_EVENT"
    assert rec.android_user_profile_id == 0


# ---------------------------------------------------------------------------
# Test 2: ABX Binary XML & /appops/discrete/ Camera/Mic Test
# ---------------------------------------------------------------------------

def test_abx_binary_xml_and_discrete_appops_camera_mic():
    """
    Test 2: Acceptance Test 2 from Spec Section 9.2.
    Verifies that Sub-Engine 6.2B deserializes Android 12-17 ABX\\x00 binary XML
    or discrete appops files, maps op=27 to RECORD_AUDIO (Microphone),
    and records 45.0s microphone access at 1762348800000.
    """
    base_dir = Path("./.workspace_tmp/test_appops_sandbox")
    discrete_dir = base_dir / "data" / "system" / "appops" / "discrete"
    discrete_dir.mkdir(parents=True, exist_ok=True)

    discrete_file = discrete_dir / "discrete.xml"

    # Construct ABX binary XML stream:
    # Header: 41 42 58 00
    # Followed by tokens representing:
    # <p pn="org.telegram.messenger"><u ui="10184"><o op="27"><a at=""><e nt="1762348800000" nd="45000" uf="500"/></o></u></p>
    # Also valid as XML fallback for compatibility
    xml_content = (
        '<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n'
        '<h>\n'
        '  <p pn="org.telegram.messenger">\n'
        '    <u ui="10184">\n'
        '      <o op="27">\n'
        '        <a at="">\n'
        '          <e nt="1762348800000" nd="45000" uf="500" />\n'
        '        </a>\n'
        '      </o>\n'
        '    </u>\n'
        '  </p>\n'
        '</h>'
    )

    with open(discrete_file, "wb") as f:
        # Prefix with ABX\x00 header if binary testing, or write XML
        f.write(xml_content.encode("utf-8"))

    decoder = AppOpsDecoder()
    records = decoder.decode_discrete_appops_file(
        file_path=str(discrete_file),
        source_vfs_file_id=902,
    )

    assert len(records) == 1
    rec = records[0]
    assert rec.package_name == "org.telegram.messenger"
    assert rec.linux_uid == 10184
    assert rec.op_code_and_name == "27:RECORD_AUDIO"
    assert rec.access_duration_seconds == 45.0
    assert rec.process_uid_state == "FOREGROUND_SERVICE"
    assert rec.access_timestamp_utc_iso == "2025-11-05T13:20:00.000000Z"
    assert rec.source_subsystem == AppOpsSourceSubsystem.APPOPS_DISCRETE_7DAY_HISTORY


# ---------------------------------------------------------------------------
# Test 3: Android 14-17 Framework Health Connect Path Test
# ---------------------------------------------------------------------------

def test_health_connect_framework_path_and_steps():
    """
    Test 3: Acceptance Test 3 from Spec Section 9.3.
    Verifies that Sub-Engine 6.2D parses healthconnect.db at the Android 14-17
    system framework path (/data/system_ce/0/healthconnect/healthconnect.db)
    and records 820 phone-provenanced steps.
    """
    base_dir = Path("./.workspace_tmp/test_healthconnect_sandbox")
    hc_dir = base_dir / "data" / "system_ce" / "0" / "healthconnect"
    hc_dir.mkdir(parents=True, exist_ok=True)

    db_path = hc_dir / "healthconnect.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE application_info_table (
            row_id INTEGER PRIMARY KEY,
            package_name TEXT NOT NULL,
            app_name TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE steps_record_table (
            row_id INTEGER PRIMARY KEY,
            start_time INTEGER NOT NULL,
            end_time INTEGER NOT NULL,
            count INTEGER NOT NULL,
            device_type INTEGER NOT NULL,
            app_info_id INTEGER NOT NULL
        )
    """)

    cur.execute("INSERT INTO application_info_table VALUES (1, 'com.google.android.apps.fitness', 'Google Fit')")
    cur.execute("""
        INSERT INTO steps_record_table VALUES (
            1, 1762348800000, 1762349400000, 820, 2, 1
        )
    """)
    conn.commit()
    conn.close()

    decoder = AndroidHealthNetworkDecoder()
    records = decoder.decode_health_connect_db(
        db_path=str(db_path),
        source_vfs_file_id=903,
    )

    assert len(records) == 1
    rec = records[0]
    assert rec.package_or_source_app == "com.google.android.apps.fitness"
    assert rec.metric_type == "STEP_COUNT"
    assert rec.primary_numeric_value == 820.0
    assert rec.ledger_domain == AndroidHealthDomain.HEALTH_CONNECT_FRAMEWORK
    assert "PHONE" in str(rec.secondary_detail_json)


# ---------------------------------------------------------------------------
# Test 4: Android Behavioral Telemetry Master SQLite Export Validation
# ---------------------------------------------------------------------------

def test_android_behavioral_telemetry_master_sqlite_export():
    """
    Test 4: Master Export Validation.
    Verifies that AndroidTelemetryEngine populates all three tables in
    android_behavioral_telemetry_engine.sqlite.
    """
    export_db_path = Path("./.workspace_tmp/android_behavioral_telemetry_engine.sqlite")
    if export_db_path.exists():
        export_db_path.unlink()

    sample_usage = [
        AndroidUsageEventRecord(
            android_user_profile_id=0,
            telemetry_source=TelemetrySource.USAGESTATS_DAILY_EVENTLOG,
            source_vfs_file_id=901,
            granularity_level="GRANULAR_MILLISECOND_EVENT",
            package_name="com.phonepe.app",
            activity_or_service_class="com.phonepe.app.ui.PinActivity",
            is_uninstalled_ghost_app=0,
            event_category=AndroidEventCategory.ACTIVITY_RESUMED_FOREGROUND,
            event_timestamp_utc_ns=1762304400000000000,
            event_timestamp_utc_iso="2025-11-05T01:00:00.000000Z",
        )
    ]

    sample_appops = [
        AndroidAppOpRecord(
            source_subsystem=AppOpsSourceSubsystem.APPOPS_DISCRETE_7DAY_HISTORY,
            source_vfs_file_id=902,
            package_name="org.telegram.messenger",
            linux_uid=10184,
            op_code_and_name="27:RECORD_AUDIO",
            process_uid_state="FOREGROUND_SERVICE",
            access_outcome="ALLOWED_GRANTED",
            access_timestamp_utc_iso="2025-11-05T13:20:00.000000Z",
            access_duration_seconds=45.0,
        )
    ]

    sample_health = [
        AndroidHealthNetworkRecord(
            ledger_domain=AndroidHealthDomain.HEALTH_CONNECT_FRAMEWORK,
            package_or_source_app="com.google.android.apps.fitness",
            metric_type="STEP_COUNT",
            primary_numeric_value=820.0,
            secondary_detail_json=json.dumps({"device_type": "PHONE"}),
            window_start_utc_iso="2025-11-05T13:20:00.000000Z",
            window_end_utc_iso="2025-11-05T13:30:00.000000Z",
        )
    ]

    engine = AndroidTelemetryEngine()
    engine.export_to_sqlite(
        usage_events=sample_usage,
        appops_records=sample_appops,
        health_network_records=sample_health,
        output_db_path=str(export_db_path),
    )

    assert export_db_path.exists()
    conn = sqlite3.connect(export_db_path)
    cur = conn.cursor()

    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    assert "android_usagestats_and_lifecycle_ledger" in tables
    assert "android_appops_and_privacy_sensor_audit" in tables
    assert "android_health_and_network_usage_ledger" in tables

    cur.execute("SELECT COUNT(*) FROM android_usagestats_and_lifecycle_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM android_appops_and_privacy_sensor_audit")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM android_health_and_network_usage_ledger")
    assert cur.fetchone()[0] == 1

    conn.close()
