"""
Test Suite: Phase 6, Module 6.1 — iOS Deep Behavioral Telemetry, Pattern-of-Life & Unified Log Engine.
Covers:
  - Sub-Engine 6.1A: CoreDuet (knowledgeC.db, ZSTRUCTUREDMETADATA, ZSECONDSFROMGMT).
  - Sub-Engine 6.1B: Apple Biome streams (SEGB v1/v2, Device.Torch) & Screen Time.
  - Sub-Engine 6.1C: Apple Unified Logs (.tracev3) & Physical Orientation (CMDeviceOrientation vs UI).
  - Sub-Engine 6.1D: Apple Health (healthdb_secure.sqlite 6-table join: iPhone vs Apple Watch).
  - Sub-Engine 6.1E: APFS FSEvents (/.fseventsd/ 2SLG binary parser & monotonic timestamp bracketing).
Complies with Phase 6 Module 6.1 Specification and AGENTS.md Constitution.
"""

import gzip
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
from src.ios_telemetry.models import (
    TelemetrySourceEngine,
    TelemetryEventCategory,
    HealthSensorMetricType,
    PhysicalOrientation,
    IOSTelemetryEventRecord,
    IOSHealthSampleRecord,
    IOSFSEventRecord,
    cocoa_to_utc_iso,
    cocoa_to_utc_ns,
    decode_fsevent_flags,
)
from src.ios_telemetry.coreduet_decoder import CoreDuetDecoder
from src.ios_telemetry.biome_screentime_decoder import BiomeScreenTimeDecoder
from src.ios_telemetry.unified_logs_orientation_decoder import UnifiedLogsOrientationDecoder
from src.ios_telemetry.health_decoder import HealthDecoder
from src.ios_telemetry.fsevents_decoder import FSEventsDecoder
from src.ios_telemetry.engine import IOSTelemetryEngine


# ---------------------------------------------------------------------------
# Test 1: knowledgeC + Biome Dual Ingestion & ZSECONDSFROMGMT Test
# ---------------------------------------------------------------------------

def test_knowledgec_and_biome_dual_ingestion_and_tz_offset():
    """
    Test 1: Acceptance Test 1 from Spec Section 9.1.
    Verifies that Sub-Engine 6.1A/B normalizes CoreDuet /app/inFocus row with
    ZSECONDSFROMGMT = 19800 (+05:30 IST) and Biome Device.Torch record into
    ios_behavioral_timeline_ledger.
    """
    base_dir = Path("./.workspace_tmp/test_knowledgec_sandbox")
    dbs_dir = base_dir / "Library" / "CoreDuet" / "Knowledge"
    dbs_dir.mkdir(parents=True, exist_ok=True)

    kc_db_path = dbs_dir / "knowledgeC.db"
    if kc_db_path.exists():
        kc_db_path.unlink()

    conn = sqlite3.connect(kc_db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE ZOBJECT (
            Z_PK INTEGER PRIMARY KEY,
            ZSTREAMNAME TEXT NOT NULL,
            ZVALUESTRING TEXT,
            ZVALUEINTEGER INTEGER,
            ZVALUEDOUBLE REAL,
            ZSTARTDATE REAL NOT NULL,
            ZENDDATE REAL NOT NULL,
            ZCREATIONDATE REAL NOT NULL,
            ZSECONDSFROMGMT INTEGER,
            ZSTRUCTUREDMETADATA INTEGER,
            ZSOURCE INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE ZSTRUCTUREDMETADATA (
            Z_PK INTEGER PRIMARY KEY,
            Z_DKAPPLICATIONMETADATAKEY__LAUNCHREASON TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE ZSOURCE (
            Z_PK INTEGER PRIMARY KEY,
            ZBUNDLEID TEXT,
            ZDEVICEID TEXT
        )
    """)

    # Insert /app/inFocus for PhonePe (Cocoa 784041600.0 = 2025-11-05T13:20:00Z)
    cur.execute("INSERT INTO ZSTRUCTUREDMETADATA VALUES (1, 'UserTappedIcon')")
    cur.execute("INSERT INTO ZSOURCE VALUES (1, 'com.phonepe.PhonePeApp', NULL)")
    cur.execute("""
        INSERT INTO ZOBJECT VALUES (
            1, '/app/inFocus', 'com.phonepe.PhonePeApp', NULL, NULL,
            784041600.0, 784041660.0, 784041661.0, 19800, 1, 1
        )
    """)
    conn.commit()
    conn.close()

    # 1. Parse knowledgeC.db
    kc_decoder = CoreDuetDecoder()
    kc_records = kc_decoder.decode_knowledgec_database(str(kc_db_path), app_instance_id=1, source_vfs_file_id=801)

    assert len(kc_records) == 1
    rec = kc_records[0]
    assert rec.telemetry_source_engine == TelemetrySourceEngine.COREDUET_KNOWLEDGEC
    assert rec.stream_or_subsystem_name == "/app/inFocus"
    assert rec.event_category == TelemetryEventCategory.APP_IN_FOCUS
    assert rec.target_app_bundle_id == "com.phonepe.PhonePeApp"
    assert rec.recorded_tz_offset_sec == 19800
    assert rec.duration_seconds == 60.0
    assert rec.start_utc_iso == "2025-11-05T13:20:00.000000Z"
    assert rec.end_utc_iso == "2025-11-05T13:21:00.000000Z"

    # 2. Simulate Biome Device.Torch record
    biome_decoder = BiomeScreenTimeDecoder()
    raw_biome_records = [
        {
            "stream_name": "Device.Torch",
            "state": "1",
            "timestamp_cocoa": 784041700.0,
            "starting": 1,
        }
    ]
    biome_records = biome_decoder.parse_biome_events(raw_biome_records, app_instance_id=1, source_vfs_file_id=802)
    assert len(biome_records) == 1
    b_rec = biome_records[0]
    assert b_rec.telemetry_source_engine == TelemetrySourceEngine.APPLE_BIOME_SEGB
    assert b_rec.event_category == TelemetryEventCategory.TORCH_FLASHLIGHT
    assert b_rec.primary_state_or_value == "TORCH_ON"


# ---------------------------------------------------------------------------
# Test 2: Physical Orientation (backboardd) vs UI Orientation Separation
# ---------------------------------------------------------------------------

def test_physical_orientation_vs_ui_orientation_separation():
    """
    Test 2: Acceptance Test 2 from Spec Section 9.2.
    Verifies that Sub-Engine 6.1C distinguishes physical sensor orientation
    (CMDeviceOrientation = 6 'Face Down') while locked from display UI orientation
    (UIInterfaceOrientation = 3 'Landscape Left') while unlocked.
    """
    decoder = UnifiedLogsOrientationDecoder()

    events = [
        {
            "subsystem": "com.apple.BackBoard",
            "category": "Orientation",
            "type": "PHYSICAL_SENSOR",
            "orientation_code": 6,
            "screen_locked": 1,
            "timestamp_ns": 1700000000000000000,
            "timestamp_iso": "2023-11-14T22:13:20.000000Z",
        },
        {
            "subsystem": "com.apple.SpringBoard",
            "category": "UIOrientation",
            "type": "DISPLAY_UI",
            "orientation_code": 3,
            "screen_locked": 0,
            "timestamp_ns": 1700000100000000000,
            "timestamp_iso": "2023-11-14T22:15:00.000000Z",
        }
    ]

    records = decoder.decode_orientation_events(events, app_instance_id=1, source_vfs_file_id=803)
    assert len(records) == 2

    phys_rec = [r for r in records if r.event_category == TelemetryEventCategory.PHYSICAL_SENSOR_ORIENTATION][0]
    assert "FaceDown (6)" in phys_rec.primary_state_or_value
    assert phys_rec.primary_state_or_value == "FaceDown (6)"

    ui_rec = [r for r in records if r.event_category == TelemetryEventCategory.DISPLAY_UI_ORIENTATION][0]
    assert "UI_LandscapeLeft (3)" in ui_rec.primary_state_or_value


# ---------------------------------------------------------------------------
# Test 3: Apple Health iPhone vs Apple Watch Hardware Provenance Test
# ---------------------------------------------------------------------------

def test_healthdb_iphone_vs_apple_watch_provenance():
    """
    Test 3: Acceptance Test 3 from Spec Section 9.3.
    Verifies that Sub-Engine 6.1D executes the 6-table join in healthdb_secure.sqlite,
    strictly setting is_local_iphone_sensor = 1 for 'iPhone16,2' and
    is_local_iphone_sensor = 0 for 'Watch7,1'.
    """
    base_dir = Path("./.workspace_tmp/test_health_sandbox")
    dbs_dir = base_dir / "Library" / "Health"
    dbs_dir.mkdir(parents=True, exist_ok=True)

    db_path = dbs_dir / "healthdb_secure.sqlite"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE source_devices (
            ROWID INTEGER PRIMARY KEY,
            name TEXT,
            hardware TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE sources (
            ROWID INTEGER PRIMARY KEY,
            bundle_identifier TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE data_provenances (
            ROWID INTEGER PRIMARY KEY,
            device_id INTEGER NOT NULL,
            source_id INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE objects (
            data_id INTEGER PRIMARY KEY,
            creation_date REAL NOT NULL,
            provenance INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE samples (
            data_id INTEGER PRIMARY KEY,
            data_type INTEGER NOT NULL,
            start_date REAL NOT NULL,
            end_date REAL NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE quantity_samples (
            data_id INTEGER PRIMARY KEY,
            quantity REAL NOT NULL
        )
    """)

    # 1. Setup Source Devices: iPhone16,2 (id 1) vs Watch7,1 (id 2)
    cur.execute("INSERT INTO source_devices VALUES (1, 'iPhone', 'iPhone16,2')")
    cur.execute("INSERT INTO source_devices VALUES (2, 'Apple Watch', 'Watch7,1')")
    cur.execute("INSERT INTO sources VALUES (1, 'com.apple.health')")

    # 2. Setup Data Provenances
    cur.execute("INSERT INTO data_provenances VALUES (1, 1, 1)")
    cur.execute("INSERT INTO data_provenances VALUES (2, 2, 1)")

    # 3. Setup Objects & Samples
    # Sample 1: iPhone steps (450 steps)
    cur.execute("INSERT INTO objects VALUES (1, 784041700.0, 1)")
    cur.execute("INSERT INTO samples VALUES (1, 7, 784041600.0, 784041660.0)")
    cur.execute("INSERT INTO quantity_samples VALUES (1, 450.0)")

    # Sample 2: Watch steps (300 steps)
    cur.execute("INSERT INTO objects VALUES (2, 784041700.0, 2)")
    cur.execute("INSERT INTO samples VALUES (2, 7, 784041600.0, 784041660.0)")
    cur.execute("INSERT INTO quantity_samples VALUES (2, 300.0)")

    conn.commit()
    conn.close()

    decoder = HealthDecoder()
    health_samples = decoder.decode_health_database(str(db_path), source_vfs_file_id=804)

    assert len(health_samples) == 2

    iphone_sample = [s for s in health_samples if s.hardware_source_model == "iPhone16,2"][0]
    assert iphone_sample.is_local_iphone_sensor == 1
    assert iphone_sample.metric_value == 450.0
    assert iphone_sample.sensor_metric_type == HealthSensorMetricType.STEP_COUNT

    watch_sample = [s for s in health_samples if s.hardware_source_model == "Watch7,1"][0]
    assert watch_sample.is_local_iphone_sensor == 0
    assert watch_sample.metric_value == 300.0


# ---------------------------------------------------------------------------
# Test 4: FSEvents 2SLG Binary Parser & Monotonic Timestamp Bracketing Test
# ---------------------------------------------------------------------------

def test_fsevents_2slg_parser_and_monotonic_bracketing_and_master_export():
    """
    Test 4: Acceptance Test 4 from Spec Section 9.4.
    Builds a real binary 2SLG page in a gzipped /.fseventsd/ file containing:
      event_id 100: existing file (btime = 10:00:00Z)
      event_id 101: deleted file IMG_0999.HEIC (ItemRemoved)
      event_id 102: existing file (btime = 10:05:00Z)
    Verifies that Sub-Engine 6.1E parses 2SLG 28-byte trailers and brackets
    IMG_0999.HEIC's deletion window to [10:00:00Z, 10:05:00Z], and validates master export.
    """
    base_dir = Path("./.workspace_tmp/test_fsevents_sandbox")
    fsevents_dir = base_dir / ".fseventsd"
    fsevents_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build binary 2SLG records:
    # Page Header (12 bytes): magic = b"2SLG" (4B), version = 1 (4B LE), page_size = ? (4B LE)
    rec1_path = b"/private/var/mobile/Containers/Data/Application/doc.pdf\x00"
    rec1_body = struct.pack("<QI Q", 100, 0x01000001, 1001)  # event_id=100, flags=IsFile|ItemCreated, inode=1001

    rec2_path = b"/private/var/mobile/Media/DCIM/100APPLE/IMG_0999.HEIC\x00"
    rec2_body = struct.pack("<QI Q", 101, 0x01000002, 9999)  # event_id=101, flags=IsFile|ItemRemoved, inode=9999

    rec3_path = b"/private/var/mobile/Library/SMS/sms.db\x00"
    rec3_body = struct.pack("<QI Q", 102, 0x01000010, 1002)  # event_id=102, flags=IsFile|ItemModified, inode=1002

    records_payload = (
        rec1_path + rec1_body +
        rec2_path + rec2_body +
        rec3_path + rec3_body
    )
    total_page_len = 12 + len(records_payload)
    page_header = b"2SLG" + struct.pack("<II", 1, total_page_len)
    full_2slg_page = page_header + records_payload

    # 2. Write as gzip file
    gz_path = fsevents_dir / "000000000008a4f2"
    with gzip.open(gz_path, "wb") as f_gz:
        f_gz.write(full_2slg_page)

    # 3. Known live filesystem anchors (existing files in vfs_index)
    existing_file_anchors = {
        "/private/var/mobile/Containers/Data/Application/doc.pdf": {
            "btime_iso": "2025-11-05T10:00:00.000000Z",
            "exists": 1,
        },
        "/private/var/mobile/Library/SMS/sms.db": {
            "btime_iso": "2025-11-05T10:05:00.000000Z",
            "exists": 1,
        },
    }

    decoder = FSEventsDecoder()
    fsevent_records = decoder.decode_fsevents_file(
        str(gz_path),
        existing_file_anchors=existing_file_anchors,
        source_vfs_file_id=805,
    )

    assert len(fsevent_records) == 3

    # Check deleted file record (IMG_0999.HEIC)
    del_rec = [r for r in fsevent_records if "IMG_0999.HEIC" in r.target_file_path][0]
    assert del_rec.fsevent_format_version == "2SLG"
    assert del_rec.monotonic_event_id == 101
    assert del_rec.apfs_inode_node_id == 9999
    assert del_rec.does_file_still_exist == 0
    assert "ItemRemoved" in del_rec.decoded_flags_list
    assert del_rec.bracket_earliest_utc_iso == "2025-11-05T10:00:00.000000Z"
    assert del_rec.bracket_latest_utc_iso == "2025-11-05T10:05:00.000000Z"

    # 4. Master SQLite Export Validation
    export_db_path = Path("./.workspace_tmp/ios_behavioral_telemetry_engine.sqlite")
    if export_db_path.exists():
        export_db_path.unlink()

    sample_telemetry = [
        IOSTelemetryEventRecord(
            telemetry_source_engine=TelemetrySourceEngine.COREDUET_KNOWLEDGEC,
            source_vfs_file_id=801,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            device_locality="LOCAL_SEIZED_IPHONE",
            stream_or_subsystem_name="/app/inFocus",
            event_category=TelemetryEventCategory.APP_IN_FOCUS,
            target_app_bundle_id="com.phonepe.PhonePeApp",
            primary_state_or_value="com.phonepe.PhonePeApp",
            start_utc_ns=1762348800000000000,
            start_utc_iso="2025-11-05T13:20:00.000000Z",
        )
    ]
    sample_health = [
        IOSHealthSampleRecord(
            source_vfs_file_id=804,
            recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
            sensor_metric_type=HealthSensorMetricType.STEP_COUNT,
            metric_value=450.0,
            hardware_source_model="iPhone16,2",
            is_local_iphone_sensor=1,
            activity_start_utc_iso="2025-11-05T13:20:00.000000Z",
            activity_end_utc_iso="2025-11-05T13:21:00.000000Z",
            db_sync_committed_utc_iso="2025-11-05T13:21:01.000000Z",
        )
    ]

    engine = IOSTelemetryEngine()
    engine.export_to_sqlite(
        telemetry_events=sample_telemetry,
        health_samples=sample_health,
        fsevents=fsevent_records,
        output_db_path=str(export_db_path),
    )

    assert export_db_path.exists()
    conn_out = sqlite3.connect(export_db_path)
    cur_out = conn_out.cursor()

    cur_out.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur_out.fetchall()}
    assert "ios_behavioral_timeline_ledger" in tables
    assert "ios_health_sensor_alibi_ledger" in tables
    assert "ios_fsevents_filesystem_audit" in tables

    cur_out.execute("SELECT COUNT(*) FROM ios_behavioral_timeline_ledger")
    assert cur_out.fetchone()[0] == 1

    cur_out.execute("SELECT COUNT(*) FROM ios_health_sensor_alibi_ledger")
    assert cur_out.fetchone()[0] == 1

    cur_out.execute("SELECT COUNT(*) FROM ios_fsevents_filesystem_audit")
    assert cur_out.fetchone()[0] == 3

    conn_out.close()
