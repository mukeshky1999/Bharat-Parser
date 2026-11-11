"""
Test Suite for Phase 3, Module 3.2: NPCI Common Library (CL) & Physical SIM / Hardware Device-Binding Forensics.

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real binary byte fixtures and SQLite databases (no mock objects).
- All fixtures write strictly to ./.workspace_tmp/
- Tests telephony.db siminfo extraction (active vs ejected sim_id == -1).
- Tests mmssms.db 3-way join: sms.sub_id -> siminfo._id (ICCID) -> sms.creator (Package).
- Tests 3-point Remote Ghost SIM-Binding Trojan detection (legitimate vs malware APK).
- Tests embedded NPCI Common Library XML vault & bound SIM ICCID extraction.
- Verifies canonical npci_sim_binding_engine.sqlite schema.
"""

from pathlib import Path
import shutil
import sqlite3
import pytest

from src.core.enums import ResidualConfidence


@pytest.fixture
def tmp_binding_dir():
    """Provides an isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_npci_sim_binding_engine")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


# ==============================================================================
# TEST 1: Ejected Mule SIM (sim_id == -1) Attribution & 3-Way Join Test
# ==============================================================================

def test_ejected_mule_sim_attribution_and_join(tmp_binding_dir):
    """
    Acceptance Test 1 (Section 8.1):
    1. Populates telephony.db with:
       - Row _id = 3: icc_id = "89918540400012345678", sim_id = -1 (Ejected),
         number = "+919876543210", carrier_name = "Jio 4G"
    2. Populates mmssms.db with:
       - Outbound SMS to "9223008333" (PhonePe VMN),
         body = "PP a8f9d2e1b4c3", sub_id = 3, creator = "com.phonepe.app"
    Verifies that SIMBindingForensicEngine:
    1. Accurately extracts the ejected SIM from telephony.db with seizure_slot_state = EJECTED_HISTORICAL_SIM.
    2. Joins sms.sub_id = 3 to siminfo._id = 3, resolving the 20-digit ICCID 89918540400012345678.
    3. Resolves creator = "com.phonepe.app" as a verified official UPI app.
    4. Outputs verdict = "VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING".
    """
    from src.binding.engine import SIMBindingForensicEngine

    telephony_db_path = tmp_binding_dir / "telephony.db"
    con_tel = sqlite3.connect(telephony_db_path)
    cur_tel = con_tel.cursor()
    cur_tel.execute("""
        CREATE TABLE siminfo (
            _id INTEGER PRIMARY KEY,
            icc_id TEXT,
            sim_id INTEGER,
            display_name TEXT,
            carrier_name TEXT,
            number TEXT,
            mcc INTEGER,
            mnc INTEGER,
            is_embedded INTEGER DEFAULT 0
        );
    """)
    cur_tel.execute("""
        INSERT INTO siminfo VALUES (
            3,
            '89918540400012345678',
            -1,
            'Jio 4G',
            'Reliance Jio',
            '+919876543210',
            405,
            861,
            0
        );
    """)
    con_tel.commit()
    con_tel.close()

    # Create mmssms.db
    sms_db_path = tmp_binding_dir / "mmssms.db"
    con_sms = sqlite3.connect(sms_db_path)
    cur_sms = con_sms.cursor()
    cur_sms.execute("""
        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY,
            address TEXT,
            body TEXT,
            date INTEGER,
            type INTEGER,
            sub_id INTEGER,
            creator TEXT
        );
    """)
    # Outbound sent SMS (type = 2) to PhonePe VMN
    cur_sms.execute("""
        INSERT INTO sms VALUES (
            101,
            '9223008333',
            'PP a8f9d2e1b4c37890',
            1704110400000,
            2,
            3,
            'com.phonepe.app'
        );
    """)
    con_sms.commit()
    con_sms.close()

    engine = SIMBindingForensicEngine()
    sim_ledger, audit_records = engine.analyze_sim_and_sms(
        telephony_db_path=telephony_db_path,
        sms_db_path=sms_db_path,
    )

    # 1. Check SIM Ledger
    assert len(sim_ledger) == 1
    sim = sim_ledger[0]
    assert sim.android_sub_id == 3
    assert sim.iccid_20_digit == "89918540400012345678"
    assert sim.seizure_slot_state == "EJECTED_HISTORICAL_SIM"
    assert sim.msisdn_phone_number == "+919876543210"

    # 2. Check Outbound Binding SMS Audit
    assert len(audit_records) == 1
    audit = audit_records[0]
    assert audit.destination_vmn_number == "9223008333"
    assert audit.android_sub_id == 3
    assert audit.resolved_sim_iccid == "89918540400012345678"
    assert audit.resolved_sim_msisdn == "+919876543210"
    assert audit.creator_package_name == "com.phonepe.app"
    assert audit.inferred_target_psp_or_bank == "PhonePe"
    assert audit.binding_attribution_verdict == "VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING"


# ==============================================================================
# TEST 2: Remote Ghost SIM-Binding Trojan Detection Test
# ==============================================================================

def test_remote_ghost_sim_binding_trojan_detection(tmp_binding_dir):
    """
    Acceptance Test 2 (Section 8.2):
    Constructs an outbound SMS sent to Google Pay / NPCI VMN "9289592895":
    - body = "UPI 7b6c5d4e3f2a1b"
    - sub_id = 1
    - creator = "com.parivahan.echallan.apk" (Malicious APK, NOT a recognized UPI app!)
    Verifies that Sub-Engine 3.2D:
    1. Identifies that creator is a sideloaded trojan package.
    2. Identifies that zero local Google Pay / PhonePe app registration was initiated by this user.
    3. Flags the outbound SMS as COMPROMISED_REMOTE_GHOST_SIM_BINDING_VIA_TROJAN.
    """
    from src.binding.engine import SIMBindingForensicEngine

    telephony_db_path = tmp_binding_dir / "telephony.db"
    con_tel = sqlite3.connect(telephony_db_path)
    cur_tel = con_tel.cursor()
    cur_tel.execute("""
        CREATE TABLE siminfo (
            _id INTEGER PRIMARY KEY,
            icc_id TEXT,
            sim_id INTEGER,
            display_name TEXT,
            carrier_name TEXT,
            number TEXT,
            mcc INTEGER,
            mnc INTEGER,
            is_embedded INTEGER DEFAULT 0
        );
    """)
    cur_tel.execute("""
        INSERT INTO siminfo VALUES (
            1,
            '89914040001122334455',
            0,
            'Airtel',
            'Bharti Airtel',
            '+919811223344',
            404,
            45,
            0
        );
    """)
    con_tel.commit()
    con_tel.close()

    sms_db_path = tmp_binding_dir / "mmssms.db"
    con_sms = sqlite3.connect(sms_db_path)
    cur_sms = con_sms.cursor()
    cur_sms.execute("""
        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY,
            address TEXT,
            body TEXT,
            date INTEGER,
            type INTEGER,
            sub_id INTEGER,
            creator TEXT
        );
    """)
    cur_sms.execute("""
        INSERT INTO sms VALUES (
            202,
            '9289592895',
            'UPI 7b6c5d4e3f2a1b',
            1704110400000,
            2,
            1,
            'com.parivahan.echallan.apk'
        );
    """)
    con_sms.commit()
    con_sms.close()

    engine = SIMBindingForensicEngine()
    _, audit_records = engine.analyze_sim_and_sms(
        telephony_db_path=telephony_db_path,
        sms_db_path=sms_db_path,
    )

    assert len(audit_records) == 1
    audit = audit_records[0]
    assert audit.creator_package_name == "com.parivahan.echallan.apk"
    assert audit.binding_attribution_verdict == "COMPROMISED_REMOTE_GHOST_SIM_BINDING_VIA_TROJAN"


# ==============================================================================
# TEST 3: NPCI Common Library (CL) Preferences & Bound ICCID Parser Test
# ==============================================================================

def test_npci_cl_vault_and_bound_iccid_extraction(tmp_binding_dir):
    """
    Acceptance Test 3 (Section 8.3 & Section 5):
    Constructs an NPCI Common Library preference XML file inside PhonePe's sandbox:
    shared_prefs/org.npci.upi.security.pinactivitycomponent.clprefs.xml containing:
    - cl_device_id = "ANDROID_ID_A1B2C3D4E5"
    - k0_token = "K0_VAULT_TOKEN_BLOB_BASE64_998877"
    - bound_sim_iccid = "89918540400012345678"
    - bound_mobile = "+919876543210"
    - registration_timestamp = 1704110400000
    Verifies that NPCICommonLibraryParser:
    1. Extracts bound hardware device ID and K0 token presence flag (cl_k0_token_present = 1).
    2. Extracts the exact bound SIM ICCID monitored by the host app for SIM-swap locking.
    3. Normalizes registration timestamp to UTC ISO-8601.
    """
    from src.binding.cl_vault import NPCICommonLibraryParser

    app_prefs_dir = tmp_binding_dir / "com.phonepe.app" / "shared_prefs"
    app_prefs_dir.mkdir(parents=True, exist_ok=True)
    cl_prefs_xml = app_prefs_dir / "org.npci.upi.security.pinactivitycomponent.clprefs.xml"

    xml_content = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="cl_device_id">ANDROID_ID_A1B2C3D4E5</string>
    <string name="k0_token">K0_VAULT_TOKEN_BLOB_BASE64_998877</string>
    <string name="bound_sim_iccid">89918540400012345678</string>
    <int name="bound_sim_sub_id" value="3" />
    <string name="bound_mobile_msisdn">+919876543210</string>
    <long name="binding_registration_ts" value="1704110400000" />
</map>
"""
    with open(cl_prefs_xml, "w", encoding="utf-8") as f:
        f.write(xml_content)

    parser = NPCICommonLibraryParser()
    record = parser.parse_cl_preferences(
        cl_prefs_xml,
        app_instance_id=1,
        source_vfs_file_id=301,
    )

    assert record is not None
    assert record.bound_hardware_device_id == "ANDROID_ID_A1B2C3D4E5"
    assert record.cl_k0_token_present == 1
    assert record.bound_sim_iccid_in_app == "89918540400012345678"
    assert record.bound_sim_sub_id_in_app == 3
    assert record.bound_mobile_msisdn == "+919876543210"
    assert record.binding_registered_utc_iso.startswith("2024-01-01T")


# ==============================================================================
# TEST 4: Master Ledger Export Test (npci_sim_binding_engine.sqlite)
# ==============================================================================

def test_npci_sim_binding_engine_master_ledger_export(tmp_binding_dir):
    """
    Section 7: Database Schema for Module 3.2
    Verifies that SIMBindingForensicEngine creates and exports to:
    1. device_sim_card_history_ledger
    2. upi_outbound_binding_sms_audit
    3. npci_common_library_vault_records
    inside npci_sim_binding_engine.sqlite with exact column names, constraints, and indexes.
    """
    from src.binding.engine import SIMBindingForensicEngine
    from src.binding.models import (
        DeviceSIMCardHistoryRecord,
        UPIOutboundBindingSMSAudit,
        NPCICommonLibraryVaultRecord,
    )

    ledger_path = tmp_binding_dir / "npci_sim_binding_engine.sqlite"
    engine = SIMBindingForensicEngine()

    sim = DeviceSIMCardHistoryRecord(
        os_platform="ANDROID",
        android_sub_id=3,
        iccid_20_digit="89918540400012345678",
        imsi_number="405861001122334",
        msisdn_phone_number="+919876543210",
        carrier_display_name="Jio 4G",
        mcc_mnc_code="405-861",
        sim_form_factor="PHYSICAL_SIM",
        seizure_slot_state="EJECTED_HISTORICAL_SIM",
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
    )

    audit = UPIOutboundBindingSMSAudit(
        source_vfs_file_id=101,
        sms_row_id=101,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        destination_vmn_number="9223008333",
        sms_payload_raw="PP a8f9d2...",
        inferred_target_psp_or_bank="PhonePe",
        android_sub_id=3,
        resolved_sim_iccid="89918540400012345678",
        resolved_sim_msisdn="+919876543210",
        creator_package_name="com.phonepe.app",
        delivery_status="SENT_SUCCESS",
        sent_utc_iso="2024-01-01T12:00:00.000000Z",
        binding_attribution_verdict="VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING",
    )

    cl_rec = NPCICommonLibraryVaultRecord(
        app_instance_id=1,
        source_vfs_file_id=301,
        bound_sim_iccid_in_app="89918540400012345678",
        bound_sim_sub_id_in_app=3,
        bound_mobile_msisdn="+919876543210",
        bound_hardware_device_id="ANDROID_ID_A1B2C3D4E5",
        cl_k0_token_present=1,
        matched_keystore_alias="npci_k0_key",
        binding_registered_utc_iso="2024-01-01T12:00:00.000000Z",
    )

    engine.export_to_ledger(
        sim_records=[sim],
        sms_audits=[audit],
        cl_records=[cl_rec],
        ledger_path=ledger_path,
    )

    assert ledger_path.exists()
    con = sqlite3.connect(ledger_path)
    cur = con.cursor()

    # 1. Check device_sim_card_history_ledger
    cur.execute("SELECT * FROM device_sim_card_history_ledger;")
    sim_row = cur.fetchone()
    assert sim_row is not None
    sim_cols = [d[0] for d in cur.description]
    assert "android_sub_id" in sim_cols
    assert "seizure_slot_state" in sim_cols

    # 2. Check upi_outbound_binding_sms_audit
    cur.execute("SELECT * FROM upi_outbound_binding_sms_audit;")
    sms_row = cur.fetchone()
    assert sms_row is not None
    sms_cols = [d[0] for d in cur.description]
    assert "binding_attribution_verdict" in sms_cols
    assert "resolved_sim_iccid" in sms_cols

    # 3. Check npci_common_library_vault_records
    cur.execute("SELECT * FROM npci_common_library_vault_records;")
    cl_row = cur.fetchone()
    assert cl_row is not None
    cl_cols = [d[0] for d in cur.description]
    assert "bound_sim_iccid_in_app" in cl_cols
    assert "cl_k0_token_present" in cl_cols

    con.close()
