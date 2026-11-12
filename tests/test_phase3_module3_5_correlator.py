"""
Test Suite for Phase 3, Module 3.5:
The 4-Way UTR Correlator, VPA Handle Resolver & Mule-Account Fraud Detector.

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real binary byte fixtures, SQLite databases, and Verhoeff/Julian math (no mock objects).
- All fixtures write strictly to ./.workspace_tmp/
- Tests 4-layer single-transaction fusion (deduplicating L1A + L1B + L2 + L3 into 1 Master Row).
- Tests 12-digit Julian-day YDDD UTR vs. Aadhaar Verhoeff D5 dihedral disambiguation.
- Tests IMPS + 18% GST micro-fee tolerance vs. true deleted-SMS balance gap detection.
- Tests 45-handle VPA router, secondary mobile suffix stripper, and direct account+IFSC parser.
- Verifies canonical financial_correlator_and_fraud_engine.sqlite schema and master tables.
"""

from pathlib import Path
import shutil
import sqlite3
import pytest

from src.core.enums import ResidualConfidence


@pytest.fixture
def tmp_correlator_dir():
    """Provides an isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_financial_correlator_engine")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


# ==============================================================================
# TEST 1: The 4-Layer Single-Transaction Deduplication Test
# ==============================================================================

def test_4_layer_single_transaction_deduplication(tmp_correlator_dir):
    """
    Acceptance Test 1 (Section 8.1):
    Inserts the same ₹50,000 transaction (UTR = "630914829104") into four layers:
    1. Layer 1A (PhonePe upi_app_sandbox_transactions): amount = 50000.0, status = "SUCCESS"
    2. Layer 1B (SBI bank_mpassbook_and_sandbox_ledger): amount = 50000.0, running_balance = 125000.0
    3. Layer 2 (dlt_financial_sms_ledger): amount = 50000.0, Avl Bal = 125000.0
    4. Layer 3 (os_financial_notification_ledger): amount = 50000.0, Duet ping
    Verifies that Sub-Engine 3.5C:
    1. Fuses all 4 records into EXACTLY 1 row in unified_financial_transactions_ledger.
    2. Sets corroboration_level = "SETTLED_BANK_AND_APP_VERIFIED".
    3. Preserves all 4 source layer record IDs in source_records_lineage_json.
    """
    from src.correlator.engine import FinancialCorrelatorEngine
    from src.upi.models import UPITransactionRecord
    from src.banking.models import BankMPassbookLedgerRecord
    from src.dlt.models import DLTFinancialSMSLedgerRecord, OSFinancialNotificationRecord

    utr_val = "630914829104"
    tx_time = "2026-11-05T12:00:00.000000Z"

    # Layer 1A: PhonePe Sandbox
    l1a_tx = UPITransactionRecord(
        app_instance_id=1,
        source_vfs_file_id=101,
        app_name="PhonePe",
        payer_vpa="user@ybl",
        payee_vpa="merchant@okaxis",
        amount_inr_decimal=50000.0,
        npci_utr_or_rrn=utr_val,
        transaction_status="SUCCESS",
        initiated_timestamp_utc_iso=tx_time,
        settled_timestamp_utc_iso=tx_time,
        source_record_rowid=11,
    )

    # Layer 1B: SBI mPassbook
    l1b_tx = BankMPassbookLedgerRecord(
        source_vfs_file_id=201,
        source_artifact_type="OFFLINE_MPASSBOOK_DB",
        payment_rail="UPI",
        tx_direction="DEBIT",
        amount_inr_decimal=50000.0,
        running_balance_inr=125000.0,
        utr_or_rrn_reference=utr_val,
        tx_utc_iso=tx_time,
        bank_tx_uid=22,
    )

    # Layer 2: DLT Bank SMS
    l2_sms = DLTFinancialSMSLedgerRecord(
        source_vfs_file_id=301,
        source_db_type="ANDROID_MMSSMS_DE",
        original_sms_rowid=33,
        raw_sender_address="AD-SBIINB-S",
        resolved_institution_name="State Bank of India (SBI)",
        sms_event_category="TX_DEBIT_OUTFLOW",
        amount_inr_decimal=50000.0,
        post_tx_available_balance_inr=125000.0,
        utr_or_rrn_reference=utr_val,
        full_sms_body_text="Rs.50,000.00 debited from A/c XX4821 on 05Nov26. UPI Ref 630914829104",
        received_utc_ns=1793887200000000000,
        received_utc_iso=tx_time,
    )

    # Layer 3: OS Push Notification
    l3_notif = OSFinancialNotificationRecord(
        source_vfs_file_id=401,
        notification_subsystem="IOS_DUET_EXPERT_CENTER",
        target_app_bundle_or_pkg="com.phonepe.PhonePeApp",
        delivered_utc_iso=tx_time,
        fin_notif_uid=44,
        is_metadata_only_no_body=1,
    )

    engine = FinancialCorrelatorEngine()
    fused_ledger = engine.fuse_and_deduplicate(
        upi_transactions=[l1a_tx],
        banking_transactions=[l1b_tx],
        dlt_sms_records=[l2_sms],
        notification_records=[l3_notif],
    )

    assert len(fused_ledger) == 1
    master_row = fused_ledger[0]
    assert master_row.utr_or_rrn == utr_val
    assert master_row.amount_inr_decimal == 50000.0
    assert master_row.post_tx_balance_inr == 125000.0
    assert master_row.corroboration_level == "SETTLED_BANK_AND_APP_VERIFIED"
    assert "L1A" in master_row.source_records_lineage_json
    assert "L1B" in master_row.source_records_lineage_json
    assert "L2" in master_row.source_records_lineage_json
    assert "L3" in master_row.source_records_lineage_json


# ==============================================================================
# TEST 2: Verhoeff Aadhaar vs. Julian-Day UTR Disambiguation Test
# ==============================================================================

def test_verhoeff_aadhaar_vs_julian_day_utr_disambiguation(tmp_correlator_dir):
    """
    Acceptance Test 2 (Section 8.2 & Section 3):
    1. Evaluates Aadhaar number "248211223343":
       - Satisfies Verhoeff D5 dihedral checksum.
       - Digits 2-4 are 482 > 366 (impossible Julian day!).
       Verifies: is_aadhaar = True, utr_validation_status = "POSSIBLE_AADHAAR_NUMBER".
    2. Evaluates UTR "630914829104":
       - Digit 1 = 6 (Year 2026).
       - Digits 2-4 = 309 (Nov 5, 2026, Julian day 309).
       Verifies: is_aadhaar = False, utr_validation_status = "VALID_NPCI_YDDD_MATCH".
    """
    from src.correlator.utr_validator import NPCIUTRJulianAndVerhoeffValidator

    validator = NPCIUTRJulianAndVerhoeffValidator()

    # 1. Test Aadhaar Number
    aadhaar_num = "248211223343"
    aadhaar_res = validator.classify_12_digit_number(
        candidate_number=aadhaar_num,
        tx_utc_iso="2026-11-05T12:00:00.000000Z",
    )
    assert aadhaar_res.is_aadhaar_number is True
    assert aadhaar_res.utr_validation_status == "POSSIBLE_AADHAAR_NUMBER"

    # 2. Test Genuine NPCI UTR
    utr_num = "630914829104"
    utr_res = validator.classify_12_digit_number(
        candidate_number=utr_num,
        tx_utc_iso="2026-11-05T12:00:00.000000Z",
    )
    assert utr_res.is_aadhaar_number is False
    assert utr_res.utr_validation_status == "VALID_NPCI_YDDD_MATCH"
    assert utr_res.extracted_julian_day == 309
    assert utr_res.extracted_year_digit == 6


# ==============================================================================
# TEST 3: IMPS+GST Fee Tolerance vs. True Deleted-SMS Gap Test
# ==============================================================================

def test_imps_gst_fee_tolerance_vs_true_deleted_sms_gap(tmp_correlator_dir):
    """
    Acceptance Test 3 (Section 8.3 & Section 6.1):
    Evaluates balance sequence for Account XX4821:
    - Step A:
      Tx 1: Starting Avl Bal = 10000.00
      Tx 2: IMPS debit of 5000.00, Avl Bal = 4994.10 (diff = 5.90, IMPS + 18% GST)
      Verifies: Classifies 5.90 as MINOR_BANK_FEE_OR_SMS_CHARGE_DELTA without false alarm.
    - Step B:
      Tx 3: Debit of 1000.00, Avl Bal = 994.10 (diff = 3000.00 missing drop!)
      Verifies: Triggers CRITICAL DELETED_SMS_BALANCE_GAP alert for exactly ₹3,000.00.
    """
    from src.correlator.fraud_detector import MuleAccountAndFraudDetector
    from src.correlator.models import UnifiedTransactionRecord

    detector = MuleAccountAndFraudDetector()

    # Step A: Normal transfer with 5.90 IMPS fee
    tx1 = UnifiedTransactionRecord(
        master_tx_uid=1,
        utr_or_rrn="630900000001",
        account_tail_digits="4821",
        tx_direction="CREDIT",
        amount_inr_decimal=10000.0,
        post_tx_balance_inr=10000.0,
        tx_utc_iso="2026-11-05T10:00:00.000000Z",
    )
    tx2 = UnifiedTransactionRecord(
        master_tx_uid=2,
        utr_or_rrn="630900000002",
        account_tail_digits="4821",
        tx_direction="DEBIT",
        amount_inr_decimal=5000.0,
        post_tx_balance_inr=4994.10,  # 10000 - 5000 - 5.90 = 4994.10
        tx_utc_iso="2026-11-05T11:00:00.000000Z",
    )

    flags_a = detector.audit_balance_continuity([tx1, tx2])
    # Should contain MINOR_BANK_FEE_OR_SMS_CHARGE_DELTA, and 0 CRITICAL gap alarms
    assert len(flags_a) == 1
    assert flags_a[0].flag_category == "MINOR_BANK_FEE_OR_SMS_CHARGE_DELTA"
    assert flags_a[0].severity == "INFO"

    # Step B: True Deleted SMS balance gap of 3000.00
    tx3 = UnifiedTransactionRecord(
        master_tx_uid=3,
        utr_or_rrn="630900000003",
        account_tail_digits="4821",
        tx_direction="DEBIT",
        amount_inr_decimal=1000.0,
        post_tx_balance_inr=994.10,  # Expected 4994.10 - 1000 = 3994.10, actual is 994.10!
        tx_utc_iso="2026-11-05T12:00:00.000000Z",
    )

    flags_b = detector.audit_balance_continuity([tx1, tx2, tx3])
    critical_gaps = [f for f in flags_b if f.flag_category == "DELETED_SMS_BALANCE_GAP"]
    assert len(critical_gaps) == 1
    gap = critical_gaps[0]
    assert gap.severity == "CRITICAL"
    assert gap.discrepancy_amount_inr == 3000.0


# ==============================================================================
# TEST 4: VPA Handle Routing & Mobile Suffix Extraction Test
# ==============================================================================

def test_vpa_routing_and_mobile_extraction(tmp_correlator_dir):
    """
    Section 4.1 & Section 4.2:
    Verifies:
    1. VPAResolver maps @ybl to PhonePe / Yes Bank.
    2. VPAResolver maps @okaxis to Google Pay India / Axis Bank.
    3. Strips secondary suffix from '9876543210-2@okaxis' to extract '9876543210'.
    4. Splits direct routing VPA '501002345678@HDFC0001234.ifsc.npci' to account '501002345678'
       and IFSC 'HDFC0001234'.
    """
    from src.correlator.vpa_resolver import VPARoutingResolver

    resolver = VPARoutingResolver()

    # 1. PhonePe / Yes Bank
    res1 = resolver.resolve_vpa("merchant@ybl")
    assert res1.owning_tpap_app == "PhonePe"
    assert res1.sponsor_psp_bank == "Yes Bank"

    # 2. Google Pay / Axis Bank with secondary account suffix "-2"
    res2 = resolver.resolve_vpa("9876543210-2@okaxis")
    assert res2.owning_tpap_app == "Google Pay India"
    assert res2.sponsor_psp_bank == "Axis Bank"
    assert res2.inferred_mobile_number == "9876543210"

    # 3. Direct Account + IFSC routing VPA
    res3 = resolver.resolve_vpa("501002345678@HDFC0001234.ifsc.npci")
    assert res3.is_direct_account_ifsc_vpa is True
    assert res3.direct_account_number == "501002345678"
    assert res3.direct_ifsc_code == "HDFC0001234"


# ==============================================================================
# TEST 5: Master Correlator Ledger Export Test
# ==============================================================================

def test_financial_correlator_master_ledger_export(tmp_correlator_dir):
    """
    Section 7: Database Schema for Module 3.5
    Verifies that FinancialCorrelatorEngine creates and exports to:
    1. unified_financial_transactions_ledger
    2. financial_corroboration_and_fraud_flags
    3. financial_counterparty_comms_crosslink
    inside financial_correlator_and_fraud_engine.sqlite with exact column names and indexes.
    """
    from src.correlator.engine import FinancialCorrelatorEngine
    from src.correlator.models import (
        UnifiedTransactionRecord,
        FinancialFraudFlagRecord,
        CounterpartyCommsCrosslinkRecord,
    )

    ledger_path = tmp_correlator_dir / "financial_correlator_and_fraud_engine.sqlite"
    engine = FinancialCorrelatorEngine()

    u_tx = UnifiedTransactionRecord(
        utr_or_rrn="630914829104",
        account_tail_digits="4821",
        tx_direction="DEBIT",
        payment_rail="UPI",
        amount_inr_decimal=50000.0,
        post_tx_balance_inr=125000.0,
        settlement_status="SETTLED_SUCCESS",
        corroboration_level="SETTLED_BANK_AND_APP_VERIFIED",
        source_records_lineage_json='{"L1": 11, "L2": 33}',
        tx_utc_iso="2026-11-05T12:00:00.000000Z",
    )

    flag = FinancialFraudFlagRecord(
        flag_category="DELETED_SMS_BALANCE_GAP",
        severity="CRITICAL",
        account_tail_digits="4821",
        discrepancy_amount_inr=3000.0,
        narrative_summary="Missing 3000.00 INR balance drop between 11:00 and 12:00",
        flagged_utc_iso="2026-11-05T12:00:00.000000Z",
    )

    crosslink = CounterpartyCommsCrosslinkRecord(
        vpa_entry_uid=1,
        counterparty_vpa_or_acct="mule@ybl",
        matched_mobile_number="9876543210",
        voice_calls_count=2,
        chat_messages_count=5,
        shortest_chat_to_tx_delta_sec=120,
    )

    engine.export_to_ledger(
        unified_transactions=[u_tx],
        fraud_flags=[flag],
        comms_crosslinks=[crosslink],
        ledger_path=ledger_path,
    )

    assert ledger_path.exists()
    con = sqlite3.connect(ledger_path)
    cur = con.cursor()

    # 1. unified_financial_transactions_ledger
    cur.execute("SELECT * FROM unified_financial_transactions_ledger;")
    u_row = cur.fetchone()
    assert u_row is not None
    u_cols = [d[0] for d in cur.description]
    assert "corroboration_level" in u_cols
    assert "source_records_lineage_json" in u_cols

    # 2. financial_corroboration_and_fraud_flags
    cur.execute("SELECT * FROM financial_corroboration_and_fraud_flags;")
    f_row = cur.fetchone()
    assert f_row is not None
    f_cols = [d[0] for d in cur.description]
    assert "flag_category" in f_cols
    assert "discrepancy_amount_inr" in f_cols

    # 3. financial_counterparty_comms_crosslink
    cur.execute("SELECT * FROM financial_counterparty_comms_crosslink;")
    c_row = cur.fetchone()
    assert c_row is not None
    c_cols = [d[0] for d in cur.description]
    assert "matched_mobile_number" in c_cols
    assert "shortest_chat_to_tx_delta_sec" in c_cols

    con.close()
