"""
Test Suite for Phase 3, Module 3.4: The Indian TRAI DLT Financial SMS & System Notification Parser.

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real binary byte fixtures, SQLite databases, and typedstream blobs (no mock objects).
- All fixtures write strictly to ./.workspace_tmp/
- Tests iOS 16–26 attributedBody typedstream unpacking when text IS NULL.
- Tests TRAI DLT -P promotional loan spam rejection vs. authentic -S transactional alerts.
- Tests 1930 NCRP cybercrime lien hold alerts & carrier SMSC spoof injection detection.
- Verifies canonical dlt_sms_and_notifications_engine.sqlite schema and 2 tables.
"""

from pathlib import Path
import shutil
import sqlite3
import pytest

from src.core.enums import ResidualConfidence


@pytest.fixture
def tmp_dlt_dir():
    """Provides an isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_dlt_sms_engine")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


def build_ios_attributed_body_blob(text: str) -> bytes:
    """
    Constructs a binary Apple typedstream NSAttributedString blob
    conforming to Section 3.2 byte layout specification.
    """
    text_bytes = text.encode("utf-8")
    l_len = len(text_bytes)

    # Magic and typedstream header leading up to NSString marker sequence
    prefix = b"streamtyped\x00\x00\x00\x00\x84\x01\x03\x84\x84\x84\x08NSString\x01\x94\x84\x01\x2b"

    # Encodes length using 0x81 uint16_le indicator (Section 8.1 Acceptance criteria)
    len_indicator = bytes([0x81, l_len & 0xFF, (l_len >> 8) & 0xFF])
    return prefix + len_indicator + text_bytes + b"\x86"


# ==============================================================================
# TEST 1: iOS 18/26 attributedBody Null-Text Unpacker & Lakh Comma Test
# ==============================================================================

def test_ios_attributed_body_null_text_unpacker(tmp_dlt_dir):
    """
    Acceptance Test 1 (Section 8.1):
    1. Creates an iOS sms.db with message.text = NULL and message.attributedBody containing
       an Apple typedstream blob encoding:
       "Dear Customer, Rs.1,25,000.00 debited from A/c XX4821 on 05Nov26 to VPA mule@ybl. UPI Ref 630914829104. Avl Bal Rs.4,500.25"
    Verifies that Sub-Engine 3.4A & Sub-Engine 3.4C:
    1. Unpacks attributedBody to recover the complete message body text.
    2. Strips the Indian Lakh comma from "1,25,000.00" to output amount_inr_decimal = 125000.0.
    3. Extracts UTR 630914829104, post_tx_available_balance_inr = 4500.25,
       account_tail_digits = "4821", and counterparty_vpa_or_name = "mule@ybl".
    4. Categorizes the event as TX_DEBIT_OUTFLOW.
    """
    from src.dlt.engine import DLTFinancialSMSNotificationEngine

    raw_text = (
        "Dear Customer, Rs.1,25,000.00 debited from A/c XX4821 on 05Nov26 to VPA mule@ybl. "
        "UPI Ref 630914829104. Avl Bal Rs.4,500.25"
    )
    blob_data = build_ios_attributed_body_blob(raw_text)

    # Create synthetic iOS sms.db
    sms_db_path = tmp_dlt_dir / "sms.db"
    con = sqlite3.connect(sms_db_path)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE message (
            ROWID INTEGER PRIMARY KEY,
            handle_id INTEGER,
            text TEXT,
            attributedBody BLOB,
            service TEXT,
            date INTEGER,
            is_from_me INTEGER DEFAULT 0
        );
    """)
    cur.execute("""
        CREATE TABLE handle (
            ROWID INTEGER PRIMARY KEY,
            id TEXT
        );
    """)
    cur.execute("INSERT INTO handle VALUES (1, 'AD-SBIINB-S');")
    # text IS NULL, attributedBody has typedstream
    cur.execute(
        """
        INSERT INTO message (ROWID, handle_id, text, attributedBody, service, date, is_from_me)
        VALUES (101, 1, NULL, ?, 'SMS', 784000000000000000, 0);
        """,
        (blob_data,),
    )
    con.commit()
    con.close()

    engine = DLTFinancialSMSNotificationEngine()
    records = engine.parse_ios_sms_db(sms_db_path)

    assert len(records) == 1
    rec = records[0]
    assert rec.amount_inr_decimal == 125000.0
    assert rec.post_tx_available_balance_inr == 4500.25
    assert rec.utr_or_rrn_reference == "630914829104"
    assert rec.sms_event_category == "TX_DEBIT_OUTFLOW"
    assert rec.account_tail_digits == "4821"
    assert rec.counterparty_vpa_or_name == "mule@ybl"
    assert "Rs.1,25,000.00 debited" in rec.full_sms_body_text


# ==============================================================================
# TEST 2: TRAI -P Promotional Loan Spam Rejection Test
# ==============================================================================

def test_trai_p_promotional_loan_spam_rejection(tmp_dlt_dir):
    """
    Acceptance Test 2 (Section 8.2):
    Evaluates two DLT messages:
    - Message 1: Sender "VM-HDFCBK-P",
      Body: "Congrats! Pre-approved Loan of Rs. 5,00,000 credited to your offer account! Click http://hdfc.lo/xyz"
    - Message 2: Sender "VM-HDFCBK-S",
      Body: "Rs. 5,00,000.00 credited to A/c XX4821 on 05-11-26 by IMPS Ref 630999887766. Avl Bal: Rs. 5,10,000.00"
    Verifies that:
    1. Message 1 is categorized as PROMOTIONAL_SPAM_IGNORED and excluded from the financial balance ledger.
    2. Message 2 is categorized as TX_CREDIT_INFLOW with amount_inr_decimal = 500000.0,
       post_tx_available_balance_inr = 510000.0, and UTR = "630999887766".
    """
    from src.dlt.dlt_headers import DLTHeaderParser
    from src.dlt.sms_grammar import FinancialSMSGrammarParser

    dlt_parser = DLTHeaderParser()
    grammar_parser = FinancialSMSGrammarParser()

    # Message 1: Promotional loan spam with -P suffix
    sender_1 = "VM-HDFCBK-P"
    body_1 = "Congrats! Pre-approved Loan of Rs. 5,00,000 credited to your offer account! Click http://hdfc.lo/xyz"
    h1 = dlt_parser.parse_header(sender_1)
    res_1 = grammar_parser.parse_sms(body=body_1, dlt_header_info=h1)

    assert h1.is_promotional_dlt is True
    assert h1.category_suffix == "P"
    assert res_1.sms_event_category == "PROMOTIONAL_SPAM_IGNORED"

    # Message 2: Legitimate credit alert with -S suffix
    sender_2 = "VM-HDFCBK-S"
    body_2 = "Rs. 5,00,000.00 credited to A/c XX4821 on 05-11-26 by IMPS Ref 630999887766. Avl Bal: Rs. 5,10,000.00"
    h2 = dlt_parser.parse_header(sender_2)
    res_2 = grammar_parser.parse_sms(body=body_2, dlt_header_info=h2)

    assert h2.is_promotional_dlt is False
    assert h2.category_suffix == "S"
    assert res_2.sms_event_category == "TX_CREDIT_INFLOW"
    assert res_2.amount_inr_decimal == 500000.0
    assert res_2.post_tx_available_balance_inr == 510000.0
    assert res_2.utr_or_rrn_reference == "630999887766"


# ==============================================================================
# TEST 3: 1930 Cybercrime Lien & Carrier SMSC Spoof Detection Test
# ==============================================================================

def test_cybercrime_lien_and_smsc_spoof_detection(tmp_dlt_dir):
    """
    Acceptance Test 3 (Section 8.3 & Section 4.3):
    1. Evaluates Message 1:
       - Sender "AD-CYBERC-G", Body "Hold of INR 45,000.00 marked on A/c XX4821 for Cyber Crime Ack No 33111260048291"
       - service_center = "+919820005444", protocol = 0
       Verifies: Category LIEN_HOLD_OR_FREEZE_ALERT, amount 45000.0, Ack No 33111260048291, is_spoofed = 0.
    2. Evaluates Message 2:
       - Sender "AD-SBIINB-S", Body "Rs. 2,00,000.00 credited to A/c XX1234"
       - service_center = NULL, creator = "com.fake.sms.maker"
       Verifies: is_spoofed_sms_suspected = 1 ("SPOOFED_LOCAL_SMS_INJECTION").
    """
    from src.dlt.dlt_headers import DLTHeaderParser
    from src.dlt.sms_grammar import FinancialSMSGrammarParser

    dlt_parser = DLTHeaderParser()
    grammar_parser = FinancialSMSGrammarParser()

    # Message 1: Genuine 1930 Cyber Crime Hold SMS
    sender_1 = "AD-CYBERC-G"
    body_1 = "Hold of INR 45,000.00 marked on A/c XX4821 for Cyber Crime Ack No 33111260048291"
    h1 = dlt_parser.parse_header(sender_1)
    res_1 = grammar_parser.parse_sms(body=body_1, dlt_header_info=h1)

    spoof_1 = dlt_parser.detect_smsc_spoof(
        service_center="+919820005444",
        creator="com.google.android.apps.messaging",
        msg_type=1,
    )

    assert res_1.sms_event_category == "LIEN_HOLD_OR_FREEZE_ALERT"
    assert res_1.amount_inr_decimal == 45000.0
    assert res_1.atm_location_or_otp_digits == "33111260048291"
    assert spoof_1 is False

    # Message 2: Injected Fake SMS (NULL service_center + third party creator)
    spoof_2 = dlt_parser.detect_smsc_spoof(
        service_center=None,
        creator="com.fake.sms.maker",
        msg_type=1,
    )
    assert spoof_2 is True


# ==============================================================================
# TEST 4: Master Ledger Export Test (dlt_sms_and_notifications_engine.sqlite)
# ==============================================================================

def test_dlt_sms_and_notifications_master_ledger_export(tmp_dlt_dir):
    """
    Section 7: Database Schema for Module 3.4
    Verifies that DLTFinancialSMSNotificationEngine creates and exports to:
    1. dlt_financial_sms_ledger
    2. os_financial_notification_ledger
    inside dlt_sms_and_notifications_engine.sqlite with exact column names, constraints, and indexes.
    """
    from src.dlt.engine import DLTFinancialSMSNotificationEngine
    from src.dlt.models import (
        DLTFinancialSMSLedgerRecord,
        OSFinancialNotificationRecord,
    )

    ledger_path = tmp_dlt_dir / "dlt_sms_and_notifications_engine.sqlite"
    engine = DLTFinancialSMSNotificationEngine()

    sms_rec = DLTFinancialSMSLedgerRecord(
        source_vfs_file_id=501,
        source_db_type="ANDROID_MMSSMS_DE",
        original_sms_rowid=1,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        raw_sender_address="AD-SBIINB-S",
        dlt_operator_and_circle="Airtel — Delhi NCR",
        dlt_entity_code="SBIINB",
        dlt_category_suffix="S",
        resolved_institution_name="State Bank of India (SBI)",
        sms_event_category="TX_DEBIT_OUTFLOW",
        masked_account_or_card="A/c XX4821",
        account_tail_digits="4821",
        payment_rail="UPI",
        utr_or_rrn_reference="630914829104",
        amount_inr_decimal=125000.0,
        post_tx_available_balance_inr=4500.25,
        counterparty_vpa_or_name="mule@ybl",
        android_sub_id=1,
        receiving_sim_iccid="89918540400012345678",
        carrier_smsc_number="+919820005444",
        is_spoofed_sms_suspected=0,
        full_sms_body_text="Dear Customer, Rs.1,25,000.00 debited...",
        received_utc_ns=1704110400000000000,
        received_utc_iso="2024-01-01T12:00:00.000000Z",
    )

    notif_rec = OSFinancialNotificationRecord(
        source_vfs_file_id=601,
        notification_subsystem="IOS_DUET_EXPERT_CENTER",
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        target_app_bundle_or_pkg="com.phonepe.PhonePeApp",
        is_metadata_only_no_body=1,
        user_interaction_state="OPENED_ENGAGED",
        delivered_utc_iso="2024-01-01T12:00:05.000000Z",
    )

    engine.export_to_ledger(
        sms_records=[sms_rec],
        notification_records=[notif_rec],
        ledger_path=ledger_path,
    )

    assert ledger_path.exists()
    con = sqlite3.connect(ledger_path)
    cur = con.cursor()

    # 1. dlt_financial_sms_ledger
    cur.execute("SELECT * FROM dlt_financial_sms_ledger;")
    sms_row = cur.fetchone()
    assert sms_row is not None
    sms_cols = [d[0] for d in cur.description]
    assert "dlt_operator_and_circle" in sms_cols
    assert "account_tail_digits" in sms_cols
    assert "utr_or_rrn_reference" in sms_cols
    assert "is_spoofed_sms_suspected" in sms_cols

    # 2. os_financial_notification_ledger
    cur.execute("SELECT * FROM os_financial_notification_ledger;")
    notif_row = cur.fetchone()
    assert notif_row is not None
    notif_cols = [d[0] for d in cur.description]
    assert "is_metadata_only_no_body" in notif_cols
    assert "target_app_bundle_or_pkg" in notif_cols

    con.close()
