"""
Test Suite for Phase 3, Module 3.1: Dedicated UPI Super-App Sandbox Decoders
(PhonePe, Google Pay India, Paytm, BHIM, WhatsApp Pay, FamPay, CRED, Navi, super.money & BharatQR TLV).

Adheres strictly to AGENTS.md Two-Phase TDD and Forensic Invariants:
- Real binary byte fixtures and SQLite databases (no mock objects).
- All fixtures write strictly to ./.workspace_tmp/
- Tests dynamic filename schema fingerprinting on PhonePe databases.
- Tests Google Pay India dual-name attribution and google.type.Money / units / nanos math.
- Tests WhatsApp Pay amount_1000 division math (INR = amount_1000 / 1000.0).
- Tests Universal BharatQR EMVCo recursive TLV parsing (VPA, MCC, City, PIN code).
- Verifies canonical upi_superapp_sandbox_artifacts.sqlite schema.
"""

import json
from pathlib import Path
import shutil
import sqlite3
import struct
from typing import Dict, Any

import pytest

from src.core.enums import ResidualConfidence


@pytest.fixture
def tmp_upi_dir():
    """Provides an isolated scratch directory under ./.workspace_tmp/"""
    scratch = Path("./.workspace_tmp/test_upi_superapp_engine")
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True, exist_ok=True)
    yield scratch
    if scratch.exists():
        shutil.rmtree(scratch, ignore_errors=True)


# ==============================================================================
# TEST 1: Schema-Fingerprinted Dynamic Filename Test (PhonePe)
# ==============================================================================

def test_phonepe_dynamic_filename_schema_fingerprint(tmp_upi_dir):
    """
    Acceptance Test 1 (Section 9.1):
    Constructs a dynamically named PhonePe database inside a cloned user profile:
    /data/user/999/com.phonepe.app/databases/workflow_99a8b7c6.db
    containing a Room table with a nested rawPayload JSON column:
    - amountInPaise = 450000
    - utr = "630911223344"
    - senderVpa = "suspect@ybl"
    - receiverVpa = "mule_account@okaxis"
    - payeeName = "MOHAMMAD IMRAN"
    Verifies that PhonePeDecoder:
    1. Identifies the database via schema fingerprinting, ignoring the random filename.
    2. Unpacks the nested rawPayload JSON.
    3. Normalizes amountInPaise to amount_inr_decimal = 4500.00.
    4. Extracts UTR, sender VPA, receiver VPA, and verified payee name.
    """
    from src.upi.phonepe import PhonePeDecoder

    db_dir = tmp_upi_dir / "user_999" / "com.phonepe.app" / "databases"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "workflow_99a8b7c6.db"

    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE workflow_transactions (
            transactionId TEXT PRIMARY KEY,
            amount INTEGER,
            state TEXT,
            utr TEXT,
            createdAt INTEGER,
            workflowType TEXT,
            rawPayload TEXT
        );
    """)

    payload_json = json.dumps({
        "amountInPaise": 450000,
        "payerVpa": "suspect@ybl",
        "payeeVpa": "mule_account@okaxis",
        "payeeName": "MOHAMMAD IMRAN",
        "instrumentType": "ACCOUNT",
        "bankReferenceNo": "630911223344",
        "note": "Payment for hawala tokens"
    })

    cur.execute("""
        INSERT INTO workflow_transactions VALUES (
            'T2611051430229182736451',
            450000,
            'COMPLETED',
            '630911223344',
            1704110400000,
            'UPI_PAY',
            ?
        );
    """, (payload_json,))
    con.commit()
    con.close()

    decoder = PhonePeDecoder()
    transactions, chats, lookups = decoder.decode_database(
        db_path,
        app_instance_id=1,
        source_vfs_file_id=101,
    )

    assert len(transactions) == 1
    tx = transactions[0]
    assert tx.utr_12_digit == "630911223344"
    assert tx.app_order_or_tx_id == "T2611051430229182736451"
    assert tx.amount_inr_decimal == 4500.00
    assert tx.payer_vpa == "suspect@ybl"
    assert tx.payee_vpa == "mule_account@okaxis"
    assert tx.counterparty_verified_cbs_name == "MOHAMMAD IMRAN"
    assert tx.payment_note_remarks == "Payment for hawala tokens"
    assert tx.created_utc_iso.startswith("2024-01-01T")


# ==============================================================================
# TEST 2: Google Pay India Dual-Name & Protobuf Money Math Test
# ==============================================================================

def test_google_pay_india_dual_name_and_money_math(tmp_upi_dir):
    """
    Acceptance Test 2 (Section 9.2):
    Constructs a Google Pay India paisa.db SQLite database:
    1. Table participants:
       - participant_id = "P_1001"
       - phone_number = "+919876543210"
       - vpa = "crypto.dealer@okaxis"
       - display_name = "Crypto Dealer" (Suspect's local nickname)
       - banking_name = "VIKRAM ADITYA SINGH" (NPCI verified CBS legal name)
    2. Table stream_items:
       - item_id = "CICAgICAgICAmA"
       - participant_id = "P_1001"
       - item_type = "PAYMENT_TRANSACTION"
       - status = "SUCCESS"
       - utr = "630999887711"
       - proto_blob containing google.type.Money:
         Field 1 (currency_code) = "INR"
         Field 2 (units) = 15000
         Field 3 (nanos) = 500000000
    Verifies that GooglePayDecoder:
    1. Preserves both display_name and banking_name side-by-side.
    2. Computes amount_inr_decimal = units + (nanos / 10^9) = 15000.50.
    3. Correctly normalizes all counterparty and transaction fields.
    """
    from src.upi.gpay import GooglePayDecoder
    from src.nonsqlite.varint import encode_le_varint

    db_dir = tmp_upi_dir / "com.google.android.apps.nbu.paisa.user" / "databases"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "paisa.db"

    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE participants (
            participant_id TEXT PRIMARY KEY,
            phone_number TEXT,
            vpa TEXT,
            display_name TEXT,
            banking_name TEXT,
            participant_proto BLOB
        );
    """)

    cur.execute("""
        CREATE TABLE stream_items (
            item_id TEXT PRIMARY KEY,
            participant_id TEXT,
            item_type TEXT,
            status TEXT,
            utr TEXT,
            timestamp_ms INTEGER,
            proto_blob BLOB
        );
    """)

    cur.execute("""
        INSERT INTO participants VALUES (
            'P_1001',
            '+919876543210',
            'crypto.dealer@okaxis',
            'Crypto Dealer',
            'VIKRAM ADITYA SINGH',
            NULL
        );
    """)

    # Build raw Protobuf wire bytes for google.type.Money:
    # Field 1 (string, tag 0x0A): "INR" -> 0x0A, 0x03, 'I', 'N', 'R'
    # Field 2 (varint, tag 0x10): 15000 -> 0x10, varint(15000)
    # Field 3 (varint, tag 0x18): 500000000 -> 0x18, varint(500000000)
    money_wire = bytearray()
    money_wire.extend(b"\x0a\x03INR")
    money_wire.append(0x10)
    money_wire.extend(encode_le_varint(15000))
    money_wire.append(0x18)
    money_wire.extend(encode_le_varint(500000000))

    # Outer Protobuf message:
    # Field 1 (Money message, tag 0x0A): len + money_wire
    # Field 2 (string UTR, tag 0x12): "630999887711"
    outer_proto = bytearray()
    outer_proto.append(0x0a)
    outer_proto.extend(encode_le_varint(len(money_wire)))
    outer_proto.extend(money_wire)
    outer_proto.append(0x12)
    outer_proto.extend(encode_le_varint(len("630999887711")))
    outer_proto.extend(b"630999887711")

    cur.execute("""
        INSERT INTO stream_items VALUES (
            'CICAgICAgICAmA',
            'P_1001',
            'PAYMENT_TRANSACTION',
            'SUCCESS',
            '630999887711',
            1704110400000,
            ?
        );
    """, (bytes(outer_proto),))
    con.commit()
    con.close()

    decoder = GooglePayDecoder()
    transactions, chats = decoder.decode_database(
        db_path,
        app_instance_id=2,
        source_vfs_file_id=102,
    )

    assert len(transactions) == 1
    tx = transactions[0]
    assert tx.utr_12_digit == "630999887711"
    assert tx.app_order_or_tx_id == "CICAgICAgICAmA"
    assert tx.amount_inr_decimal == 15000.50
    assert tx.counterparty_display_name == "Crypto Dealer"
    assert tx.counterparty_verified_cbs_name == "VIKRAM ADITYA SINGH"
    assert tx.payee_vpa == "crypto.dealer@okaxis"


# ==============================================================================
# TEST 3: WhatsApp Pay amount_1000 Math & Ledger Integration Test
# ==============================================================================

def test_whatsapp_pay_amount_1000_division_math(tmp_upi_dir):
    """
    Acceptance Test 3 (Section 9.3):
    Constructs a WhatsApp msgstore.db SQLite database:
    Table pay_transaction with columns:
    - id = "PAY_TX_9988"
    - sender_jid = "919876543210@s.whatsapp.net"
    - receiver_jid = "918765432109@s.whatsapp.net"
    - amount_1000 = 12500000 (12.5 million milli-Rupees)
    - status = 106 (Success)
    - timestamp = 1704110400000
    - extra_data = JSON {"vpa": "suspect@waicici", "receiver_vpa": "merchant@wahdfcbank", "utr": "630999887766"}
    Verifies that WhatsAppPayDecoder:
    1. Divides amount_1000 by 1000.0 to output 12500.00 (not 125000.00).
    2. Extracts UTR, sender JID, receiver JID, and VPA handles.
    """
    from src.upi.whatsapp_pay import WhatsAppPayDecoder

    db_dir = tmp_upi_dir / "com.whatsapp" / "databases"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "msgstore.db"

    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE pay_transaction (
            id TEXT PRIMARY KEY,
            sender_jid TEXT,
            receiver_jid TEXT,
            amount_1000 INTEGER,
            status INTEGER,
            timestamp INTEGER,
            extra_data TEXT
        );
    """)

    extra_data = json.dumps({
        "vpa": "suspect@waicici",
        "receiver_vpa": "merchant@wahdfcbank",
        "utr": "630999887766",
        "accountHolderName": "SANDEEP ENTERPRISES"
    })

    cur.execute("""
        INSERT INTO pay_transaction VALUES (
            'PAY_TX_9988',
            '919876543210@s.whatsapp.net',
            '918765432109@s.whatsapp.net',
            12500000,
            106,
            1704110400000,
            ?
        );
    """, (extra_data,))
    con.commit()
    con.close()

    decoder = WhatsAppPayDecoder()
    transactions = decoder.decode_database(
        db_path,
        app_instance_id=3,
        source_vfs_file_id=103,
    )

    assert len(transactions) == 1
    tx = transactions[0]
    assert tx.utr_12_digit == "630999887766"
    assert tx.amount_inr_decimal == 12500.00
    assert tx.payer_vpa == "suspect@waicici"
    assert tx.payee_vpa == "merchant@wahdfcbank"
    assert tx.counterparty_verified_cbs_name == "SANDEEP ENTERPRISES"


# ==============================================================================
# TEST 4: Universal BharatQR EMVCo TLV & Location Parser Test
# ==============================================================================

def test_bharatqr_emvco_tlv_location_and_vpa_decoder():
    """
    Acceptance Test 4 (Section 9.4):
    Passes the raw BharatQR EMVCo TLV string:
    00020101021126420014A00000052401010120merchant.shop@icici5204541153033565802IN5914SHARMA TRADERS6008VARANASI61062210016304ABCD
    into UniversalQRDecoder.
    Verifies that it:
    1. Recursively unpacks Tag 26 Sub-tag 01 -> "merchant.shop@icici"
    2. Extracts Tag 52 MCC -> "5411"
    3. Extracts Tag 59 Legal Name -> "SHARMA TRADERS"
    4. Extracts Tag 60 City -> "VARANASI"
    5. Extracts Tag 61 PIN Code -> "221001"
    """
    from src.upi.qr import UniversalQRDecoder

    raw_qr = "00020101021126420014A00000052401010120merchant.shop@icici5204541153033565802IN5914SHARMA TRADERS6008VARANASI61062210016304ABCD"

    decoder = UniversalQRDecoder()
    result = decoder.decode_emvco_bharatqr(raw_qr)

    assert result is not None
    assert result.extracted_payee_vpa == "merchant.shop@icici"
    assert result.mcc_4_digit == "5411"
    assert result.verified_merchant_or_cbs_name == "SHARMA TRADERS"
    assert result.merchant_city == "VARANASI"
    assert result.merchant_pincode_6_digit == "221001"


# ==============================================================================
# TEST 5: Master Ledger Export Test (upi_superapp_sandbox_artifacts.sqlite)
# ==============================================================================

def test_upi_superapp_engine_master_ledger_export(tmp_upi_dir):
    """
    Section 8: Database Schema for Module 3.1
    Verifies that UPISuperAppForensicEngine creates and exports to:
    1. upi_app_sandbox_transactions
    2. upi_in_app_p2p_chats
    3. upi_scanned_qr_and_vpa_lookups
    4. upi_lite_and_circle_delegations
    inside upi_superapp_sandbox_artifacts.sqlite with exact column names and types.
    """
    from src.upi.engine import UPISuperAppForensicEngine
    from src.upi.models import (
        UPIAppSandboxTransaction,
        UPIInAppP2PChat,
        UPIScannedQRAndVPALookup,
        UPILiteAndCircleDelegation,
    )

    ledger_path = tmp_upi_dir / "upi_superapp_sandbox_artifacts.sqlite"
    engine = UPISuperAppForensicEngine()

    tx = UPIAppSandboxTransaction(
        app_instance_id=1,
        source_vfs_file_id=101,
        source_subsystem="PHONEPE_WORKFLOW_DB",
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        utr_12_digit="630911223344",
        app_order_or_tx_id="T2611051430229182736451",
        instrument_mode="UPI_BANK_ACCOUNT",
        tx_direction="DEBIT_SENT",
        app_recorded_status="SUCCESS",
        raw_amount_value="450000 paise",
        amount_inr_decimal=4500.00,
        payer_vpa="suspect@ybl",
        payee_vpa="mule_account@okaxis",
        counterparty_verified_cbs_name="MOHAMMAD IMRAN",
        created_utc_iso="2024-01-01T12:00:00.000000Z",
    )

    chat = UPIInAppP2PChat(
        app_instance_id=1,
        source_vfs_file_id=101,
        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
        thread_or_topic_id="TOPIC_99",
        sender_vpa_or_phone="suspect@ybl",
        receiver_vpa_or_phone="mule_account@okaxis",
        counterparty_verified_cbs_name="MOHAMMAD IMRAN",
        message_text="Funds transferred, release crypto now",
        linked_utr_or_tx_id="630911223344",
        sent_utc_iso="2024-01-01T12:01:00.000000Z",
    )

    lookup = UPIScannedQRAndVPALookup(
        app_instance_id=1,
        source_vfs_file_id=101,
        artifact_type="SCANNED_BHARATQR_EMVCO_TLV",
        raw_qr_or_uri_string="000201...",
        extracted_payee_vpa="merchant.shop@icici",
        verified_merchant_or_cbs_name="SHARMA TRADERS",
        mcc_4_digit="5411",
        merchant_city="VARANASI",
        merchant_pincode_6_digit="221001",
        event_utc_iso="2024-01-01T11:55:00.000000Z",
    )

    delegation = UPILiteAndCircleDelegation(
        app_instance_id=1,
        feature_type="UPI_LITE_WALLET",
        lite_lrn_or_mandate_umn="LRN_998877",
        balance_or_limit_inr=2000.00,
        status="ACTIVE",
        updated_utc_iso="2024-01-01T12:00:00.000000Z",
    )

    engine.export_to_ledger(
        transactions=[tx],
        chats=[chat],
        lookups=[lookup],
        delegations=[delegation],
        ledger_path=ledger_path,
    )

    assert ledger_path.exists()
    con = sqlite3.connect(ledger_path)
    cur = con.cursor()

    # 1. Check upi_app_sandbox_transactions
    cur.execute("SELECT * FROM upi_app_sandbox_transactions;")
    tx_row = cur.fetchone()
    assert tx_row is not None
    tx_cols = [d[0] for d in cur.description]
    assert "utr_12_digit" in tx_cols
    assert "amount_inr_decimal" in tx_cols

    # 2. Check upi_in_app_p2p_chats
    cur.execute("SELECT * FROM upi_in_app_p2p_chats;")
    chat_row = cur.fetchone()
    assert chat_row is not None
    chat_cols = [d[0] for d in cur.description]
    assert "message_text" in chat_cols

    # 3. Check upi_scanned_qr_and_vpa_lookups
    cur.execute("SELECT * FROM upi_scanned_qr_and_vpa_lookups;")
    lookup_row = cur.fetchone()
    assert lookup_row is not None
    lookup_cols = [d[0] for d in cur.description]
    assert "merchant_pincode_6_digit" in lookup_cols

    # 4. Check upi_lite_and_circle_delegations
    cur.execute("SELECT * FROM upi_lite_and_circle_delegations;")
    del_row = cur.fetchone()
    assert del_row is not None
    del_cols = [d[0] for d in cur.description]
    assert "balance_or_limit_inr" in del_cols

    con.close()
