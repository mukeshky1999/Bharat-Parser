"""
Tier 1 Feature Coverage: Indian UPI Super-App Parsers
Tests PhonePe, Google Pay (Tez), Paytm, BHIM, WhatsApp Pay, Universal BharatQR,
VPA harvesting, and CRED substring disambiguation.
"""

from __future__ import annotations

import json
import sqlite3
import struct
import sys
import unittest
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from src.nonsqlite.varint import encode_le_varint
from src.upi.gpay import GooglePayDecoder
from src.upi.phonepe import PhonePeDecoder
from src.upi.qr import UniversalQRDecoder
from src.upi.whatsapp_pay import WhatsAppPayDecoder
from parsers.app_overrides import PHONEPE_TID_RE
from parsers.corroboration_engine import parse_indian_financial_text
from parsers.vpa_harvester import clean_and_validate_vpa, is_valid_indian_mobile


class TestTier1UPIParsers(unittest.TestCase):
    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t1_upi_")

    def tearDown(self):
        env_setup.cleanup_isolated_sandbox(self.sandbox)

    def test_phonepe_room_database_and_tid_timestamp(self):
        """
        T1.3.1: Validates PhonePe Room database decoding, rawPayload JSON unpacking,
        amountInPaise to INR normalization, and TID regex validation.
        Authoritative source: PhonePe App Storage Specification & NPCI UPI Standards.
        """
        db_path = self.sandbox / "workflow_99a8b7c6.db"
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

        tid = "T2405041040001234567890"
        self.assertTrue(bool(PHONEPE_TID_RE.match(tid)))

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
                ?,
                450000,
                'COMPLETED',
                '630911223344',
                1714819200000,
                'UPI_PAY',
                ?
            );
        """, (tid, payload_json))
        con.commit()
        con.close()

        decoder = PhonePeDecoder()
        transactions, chats, lookups = decoder.decode_database(
            db_path,
            app_instance_id=1,
            source_vfs_file_id=101,
        )

        self.assertEqual(len(transactions), 1)
        tx = transactions[0]
        self.assertEqual(tx.utr_12_digit, "630911223344")
        self.assertEqual(tx.app_order_or_tx_id, tid)
        self.assertEqual(tx.amount_inr_decimal, 4500.00)
        self.assertEqual(tx.payer_vpa, "suspect@ybl")
        self.assertEqual(tx.payee_vpa, "mule_account@okaxis")
        self.assertEqual(tx.counterparty_verified_cbs_name, "MOHAMMAD IMRAN")
        self.assertEqual(tx.payment_note_remarks, "Payment for hawala tokens")

    def test_google_pay_protobuf_and_dual_name_attribution(self):
        """
        T1.3.2: Validates Google Pay India paisa.db Protobuf wire format decoding:
        google.type.Money (units + nanos), display_name, and NPCI CBS banking_name.
        Authoritative source: Google Protobuf google.type.Money specification.
        """
        db_path = self.sandbox / "paisa.db"
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

        # Protobuf wire bytes for google.type.Money (units=15000, nanos=500000000 -> 15000.50 INR)
        money_wire = bytearray()
        money_wire.extend(b"\x0a\x03INR")
        money_wire.append(0x10)
        money_wire.extend(encode_le_varint(15000))
        money_wire.append(0x18)
        money_wire.extend(encode_le_varint(500000000))

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
                1714819200000,
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

        self.assertEqual(len(transactions), 1)
        tx = transactions[0]
        self.assertEqual(tx.utr_12_digit, "630999887711")
        self.assertEqual(tx.amount_inr_decimal, 15000.50)
        self.assertEqual(tx.counterparty_display_name, "Crypto Dealer")
        self.assertEqual(tx.counterparty_verified_cbs_name, "VIKRAM ADITYA SINGH")
        self.assertEqual(tx.payee_vpa, "crypto.dealer@okaxis")

    def test_whatsapp_pay_milli_rupee_math(self):
        """
        T1.3.3: Validates WhatsApp Pay amount_1000 division (INR = amount_1000 / 1000.0)
        and JSON country_data / extra_data parsing.
        Authoritative source: WhatsApp Pay DB schema & NPCI Common Library.
        """
        db_path = self.sandbox / "msgstore.db"
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
                1714819200000,
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

        self.assertEqual(len(transactions), 1)
        tx = transactions[0]
        self.assertEqual(tx.utr_12_digit, "630999887766")
        self.assertEqual(tx.amount_inr_decimal, 12500.00)
        self.assertEqual(tx.payer_vpa, "suspect@waicici")
        self.assertEqual(tx.payee_vpa, "merchant@wahdfcbank")
        self.assertEqual(tx.counterparty_verified_cbs_name, "SANDEEP ENTERPRISES")

    def test_universal_bharatqr_emvco_tlv_parsing(self):
        """
        T1.3.4: Validates recursive Tag-Length-Value (TLV) parsing of EMVCo/BharatQR codes.
        Authoritative source: EMVCo Merchant-Presented QR Code Specification v1.1.
        """
        raw_qr = "00020101021126420014A00000052401010120merchant.shop@icici5204541153033565802IN5914SHARMA TRADERS6008VARANASI61062210016304ABCD"

        decoder = UniversalQRDecoder()
        result = decoder.decode_emvco_bharatqr(raw_qr)

        self.assertIsNotNone(result)
        self.assertEqual(result.extracted_payee_vpa, "merchant.shop@icici")
        self.assertEqual(result.mcc_4_digit, "5411")
        self.assertEqual(result.verified_merchant_or_cbs_name, "SHARMA TRADERS")
        self.assertEqual(result.merchant_city, "VARANASI")
        self.assertEqual(result.merchant_pincode_6_digit, "221001")

    def test_vpa_harvester_and_cleaner(self):
        """
        T1.3.5: Validates strict VPA candidate cleaning, trailing delimiter stripping,
        and Indian mobile number normalization.
        Authoritative source: NPCI UPI Addressing Guidelines.
        """
        # Test clean_and_validate_vpa
        clean_vpa = clean_and_validate_vpa("user.name123@okhdfcbank;,\"'")
        self.assertEqual(clean_vpa, "user.name123@okhdfcbank")

        # Test phone number validation (strictly expects 10-digit format starting with 6, 7, 8, or 9)
        self.assertTrue(is_valid_indian_mobile("9876543210"))
        self.assertFalse(is_valid_indian_mobile("1234567890"))
        self.assertFalse(is_valid_indian_mobile("6520700000"))  # Rejects binary timer float ending in 0000
        self.assertFalse(is_valid_indian_mobile("9999999999"))  # Rejects 5+ consecutive identical digits

    def test_cred_vs_credited_disambiguation(self):
        """
        T1.3.6: Proves disambiguation of the 'cred' substring against financial texts containing 'credited'.
        Authoritative source: TRAI DLT Commercial Communication Regulations.
        """
        from parsers.corroboration_engine import BODY_ATTRIBUTION_PATTERNS

        cred_pattern = None
        for pat, app_name in BODY_ATTRIBUTION_PATTERNS:
            if app_name == "CRED":
                cred_pattern = pat
                break
        self.assertIsNotNone(cred_pattern)

        # 1. Text containing "credited" must NOT match CRED regex
        text_credited = "Your account XX4821 has been credited with Rs. 25,000.00 via UPI."
        self.assertIsNone(cred_pattern.search(text_credited))

        # 2. Text containing CRED app attribution must match CRED regex
        text_cred = "Paid via CRED app for HDFC Credit Card Ref 748392019283"
        match = cred_pattern.search(text_cred)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(0).lower(), "via cred")

        # 3. Test parse_indian_financial_text polarity and extraction
        sms_text = "Rs. 25,000.00 credited to your A/c XX4821 by Ramesh Sharma UTR 839201948201"
        res = parse_indian_financial_text(sms_text)
        self.assertIsNotNone(res)
        self.assertEqual(res["Type"], "CREDIT")
        self.assertEqual(res["Amount"], 25000.00)
        self.assertEqual(res["Transaction_ID"], "839201948201")


if __name__ == "__main__":
    unittest.main()
