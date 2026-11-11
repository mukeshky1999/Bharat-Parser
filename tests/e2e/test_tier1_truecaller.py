"""
Tier 1 Feature Coverage: Truecaller & Telephony Forensics
Tests caller ID lookup extraction, spam score attribution, P2P instant messaging,
call log fusion, and phone number normalization.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from src.unified_chat.truecaller_decoder import (
    TruecallerDecoder,
    canonical_phone_10_and_e164,
)
from parsers.social_interaction_comms_parsers import parse_truecaller_database


class TestTier1Truecaller(unittest.TestCase):
    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t1_truecaller_")

    def tearDown(self):
        env_setup.cleanup_isolated_sandbox(self.sandbox)

    def test_truecaller_caller_id_cache_and_spam_tags(self):
        """
        T1.5.1: Validates extraction of cached caller identities and spam tags from tc.db.
        Authoritative source: Truecaller Android SQLite Schema (aggregated_contact).
        """
        db_path = self.sandbox / "tc.db"
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE aggregated_contact (
                rowid INTEGER PRIMARY KEY,
                name TEXT,
                phone_number TEXT,
                spam_score TEXT
            );
        """)
        cur.execute("INSERT INTO aggregated_contact VALUES (1, 'Rajesh Mule Account', '+919876543210', '85')")
        cur.execute("INSERT INTO aggregated_contact VALUES (2, 'Verified Merchant', '+918765432109', '0')")
        con.commit()
        con.close()

        df = parse_truecaller_database(str(db_path))
        self.assertEqual(len(df), 2)

        # Record 1: Spam Mule
        mule_row = df[df["Artifact_ID"] == "TC_IDENT_1"].iloc[0]
        self.assertEqual(mule_row["Sender_Name"], "Rajesh Mule Account")
        self.assertEqual(mule_row["Sender_ID"], "+919876543210")
        self.assertEqual(mule_row["Status"], "Spam / Fraud Tagged")
        self.assertIn("Spam/Fraud Score: 85", mule_row["Message_Text"])

        # Record 2: Clean Merchant
        merchant_row = df[df["Artifact_ID"] == "TC_IDENT_2"].iloc[0]
        self.assertEqual(merchant_row["Sender_Name"], "Verified Merchant")
        self.assertEqual(merchant_row["Status"], "Identified")

    def test_truecaller_instant_messages_msg_db(self):
        """
        T1.5.2: Validates extraction of Truecaller instant messages from msg.db.
        Authoritative source: Truecaller Android SQLite Schema (msg_messages).
        """
        db_path = self.sandbox / "msg.db"
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE msg_messages (
                rowid INTEGER PRIMARY KEY,
                text TEXT,
                date INTEGER,
                participant_id TEXT,
                type INTEGER
            );
        """)
        # Incoming message (type = 1)
        cur.execute("INSERT INTO msg_messages VALUES (1, 'Send OTP immediately for verification', 1714819200000, '+919123456789', 1)")
        # Outgoing message (type = 2)
        cur.execute("INSERT INTO msg_messages VALUES (2, 'Sent 50k to mule account', 1714819260000, '+919123456789', 2)")
        con.commit()
        con.close()

        df = parse_truecaller_database(str(db_path))
        self.assertEqual(len(df), 2)

        incoming = df[df["Artifact_ID"] == "TC_MSG_1"].iloc[0]
        self.assertEqual(incoming["Direction"], "Incoming")
        self.assertEqual(incoming["Message_Text"], "Send OTP immediately for verification")
        self.assertEqual(incoming["Sender_ID"], "+919123456789")

        outgoing = df[df["Artifact_ID"] == "TC_MSG_2"].iloc[0]
        self.assertEqual(outgoing["Direction"], "Outgoing")
        self.assertEqual(outgoing["Message_Text"], "Sent 50k to mule account")
        self.assertEqual(outgoing["Recipient_ID"], "+919123456789")

    def test_truecaller_decoder_enrichment_record(self):
        """
        T1.5.3: Validates deep domain decoding using TruecallerDecoder.
        Authoritative source: Unified Chat TruecallerDecoder engine.
        """
        db_path = self.sandbox / "tc.db"
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE aggregated_contact (
                _id INTEGER PRIMARY KEY,
                number TEXT,
                name TEXT,
                spam_score INTEGER,
                carrier TEXT,
                city_area TEXT
            );
        """)
        cur.execute("""
            INSERT INTO aggregated_contact (_id, number, name, spam_score, carrier, city_area)
            VALUES (101, '+919876543210', 'VIKRAM BOSS', 92, 'Jio', 'Mumbai')
        """)
        con.commit()
        con.close()

        decoder = TruecallerDecoder()
        records = decoder.decode_truecaller_database(str(db_path), source_vfs_file_id=701)
        self.assertGreaterEqual(len(records), 1)

        rec = records[0]
        self.assertEqual(rec.tc_resolved_name, "VIKRAM BOSS")
        self.assertEqual(rec.normalized_e164_phone, "+919876543210")
        self.assertEqual(rec.tc_spam_score, 92)

    def test_canonical_phone_10_and_e164_normalization(self):
        """
        T1.5.4: Validates Indian mobile number normalization to 10-digit national and E.164.
        Authoritative source: Indian Telephony National Numbering Plan (NNP).
        """
        e164, phone_10 = canonical_phone_10_and_e164("+91 98765 43210")
        self.assertEqual(phone_10, "9876543210")
        self.assertEqual(e164, "+919876543210")

        e164_zero, phone_10_zero = canonical_phone_10_and_e164("09876543210")
        self.assertEqual(phone_10_zero, "9876543210")
        self.assertEqual(e164_zero, "+919876543210")

        e164_plain, phone_10_plain = canonical_phone_10_and_e164("9876543210")
        self.assertEqual(phone_10_plain, "9876543210")
        self.assertEqual(e164_plain, "+919876543210")

    def test_truecaller_empty_and_missing_handling(self):
        """
        T1.5.5: Validates graceful degradation on missing or empty Truecaller databases.
        Authoritative source: Opaque-Box Fault Tolerance Requirement.
        """
        non_existent = self.sandbox / "missing_tc.db"
        df = parse_truecaller_database(str(non_existent))
        self.assertEqual(len(df), 0)

        empty_db = self.sandbox / "empty.db"
        sqlite3.connect(empty_db).close()
        df_empty = parse_truecaller_database(str(empty_db))
        self.assertEqual(len(df_empty), 0)


if __name__ == "__main__":
    unittest.main()
