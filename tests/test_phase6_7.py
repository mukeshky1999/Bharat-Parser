"""
Comprehensive Phase 6 & 7 Verification Test Suite
Testing Chat, Social, Privacy, Ephemeral, Dating App Parsers,
OS-Level Privacy Spillover Recovery, and Plugin Registry.
"""

import binascii
import json
import os
import shutil
import sqlite3
import struct
import tempfile
import unittest
import zlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from parsers.chat_social_privacy_parsers import (
    WhatsAppDeepParser,
    TelegramTLDeserializer,
    SignalDeepParser,
    ZangiDeepParser,
    ElementMatrixDeepParser,
    SessionDeepParser,
    PrivacyNicheDeepParsers,
    SnapchatDeepParser,
    InstagramDirectDeepParser,
    DatingAppsDeepParser,
    normalize_iso_ist,
    format_hex_offset
)
from parsers.os_privacy_spillover import OsPrivacySpilloverRecovery
from parsers.plugin_loader import PluginRegistry


class TestTimestampAndFormatting(unittest.TestCase):
    def test_normalize_iso_ist(self):
        utc, ist, ep = normalize_iso_ist(1760432521000)
        self.assertIn("IST (+05:30)", ist)
        self.assertEqual(ep, 1760432521000)
        self.assertTrue(utc.endswith("Z"))

    def test_format_hex_offset(self):
        self.assertEqual(format_hex_offset(0x1000), "0x00001000")
        self.assertEqual(format_hex_offset("4096"), "0x00001000")
        self.assertEqual(format_hex_offset(None), "0x00000000")


class TestWhatsAppDeepParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_crypt14_15_decryptor(self):
        key_bytes = os.urandom(32)
        key_file_path = os.path.join(self.test_dir, "whatsapp_key")
        with open(key_file_path, "wb") as f:
            f.write(b"\x00" * 126)
            f.write(key_bytes)
            f.write(b"\x00" * 32)

        raw_db = b"SQLite format 3\x00" + b"X" * 600
        compressed_payload = zlib.compress(raw_db)

        iv = os.urandom(12)
        aesgcm = AESGCM(key_bytes)
        ciphertext = aesgcm.encrypt(iv, compressed_payload, None)

        crypt_path = os.path.join(self.test_dir, "msgstore.db.crypt14")
        with open(crypt_path, "wb") as f:
            f.write(b"\x00" * 191 + iv + ciphertext)

        output_db = os.path.join(self.test_dir, "decrypted_msgstore.db")
        success = WhatsAppDeepParser.decrypt_crypt14_15(crypt_path, key_file_path, output_db)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_db))
        with open(output_db, "rb") as f:
            decrypted = f.read()
        self.assertEqual(decrypted, raw_db)

    def test_whatsapp_sqlite_parsing(self):
        db_path = os.path.join(self.test_dir, "msgstore.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT NOT NULL);")
        cur.execute("INSERT INTO jid VALUES (1, '919876543210@s.whatsapp.net');")
        cur.execute("INSERT INTO jid VALUES (2, '919876500000@s.whatsapp.net');")

        cur.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);")
        cur.execute("INSERT INTO chat VALUES (1, 1, 'Mule Contact');")

        cur.execute("""
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER,
                sender_jid_row_id INTEGER,
                from_me INTEGER,
                key_id TEXT,
                timestamp INTEGER,
                status INTEGER,
                text_data TEXT,
                message_type INTEGER,
                starred INTEGER,
                origination_flags INTEGER,
                forwarding_score INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO message VALUES (
                101, 1, 1, 0, 'MSG_KEY_01', 1760432400000, 13,
                'Send 45000 INR immediately to mule.layer1@ybl', 0, 1, 0, 0
            );
        """)
        cur.execute("""
            CREATE TABLE message_ephemeral (
                message_row_id INTEGER PRIMARY KEY,
                expire_timestamp INTEGER,
                keep_in_chat INTEGER
            );
        """)
        cur.execute("INSERT INTO message_ephemeral VALUES (101, 1760518800000, 0);")

        conn.commit()
        conn.close()

        records = WhatsAppDeepParser.parse(db_path)
        self.assertGreaterEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["Source_App"], "WhatsApp")
        self.assertIn("mule.layer1@ybl", r["Message_Text"])
        self.assertIn("IST (+05:30)", r["Timestamp_IST"])


class TestTelegramTLDeserializer(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_tl_string_decoding(self):
        payload = b"Hello Telegram Mule Network"
        padding_len = (4 - ((1 + len(payload)) % 4)) % 4
        tl_bytes = bytes([len(payload)]) + payload + (b"\x00" * padding_len) + b"NEXT_BYTES"

        deserializer = TelegramTLDeserializer()
        text, next_offset = deserializer.read_tl_string(tl_bytes, 0)
        self.assertEqual(text, "Hello Telegram Mule Network")
        self.assertEqual(next_offset, 1 + len(payload) + padding_len)

    def test_tl_message_deserialization(self):
        msg_text = "Task: Extract OTP via bot7192834012"
        pad = (4 - ((1 + len(msg_text)) % 4)) % 4
        tl_str = bytes([len(msg_text)]) + msg_text.encode('utf-8') + (b"\x00" * pad)

        stream = (
            struct.pack('<I', 0x761450F7) +
            struct.pack('<I', 0x00000002) +
            tl_str
        )

        deserializer = TelegramTLDeserializer()
        res = deserializer.deserialize_tl_message(stream)
        self.assertIsNotNone(res)
        self.assertEqual(res["text"], msg_text)
        self.assertEqual(res["constructor_id"], "0x761450F7")

    def test_telegram_database_parsing(self):
        db_path = os.path.join(self.test_dir, "cache4.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("CREATE TABLE users (uid INTEGER PRIMARY KEY, name TEXT, data BLOB);")
        cur.execute("CREATE TABLE chats (uid INTEGER PRIMARY KEY, name TEXT, data BLOB);")

        cur.execute("""
            CREATE TABLE messages_v2 (
                mid INTEGER PRIMARY KEY,
                uid INTEGER,
                read_state INTEGER,
                send_state INTEGER,
                date INTEGER,
                data BLOB,
                out INTEGER,
                ttl INTEGER,
                media INTEGER,
                replydata BLOB
            );
        """)

        msg_text = "C2 Command: Forward OTP now"
        pad = (4 - ((1 + len(msg_text)) % 4)) % 4
        tl_blob = (
            struct.pack('<I', 0x761450F7) +
            struct.pack('<I', 0x00000001) +
            bytes([len(msg_text)]) + msg_text.encode('utf-8') + (b"\x00" * pad)
        )

        cur.execute("""
            INSERT INTO messages_v2 VALUES (
                501, 819283741, 1, 0, 1760431200,
                ?, 0, 0, 0, NULL
            );
        """, (tl_blob,))

        conn.commit()
        conn.close()

        records = TelegramTLDeserializer.parse_database(db_path)
        self.assertGreaterEqual(len(records), 1)
        self.assertEqual(records[0]["Source_App"], "Telegram")
        self.assertIn("C2 Command", records[0]["Message_Text"])


class TestSignalDeepParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_signal_database_parsing(self):
        db_path = os.path.join(self.test_dir, "signal.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE recipient (
                _id INTEGER PRIMARY KEY,
                phone TEXT,
                system_joined_name TEXT,
                profile_given_name TEXT,
                aci TEXT
            );
        """)
        cur.execute("INSERT INTO recipient VALUES (1, '+12025550198', 'Handler Ghost', 'Ghost', 'aci_123');")

        cur.execute("""
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                recipient_id INTEGER,
                date_sent INTEGER,
                date_received INTEGER,
                body TEXT,
                type INTEGER,
                expires_in INTEGER,
                view_once INTEGER,
                quote_id INTEGER,
                quote_body TEXT
            );
        """)
        cur.execute("""
            INSERT INTO message VALUES (
                10, 1, 1760432800000, 1760432805000,
                'Burn phone after cashout. Ephemeral timer set to 30s.',
                1, 30000, 0, NULL, NULL
            );
        """)

        conn.commit()
        conn.close()

        records = SignalDeepParser.parse(db_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["Source_App"], "Signal")
        self.assertIn("Burn phone", records[0]["Message_Text"])
        self.assertEqual(records[0]["Disappearing_Timer_Sec"], 30)


class TestZangiDeepParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_zangi_database_parsing(self):
        db_path = os.path.join(self.test_dir, "zangi.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE messages (
                rowid INTEGER PRIMARY KEY,
                body TEXT,
                timestamp INTEGER,
                sender_id TEXT,
                receiver_id TEXT,
                is_outgoing INTEGER,
                file_path TEXT
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                1, 'Call on Zangi VoIP now. 10-digit military encryption active.',
                1760432900000, '1084920194', '1099281726', 0, NULL
            );
        """)

        conn.commit()
        conn.close()

        records = ZangiDeepParser.parse(db_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["Source_App"], "Zangi")
        self.assertEqual(records[0]["Sender_ID"], "1084920194")
        self.assertIn("10-digit military encryption", records[0]["Message_Text"])


class TestElementMatrixDeepParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_element_matrix_parsing(self):
        db_path = os.path.join(self.test_dir, "matrix-sdk.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("CREATE TABLE events (rowid INTEGER PRIMARY KEY, event_json_payload TEXT);")
        event_content = json.dumps({
            "type": "m.room.message",
            "sender": "@shadow:matrix.org",
            "room_id": "!darknet:matrix.org",
            "origin_server_ts": 1760430000000,
            "content": {
                "msgtype": "m.text",
                "body": "Batch of 50 Indian banking logs ready for extraction."
            }
        })
        cur.execute("INSERT INTO events VALUES (1, ?);", (event_content,))

        conn.commit()
        conn.close()

        records = ElementMatrixDeepParser.parse(db_path)
        self.assertEqual(len(records), 1)
        self.assertIn("Element", records[0]["Source_App"])
        self.assertIn("Batch of 50 Indian banking logs", records[0]["Message_Text"])


class TestSessionDeepParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_session_parsing(self):
        db_path = os.path.join(self.test_dir, "session.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("CREATE TABLE contacts (address TEXT, display_name TEXT);")
        session_id = "05b98721094827103859182740192837461928374619283746192837461928374a"
        cur.execute("INSERT INTO contacts VALUES (?, 'Session Operator');", (session_id,))

        cur.execute("""
            CREATE TABLE messages (
                rowid INTEGER PRIMARY KEY,
                body TEXT,
                address TEXT,
                date_sent INTEGER,
                type INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                1, 'Lokinet onion routed: Transfer 500 USDT TRC-20 directly to Bybit.',
                ?, 1760433100000, 20
            );
        """, (session_id,))

        conn.commit()
        conn.close()

        records = SessionDeepParser.parse(db_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["Source_App"], "Session")
        self.assertEqual(records[0]["Sender_ID"], session_id)


class TestPrivacyNicheDeepParsers(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_threema_parsing(self):
        db_path = os.path.join(self.test_dir, "threema.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE message (
                rowid INTEGER PRIMARY KEY,
                identity TEXT,
                body TEXT,
                created_at INTEGER,
                is_outbox INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO message VALUES (
                1, 'XYZ98765', 'Clean fiat cash delivered at drop point.',
                1760433400000, 0
            );
        """)

        conn.commit()
        conn.close()

        records = PrivacyNicheDeepParsers.parse_threema(db_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["Source_App"], "Threema")
        self.assertIn("Clean fiat cash", records[0]["Message_Text"])


class TestSnapchatDeepParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_snapchat_arroyo_protobuf(self):
        snap_msg = "Join my private Telegram channel for investment returns!"
        proto_payload = bytes([0x0A, len(snap_msg)]) + snap_msg.encode('utf-8')

        db_path = os.path.join(self.test_dir, "arroyo.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE conversation_message (
                rowid INTEGER PRIMARY KEY,
                client_conversation_id TEXT,
                server_message_id TEXT,
                sender_id TEXT,
                creation_timestamp INTEGER,
                read_timestamp INTEGER,
                content_type INTEGER,
                message_content BLOB
            );
        """)
        cur.execute("""
            INSERT INTO conversation_message VALUES (
                1, 'conv_snap_01', 'srv_01', 'snap_pooja99',
                1760429500000, 1760429505000, 1, ?
            );
        """, (proto_payload,))

        conn.commit()
        conn.close()

        records = SnapchatDeepParser.parse_arroyo(db_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["Source_App"], "Snapchat")
        self.assertIn("Join my private Telegram", records[0]["Message_Text"])


class TestInstagramDirectDeepParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_instagram_direct_parsing(self):
        db_path = os.path.join(self.test_dir, "direct.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE messages (
                rowid INTEGER PRIMARY KEY,
                text TEXT,
                timestamp INTEGER,
                message_type TEXT,
                message TEXT
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                1, 'Deposit 45,000 INR to start high frequency UPI arbitrage.',
                1760428000000000, 'text', NULL
            );
        """)

        conn.commit()
        conn.close()

        records = InstagramDirectDeepParser.parse(db_path)
        self.assertEqual(len(records), 1)
        self.assertIn("Instagram", records[0]["Source_App"])
        self.assertIn("Deposit 45,000 INR", records[0]["Message_Text"])


class TestDatingAppsDeepParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_tinder_parsing(self):
        db_path = os.path.join(self.test_dir, "tinder.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE messages (
                rowid INTEGER PRIMARY KEY,
                text TEXT,
                sent_date INTEGER,
                from_id TEXT,
                match_id TEXT
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                1, 'Hey dear! I make $5000 weekly on forex. Deposit via UPI.',
                1760426000000, 'alisha_scam', 'match_882'
            );
        """)

        conn.commit()
        conn.close()

        records = DatingAppsDeepParser.parse_tinder(db_path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["Source_App"], "Tinder")
        self.assertIn("Hey dear!", records[0]["Message_Text"])


class TestOsPrivacySpilloverRecovery(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_notification_log_parsing(self):
        db_path = os.path.join(self.test_dir, "notification_log.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE notification_records (
                rowid INTEGER PRIMARY KEY,
                package_name TEXT,
                title TEXT,
                text TEXT,
                post_time INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO notification_records VALUES (
                1, 'com.sbi.reward.secureapp', 'SMS Intercept Notification',
                'OTP Alert: 492019 is your verification code for transfer of 45,000 to mule.layer1@ybl',
                1760432500000
            );
        """)

        conn.commit()
        conn.close()

        spillovers = OsPrivacySpilloverRecovery.parse_notification_spillover(db_path)
        self.assertGreaterEqual(len(spillovers), 1)
        self.assertIn("com.sbi.reward", spillovers[0]["Source_App"])
        self.assertIn("492019", spillovers[0]["Message_Text"])

    def test_keyboard_clipboard_regex_extraction(self):
        cache_file = os.path.join(self.test_dir, "clipboard_dump.txt")
        # 34-character TRON USDT address: 'T' + 33 base58 characters
        tron_addr = "TYM293819283401293810293810293847"
        with open(cache_file, "w", encoding="utf-8") as f:
            f.write(f"Cached text with TRC20: {tron_addr} and Zangi ID 1084920194")

        findings = OsPrivacySpilloverRecovery.parse_keyboard_clipboard_caches(cache_file)
        self.assertGreaterEqual(len(findings), 1)
        extracted = [f["Extracted_Value"] for f in findings]
        self.assertTrue(any(tron_addr in v for v in extracted) or any("1084920194" in v for v in extracted))


class TestPluginRegistryCompleteness(unittest.TestCase):
    def test_all_65_plugins_loaded(self):
        registry = PluginRegistry()
        plugins = registry.all_plugins()
        self.assertGreaterEqual(len(plugins), 65)

        names = [p.app_name for p in plugins]
        self.assertIn("WhatsApp", names)
        self.assertIn("Telegram", names)
        self.assertIn("Signal", names)
        self.assertIn("Zangi", names)
        self.assertIn("Element", names)
        self.assertIn("Session", names)
        self.assertIn("Snapchat", names)
        self.assertIn("Instagram", names)
        self.assertIn("Dating Apps", names)

    def test_all_14_apps_resolvable_via_get_plugin(self):
        registry = PluginRegistry()
        target_apps = [
            ("WhatsApp", "WhatsApp"),
            ("WhatsApp Business", "WhatsApp"),
            ("Telegram", "Telegram"),
            ("Telegram X", "Telegram"),
            ("Signal", "Signal"),
            ("Zangi", "Zangi"),
            ("Element", "Element"),
            ("Session", "Session"),
            ("Threema", "Threema"),
            ("SimpleX Chat", "Threema"),
            ("Snapchat", "Snapchat"),
            ("Instagram", "Instagram"),
            ("Tinder", "Dating Apps"),
            ("Bumble", "Dating Apps"),
            ("Hinge", "Dating Apps"),
            ("Grindr", "Dating Apps"),
        ]
        for query_name, expected_plugin_name in target_apps:
            p = registry.get_plugin(query_name)
            self.assertIsNotNone(p, f"Failed to resolve plugin for: {query_name}")
            self.assertEqual(p.app_name, expected_plugin_name)

    def test_match_path_dual_and_keyword_invocations(self):
        sample_path = "data/data/com.whatsapp/databases/msgstore.db"
        # 1. Instance call with positional argument
        reg = PluginRegistry()
        p1 = reg.match_path(sample_path)
        self.assertIsNotNone(p1)
        self.assertEqual(p1.app_name, "WhatsApp")

        # 2. Instance call with keyword clean_path
        p2 = reg.match_path(clean_path=sample_path)
        self.assertIsNotNone(p2)
        self.assertEqual(p2.app_name, "WhatsApp")

        # 3. None / empty path handling (instance method; the old class-level call was a test bug)
        self.assertIsNone(reg.match_path(None))
        self.assertIsNone(reg.match_path(""))
        self.assertIsNone(reg.match_path(clean_path=None))


class TestHeuristicEngineCategorizedRouting(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_heuristic_engine_whatsapp_routing_never_flattens(self):
        from parsers.heuristic_engine import parse_database_artifacts
        from parsers.enterprise_1tb_chat_and_container_engine import PA_CATEGORIZED_CHAT_COLUMNS

        db_path = os.path.join(self.test_dir, "msgstore.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT)")
        cur.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT)")
        cur.execute("""
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                chat_row_id INTEGER,
                from_me INTEGER,
                key_id TEXT,
                sender_jid_row_id INTEGER,
                timestamp INTEGER,
                text_data TEXT,
                status INTEGER,
                starred INTEGER
            )
        """)
        cur.execute("INSERT INTO jid VALUES (1, '919876543210@s.whatsapp.net')")
        cur.execute("INSERT INTO chat VALUES (1, 1, 'Victim Direct')")
        cur.execute("INSERT INTO message VALUES (1, 1, 0, 'MSG_HEX_1', 1, 1704067200000, 'Test Heuristic Routing', 13, 0)")
        conn.commit()
        conn.close()

        artifacts = parse_database_artifacts(db_path, app_label="com.whatsapp")
        self.assertIn("chats", artifacts)
        chats_df = artifacts["chats"]
        self.assertFalse(chats_df.empty)
        self.assertEqual(len(chats_df), 1)

        # The case store and UI use the canonical categorized chat schema; it must never be flattened.
        for col in PA_CATEGORIZED_CHAT_COLUMNS:
            self.assertIn(col, chats_df.columns, f"Missing categorized column: {col}")

        # Real values, not just column presence.
        row = chats_df.iloc[0]
        self.assertEqual(row["Message_Body"], "Test Heuristic Routing")
        self.assertEqual(row["Sender_Identifier"], "919876543210@s.whatsapp.net")
        self.assertEqual(row["Direction"], "Incoming")
        self.assertEqual(row["Application"], "WhatsApp")
        self.assertIn("2024-01-01", row["Timestamp_UTC"])

    def test_heuristic_engine_signal_routing(self):
        from parsers.heuristic_engine import parse_database_artifacts
        from parsers.chat_social_privacy_parsers import CATEGORIZED_FORENSIC_COLUMNS

        db_path = os.path.join(self.test_dir, "signal.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE recipient (_id INTEGER PRIMARY KEY, phone TEXT, system_joined_name TEXT, profile_given_name TEXT, aci TEXT)")
        cur.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, recipient_id INTEGER, date_sent INTEGER, date_received INTEGER, body TEXT, type INTEGER, expires_in INTEGER, view_once INTEGER, quote_id INTEGER, quote_body TEXT)")
        cur.execute("INSERT INTO recipient VALUES (1, '+919988776655', 'Agent X', 'Agent', 'aci_123')")
        cur.execute("INSERT INTO message VALUES (1, 1, 1704067200000, 1704067201000, 'Burn after 10s', 20, 10000, 0, NULL, NULL)")
        conn.commit()
        conn.close()

        artifacts = parse_database_artifacts(db_path, app_label="org.thoughtcrime.securesms")
        chats_df = artifacts["chats"]
        self.assertFalse(chats_df.empty)
        for col in CATEGORIZED_FORENSIC_COLUMNS:
            self.assertIn(col, chats_df.columns)
        self.assertEqual(chats_df.iloc[0]["Message_Text"], "Burn after 10s")
        self.assertTrue(chats_df.iloc[0]["Is_Ephemeral"])
        self.assertEqual(chats_df.iloc[0]["Ephemeral_Duration_Seconds"], 10)

    def test_heuristic_engine_tinder_routing(self):
        from parsers.heuristic_engine import parse_database_artifacts
        from parsers.chat_social_privacy_parsers import CATEGORIZED_FORENSIC_COLUMNS

        db_path = os.path.join(self.test_dir, "tinder.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE messages (rowid INTEGER PRIMARY KEY, text TEXT, sent_date INTEGER, from_id TEXT, match_id TEXT)")
        cur.execute("INSERT INTO messages VALUES (1, 'Hey there! Exclusive offer.', 1704067200000, 'tinder_match_1', 'match_99')")
        conn.commit()
        conn.close()

        artifacts = parse_database_artifacts(db_path, app_label="com.tinder")
        chats_df = artifacts["chats"]
        self.assertFalse(chats_df.empty)
        for col in CATEGORIZED_FORENSIC_COLUMNS:
            self.assertIn(col, chats_df.columns)
        self.assertEqual(chats_df.iloc[0]["Message_Text"], "Hey there! Exclusive offer.")
        self.assertEqual(chats_df.iloc[0]["Source_App"], "Tinder")


if __name__ == "__main__":
    unittest.main()
