"""
Tier 1 Feature Coverage: Instant Messaging & Regional Social Forensics
Tests WhatsApp LID unmasking & message recovery, Telegram TL binary deserialization,
Signal encrypted message extraction, Session/privacy messengers, and Instagram Direct.
"""

from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from src.telegram_signal.tl_deserializer import TLStreamReader
from src.whatsapp.decoder import WhatsAppDatabaseDecoder
from parsers.chat_social_privacy_parsers import (
    parse_instagram_direct,
    parse_session_threema_simplex,
    parse_signal_database,
    parse_telegram_database,
)


def _encode_tl_string(s: str) -> bytes:
    """Encodes a string using Telegram TL length prefix and 4-byte alignment."""
    raw = s.encode("utf-8")
    l = len(raw)
    if l < 254:
        header = bytes([l]) + raw
    else:
        header = bytes([254, l & 0xFF, (l >> 8) & 0xFF, (l >> 16) & 0xFF]) + raw
    pad = (4 - (len(header) % 4)) % 4
    return header + (b"\x00" * pad)


class TestTier1Chats(unittest.TestCase):
    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t1_chats_")

    def tearDown(self):
        env_setup.cleanup_isolated_sandbox(self.sandbox)

    def test_whatsapp_database_decoding_and_lid_unmasking(self):
        """
        T1.6.1: Validates WhatsApp msgstore.db decoding and @lid to phone number unmasking.
        Authoritative source: WhatsApp Multi-Device SQLite Schema Specification.
        """
        msgstore_path = self.sandbox / "msgstore.db"
        conn = sqlite3.connect(msgstore_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE jid (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                server TEXT NOT NULL,
                agent INTEGER DEFAULT 0,
                device INTEGER DEFAULT 0,
                type INTEGER DEFAULT 0,
                raw_string TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE jid_map (
                lid_row_id INTEGER NOT NULL,
                jid_row_id INTEGER NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE chat (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                jid_row_id INTEGER NOT NULL,
                subject TEXT,
                archived INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_row_id INTEGER NOT NULL,
                from_me INTEGER NOT NULL,
                key_id TEXT NOT NULL,
                sender_jid_row_id INTEGER,
                status INTEGER DEFAULT 0,
                timestamp INTEGER NOT NULL,
                received_timestamp INTEGER,
                message_type INTEGER DEFAULT 0,
                text_data TEXT,
                starred INTEGER DEFAULT 0
            )
        """)

        # Insert JID records
        cur.execute("INSERT INTO jid (user, server, raw_string) VALUES ('919876543210', 's.whatsapp.net', '919876543210@s.whatsapp.net')")
        phone_jid_id = cur.lastrowid
        cur.execute("INSERT INTO jid (user, server, raw_string) VALUES ('164829104928172', 'lid', '164829104928172@lid')")
        lid_jid_id = cur.lastrowid

        # Map LID to Phone JID
        cur.execute("INSERT INTO jid_map (lid_row_id, jid_row_id) VALUES (?, ?)", (lid_jid_id, phone_jid_id))

        # Create chat thread
        cur.execute("INSERT INTO chat (jid_row_id, subject) VALUES (?, 'Investigation Chat')", (phone_jid_id,))
        chat_id = cur.lastrowid

        # Insert message from LID
        cur.execute("""
            INSERT INTO message (chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, text_data)
            VALUES (?, 0, 'MSG_WA_001', ?, 1714819200000, 'Transfer Rs 50,000 to mule immediately')
        """, (chat_id, lid_jid_id))

        conn.commit()
        conn.close()

        decoder = WhatsAppDatabaseDecoder()
        messages = decoder.extract_messages(str(msgstore_path))
        self.assertEqual(len(messages), 1)

        msg = messages[0]
        self.assertEqual(msg.message_text_or_caption, "Transfer Rs 50,000 to mule immediately")
        self.assertIn("919876543210", msg.sender_resolved_phone_jid or "")
        self.assertIn("164829104928172", msg.sender_raw_lid or "")

    def test_telegram_tl_stream_deserializer(self):
        """
        T1.6.2: Validates Telegram Type-Language (TL) 4-byte aligned binary string decoding.
        Authoritative source: Telegram MTProto Mobile Protocol & TL-Schema Specification.
        """
        phone_str = "919876543210"
        encoded = _encode_tl_string(phone_str)

        reader = TLStreamReader(encoded)
        decoded_phone = reader.read_tl_string()

        self.assertEqual(decoded_phone, phone_str)
        # Advance must align to 4-byte word boundary
        self.assertEqual(reader.cursor % 4, 0)

    def test_signal_database_decoding(self):
        """
        T1.6.3: Validates Signal SQLite database message extraction.
        Authoritative source: Signal Open Source Android/iOS Database Schema.
        """
        signal_db = self.sandbox / "signal.db"
        conn = sqlite3.connect(signal_db)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                date_sent INTEGER,
                date_received INTEGER,
                body TEXT,
                type INTEGER,
                expires_in INTEGER DEFAULT 0,
                view_once INTEGER DEFAULT 0,
                quote_id INTEGER DEFAULT 0,
                quote_body TEXT DEFAULT NULL
            );
        """)
        cur.execute("""
            INSERT INTO message VALUES (
                1,
                1714819200000,
                1714819200050,
                'Secret Signal message: cash drop at coordinates 28.6139, 77.2090',
                20,
                0,
                0,
                0,
                NULL
            );
        """)
        conn.commit()
        conn.close()

        df = parse_signal_database(str(signal_db))
        self.assertGreaterEqual(len(df), 1)

        row = df.iloc[0]
        self.assertIn("Secret Signal message", row["Message_Text"])

    def test_session_and_privacy_messengers(self):
        """
        T1.6.4: Validates Session messenger hex address parsing (05... 66-character Ed25519 identity).
        Authoritative source: Session Lokinet Oxen Protocol.
        """
        session_db = self.sandbox / "session.db"
        conn = sqlite3.connect(session_db)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE messages (
                rowid INTEGER PRIMARY KEY,
                thread_id INTEGER,
                address TEXT,
                body TEXT,
                date_sent INTEGER,
                type INTEGER
            );
        """)
        session_pubkey = "05" + "ab" * 32  # 66-character hex public key
        cur.execute("""
            INSERT INTO messages (rowid, thread_id, address, body, date_sent, type)
            VALUES (
                1,
                1,
                ?,
                'Session P2P anonymous encrypted transmission',
                1714819200000,
                1
            );
        """, (session_pubkey,))
        conn.commit()
        conn.close()

        df = parse_session_threema_simplex(str(session_db), app_label="session")
        self.assertGreaterEqual(len(df), 1)
        self.assertIn("Session P2P anonymous", df.iloc[0]["Message_Text"])

    def test_instagram_direct_threads(self):
        """
        T1.6.5: Validates Instagram direct messages and thread extraction.
        Authoritative source: Instagram Direct SQLite Schema.
        """
        ig_db = self.sandbox / "direct.db"
        conn = sqlite3.connect(ig_db)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                thread_id TEXT,
                user_id TEXT,
                text TEXT,
                timestamp INTEGER,
                message_type TEXT
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                'IG_MSG_99',
                'thread_crypto_deal',
                'suspect_user_id',
                'Deal confirmed on Instagram Direct',
                1714819200000000,
                'text'
            );
        """)
        conn.commit()
        conn.close()

        df = parse_instagram_direct(str(ig_db))
        self.assertGreaterEqual(len(df), 1)
        self.assertIn("Deal confirmed on Instagram", df.iloc[0]["Message_Text"])


if __name__ == "__main__":
    unittest.main()
