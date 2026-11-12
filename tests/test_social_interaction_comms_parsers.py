"""
Unit Tests for Social, Interaction, and Cross-Border Comms Parsers.
Verifies parsing of Facebook, Messenger, Discord, Skype, Teams, Viber, WeChat,
LINE, IMO, KakaoTalk, Twitter/X, LinkedIn, Truecaller, OLX, and ShareChat.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest

from parsers.social_interaction_comms_parsers import (
    parse_facebook_messenger_database,
    parse_facebook_contacts_database,
    parse_discord_database,
    parse_skype_teams_database,
    parse_viber_database,
    parse_wechat_database,
    parse_line_database,
    parse_imo_kakaotalk_database,
    parse_twitter_threads_reddit_linkedin,
    parse_truecaller_database,
    parse_olx_database,
    parse_sharechat_moj_database,
    SOCIAL_INTERACTION_MANIFESTS,
)
from parsers.plugin_loader import PluginRegistry


class TestSocialInteractionParsers(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_social_interaction_manifests_registered(self):
        reg = PluginRegistry()
        names = [p.app_name for p in reg.all_plugins()]
        self.assertIn("Facebook Messenger", names)
        self.assertIn("Discord", names)
        self.assertIn("Skype", names)
        self.assertIn("Microsoft Teams", names)
        self.assertIn("Viber", names)
        self.assertIn("WeChat", names)
        self.assertIn("LINE", names)
        self.assertIn("Truecaller", names)
        self.assertIn("OLX India", names)

    def test_facebook_messenger_parser(self):
        db_path = os.path.join(self.tmp_dir, "threads_db2")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE messages (
                msg_id TEXT,
                thread_key TEXT,
                text TEXT,
                sender TEXT,
                timestamp_ms INTEGER,
                msg_type TEXT,
                is_unsent INTEGER,
                attachments TEXT,
                shares TEXT
            );
        """)
        cur.execute("""
            CREATE TABLE threads (
                thread_key TEXT,
                name TEXT
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                'm_101', 'ONE_TO_ONE:10008892', 'Transfer cash to cyber mule',
                '{"user_key":"FACEBOOK:10008892","name":"Rohan Boss"}', 1760432400000,
                'regular', 0, '', ''
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                'm_102', 'ONE_TO_ONE:10008892', 'Delete previous message',
                '{"user_key":"FACEBOOK:10008892","name":"Rohan Boss"}', 1760432500000,
                'regular', 1, '', ''
            );
        """)
        conn.commit()
        conn.close()

        df = parse_facebook_messenger_database(db_path)
        self.assertEqual(len(df), 2)
        self.assertEqual(df.iloc[0]["Source_App"], "Facebook Messenger")
        self.assertEqual(df.iloc[0]["Sender_Name"], "Rohan Boss")
        self.assertTrue(df.iloc[1]["Is_Deleted"])
        # an unsent flag in the live table is not evidence of freelist recovery (review R-13)
        self.assertEqual(df.iloc[1]["Recovery_Method"], "ACTIVE_SQLITE (unsent flag set)")

    def test_truecaller_parser(self):
        db_path = os.path.join(self.tmp_dir, "tc.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE msg_messages (
                text TEXT,
                date INTEGER,
                participant_id TEXT,
                type INTEGER
            );
        """)
        cur.execute("""
            CREATE TABLE aggregated_contact (
                name TEXT,
                phone_number TEXT,
                spam_score INTEGER
            );
        """)
        cur.execute("INSERT INTO msg_messages VALUES ('Your loan has been approved click link', 1760430000000, '+919988776655', 1);")
        cur.execute("INSERT INTO aggregated_contact VALUES ('Instant Loan Scam Syndicate', '+919988776655', 98);")
        conn.commit()
        conn.close()

        df = parse_truecaller_database(db_path)
        self.assertEqual(len(df), 2)
        self.assertEqual(df.iloc[0]["Source_App"], "Truecaller")
        self.assertIn("Spam / Fraud Tagged", df.iloc[1]["Status"])

    def test_olx_parser(self):
        db_path = os.path.join(self.tmp_dir, "olx_chat.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE messages (
                message TEXT,
                created_at INTEGER,
                sender_id TEXT,
                thread_id TEXT
            );
        """)
        cur.execute("INSERT INTO messages VALUES ('Please scan this UPI QR code to receive advance payment: upi://pay?pa=fake.advance@okaxis', 1760430000000, 'seller_401', 'ad_89102');")
        conn.commit()
        conn.close()

        df = parse_olx_database(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "OLX India")
        self.assertEqual(df.iloc[0]["Message_Type"], "UPI Lure / Payment Request")
        self.assertTrue(df.iloc[0]["Is_Starred"])

    def test_discord_parser(self):
        db_path = os.path.join(self.tmp_dir, "discord.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE messages (
                id TEXT,
                channel_id TEXT,
                content TEXT,
                author TEXT,
                timestamp INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                'disc_99', 'chan_123', 'Check cyber syndicate channel',
                '{"username":"CyberLead#1234","id":"998877"}', 1760430000000
            );
        """)
        conn.commit()
        conn.close()

        df = parse_discord_database(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "Discord")
        self.assertEqual(df.iloc[0]["Sender_Name"], "CyberLead#1234")
        self.assertIn("Check cyber syndicate", df.iloc[0]["Message_Text"])

    def test_skype_teams_parser(self):
        db_path = os.path.join(self.tmp_dir, "main.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE Messages (
                id INTEGER PRIMARY KEY,
                convo_id TEXT,
                author TEXT,
                from_dispname TEXT,
                body_xml TEXT,
                timestamp INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO Messages VALUES (
                1, '8:live_examiner', 'live:mule_recruiter', 'Mule Recruiter',
                '<part>Call me on <b>signal</b> immediately</part>', 1760430000
            );
        """)
        conn.commit()
        conn.close()

        df = parse_skype_teams_database(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "Skype")
        self.assertEqual(df.iloc[0]["Sender_Name"], "Mule Recruiter")
        self.assertEqual(df.iloc[0]["Message_Text"], "Call me on signal immediately")

    def test_viber_parser(self):
        db_path = os.path.join(self.tmp_dir, "viber_messages.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE messages (
                _id INTEGER PRIMARY KEY,
                body TEXT,
                msg_date INTEGER,
                send_type INTEGER,
                conversation_id INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                10, 'Offshore transfer confirmed via crypto', 1760430000000, 0, 42
            );
        """)
        conn.commit()
        conn.close()

        df = parse_viber_database(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "Viber")
        self.assertEqual(df.iloc[0]["Direction"], "Incoming")

    def test_wechat_parser(self):
        db_path = os.path.join(self.tmp_dir, "EnMicroMsg.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE message (
                msgId INTEGER PRIMARY KEY,
                talker TEXT,
                content TEXT,
                createTime INTEGER,
                isSend INTEGER,
                type INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO message VALUES (
                501, 'wxid_syndicate', 'Cross border settlement complete', 1760430000000, 1, 1
            );
        """)
        conn.commit()
        conn.close()

        df = parse_wechat_database(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "WeChat")
        self.assertEqual(df.iloc[0]["Direction"], "Outgoing")

    def test_line_parser(self):
        db_path = os.path.join(self.tmp_dir, "naver_line.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE chat_history (
                id INTEGER PRIMARY KEY,
                chat_id TEXT,
                from_mid TEXT,
                content TEXT,
                created_time INTEGER
            );
        """)
        cur.execute("""
            INSERT INTO chat_history VALUES (
                1, 'c_line_group', 'u_line_user', 'Target bank account details attached', 1760430000000
            );
        """)
        conn.commit()
        conn.close()

        df = parse_line_database(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "LINE")

    def test_imo_kakaotalk_parser(self):
        db_path = os.path.join(self.tmp_dir, "imodb.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE immessages (
                id INTEGER PRIMARY KEY,
                message TEXT,
                timestamp INTEGER,
                buid TEXT
            );
        """)
        cur.execute("""
            INSERT INTO immessages VALUES (
                1, 'IMO encrypted syndicate chatter', 1760430000000, 'buid_9988'
            );
        """)
        conn.commit()
        conn.close()

        df = parse_imo_kakaotalk_database(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "IMO")

    def test_twitter_threads_reddit_linkedin_parser(self):
        db_path = os.path.join(self.tmp_dir, "voyager.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY,
                text TEXT,
                created_at INTEGER,
                sender_id TEXT
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                1, 'Job offer recruitment scam on LinkedIn', 1760430000000, 'recruiter_77'
            );
        """)
        conn.commit()
        conn.close()

        df = parse_twitter_threads_reddit_linkedin(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "LinkedIn")

    def test_sharechat_moj_parser(self):
        db_path = os.path.join(self.tmp_dir, "sharechat.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY,
                message TEXT,
                timestamp INTEGER,
                sender_id TEXT
            );
        """)
        cur.execute("""
            INSERT INTO messages VALUES (
                1, 'Regional recruitment lead in Telugu/Hindi', 1760430000000, 'user_sc_12'
            );
        """)
        conn.commit()
        conn.close()

        df = parse_sharechat_moj_database(db_path)
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["Source_App"], "ShareChat / Moj")


if __name__ == "__main__":
    unittest.main()
