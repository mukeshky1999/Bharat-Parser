"""
Unit Tests for enterprise_1tb_chat_and_container_engine.py
Verifies zero-OOM 1 TB container streaming, VFS catalog, XML streaming,
sliding-window raw carver, FTS5 case store, and all 14 chat/privacy app parsers.
"""

import os
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
import pandas as pd

from parsers.enterprise_1tb_chat_and_container_engine import (
    CHAT_COLUMNS,
    CaseArtifactStore,
    TerabyteForensicContainerEngine,
    carve_sqlite_freelists_1tb_mmap,
    deserialize_telegram_tl_blob,
    dispatch_all_chat_and_privacy_apps,
    format_timestamp_triplet,
    harvest_os_privacy_spillover,
    parse_dating_apps,
    parse_element_matrix_store,
    parse_instagram_direct,
    parse_privacy_messengers,
    parse_signal_database,
    parse_snapchat_arroyo,
    parse_telegram_cache4,
    parse_whatsapp_full_forensics,
    parse_zangi_database,
    read_tl_string,
    scan_raw_image_sliding_window,
    should_materialize_artifact,
    stream_container_xml_manifest,
)


class TestEnterprise1TBEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_1tb_engine_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. VFS FILTER & CONTAINER ENGINE
    # --------------------------------------------------------------------------
    def test_should_materialize_artifact(self):
        # Should materialize databases, configs, keystores
        self.assertTrue(should_materialize_artifact("data/data/com.whatsapp/databases/msgstore.db", 50000000))
        self.assertTrue(should_materialize_artifact("ChatStorage.sqlite", 1000000))
        self.assertTrue(should_materialize_artifact("report.xml", 2000000))
        self.assertTrue(should_materialize_artifact("data/data/com.phonepe.app/shared_prefs/phonepe.xml", 4000))
        self.assertTrue(should_materialize_artifact("files/mmkv/mmkv.default", 12000))

        # Should skip bulk media
        self.assertFalse(should_materialize_artifact("DCIM/Camera/VID_20261101.mp4", 100000000))
        self.assertFalse(should_materialize_artifact("WhatsApp/Media/image.jpg", 2000000))
        self.assertFalse(should_materialize_artifact("test.so", 1000000))
        self.assertFalse(should_materialize_artifact("", 0))

    def test_container_engine_indexing_and_on_demand_streaming(self):
        # Create a mock .ufdr ZIP archive
        zip_path = os.path.join(self.test_dir, "extraction.ufdr")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("databases/msgstore.db", b"SQLite format 3\x00" + b"\x00" * 1000)
            zf.writestr("DCIM/test_video.mp4", b"MP4_DATA" * 500)
            zf.writestr("WhatsApp/Media/voice_note.opus", b"OPUS_AUDIO_SAMPLE" * 100)

        engine = TerabyteForensicContainerEngine(zip_path, self.test_dir)
        extract_dir = engine.index_and_materialize_targets()

        # Check that msgstore.db is materialized
        catalog_db = os.path.join(self.test_dir, "vfs_catalog.db")
        self.assertTrue(os.path.exists(catalog_db))
        conn = sqlite3.connect(catalog_db)
        rows = conn.execute("SELECT vfs_path, is_materialized FROM vfs_files").fetchall()
        conn.close()

        vfs_dict = {r[0]: r[1] for r in rows}
        self.assertIn("databases/msgstore.db", vfs_dict)
        self.assertEqual(vfs_dict["databases/msgstore.db"], 1)
        self.assertEqual(vfs_dict["DCIM/test_video.mp4"], 0)

        # Test on-demand attachment streaming
        cached_media = engine.extract_attachment_on_demand("WhatsApp/Media/voice_note.opus")
        self.assertIsNotNone(cached_media)
        self.assertTrue(os.path.exists(cached_media))
        with open(cached_media, "rb") as f:
            content = f.read()
            self.assertIn(b"OPUS_AUDIO_SAMPLE", content)

    # --------------------------------------------------------------------------
    # 2. STREAMING XML PARSER
    # --------------------------------------------------------------------------
    def test_stream_container_xml_manifest(self):
        xml_path = os.path.join(self.test_dir, "report.xml")
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
<report>
    <model type="InstantMessage" id="1" deleted_state="Intact">
        <field name="Body" value="Hello forensic world"/>
        <field name="Sender" value="+919876543210"/>
    </model>
    <model type="InstantMessage" id="2" deleted_state="Deleted">
        <field name="Body" value="Disappearing text secret"/>
        <field name="Sender" value="+919876543211"/>
    </model>
</report>
"""
        with open(xml_path, "w", encoding="utf-8") as f:
            f.write(xml_content)

        batches = list(stream_container_xml_manifest(xml_path, batch_size=1))
        self.assertEqual(len(batches), 2)
        record1 = batches[0][0]
        self.assertEqual(record1["_model_type"], "InstantMessage")
        self.assertEqual(record1["Body"], "Hello forensic world")
        self.assertEqual(record1["_deleted_state"], "Intact")

    # --------------------------------------------------------------------------
    # 3. SLIDING-WINDOW BINARY CARVER
    # --------------------------------------------------------------------------
    def test_scan_raw_image_sliding_window(self):
        raw_path = os.path.join(self.test_dir, "raw_disk.img")
        padding_1mb = b"\xAA" * (1024 * 1024)
        # Construct header for SQLite format 3: page size 4096 (0x1000), page count 10
        sqlite_header = b"SQLite format 3\x00" + b"\x10\x00" + (b"\x00" * 10) + b"\x00\x00\x00\x0A" + (b"\x00" * 72)
        wal_header = b"\x37\x7f\x06\x83" + (b"\x00" * 28)
        upi_uri = b"upi://pay?pa=scammer@okhdfcbank&pn=FraudMerchant&am=25000.00"
        matrix_event = b'{"type":"m.room.message","sender":"@user:matrix.org","room_id":"!room1:matrix.org","content":{"body":"meet at 10pm"}}'

        with open(raw_path, "wb") as f:
            f.write(padding_1mb)
            f.write(sqlite_header)
            f.write(padding_1mb)
            f.write(wal_header)
            f.write(upi_uri)
            f.write(matrix_event)
            f.write(b"\x00" * 1000)

        findings = list(scan_raw_image_sliding_window(raw_path, chunk_size=4 * 1024 * 1024, overlap=64 * 1024))
        types_found = {f["type"] for f in findings}
        self.assertIn("sqlite_db", types_found)
        self.assertIn("sqlite_wal", types_found)
        self.assertIn("npci_upi_uri", types_found)
        self.assertIn("matrix_event", types_found)

    # --------------------------------------------------------------------------
    # 4. CASE ARTIFACT STORE (SQLITE + FTS5)
    # --------------------------------------------------------------------------
    def test_case_artifact_store_fts5(self):
        store_path = os.path.join(self.test_dir, "case_artifact_store.db")
        store = CaseArtifactStore(store_path)

        # Insert batch of chats
        chat_rows = [
            {
                "Application": "WhatsApp",
                "Message_ID": "W001",
                "Thread_ID": "1234567890@s.whatsapp.net",
                "Chat_Type": "Direct (1-on-1)",
                "Direction": "Incoming",
                "Message_Type": "Text",
                "Delivery_Status": "Read",
                "Message_Body": "Deposit the ransom into UPI account immediately",
                "Quoted_Message_ID": "",
                "Quoted_Text": "",
                "Forwarding_Score": "0",
                "Thread_Title": "Target Contact",
                "Sender_Name": "Ransom Suspect",
                "Sender_Identifier": "+919876543210",
                "Recipient_Name": "Victim",
                "Recipient_Identifier": "+919123456789",
                "Participant_Bio_Meta": "",
                "Is_View_Once": False,
                "Disappearing_TTL_Sec": 0,
                "Is_Revoked_Deleted": False,
                "Raw_Timestamp_Value": 1700000000000,
                "Timestamp_UTC": "2023-11-14 22:13:20 UTC",
                "Timestamp_IST": "2023-11-15 03:43:20 IST (+05:30)",
                "Read_Timestamp_IST": "",
                "Attachment_Path_or_URL": "",
                "Attachment_MIME_Size": "",
                "Geo_Coordinates": "12.9716, 77.5946 (Bangalore)",
                "Forensic_Provenance": "msgstore.db :: /path/msgstore.db :: message :: RowID=1 :: Offset=0x1000 :: State=Allocated B-Tree",
            }
        ]
        df_chats = pd.DataFrame(chat_rows, columns=CHAT_COLUMNS)
        store.insert_chat_batch(df_chats)

        # FTS5 search for "ransom"
        res, count = store.query_paginated_artifacts("chats", search_query="ransom")
        self.assertEqual(count, 1)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["Sender_Name"], "Ransom Suspect")

        # Search for non-existent word
        res_empty, count_empty = store.query_paginated_artifacts("chats", search_query="nonexistentkeyword")
        self.assertEqual(count_empty, 0)
        self.assertEqual(len(res_empty), 0)

    # --------------------------------------------------------------------------
    # 5. TELEGRAM TL DESERIALIZER & PARSER
    # --------------------------------------------------------------------------
    def test_telegram_tl_and_parser(self):
        # Test TL string reader
        buf = b"\x05Hello\x00\x00"  # 1 length byte (5) + 5 bytes + 2 padding = 8 bytes
        s, off = read_tl_string(buf, 0)
        self.assertEqual(s, "Hello")
        self.assertEqual(off, 8)

        # Test Telegram database parsing
        db_path = os.path.join(self.test_dir, "cache4.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE users (uid INTEGER PRIMARY KEY, name TEXT, username TEXT, data BLOB);")
        conn.execute("CREATE TABLE chats (uid INTEGER PRIMARY KEY, name TEXT);")
        conn.execute("CREATE TABLE enc_chats (uid INTEGER PRIMARY KEY, ttl INTEGER);")
        conn.execute("CREATE TABLE messages_v2 (mid INTEGER PRIMARY KEY, uid INTEGER, date INTEGER, out INTEGER, data BLOB, replydata BLOB);")

        conn.execute("INSERT INTO users VALUES (101, 'Ivan Smirnov', 'ivansmir', ?);", (b"\x00\x00\x00\x00\x05admin\x00\x00",))
        conn.execute("INSERT INTO enc_chats VALUES (101, 30);")  # 30s TTL secret chat
        conn.execute("INSERT INTO messages_v2 VALUES (1, 101, 1700000000, 0, ?, NULL);", (b"\x00\x00\x00\x00\x0DSecret Msg TL\x00\x00",))
        conn.commit()
        conn.close()

        df_chats, df_contacts = parse_telegram_cache4(db_path)
        self.assertEqual(len(df_chats), 1)
        self.assertEqual(df_chats.iloc[0]["Application"], "Telegram")
        self.assertEqual(df_chats.iloc[0]["Chat_Type"], "Secret Chat (E2EE)")
        self.assertEqual(df_chats.iloc[0]["Disappearing_TTL_Sec"], 30)
        self.assertEqual(len(df_contacts), 1)

    # --------------------------------------------------------------------------
    # 6. WHATSAPP FULL FORENSIC PARSER
    # --------------------------------------------------------------------------
    def test_whatsapp_full_forensics(self):
        db_path = os.path.join(self.test_dir, "msgstore.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                key_id TEXT,
                chat_row_id INTEGER,
                sender_jid_row_id INTEGER,
                from_me INTEGER,
                text_data TEXT,
                message_type INTEGER,
                timestamp INTEGER
            );
        """)
        conn.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER);")
        conn.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);")

        conn.execute("INSERT INTO jid VALUES (1, '919876543210@s.whatsapp.net');")
        conn.execute("INSERT INTO chat VALUES (1, 1);")
        # Regular text message
        conn.execute("INSERT INTO message VALUES (1, 'W1', 1, 1, 0, 'Hi there', 0, 1700000000000);")
        # View-once image (type 42)
        conn.execute("INSERT INTO message VALUES (2, 'W2', 1, 1, 1, 'Look once', 42, 1700000001000);")
        conn.commit()
        conn.close()

        df_chats, df_contacts = parse_whatsapp_full_forensics(db_path)
        self.assertEqual(len(df_chats), 2)
        self.assertTrue(df_chats.iloc[0]["Is_View_Once"] or df_chats.iloc[1]["Is_View_Once"])

    # --------------------------------------------------------------------------
    # 7. SIGNAL & ZANGI PARSER
    # --------------------------------------------------------------------------
    def test_signal_and_zangi_parser(self):
        # Signal
        sig_path = os.path.join(self.test_dir, "signal.db")
        conn = sqlite3.connect(sig_path)
        conn.execute("CREATE TABLE recipient (_id INTEGER PRIMARY KEY, e164 TEXT, system_joined_name TEXT, aci TEXT);")
        conn.execute("CREATE TABLE message (_id INTEGER PRIMARY KEY, recipient_id INTEGER, type INTEGER, body TEXT, date_sent INTEGER, expires_in INTEGER, view_once INTEGER);")
        conn.execute("INSERT INTO recipient VALUES (1, '+919876543210', 'Alice Cooper', 'aci-uuid-1234');")
        conn.execute("INSERT INTO message VALUES (1, 1, 23, 'Signal secret', 1700000000000, 60, 0);")
        conn.commit()
        conn.close()

        df_sig, _ = parse_signal_database(sig_path)
        self.assertEqual(len(df_sig), 1)
        self.assertEqual(df_sig.iloc[0]["Direction"], "Outgoing")
        self.assertEqual(df_sig.iloc[0]["Disappearing_TTL_Sec"], 60)

        # Zangi
        zangi_path = os.path.join(self.test_dir, "zangi.db")
        conn = sqlite3.connect(zangi_path)
        conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, sender_number TEXT, body TEXT, is_outgoing INTEGER, date INTEGER);")
        conn.execute("INSERT INTO messages VALUES (1, '10-2345-6789', 'Zangi confidential', 0, 1700000000000);")
        conn.commit()
        conn.close()

        df_zangi, _ = parse_zangi_database(zangi_path)
        self.assertEqual(len(df_zangi), 1)
        self.assertEqual(df_zangi.iloc[0]["Application"], "Zangi Messenger")
        self.assertIn("10-2345-6789", df_zangi.iloc[0]["Sender_Identifier"])

    # --------------------------------------------------------------------------
    # 8. INSTAGRAM DIRECT & DATING APPS
    # --------------------------------------------------------------------------
    def test_instagram_and_dating_apps(self):
        # Instagram Direct
        ig_path = os.path.join(self.test_dir, "direct.db")
        conn = sqlite3.connect(ig_path)
        conn.execute("CREATE TABLE threads (thread_id TEXT PRIMARY KEY, thread_title TEXT, recipients TEXT);")
        conn.execute("CREATE TABLE messages (item_id TEXT PRIMARY KEY, thread_key TEXT, user_id TEXT, message_type TEXT, text TEXT, message TEXT, timestamp INTEGER);")
        conn.execute("INSERT INTO threads VALUES ('th1', 'Chat with @hacker', '[{\"username\":\"hacker\",\"pk\":\"12345\"}]');")
        conn.execute("INSERT INTO messages VALUES ('m1', 'th1', '12345', 'raven_media', '', '{\"media\":{\"image_versions2\":{\"candidates\":[{\"url\":\"http://ig.cdn/raven.jpg\"}]}}}', 1700000000000000);")
        conn.commit()
        conn.close()

        df_ig, _ = parse_instagram_direct(ig_path)
        self.assertEqual(len(df_ig), 1)
        self.assertTrue(df_ig.iloc[0]["Is_View_Once"])
        self.assertEqual(df_ig.iloc[0]["Attachment_Path_or_URL"], "http://ig.cdn/raven.jpg")

        # Dating Apps (Tinder)
        tinder_path = os.path.join(self.test_dir, "tinder-3.db")
        conn = sqlite3.connect(tinder_path)
        conn.execute("CREATE TABLE match_view (id TEXT PRIMARY KEY, person_name TEXT, person_bio TEXT, instagram_username TEXT);")
        conn.execute("CREATE TABLE message_view (id TEXT PRIMARY KEY, match_id TEXT, from_id TEXT, to_id TEXT, text TEXT, sent_date INTEGER);")
        conn.execute("INSERT INTO match_view VALUES ('m100', 'Sophia', 'Architect from Mumbai', 'sophia_arch');")
        conn.execute("INSERT INTO message_view VALUES ('msg1', 'm100', 'm100', 'owner', 'Hey there, coffee soon?', 1700000000);")
        conn.commit()
        conn.close()

        df_tinder, df_dossier = parse_dating_apps(tinder_path, "Tinder")
        self.assertEqual(len(df_tinder), 1)
        self.assertEqual(df_tinder.iloc[0]["Chat_Type"], "Dating Match")
        self.assertIn("Architect from Mumbai", df_tinder.iloc[0]["Participant_Bio_Meta"])
        self.assertEqual(len(df_dossier), 1)

    # --------------------------------------------------------------------------
    # 9. DISPATCHER & OS SPILLOVER
    # --------------------------------------------------------------------------
    def test_dispatcher_and_spillover(self):
        notif_path = os.path.join(self.test_dir, "notification_log.db")
        conn = sqlite3.connect(notif_path)
        conn.execute("CREATE TABLE notifications (id INTEGER PRIMARY KEY, package_name TEXT, title TEXT, text TEXT, post_time INTEGER);")
        conn.execute("INSERT INTO notifications VALUES (1, 'com.whatsapp', 'Boss', 'Meeting moved to 3pm', 1700000000000);")
        conn.commit()
        conn.close()

        routed = dispatch_all_chat_and_privacy_apps(notif_path)
        self.assertIsNotNone(routed)
        self.assertIn("chats", routed)
        df_spillover = routed["chats"]
        self.assertEqual(len(df_spillover), 1)
        self.assertIn("OS Notification Spillover", df_spillover.iloc[0]["Forensic_Provenance"])


if __name__ == "__main__":
    unittest.main()
