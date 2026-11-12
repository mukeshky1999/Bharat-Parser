"""
Unit Tests for ui_fts5_paginator.py
Verifies SQLite+FTS5 paginated case store, streaming chunked ingestion,
live PA project tree counts, conversation thread aggregation, and mmap hex streamer.
"""

import os
import shutil
import tempfile
import unittest
import pandas as pd

from parsers.enterprise_1tb_chat_and_container_engine import CHAT_COLUMNS
from parsers.ui_fts5_paginator import CaseUIPaginatorStore


class TestCaseUIPaginatorStore(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_ui_store_")
        self.store = CaseUIPaginatorStore(self.test_dir, db_name="test_case_ui_store.db")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_database_initialization_and_pragmas(self):
        self.assertTrue(os.path.exists(self.store.db_path))
        conn = self.store._get_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode")
        journal_mode = cur.fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal")

        # Verify FTS5 tables exist
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_fts'")
        fts_tables = [r[0] for r in cur.fetchall()]
        self.assertIn("chats_fts", fts_tables)
        self.assertIn("transactions_fts", fts_tables)
        self.assertIn("contacts_fts", fts_tables)
        conn.close()

    def test_chunked_ingestion_and_fts5_search(self):
        # 1. Ingest sample chats
        chat_rows = [
            {
                "Application": "WhatsApp",
                "Message_ID": "WA_101",
                "Thread_ID": "919876543210@s.whatsapp.net",
                "Chat_Type": "DIRECT",
                "Direction": "Incoming",
                "Message_Type": "TEXT",
                "Delivery_Status": "READ",
                "Message_Body": "Transfer the ₹50,000 ransom to the mule account immediately",
                "Thread_Title": "Ransom Contact",
                "Sender_Name": "Unknown Suspect",
                "Sender_Identifier": "+919876543210",
                "Recipient_Name": "Victim",
                "Recipient_Identifier": "+919123456789",
                "Participant_Bio_Meta": "Bio: Available",
                "Is_View_Once": 0,
                "Disappearing_TTL_Sec": 0,
                "Is_Revoked_Deleted": 0,
                "Raw_Timestamp_Value": "1700000000",
                "Timestamp_UTC": "2023-11-14 22:13:20",
                "Timestamp_IST": "2023-11-15 03:43:20",
                "Forensic_Provenance": "msgstore.db :: Table=message :: RowID=101 :: Page_2 :: Offset=0x00066000 :: State=ACTIVE",
            },
            {
                "Application": "Telegram",
                "Message_ID": "TG_202",
                "Thread_ID": "tg_chat_88291",
                "Chat_Type": "DIRECT",
                "Direction": "Outgoing",
                "Message_Type": "TEXT",
                "Delivery_Status": "SENT",
                "Message_Body": "USDT TRC20 address sent on secret channel",
                "Thread_Title": "Crypto Offramp",
                "Sender_Name": "Owner",
                "Sender_Identifier": "tg_user_owner",
                "Recipient_Name": "Mule Broker",
                "Recipient_Identifier": "@mule_handler",
                "Participant_Bio_Meta": "@mule_handler :: Escrow specialist",
                "Is_View_Once": 0,
                "Disappearing_TTL_Sec": 30,
                "Is_Revoked_Deleted": 1,
                "Raw_Timestamp_Value": "1700000050",
                "Timestamp_UTC": "2023-11-14 22:14:10",
                "Timestamp_IST": "2023-11-15 03:44:10",
                "Forensic_Provenance": "cache4.db :: Table=messages_v2 :: RowID=202 :: Page_4 :: Offset=0x00088000 :: State=WAL_RECOVERED",
            },
            {
                "Application": "Tinder",
                "Message_ID": "TD_303",
                "Thread_ID": "match_lead_99",
                "Chat_Type": "DIRECT",
                "Direction": "Incoming",
                "Message_Type": "TEXT",
                "Delivery_Status": "DELIVERED",
                "Message_Body": "Investing in gold futures gave 40% returns [Aadhaar Redacted]",
                "Thread_Title": "Elena",
                "Sender_Name": "Elena",
                "Sender_Identifier": "tinder_user_elena",
                "Recipient_Name": "Target",
                "Recipient_Identifier": "tinder_target",
                "Participant_Bio_Meta": "Elena, 26 :: Crypto Investor :: 4.2 km away",
                "Is_View_Once": 0,
                "Disappearing_TTL_Sec": 0,
                "Is_Revoked_Deleted": 0,
                "Raw_Timestamp_Value": "1700000100",
                "Timestamp_UTC": "2023-11-14 22:15:00",
                "Timestamp_IST": "2023-11-15 03:45:00",
                "Forensic_Provenance": "tinder.db :: Table=messages :: RowID=303 :: Page_1 :: Offset=0x00021000 :: State=ACTIVE",
            },
        ]

        df_chats = pd.DataFrame(chat_rows)
        inserted = self.store.ingest_dataframe_chunked("chats", df_chats, chunk_size=2)
        self.assertEqual(inserted, 3)

        # 2. Test FTS5 Search for "ransom"
        df_res, count = self.store.get_paginated_rows("chats", search_query="ransom")
        self.assertEqual(count, 1)
        self.assertEqual(df_res.iloc[0]["Application"], "WhatsApp")

        # 3. Test FTS5 Search for "USDT"
        df_res, count = self.store.get_paginated_rows("chats", search_query="USDT")
        self.assertEqual(count, 1)
        self.assertEqual(df_res.iloc[0]["Application"], "Telegram")

    def test_pa_project_tree_counts(self):
        # Ingest chats across apps
        df_chats = pd.DataFrame([
            {
                "Application": "WhatsApp",
                "Message_ID": "1",
                "Thread_ID": "T1",
                "Forensic_Provenance": "msgstore.db :: Page_1 :: Offset=0x1000 :: State=ACTIVE",
                "Is_Revoked_Deleted": 0,
            },
            {
                "Application": "WhatsApp",
                "Message_ID": "2",
                "Thread_ID": "T1",
                "Forensic_Provenance": "msgstore.db :: Page_1 :: Offset=0x2000 :: State=WAL_RECOVERED",
                "Is_Revoked_Deleted": 0,
            },
            {
                "Application": "Telegram",
                "Message_ID": "3",
                "Thread_ID": "T2",
                "Forensic_Provenance": "cache4.db :: Page_2 :: Offset=0x3000 :: State=CARVED_FREELIST",
                "Is_Revoked_Deleted": 1,
            },
            {
                "Application": "Tinder",
                "Message_ID": "4",
                "Thread_ID": "T3",
                "Forensic_Provenance": "tinder.db :: Page_3 :: Offset=0x4000 :: State=ACTIVE",
                "Is_Revoked_Deleted": 0,
            },
        ])
        self.store.ingest_dataframe_chunked("chats", df_chats)

        # Ingest transactions
        df_tx = pd.DataFrame([
            {
                "Application": "PhonePe",
                "Transaction_ID": "TXN_01",
                "Counterparty": "merchant@ybl",
                "Amount": 1500.0,
                "Forensic_Provenance": "phonepe.db :: Offset=0x5000 :: State=ACTIVE",
                "Clock_Tamper_Detected": 0,
                "Direction": "DEBIT",
            },
            {
                "Application": "PhonePe",
                "Transaction_ID": "TXN_02",
                "Counterparty": "scammer@paytm",
                "Amount": 25000.0,
                "Forensic_Provenance": "phonepe.db :: Offset=0x6000 :: State=WAL_RECOVERED",
                "Clock_Tamper_Detected": 1,
                "Direction": "GHOST_INTENT",
            },
        ])
        self.store.ingest_dataframe_chunked("transactions", df_tx)

        counts = self.store.get_project_tree_counts()

        # WhatsApp: 1 active, 1 carved/WAL, 2 total
        self.assertEqual(counts["chats_whatsapp"]["total"], 2)
        self.assertEqual(counts["chats_whatsapp"]["active"], 1)
        self.assertEqual(counts["chats_whatsapp"]["wal_and_carved"], 1)

        # Telegram: 0 active, 1 carved/WAL, 1 total
        self.assertEqual(counts["chats_telegram"]["total"], 1)
        self.assertEqual(counts["chats_telegram"]["active"], 0)
        self.assertEqual(counts["chats_telegram"]["wal_and_carved"], 1)

        # Dating: 1 active, 0 carved, 1 total
        self.assertEqual(counts["chats_dating"]["total"], 1)
        self.assertEqual(counts["chats_dating"]["active"], 1)

        # UPI PhonePe: 2 total, 1 clock tamper, 1 ghost intent
        self.assertEqual(counts["upi_phonepe"]["total"], 2)
        self.assertEqual(counts["upi_ghost_intents"]["total"], 1)
        self.assertEqual(counts["upi_clock_tamper"]["total"], 1)

    def test_get_chat_threads_summary(self):
        df_chats = pd.DataFrame([
            {
                "Application": "WhatsApp",
                "Thread_ID": "919876543210@s.whatsapp.net",
                "Thread_Title": "Suspect Chat",
                "Chat_Type": "DIRECT",
                "Sender_Name": "Unknown",
                "Sender_Identifier": "+919876543210",
                "Recipient_Name": "Victim",
                "Recipient_Identifier": "+919123456789",
                "Participant_Bio_Meta": "Bio info",
                "Timestamp_IST": "2023-11-15 10:00:00",
                "Forensic_Provenance": "msgstore.db :: Offset=0x1000 :: State=ACTIVE",
                "Is_Revoked_Deleted": 0,
            },
            {
                "Application": "WhatsApp",
                "Thread_ID": "919876543210@s.whatsapp.net",
                "Thread_Title": "Suspect Chat",
                "Chat_Type": "DIRECT",
                "Sender_Name": "Unknown",
                "Sender_Identifier": "+919876543210",
                "Recipient_Name": "Victim",
                "Recipient_Identifier": "+919123456789",
                "Participant_Bio_Meta": "Bio info",
                "Timestamp_IST": "2023-11-15 10:05:00",
                "Forensic_Provenance": "msgstore.db :: Offset=0x1050 :: State=WAL_RECOVERED",
                "Is_Revoked_Deleted": 1,
            },
            {
                "Application": "Signal",
                "Thread_ID": "signal_lead_01",
                "Thread_Title": "Encrypted Lead",
                "Chat_Type": "DIRECT",
                "Sender_Name": "Agent",
                "Sender_Identifier": "+919888888888",
                "Recipient_Name": "Target",
                "Recipient_Identifier": "+919777777777",
                "Participant_Bio_Meta": "",
                "Timestamp_IST": "2023-11-15 11:00:00",
                "Forensic_Provenance": "signal.db :: Offset=0x2000 :: State=ACTIVE",
                "Is_Revoked_Deleted": 0,
            },
        ])
        self.store.ingest_dataframe_chunked("chats", df_chats)

        threads = self.store.get_chat_threads_summary()
        self.assertEqual(len(threads), 2)
        wa_thread = threads[threads["Application"] == "WhatsApp"].iloc[0]
        self.assertEqual(wa_thread["Total_Messages"], 2)
        self.assertEqual(wa_thread["Deleted_Carved_Count"], 1)
        self.assertEqual(wa_thread["Thread_Title"], "Suspect Chat")

    def test_read_provenance_hex_window(self):
        prov_str = "Physical_Dump.tar :: Table=messages :: RowID=42 :: Page_2 :: Offset=0x00066000 :: State=WAL_RECOVERED"
        res = self.store.read_provenance_hex_window(prov_str, window_bytes=4096)

        # Provenance is parsed, but the file does not exist: no bytes may be invented (C-04).
        self.assertEqual(res["target_offset"], 0x00066000)
        self.assertEqual(res["provenance_parsed"]["page_number"], 2)
        self.assertEqual(res["provenance_parsed"]["table_name"], "messages")
        self.assertEqual(res["provenance_parsed"]["recovery_state"], "WAL_RECOVERED")
        self.assertEqual(res["window_bytes"], 0)
        self.assertEqual(res["hex_lines"], [])
        self.assertEqual(res["raw_hex"], "")
        self.assertIn("File not found", res["error"])

    def test_read_provenance_hex_window_reads_real_bytes(self):
        path = os.path.join(self.test_dir, "real.bin")
        payload = bytes(range(256)) * 32
        with open(path, "wb") as f:
            f.write(payload)
        res = self.store.read_provenance_hex_window(file_path=path, byte_offset=512, window_size=256)
        self.assertNotIn("error", res)
        start = res["start_offset"]
        self.assertEqual(bytes.fromhex(res["raw_hex"]), payload[start:start + res["window_bytes"]])
        self.assertTrue(any(b["isHighlighted"] for l in res["hex_lines"] for b in l["bytes"]))

        beyond = self.store.read_provenance_hex_window(file_path=path, byte_offset=10**6, window_size=256)
        self.assertEqual(beyond["raw_hex"], "")
        self.assertIn("beyond end of file", beyond["error"])


if __name__ == "__main__":
    unittest.main()
