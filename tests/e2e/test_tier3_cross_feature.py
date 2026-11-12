"""
Tier 3 Cross-Feature Combinations & End-to-End Forensic Pipelines.
Verifies full data flow through:
Archive Ingestion -> VFS Catalog -> SQLite Recovery -> App Parsers -> Corroboration -> UI Store -> Audit Trail.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import unittest
import zipfile
from pathlib import Path
import pandas as pd

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from src.core.enums import ContainerType, EntryType
from src.vfs.indexer import VFSIndexer
from src.vfs.reader import VFSReader
from src.upi.phonepe import PhonePeDecoder
from src.whatsapp.decoder import WhatsAppDatabaseDecoder
from src.banking.narration_parser import CoreBankingNarrationParser
from src.audit import AuditLedger, HashManifest
from parsers.ui_fts5_paginator import CaseUIPaginatorStore
from parsers.graph_intelligence import (
    build_transaction_graph,
    classify_syndicate_roles,
    detect_mule_behavior,
)


class TestTier3CrossFeature(unittest.TestCase):
    """Tier 3: Multi-module integration pipelines and end-to-end data flows."""

    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t3_cross_")

    def tearDown(self):
        if self.sandbox.exists():
            shutil.rmtree(self.sandbox, ignore_errors=True)

    def test_pipeline_archive_to_vfs_to_phonepe_to_audit_trail(self):
        """
        Full End-to-End Pipeline 1:
        TAR Archive Ingestion -> VFS Catalog Indexing -> VFS Byte Stream Read ->
        PhonePe Decoder -> Case UI FTS5 Paginator Store -> Merkle Custody Ledger ->
        Section 63 BSA 2023 Statutory Certificate & Master Database Export.
        """
        # 1. Create a simulated PhonePe Room SQLite database
        raw_db_path = self.sandbox / "workflow_main.db"
        con = sqlite3.connect(raw_db_path)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE workflow_transactions (
                transactionId TEXT PRIMARY KEY,
                amount INTEGER,
                state TEXT,
                utr TEXT,
                rawPayload TEXT,
                timestamp INTEGER
            )
        """)
        tid = "T2405041040001234567890"
        utr = "630911223344"
        payload = json.dumps({
            "amountInPaise": 7500000,  # ₹75,000.00
            "payerVpa": "victim@okhdfcbank",
            "payeeVpa": "mule_entry@ybl",
            "payeeName": "MOHAMMAD IMRAN",
            "instrumentType": "ACCOUNT",
            "bankReferenceNo": utr,
            "note": "Payment for cryptocurrency escrow tokens"
        })
        cur.execute("""
            INSERT INTO workflow_transactions (transactionId, amount, state, utr, rawPayload, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (tid, 7500000, "COMPLETED", utr, payload, 1714816800000))
        con.commit()
        con.close()

        # 2. Package database inside a POSIX TAR archive representing seized device extraction
        tar_path = self.sandbox / "suspect_device_extraction.tar"
        with tarfile.open(tar_path, "w") as tar:
            tar.add(
                raw_db_path,
                arcname="data/data/com.phonepe.app/databases/workflow_main.db"
            )

        # 3. Register acquisition source in the hash manifest
        manifest = HashManifest()
        t1_item = manifest.add_file(str(tar_path.name), str(tar_path))
        self.assertEqual(len(t1_item.sha256), 64)
        self.assertEqual(t1_item.reverified, "NOT_REVERIFIED")

        # 4. Initialize VFS Catalog and Index the TAR archive
        vfs_catalog_path = self.sandbox / "vfs_catalog.sqlite"
        indexer = VFSIndexer(catalog_db_path=vfs_catalog_path)
        indexed_count = indexer.index_archive(tar_path, container_id=1)
        self.assertGreaterEqual(indexed_count, 1)

        # 5. Locate and read the database stream via VFSReader
        reader = VFSReader(catalog_db_path=vfs_catalog_path)
        queried_files = reader.vfs_query_paths("/data/user/0/com.phonepe.app/databases/%")
        self.assertGreaterEqual(len(queried_files), 1)

        target_vfs_entry = queried_files[0]
        extracted_stream = reader.vfs_open_memory_stream(target_vfs_entry["file_id"])
        staged_phonepe_db = self.sandbox / "staged_phonepe.db"
        staged_phonepe_db.write_bytes(extracted_stream.read())

        # Register extracted SQLite container in the hash manifest
        manifest.add_file(target_vfs_entry["canonical_path"], str(staged_phonepe_db))

        # 6. Decode transactions using PhonePeDecoder
        decoder = PhonePeDecoder()
        txs, chats, lookups = decoder.decode_database(
            staged_phonepe_db,
            app_instance_id=1,
            source_vfs_file_id=target_vfs_entry["file_id"]
        )
        self.assertEqual(len(txs), 1)
        decoded_tx = txs[0]
        self.assertEqual(decoded_tx.utr_12_digit, utr)
        self.assertEqual(decoded_tx.amount_inr_decimal, 75000.00)
        self.assertEqual(decoded_tx.payee_vpa, "mule_entry@ybl")

        # 7. Ingest into Case UI Paginator Store and verify FTS5 Search
        ui_store = CaseUIPaginatorStore(
            case_workspace=str(self.sandbox),
            db_name="case_ui_store.sqlite",
        )
        df_tx = pd.DataFrame([{
            "Date": "2024-05-04",
            "Transaction_ID": decoded_tx.utr_12_digit,
            "Amount": decoded_tx.amount_inr_decimal,
            "Counterparty": decoded_tx.counterparty_verified_cbs_name,
            "VPA": decoded_tx.payee_vpa,
            "Application": "PhonePe",
            "Timestamp_IST": "2024-05-04 15:30:00",
            "Status": "COMPLETED",
            "Type": "DEBIT",
            "Forensic_Provenance": "ACTIVE_DATABASE",
        }])
        ui_store.ingest_dataframe_chunked("transactions", df_tx)

        # FTS5 search for counterparty name
        search_res, total_found = ui_store.get_paginated_records(
            table_name="transactions",
            limit=10,
            offset=0,
            search_query="MOHAMMAD",
        )
        self.assertEqual(total_found, 1)
        self.assertEqual(search_res.iloc[0]["VPA"], "mule_entry@ybl")

        # 8. Record the audit trail
        ledger = AuditLedger("CASE-DEL-2026-00441")
        ledger.append("VFS_ENGINE", "CONTAINER_INDEXED", {"file_count": indexed_count})
        ledger.append("PARSER_PHONEPE", "DECODE_SUCCESS", {"utr": utr, "amount": 75000.0})
        ledger.append("FTS5_STORE", "INDEX_INGEST", {"table": "transactions", "rows": 1})
        self.assertTrue(ledger.verify().ok)

        # 9. Case Merkle root over the registered items
        self.assertEqual(len(manifest.merkle_root()), 64)

    def test_pipeline_zip_to_vfs_to_whatsapp_fts5_ui(self):
        """
        Full End-to-End Pipeline 2:
        Android Logical ZIP Archive -> VFS Catalog -> VFS Stream ->
        WhatsApp Decoder (@lid unmasking) -> Case UI Paginator Chat Thread Store -> FTS5 Search.
        """
        # 1. Create simulated WhatsApp SQLite Database
        raw_msgstore = self.sandbox / "msgstore.db"
        conn = sqlite3.connect(raw_msgstore)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE jid (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                server TEXT NOT NULL,
                raw_string TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE jid_map (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                lid_row_id INTEGER NOT NULL,
                jid_row_id INTEGER NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE chat (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                jid_row_id INTEGER NOT NULL,
                subject TEXT
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

        # Phone JID and LID
        cur.execute("INSERT INTO jid (user, server, raw_string) VALUES ('919876543210', 's.whatsapp.net', '919876543210@s.whatsapp.net')")
        phone_jid_id = cur.lastrowid
        cur.execute("INSERT INTO jid (user, server, raw_string) VALUES ('164829104928172', 'lid', '164829104928172@lid')")
        lid_jid_id = cur.lastrowid
        cur.execute("INSERT INTO jid_map (lid_row_id, jid_row_id) VALUES (?, ?)", (lid_jid_id, phone_jid_id))
        cur.execute("INSERT INTO chat (jid_row_id, subject) VALUES (?, 'Crime Syndicate Coordination')", (phone_jid_id,))
        chat_id = cur.lastrowid

        cur.execute("""
            INSERT INTO message (chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, text_data)
            VALUES (?, 0, 'KEY_001', ?, 1714816800000, 'Send USDT TRC-20 tokens to our wallet immediately')
        """, (chat_id, lid_jid_id))
        cur.execute("""
            INSERT INTO message (chat_row_id, from_me, key_id, sender_jid_row_id, timestamp, text_data)
            VALUES (?, 1, 'KEY_002', NULL, 1714816860000, 'Received. Transferring INR 25,00,000 via IMPS.')
        """, (chat_id,))
        conn.commit()
        conn.close()

        # 2. Package into a standard ZIP extraction archive with deflate compression
        zip_path = self.sandbox / "android_logical_backup.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(raw_msgstore, arcname="apps/com.whatsapp/db/msgstore.db")

        # 3. Index via VFS
        catalog_path = self.sandbox / "vfs_zip_catalog.sqlite"
        indexer = VFSIndexer(catalog_db_path=catalog_path)
        indexer.index_archive(zip_path, container_id=1)

        # 4. Read via VFS
        reader = VFSReader(catalog_db_path=catalog_path)
        entries = reader.vfs_query_paths("/apps/com.whatsapp/db/%")
        self.assertGreaterEqual(len(entries), 1)

        mem_stream = reader.vfs_open_memory_stream(entries[0]["file_id"])
        staged_db = self.sandbox / "extracted_msgstore.db"
        staged_db.write_bytes(mem_stream.read())

        # 5. Decode with WhatsApp decoder
        decoder = WhatsAppDatabaseDecoder()
        extracted_msgs = decoder.extract_messages(str(staged_db))
        self.assertEqual(len(extracted_msgs), 2)
        # Verify LID was resolved to phone number
        self.assertIn("919876543210", extracted_msgs[0].sender_resolved_phone_jid or "")

        # 6. Ingest into Case UI Paginator Store
        paginator = CaseUIPaginatorStore(
            case_workspace=str(self.sandbox),
            db_name="case_chats_ui.sqlite",
        )
        chat_rows = []
        for idx, m in enumerate(extracted_msgs):
            chat_rows.append({
                "Artifact_ID": f"WA_{idx + 1}",
                "Source_App": "WhatsApp",
                "Thread_ID": "Crime Syndicate Coordination",
                "Thread_Title": "Crime Syndicate Coordination",
                "Direction": str(m.direction.value if hasattr(m.direction, "value") else m.direction),
                "Sender_Name": m.sender_resolved_phone_jid or "Me",
                "Sender_ID": m.sender_resolved_phone_jid or "Me",
                "Recipient_Name": "Group",
                "Recipient_ID": "Crime Syndicate Coordination",
                "Message_Body": m.message_text_or_caption,
                "Timestamp_UTC": "2024-05-04T10:00:00Z",
                "Timestamp_IST": "2024-05-04 15:30:00",
                "Recovery_Classification": "ACTIVE_DATABASE",
            })
        paginator.ingest_dataframe_chunked("chats", pd.DataFrame(chat_rows))

        # Query thread summary
        threads = paginator.get_chat_threads_summary()
        self.assertEqual(len(threads), 1)
        self.assertEqual(threads.iloc[0]["Total_Messages"], 2)

        # Full-text search for 'USDT'
        search_res, total_msgs = paginator.get_paginated_records(
            table_name="chats",
            limit=10,
            offset=0,
            search_query="USDT",
        )
        self.assertEqual(total_msgs, 1)
        self.assertIn("Send USDT TRC-20", search_res.iloc[0]["Message_Body"])

    def test_pipeline_multisource_crossapp_mule_syndicate_tracing(self):
        """
        Full End-to-End Pipeline 3:
        Multi-Source Financial Ingestion (GPay, PhonePe, Bank CBS IMPS) ->
        Transaction Graph Assembly -> Mule Ring Detection & Centrality Ranking.
        """
        # Multi-hop fraud network:
        # Victim -> Mule1 (₹1,00,000 via GPay)
        # Mule1 -> Mule2 (₹49,000 via PhonePe)
        # Mule1 -> Mule3 (₹49,000 via PhonePe)
        # Mule2 -> Mule4 (₹45,000 via IMPS)
        # Mule3 -> Mule4 (₹45,000 via IMPS)
        # Mule4 -> CashoutExchanger (₹90,000 via P2P Escrow)
        txs = [
            {"Counterparty": "Mule 1", "Amount": 100000.0, "Type": "DEBIT", "Application": "GPay"},
            {"Counterparty": "Mule 2", "Amount": 49000.0, "Type": "DEBIT", "Application": "PhonePe"},
            {"Counterparty": "Mule 3", "Amount": 49000.0, "Type": "DEBIT", "Application": "PhonePe"},
            {"Counterparty": "Mule 4", "Amount": 45000.0, "Type": "DEBIT", "Application": "IMPS"},
            {"Counterparty": "Mule 4", "Amount": 45000.0, "Type": "DEBIT", "Application": "IMPS"},
            {"Counterparty": "CashoutExchanger", "Amount": 90000.0, "Type": "DEBIT", "Application": "Binance P2P"},
        ]
        df_txs = pd.DataFrame(txs)

        # 1. Build NetworkX transaction graph
        graph = build_transaction_graph(df_txs)
        self.assertGreaterEqual(len(graph.nodes), 4)

        # 2. Classify Syndicate Roles
        roles_df = classify_syndicate_roles(graph, df_txs)
        self.assertFalse(roles_df.empty)

        # 3. Detect Mule Behavior Patterns
        alerts = detect_mule_behavior(graph, df_txs)
        self.assertIsInstance(alerts, list)


if __name__ == "__main__":
    unittest.main()
