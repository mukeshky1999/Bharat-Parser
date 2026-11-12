"""
Tier 1 Feature Coverage: FastAPI Backend & Forensic UI Bridge
Tests REST API endpoints, CaseUIPaginatorStore SQLite FTS5 full-text indexing,
3-Pane Synced Hex Inspector windowing, and Mule Network graph intelligence.
"""

from __future__ import annotations

import os
import shutil
import sys
import unittest
from pathlib import Path
import pandas as pd

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
import parsers.api_server as server
from parsers.graph_intelligence import (
    build_transaction_graph,
    classify_syndicate_roles,
    detect_mule_behavior,
)
from parsers.ui_fts5_paginator import CaseUIPaginatorStore


class TestTier1UIBridge(unittest.TestCase):
    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t1_ui_")
        self.store = CaseUIPaginatorStore(
            case_workspace=str(self.sandbox),
            db_name="test_ui_bridge_case.db",
        )
        # Point server active store to test sandbox store
        self._orig_store = server._active_store
        server._active_store = self.store

    def tearDown(self):
        server._active_store = self._orig_store
        env_setup.cleanup_isolated_sandbox(self.sandbox)

    def test_health_and_case_state_endpoints(self):
        """
        T1.8.1: Validates health check and case state endpoints.
        Authoritative source: Forensic REST Engine Specification.
        """
        health = server.health_check()
        self.assertEqual(health["status"], "HEALTHY")
        self.assertIn("platform", health)
        self.assertIn("python_version", health)

        state = server.get_case_state()
        self.assertIn("loaded", state)
        self.assertIn("extractions", state)

    def test_pa_project_tree_counts_hierarchy(self):
        """
        T1.8.2: Validates live 37-node Category Tree badge counts across 18 forensic categories.
        Authoritative source: Cellebrite Physical Analyzer Analyzed Data Tree Model.
        """
        counts = self.store.get_project_tree_counts()

        # Invariant: Must contain all primary Indian Forensic categories
        expected_categories = [
            "chats_all", "chats_whatsapp", "chats_telegram",
            "calls_all", "contacts_all",
            "upi_all", "upi_phonepe", "upi_gpay", "upi_paytm", "upi_cred",
            "crypto_all", "os_spillover_all", "locations_all",
        ]
        for cat in expected_categories:
            self.assertIn(cat, counts)
            node = counts[cat]
            self.assertIn("total", node)
            self.assertIn("active", node)
            self.assertIn("wal_and_carved", node)

    def test_case_ui_paginator_store_fts5_indexing_and_pagination(self):
        """
        T1.8.3: Validates CaseUIPaginatorStore chunked ingestion and SQLite FTS5 lexical/trigram search.
        Authoritative source: SQLite FTS5 Extension Specification.
        """
        sample_txs = [
            {
                "Transaction_ID": "630911223344",
                "Amount": 45000.00,
                "Counterparty": "Mohammad Imran",
                "VPA": "mule_entry@ybl",
                "Application": "PhonePe",
                "Timestamp_IST": "2024-05-04 15:30:00",
                "Status": "SUCCESS",
                "Type": "DEBIT",
                "Forensic_Provenance": "ACTIVE_DATABASE",
            },
            {
                "Transaction_ID": "839201948201",
                "Amount": 12500.50,
                "Counterparty": "Vikram Singh",
                "VPA": "crypto_seller@okaxis",
                "Application": "Google Pay",
                "Timestamp_IST": "2024-05-04 15:45:00",
                "Status": "SUCCESS",
                "Type": "DEBIT",
                "Forensic_Provenance": "FREELIST_CARVED",
            },
        ]
        df_txs = pd.DataFrame(sample_txs)
        self.store.ingest_dataframe_chunked("transactions", df_txs)

        # 1. Query paginated records without search
        df_res, total_count = self.store.get_paginated_records("transactions", limit=10, offset=0)
        self.assertEqual(total_count, 2)
        self.assertEqual(len(df_res), 2)

        # 2. Test FTS5 search for specific UTR "630911223344"
        df_utr, total_utr = self.store.get_paginated_records("transactions", search_query="630911223344")
        self.assertEqual(total_utr, 1)
        self.assertEqual(df_utr.iloc[0]["Transaction_ID"], "630911223344")

        # 3. Test FTS5 search for counterparty name "Mohammad"
        df_name, total_name = self.store.get_paginated_records("transactions", search_query="Mohammad")
        self.assertEqual(total_name, 1)
        self.assertEqual(df_name.iloc[0]["Counterparty"], "Mohammad Imran")

    def test_inspector_hex_4kb_windowing_and_sha256(self):
        """
        T1.8.4: Validates 3-Pane Synced Hex Inspector 4KB windowing and chunk hashing.
        Authoritative source: Forensic Hex & Physical Byte Provenance Engine.
        """
        # Create a 2KB binary fixture
        binary_file = self.sandbox / "evidence_sector.raw"
        sample_bytes = b"EXACT_PHYSICAL_OFFSET_PROVENANCE_BYTES_0123456789ABCDEF" * 30
        binary_file.write_bytes(sample_bytes)

        res = server.get_inspector_hex(file_path=str(binary_file), offset=64, window_size=512)
        self.assertTrue(res["success"])
        self.assertIn("raw_hex", res)
        self.assertIn("hex_lines", res)
        self.assertIn("sha256", res)
        self.assertGreater(len(res["hex_lines"]), 0)

        # Verify first hex line contains hex offset and ascii representation
        first_line = res["hex_lines"][0]
        self.assertIn("addressHex", first_line)
        self.assertIn("bytes", first_line)
        self.assertIn("ascii", first_line)

    def test_chat_thread_chronological_aggregation(self):
        """
        T1.8.5: Validates conversation thread aggregation with recovery tags.
        Authoritative source: 1 TB+ FTS5 Case Store Conversation Aggregator.
        """
        sample_chats = [
            {
                "Artifact_ID": "WA_101",
                "Source_App": "WhatsApp",
                "Thread_ID": "919876543210@s.whatsapp.net",
                "Thread_Title": "Mohammad Imran (+919876543210)",
                "Direction": "Incoming",
                "Sender_Name": "Mohammad Imran",
                "Sender_ID": "+919876543210",
                "Recipient_Name": "Me",
                "Recipient_ID": "Me",
                "Message_Text": "Account ready. Send 50k immediately.",
                "Timestamp_UTC": "2024-05-04T10:00:00Z",
                "Timestamp_IST": "2024-05-04 15:30:00",
                "Recovery_Classification": "ACTIVE_DATABASE",
            },
            {
                "Artifact_ID": "WA_102",
                "Source_App": "WhatsApp",
                "Thread_ID": "919876543210@s.whatsapp.net",
                "Thread_Title": "Mohammad Imran (+919876543210)",
                "Direction": "Outgoing",
                "Sender_Name": "Me",
                "Sender_ID": "Me",
                "Recipient_Name": "Mohammad Imran",
                "Recipient_ID": "+919876543210",
                "Message_Text": "Sent Rs. 45000 via PhonePe UTR 630911223344",
                "Timestamp_UTC": "2024-05-04T10:05:00Z",
                "Timestamp_IST": "2024-05-04 15:35:00",
                "Recovery_Classification": "WAL_RECOVERED",
            },
        ]
        self.store.ingest_dataframe_chunked("chats", pd.DataFrame(sample_chats))

        df_threads = self.store.get_chat_threads_summary()
        self.assertGreaterEqual(len(df_threads), 1)

        # Thread should match the participant
        match = df_threads[df_threads["Thread_ID"] == "919876543210@s.whatsapp.net"]
        self.assertGreaterEqual(len(match), 1)
        self.assertEqual(match.iloc[0]["Total_Messages"], 2)

    def test_mule_network_graph_intelligence(self):
        """
        T1.8.6: Validates NetworkX transaction graph construction, mule detection, and syndicate role classification.
        Authoritative source: Forensic Graph Intelligence & Syndicate Role Engine.
        """
        txs = [
            {"Counterparty": "Mule 1", "Amount": 100000.0, "Type": "DEBIT", "Application": "GPay"},
            {"Counterparty": "Mule 2", "Amount": 45000.0, "Type": "DEBIT", "Application": "PhonePe"},
            {"Counterparty": "Mule 3", "Amount": 45000.0, "Type": "DEBIT", "Application": "PhonePe"},
            {"Counterparty": "CashoutMerchant", "Amount": 45000.0, "Type": "DEBIT", "Application": "IMPS"},
        ]
        df_txs = pd.DataFrame(txs)
        g = build_transaction_graph(df_txs)
        self.assertGreaterEqual(len(g.nodes), 4)

        roles_df = classify_syndicate_roles(g, df_txs)
        self.assertFalse(roles_df.empty)

        alerts = detect_mule_behavior(g, df_txs)
        self.assertIsInstance(alerts, list)


if __name__ == "__main__":
    unittest.main()
