"""
Unified Test Suite for Milestone 4: FastAPI Backend REST Server & Forensic UI Bridge.
Tests all REST endpoints, concurrency locks, sandboxing, Myers redline diffing,
5-stage Sankey laundering canvas, Section 63 BSA certificate, Section 230 BNSS defense bundle,
and 1930 NCRP bank freeze sheet with Complainant / Victim Safeguard Lock.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import pandas as pd
from fastapi import HTTPException

import parsers.api_server as server
from parsers.api_server import (
    ChatRedlineRequest,
    NcrpFreezeRequest,
    OcrAnalyzeRequest,
    Sec63BsaRequest,
    Sec230BnssRequest,
    ArtifactCategoryEnum,
)
from parsers.ui_fts5_paginator import CaseUIPaginatorStore


class TestUIAPIServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bharat_ui_api_test_")
        cls.workspace = os.path.join(cls.temp_dir, "test_case")
        os.makedirs(cls.workspace, exist_ok=True)

        # Create isolated test SQLite FTS5 Case Store
        cls.store = CaseUIPaginatorStore(
            case_workspace=cls.workspace,
            db_name="test_bharat_case.db"
        )

        # Seed sample transactions
        conn = cls.store._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO transactions (
                Application, Transaction_ID, Bank_Ref_No, Amount, Type,
                Date, Counterparty, VPA, Status, Forensic_Provenance
            ) VALUES
            ('PhonePe', 'T261108142000', '412345678901', 250000.0, 'DEBIT',
             '2026-11-08 14:20:00', 'Mule Layer 1', 'victim@okhdfcbank', 'SUCCESS', 'ACTIVE'),
            ('GPay', 'CICAgICAgICAgA', '412345678902', 235000.0, 'TRANSFER',
             '2026-11-08 14:35:12', 'Mule Layer 2', 'mule1@oksbi', 'SUCCESS', 'WAL_RECOVERED'),
            ('Paytm', 'PTM1108150240', '412345678903', 220000.0, 'TRANSFER',
             '2026-11-08 15:02:40', 'Binance P2P Escrow', 'mule2@icici', 'SUCCESS', 'CARVED_UNALLOCATED')
        """)

        # Seed sample chat records
        cur.execute("""
            INSERT INTO chats (
                Application, Thread_ID, Thread_Title, Sender_Name, Recipient_Name,
                Message_Body, Timestamp_IST, Forensic_Provenance, Is_View_Once
            ) VALUES
            ('WhatsApp', 'thread_mule_01', 'Syndicate P2P Coordination', 'Mule Boss', 'This Phone',
             'Send ₹50,000 to user@okhdfcbank immediately for USDT release', '2026-11-08 14:15:00', 'ACTIVE', 0),
            ('WhatsApp', 'thread_mule_01', 'Syndicate P2P Coordination', 'This Phone', 'Mule Boss',
             'Done. Transaction UTR is 412345678901', '2026-11-08 14:21:00', 'ACTIVE', 0),
            ('Telegram', 'thread_tg_secret', 'Offshore P2P OTC', 'Boss C2', 'This Phone',
             'Wallet address: TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t', '2026-11-08 15:10:00', 'WAL_RECOVERED', 1)
        """)
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def setUp(self):
        self._orig_store = server._active_store
        self._orig_state = dict(server._case_state)
        server._active_store = self.store
        server._case_state.update({
            "loaded": True,
            "case_id": "TEST_CASE_M4_001",
            "case_name": "Test Cyber Fraud Investigation",
            "evidence_path": self.workspace,
            "examiner_name": "Inspector Rajesh Verma",
            "agency_name": "Special Cyber Crime Investigation Unit",
            "hashes": {
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "fileSizeBytes": 1048576,
            },
            "device_metadata": {
                "model": "Redmi Note 12 5G",
                "manufacturer": "Xiaomi",
                "androidVersion": "14.0",
                "serialNumber": "SN987654321",
                "imei1": "862910058291048",
            },
            "mule_alerts": [
                {"alert_type": "HIGH_VELOCITY_SMURFING", "severity": "CRITICAL", "amount": 250000.0}
            ],
            "syndicate_roles": [
                {"entity": "Mule Layer 1", "role": "Layer-1 Smurfing Mule", "inflow": 250000.0, "outflow": 235000.0}
            ],
        })

    def tearDown(self):
        server._active_store = self._orig_store
        server._case_state.clear()
        server._case_state.update(self._orig_state)

    def test_01_health_and_root_endpoints(self):
        """Validates / and /api/health endpoints."""
        root_res = server.root()
        self.assertEqual(root_res["service"], "Bharat-PA Forensics REST Engine")
        self.assertEqual(root_res["status"], "ONLINE")
        self.assertTrue(root_res["case_loaded"])

        health_res = server.health_check()
        self.assertEqual(health_res["status"], "HEALTHY")
        self.assertIn("platform", health_res)
        self.assertIn("python_version", health_res)
        self.assertTrue(health_res["case_loaded"])
        self.assertTrue(health_res["database_exists"])

    def test_02_case_state_and_summary(self):
        """Validates /api/case/state and /api/case/summary."""
        state = server.get_case_state()
        self.assertTrue(state["loaded"])
        self.assertEqual(state["case_id"], "TEST_CASE_M4_001")
        self.assertIn("counts", state)

        summary = server.get_case_summary()
        self.assertTrue(summary["loaded"])
        self.assertEqual(summary["examiner_name"], "Inspector Rajesh Verma")
        self.assertEqual(len(summary["mule_alerts"]), 1)
        self.assertIn("hashes", summary)

    def test_03_category_tree_counts_hierarchy(self):
        """Validates /api/case/tree-counts returns active vs carved counts."""
        res = server.get_tree_counts()
        self.assertTrue(res["success"])
        counts = res["counts"]
        self.assertIn("upi_all", counts)
        self.assertIn("chats_all", counts)
        self.assertGreaterEqual(counts["upi_all"]["total"], 3)
        self.assertGreaterEqual(counts["chats_all"]["total"], 3)

    def test_04_artifacts_query_fts5_and_pagination(self):
        """Validates /api/artifacts/query with FTS5 search and sorting."""
        res = server.query_artifacts(
            category="transactions",
            search_query="PhonePe",
            limit=10,
            offset=0
        )
        self.assertTrue(res["success"])
        self.assertGreaterEqual(res["total"], 1)
        self.assertEqual(res["rows"][0]["Application"], "PhonePe")
        self.assertIn("PhonePe", res["apps_available"])

        # FTS5 search across chats
        chat_res = server.query_artifacts(
            category="chats",
            search_query="USDT",
            limit=10,
            offset=0
        )
        self.assertTrue(chat_res["success"])
        self.assertGreaterEqual(chat_res["total"], 1)
        self.assertIn("USDT", chat_res["rows"][0]["Message_Body"])

    def test_05_4kb_hex_inspector_window(self):
        """Validates /api/inspector/hex returns 4KB slice with SHA-256."""
        # Create synthetic binary evidence file in workspace
        ev_file = os.path.join(self.workspace, "evidence_test.bin")
        dummy_data = b"FORENSIC_EVIDENCE_PAGE_HEADER\x00" + (b"A" * 8192)
        with open(ev_file, "wb") as f:
            f.write(dummy_data)

        hex_res = server.get_inspector_hex(file_path=ev_file, offset=0, window_size=4096)
        self.assertTrue(hex_res["success"])
        self.assertEqual(hex_res["target_offset"], 0)
        self.assertGreater(len(hex_res["raw_hex"]), 0)
        self.assertIsNotNone(hex_res["sha256"])
        self.assertGreater(len(hex_res["hex_lines"]), 0)

    def test_06_chats_thread_singular_and_plural_routes(self):
        """Validates both /api/chats/thread (singular) and /api/chats/threads (plural)."""
        # Test plural thread summaries
        threads_res = server.get_chat_threads()
        self.assertTrue(threads_res["success"])
        self.assertGreater(threads_res["count"], 0)

        # Test singular alias fetching specific thread history
        thread_history = server.get_chat_thread_singular(thread_id="thread_mule_01")
        self.assertTrue(thread_history["success"])
        self.assertEqual(thread_history["thread_id"], "thread_mule_01")
        self.assertGreaterEqual(thread_history["total"], 2)
        self.assertEqual(len(thread_history["messages"]), 2)

    def test_07_chat_redline_myers_diff(self):
        """Validates POST /api/chat-redline computes Myers SES diff and detects financial tokens."""
        req = ChatRedlineRequest(
            original_text="Transfer ₹50,000 to user@okhdfcbank right now",
            edited_text="Transfer ₹10,000 to user@okhdfcbank right now"
        )
        res = server.compute_chat_redline(req)
        self.assertTrue(res.success)
        self.assertTrue(res.has_financial_or_crypto_token)
        self.assertIn("<del>", res.rendered_markup)
        self.assertIn("</del>", res.rendered_markup)
        self.assertIn("<ins>", res.rendered_markup)
        self.assertIn("</ins>", res.rendered_markup)
        self.assertIn("50,000", res.rendered_markup)
        self.assertIn("10,000", res.rendered_markup)
        self.assertGreater(len(res.tokens), 0)

    def test_08_graph_mule_network_and_sankey(self):
        """Validates GET /api/graph/mule-network and GET /api/graph/sankey-svg."""
        net_res = server.get_graph_mule_network()
        self.assertTrue(net_res["success"])
        self.assertIn("nodes", net_res)
        self.assertIn("edges", net_res)
        self.assertIn("sankey_layout", net_res)
        self.assertIn("stages", net_res["sankey_layout"])
        self.assertIn("ribbons", net_res["sankey_layout"])

        svg_res = server.get_graph_sankey_svg()
        svg_content = svg_res.body.decode("utf-8")
        self.assertIn("<svg", svg_content)
        self.assertIn("</svg>", svg_content)
        self.assertIn("STAGE 1: SOURCE", svg_content)
        self.assertIn("MULE L1", svg_content)
        self.assertEqual(svg_res.media_type, "image/svg+xml")

    def test_09_report_sec63_bsa_certificate(self):
        """Validates Section 63 BSA 2023 statutory certificate generation."""
        cert_res = server.generate_sec63_bsa_certificate()
        html_text = cert_res.body.decode("utf-8")
        self.assertIn("Section 63(4)(c)", html_text)
        self.assertIn("Bharatiya Sakshya Adhiniyam, 2023", html_text)
        self.assertIn("TEST_CASE_M4_001", html_text)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", html_text)

        # Test POST route
        post_req = Sec63BsaRequest(
            case_id="TEST_CASE_POST_63",
            examiner_name="Inspector S. K. Gupta"
        )
        post_res = server.generate_sec63_bsa_certificate_post(post_req)
        self.assertIn("TEST_CASE_POST_63", post_res.body.decode("utf-8"))

    def test_10_report_sec230_bnss_defense_bundle(self):
        """Validates Section 230 BNSS statutory defense disclosure bundle generation."""
        out_dir = os.path.join(self.workspace, "sec230_test_out")
        req = Sec230BnssRequest(
            case_id="TEST_SEC230_CASE",
            output_dir=out_dir,
            anonymize_victim_identity=True,
            victim_name="Ananya Sharma"
        )
        res = server.generate_sec230_bnss_report(req)
        self.assertTrue(res["success"])
        self.assertEqual(res["pocso_withheld_count"], 1)
        self.assertTrue(os.path.isdir(res["bundle_path"]))
        self.assertTrue(os.path.isfile(res["html_viewer_path"]))

        # Check victim anonymization in Open_Case_Dossier.html
        with open(res["html_viewer_path"], "r", encoding="utf-8") as f:
            dossier_html = f.read()
        self.assertNotIn("Ananya Sharma", dossier_html)
        self.assertIn("[VICTIM_PROTECTED_ID_01]", dossier_html)

        # Check that statutory withheld notice card was generated
        exhibits_dir = os.path.join(out_dir, "exhibits")
        withheld_notice = os.path.join(exhibits_dir, "withheld_sensitive_stream_02_WITHHELD_NOTICE.txt")
        self.assertTrue(os.path.isfile(withheld_notice))
        with open(withheld_notice, "r", encoding="utf-8") as f:
            notice_text = f.read()
        self.assertIn("STATUTORY JUDICIAL-INSPECTION NOTICE CARD", notice_text)
        self.assertIn("P. Gopalkrishnan v. State of Kerala", notice_text)

    def test_11_report_1930_ncrp_bank_freeze_with_victim_safeguard(self):
        """Validates 14-column 1930 NCRP bank freeze sheet and Complainant Safeguard Lock."""
        out_dir = os.path.join(self.workspace, "ncrp_test_out")
        req = NcrpFreezeRequest(
            case_id="TEST_NCRP_CASE",
            output_dir=out_dir,
            complainant_account="VICTIM_ACCOUNT_112233"
        )
        res = server.generate_ncrp_freeze_report(req)
        self.assertTrue(res["success"])
        self.assertTrue(os.path.isfile(res["csv_path"]))
        self.assertGreater(len(res["sha256"]), 0)
        self.assertGreaterEqual(res["total_freeze_targets"], 2)

        # Verify Complainant Safeguard Lock
        victim_safeguard = next(s for s in res["safeguards"] if s["is_victim"])
        self.assertTrue(victim_safeguard["is_freeze_locked"])
        self.assertTrue(victim_safeguard["freeze_checkbox_disabled"])
        self.assertIn("DO NOT FREEZE", victim_safeguard["role_badge"])

        # Verify that CSV does not include victim account in beneficiary freeze column
        with open(res["csv_path"], "r", encoding="utf-8") as f:
            csv_lines = f.readlines()
        self.assertGreaterEqual(len(csv_lines), 3)  # header + at least 2 mule targets
        for line in csv_lines[1:]:
            parts = line.strip().split(",")
            # column 2 is Beneficiary_Account_to_Freeze
            beneficiary_acc = parts[2]
            self.assertNotEqual(beneficiary_acc, "VICTIM_ACCOUNT_112233")

        # Test GET download route
        csv_download = server.get_ncrp_freeze_csv(case_id="TEST_NCRP_CASE")
        self.assertEqual(csv_download.media_type, "text/csv")
        self.assertIn("Acknowledgement_No", csv_download.body.decode("utf-8"))

    def test_12_ocr_analyze_endpoint(self):
        """Validates POST /api/ocr/analyze extracts text, UTRs, and VPAs."""
        img_path = os.path.join(self.workspace, "sample_receipt.txt")
        receipt_text = (
            "Payment Successful to payee@oksbi\n"
            "Transaction Ref / UTR: 412345678901\n"
            "Amount: Rs 25,000.00\n"
            "IFSC: SBIN0001234\n"
            "PAN: ABCDE1234F\n"
        )
        with open(img_path, "w", encoding="utf-8") as f:
            f.write(receipt_text)

        ocr_res = server.analyze_image_ocr(OcrAnalyzeRequest(image_path=img_path))
        self.assertTrue(ocr_res["success"])
        self.assertIn("payee@oksbi", ocr_res["vpas"])
        self.assertIn("412345678901", ocr_res["extracted_utrs"])
        self.assertIn("SBIN0001234", ocr_res["extracted_ifscs"])
        self.assertIn("ABCDE1234F", ocr_res["extracted_pans"])

    def test_13_concurrency_locks_and_error_guards(self):
        """Validates 409 Conflict concurrency locks and 412 / 403 error guards."""
        # Test 409 on ingestion lock
        server._ingest_lock._locked = True
        try:
            with self.assertRaises(HTTPException) as ctx:
                coro = server.ingest_evidence_case(
                    server.IngestCaseRequest(evidence_path=self.workspace)
                )
                coro.send(None)
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertIn("Conflict", ctx.exception.detail)
        finally:
            server._ingest_lock._locked = False

        # Test 409 on benchmark lock
        server._benchmark_lock._locked = True
        try:
            with self.assertRaises(HTTPException) as ctx:
                coro = server.run_benchmark(
                    server.BenchmarkRequest(dump_path=self.workspace)
                )
                coro.send(None)
            self.assertEqual(ctx.exception.status_code, 409)
            self.assertIn("Conflict", ctx.exception.detail)
        finally:
            server._benchmark_lock._locked = False

        # Test 412 Precondition Failed when no case is loaded
        server._case_state["loaded"] = False
        with self.assertRaises(HTTPException) as ctx:
            coro = server.get_paginated_records(category=ArtifactCategoryEnum.CHATS)
            coro.send(None)
        self.assertEqual(ctx.exception.status_code, 412)

        with self.assertRaises(HTTPException) as ctx:
            coro = server.get_hex_window(file_path=self.workspace, offset=0)
            coro.send(None)
        self.assertEqual(ctx.exception.status_code, 412)

        # Test 403 Forbidden sandboxing when target is outside workspace
        server._case_state["loaded"] = True
        with self.assertRaises(HTTPException) as ctx:
            coro = server.get_hex_window(
                file_path=r"C:\Windows\System32\cmd.exe",
                offset=0
            )
            coro.send(None)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Access Denied", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()
