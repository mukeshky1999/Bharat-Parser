"""
Adversarial QA & Stress-Test Harness for Milestone 4 (API Bridge & Forensic UI Workbench).
Tests edge cases, malicious payloads, path traversals, XSS injection, FTS5 SQL injection,
Complainant Safeguard Lock stress scenarios, and concurrency conflict safety.
"""

from __future__ import annotations

import asyncio
import os
from tests.legal_fixtures import ncrp_candidates, sec230_items
import shutil
import tempfile
import unittest
from pathlib import Path
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


class TestAdversarialM4Challenge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bharat_adv_challenge_")
        cls.workspace = os.path.join(cls.temp_dir, "adv_case_ws")
        os.makedirs(cls.workspace, exist_ok=True)

        cls.store = CaseUIPaginatorStore(
            case_workspace=cls.workspace,
            db_name="adv_case_store.db"
        )

        conn = cls.store._get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO transactions (
                Application, Transaction_ID, Bank_Ref_No, Amount, Type,
                Date, Counterparty, VPA, Status, Forensic_Provenance
            ) VALUES
            ('PhonePe', 'T_ADV_01', '998877665544', 100000.0, 'DEBIT',
             '2026-11-09 10:00:00', 'Victim Account', 'victim@okhdfcbank', 'SUCCESS', 'ACTIVE'),
            ('Paytm', 'T_ADV_02', '998877665545', 95000.0, 'TRANSFER',
             '2026-11-09 10:15:00', 'Mule A', 'mule_a@paytm', 'SUCCESS', 'ACTIVE')
        """)

        cur.execute("""
            INSERT INTO chats (
                Application, Thread_ID, Thread_Title, Sender_Name, Recipient_Name,
                Message_Body, Timestamp_IST, Forensic_Provenance, Is_View_Once
            ) VALUES
            ('WhatsApp', 'th_adv_01', 'Test Redline Thread', 'Victim', 'Scammer',
             'Original test message before redline', '2026-11-09 10:00:00', 'ACTIVE', 0)
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
            "case_id": "CASE_ADV_STRESS_001",
            "case_name": "Adversarial Stress Test",
            "evidence_path": self.workspace,
            "examiner_name": "Lead Auditor",
            "agency_name": "Adversarial Forensics Unit",
            "hashes": {
                "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "md5": "0123456789abcdef0123456789abcdef",
                "fileSizeBytes": 2048,
            },
            "device_metadata": {
                "model": "Pixel 8 Pro",
                "manufacturer": "Google",
                "androidVersion": "15.0",
                "serialNumber": "SN_ADV_888",
                "imei1": "351234567890123",
            },
            "mule_alerts": [],
            "syndicate_roles": [],
        })

    def tearDown(self):
        server._active_store = self._orig_store
        server._case_state.clear()
        server._case_state.update(self._orig_state)

    def test_adv_01_xss_injection_myers_redline(self):
        """Adversarially attempts XSS injection into chat-redline original & edited text."""
        xss_payloads = [
            ("<script>alert('XSS_ORIG')</script>", "<script>alert('XSS_EDIT')</script>"),
            ("<img src=x onerror=alert('PWNED')>", "Normal replacement text"),
            ("<a href=\"javascript:evil()\">Click</a>", "<iframe src=\"http://malicious.org\"></iframe>"),
            ("<div><span>Nested unclosed", "</div></span>"),
        ]

        for orig, edit in xss_payloads:
            req = ChatRedlineRequest(original_text=orig, edited_text=edit)
            res = server.compute_chat_redline(req)
            self.assertTrue(res.success)
            # Verify no unescaped raw <script>, <img, <iframe, or <a tags remain in rendered_markup
            markup_lower = res.rendered_markup.lower()
            self.assertNotIn("<script", markup_lower)
            self.assertNotIn("<img", markup_lower)
            self.assertNotIn("<iframe", markup_lower)
            self.assertNotIn("<a ", markup_lower)
            # Verify only allowed styling tags are used: <ins>, </ins>, <del>, </del>
            # Stripping allowed tags should leave no HTML tags '<'
            stripped = markup_lower.replace("<del>", "").replace("</del>", "").replace("<ins>", "").replace("</ins>", "")
            self.assertNotIn("<", stripped)
            self.assertNotIn(">", stripped)

    def test_adv_02_path_traversal_hex_window(self):
        """Adversarially attempts directory traversal and unauthorized file reads."""
        traversal_attempts = [
            r"..\..\..\Windows\win.ini",
            r"../../../../etc/passwd",
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Program Files",
            r"\\127.0.0.1\c$\Windows",
        ]

        for bad_path in traversal_attempts:
            with self.assertRaises(HTTPException) as ctx:
                coro = server.get_hex_window(file_path=bad_path, offset=0)
                coro.send(None)
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertIn("Access Denied", ctx.exception.detail)

    def test_adv_03_complainant_safeguard_lock_stress(self):
        """Adversarially stresses Complainant Safeguard Lock with multiple accounts and edge formats."""
        out_dir = os.path.join(self.workspace, "adv_ncrp_out")
        
        # Test candidate list where victim account is deliberately placed amongst mules
        adv_candidates = [
            {
                "account_no": "VICTIM_ACC_001",
                "ifsc": "HDFC0000001",
                "vpa": "victim@okhdfcbank",
                "is_complainant_victim": True,
                "volume_inr": 500000.0,
            },
            {
                "account_no": "MULE_ACC_L1",
                "ifsc": "SBIN0001111",
                "vpa": "mule1@oksbi",
                "is_complainant_victim": False,
                "volume_inr": 480000.0,
            },
            {
                "account_no": "VICTIM_ACC_002",
                "ifsc": "ICIC0002222",
                "vpa": "victim.secondary@icici",
                "is_complainant_victim": True,
                "volume_inr": 20000.0,
            },
            {
                "account_no": "MULE_ACC_L2",
                "ifsc": "PUNB0003333",
                "vpa": "mule2@okaxis",
                "is_complainant_victim": False,
                "volume_inr": 450000.0,
            },
            {
                "account_no": "BESCOM_UTILITY_ESCROW",
                "ifsc": "SBIN0009999",
                "vpa": "bescom.billdesk@icici",
                "is_complainant_victim": False,
                "volume_inr": 1200.0,
            }
        ]

        req = NcrpFreezeRequest(acknowledgement_no="NCRP-TEST-001", 
            case_id="CASE_ADV_NCRP",
            output_dir=out_dir,
            complainant_account="VICTIM_ACC_001",
            candidates=adv_candidates
        )
        res = server.generate_ncrp_freeze_report(req)
        self.assertTrue(res["success"])

        # Check safeguards list
        safeguards = {s["account_no"]: s for s in res["safeguards"]}
        self.assertTrue(safeguards["VICTIM_ACC_001"]["is_freeze_locked"])
        self.assertTrue(safeguards["VICTIM_ACC_001"]["freeze_checkbox_disabled"])
        self.assertTrue(safeguards["VICTIM_ACC_002"]["is_freeze_locked"])
        self.assertTrue(safeguards["VICTIM_ACC_002"]["freeze_checkbox_disabled"])

        # Mule accounts must NOT be locked
        self.assertFalse(safeguards["MULE_ACC_L1"]["is_freeze_locked"])
        self.assertFalse(safeguards["MULE_ACC_L1"]["freeze_checkbox_disabled"])
        self.assertFalse(safeguards["MULE_ACC_L2"]["is_freeze_locked"])
        self.assertFalse(safeguards["MULE_ACC_L2"]["freeze_checkbox_disabled"])

        # Verify CSV content: parse row columns
        with open(res["csv_path"], "r", encoding="utf-8") as f:
            csv_lines = [line.strip().split(",") for line in f if line.strip()]

        headers = csv_lines[0]
        data_rows = csv_lines[1:]
        self.assertGreaterEqual(len(data_rows), 2)

        # In every data row:
        # Col 1: Complainant_Source_Account
        # Col 2: Beneficiary_Account_to_Freeze
        frozen_beneficiaries = [row[2] for row in data_rows]
        self.assertNotIn("VICTIM_ACC_001", frozen_beneficiaries)
        self.assertNotIn("VICTIM_ACC_002", frozen_beneficiaries)
        self.assertNotIn("BESCOM_UTILITY_ESCROW", frozen_beneficiaries)
        self.assertIn("MULE_ACC_L1", frozen_beneficiaries)
        self.assertIn("MULE_ACC_L2", frozen_beneficiaries)

    def test_adv_04_concurrency_lock_and_release(self):
        """Verifies concurrency locks reject overlapping requests and permit execution once unlocked."""
        # 1. Manually engage lock
        server._ingest_lock._locked = True
        try:
            with self.assertRaises(HTTPException) as ctx:
                coro = server.ingest_evidence_case(
                    server.IngestCaseRequest(evidence_path=self.workspace)
                )
                coro.send(None)
            self.assertEqual(ctx.exception.status_code, 409)
        finally:
            server._ingest_lock._locked = False

        # 2. Lock is now free, should proceed without 409 Conflict
        self.assertFalse(server._ingest_lock._locked)

    def test_adv_05_fts5_malicious_query_injection(self):
        """Adversarially injects SQL syntax and FTS5 operator attacks into search_query."""
        malicious_queries = [
            "'; DROP TABLE chats; --",
            "\"unmatched quote",
            "OR 1=1",
            "NEAR/0 (a, b)",
            "*",
            "*** NOT AND OR ***",
            "'\"; -- /* test */",
            "CASE_HEX_%_OR_1=1",
        ]

        for q in malicious_queries:
            # Must not throw unhandled exception or 500 Internal Server Error
            try:
                res = server.query_artifacts(
                    category="transactions",
                    search_query=q,
                    limit=5,
                    offset=0
                )
                self.assertTrue(res["success"])
                self.assertIsInstance(res["rows"], list)
            except Exception as e:
                self.fail(f"query_artifacts crashed on hostile FTS5 input '{q}': {e}")

    def test_adv_06_ocr_analyze_edge_inputs(self):
        """Tests OCR analyze endpoint with non-existent file and empty text."""
        # 1. Non-existent file should raise 404
        with self.assertRaises(HTTPException) as ctx:
            server.analyze_image_ocr(OcrAnalyzeRequest(image_path="non_existent_image_123.jpg"))
        self.assertEqual(ctx.exception.status_code, 404)

        # 2. Zero-byte file in workspace
        empty_img = os.path.join(self.workspace, "empty_evidence.png")
        with open(empty_img, "wb") as f:
            f.write(b"")

        res = server.analyze_image_ocr(OcrAnalyzeRequest(image_path=empty_img))
        self.assertTrue(res["success"])
        self.assertEqual(res["extracted_utrs"], [])
        self.assertEqual(res["vpas"], [])

    def test_adv_07_sec230_bnss_special_regex_victim_name(self):
        """Tests Section 230 BNSS redaction when victim name contains regex metacharacters."""
        out_dir = os.path.join(self.workspace, "adv_sec230_out")
        
        # Name with brackets, asterisks, pluses, questions
        complex_victim_name = "Priya [Victim] (Witness) *Protected* +1?"
        req = Sec230BnssRequest(items=sec230_items(self.workspace), 
            case_id="CASE_ADV_SEC230",
            output_dir=out_dir,
            anonymize_victim_identity=True,
            victim_name=complex_victim_name
        )
        
        # Must execute cleanly without re.error or regex crash
        res = server.generate_sec230_bnss_report(req)
        self.assertTrue(res["success"])
        self.assertTrue(os.path.isdir(res["bundle_path"]))
        self.assertTrue(os.path.isfile(res["html_viewer_path"]))


if __name__ == "__main__":
    unittest.main()
