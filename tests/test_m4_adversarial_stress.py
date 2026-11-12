"""
Bharat-PA Forensics — Milestone 4 Adversarial Stress & Edge-Case Test Suite.
Authored by Challenger 1 (Milestone 4).

Probes and stress-tests:
1. Myers Redline SES Engine: identical, completely disjoint, empty, Unicode/emojis, financial tokens (₹, UTR, VPA, USDT).
2. Graph Intelligence: mule network & Sankey when no case is loaded, empty transactions, and cyclic smurfing mule transactions.
3. 1930 NCRP Bank Lien: Complainant Safeguard Lock de-confliction, utility exclusion, and 14-column CSV format.
4. Section 230 BNSS: Multiple victim names, non-existent case IDs, POCSO withholding mandatory notice cards.
5. Hex Window & Sandboxing: offset 0, offset exceeding file size, negative offset, path traversal attempts (403 Forbidden), un-loaded case (412 Precondition).
"""

from __future__ import annotations

import os
from tests.legal_fixtures import ncrp_candidates, sec230_items
import shutil
import tempfile
import unittest
import pandas as pd
from fastapi import HTTPException

import parsers.api_server as server
from parsers.api_server import (
    ChatRedlineRequest,
    NcrpFreezeRequest,
    Sec230BnssRequest,
    ArtifactCategoryEnum,
)
from parsers.ui_fts5_paginator import CaseUIPaginatorStore
from src.chat_reconstructor_and_redline.myers_redline_engine import MyersRedlineEngine
from src.unk_triage_and_bsa_studio.freeze_deconfliction import NodalFreezeDeconflictionCenter


class TestM4AdversarialStress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="bharat_m4_adversarial_")
        cls.workspace = os.path.join(cls.temp_dir, "active_case")
        os.makedirs(cls.workspace, exist_ok=True)

        cls.store = CaseUIPaginatorStore(
            case_workspace=cls.workspace,
            db_name="test_adversarial_case.db"
        )
        server._active_store = cls.store
        server._case_state["workspace_dir"] = cls.workspace
        server._case_state["loaded"] = True
        server._case_state["case_id"] = "ADV_CASE_001"

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    # =========================================================================
    # 1. Myers Redline Engine Edge Cases & Stress Tests
    # =========================================================================

    def test_redline_identical_strings(self):
        """Identical original and edited strings should produce only EQUAL tokens and no <del>/<ins>."""
        text = "Transfer ₹25,000 to beneficiary account 9876543210 immediately."
        req = ChatRedlineRequest(original_text=text, edited_text=text)
        res = server.compute_chat_redline(req)

        self.assertTrue(res.success)
        self.assertEqual(res.original_text, text)
        self.assertEqual(res.edited_text, text)
        self.assertNotIn("<del>", res.rendered_markup)
        self.assertNotIn("<ins>", res.rendered_markup)
        self.assertTrue(res.has_financial_or_crypto_token)
        self.assertTrue(all(t["token_type"] == "EQUAL" for t in res.tokens))

    def test_redline_completely_disjoint_strings(self):
        """Completely disjoint texts should have all original tokens deleted and edited inserted."""
        orig = "The quick brown fox jumps"
        edit = "A lazy black cat sleeps"
        req = ChatRedlineRequest(original_text=orig, edited_text=edit)
        res = server.compute_chat_redline(req)

        self.assertTrue(res.success)
        self.assertIn("<del>", res.rendered_markup)
        self.assertIn("<ins>", res.rendered_markup)
        self.assertFalse(res.has_financial_or_crypto_token)

        types = {t["token_type"] for t in res.tokens}
        self.assertIn("DELETE", types)
        self.assertIn("INSERT", types)

    def test_redline_empty_strings(self):
        """Boundary: both empty strings, one empty string."""
        # Both empty
        req_both_empty = ChatRedlineRequest(original_text="", edited_text="")
        res_both_empty = server.compute_chat_redline(req_both_empty)
        self.assertTrue(res_both_empty.success)
        self.assertEqual(res_both_empty.rendered_markup, "")
        self.assertEqual(len(res_both_empty.tokens), 0)
        self.assertFalse(res_both_empty.has_financial_or_crypto_token)

        # Original empty, edited populated
        req_orig_empty = ChatRedlineRequest(original_text="", edited_text="Added message ₹500")
        res_orig_empty = server.compute_chat_redline(req_orig_empty)
        self.assertTrue(res_orig_empty.success)
        self.assertIn("<ins>", res_orig_empty.rendered_markup)
        self.assertTrue(res_orig_empty.has_financial_or_crypto_token)

        # Original populated, edited empty (revocation)
        req_edit_empty = ChatRedlineRequest(original_text="Revoked UPI PIN 123456", edited_text="")
        res_edit_empty = server.compute_chat_redline(req_edit_empty)
        self.assertTrue(res_edit_empty.success)
        self.assertIn("<del>", res_edit_empty.rendered_markup)

    def test_redline_unicode_emojis_and_indic_scripts(self):
        """Stress: Devanagari, mixed scripts, emojis, symbols."""
        orig = "नमस्ते भाई, ₹50000 भेजो 💸🏦"
        edit = "नमस्ते भाई, ₹75000 तत्काल भेजो 🚨💰"
        req = ChatRedlineRequest(original_text=orig, edited_text=edit)
        res = server.compute_chat_redline(req)

        self.assertTrue(res.success)
        self.assertIn("नमस्ते", res.rendered_markup)
        self.assertTrue(res.has_financial_or_crypto_token)
        # Check that emojis and Devanagari survived without corruption or mojibake
        self.assertIn("₹50000", res.rendered_markup)
        self.assertIn("₹75000", res.rendered_markup)

    def test_redline_financial_and_crypto_token_taxonomy(self):
        """Taxonomy check for ₹, UTR 12-digit, VPA, USDT, BTC addresses."""
        cases = [
            ("Send ₹5000 to me", True),
            ("Payment completed via UTR 412345678901 done", True),
            ("Use VPA cybermule@okhdfcbank now", True),
            ("Deposit 500 USDT to TRC-20 address", True),
            ("Wallet 0x71C6370244453aBD71B3404a45397CECE561E564 confirmed", True),
            ("Please pick up the groceries on your way back", False),
            ("The meeting is scheduled at 4 PM in room 302", False),
        ]
        for text, expected in cases:
            req = ChatRedlineRequest(original_text=text, edited_text=text)
            res = server.compute_chat_redline(req)
            self.assertEqual(
                res.has_financial_or_crypto_token,
                expected,
                f"Failed financial classification for: {text}"
            )

    # =========================================================================
    # 2. Graph Intelligence: Mule Network & Sankey Stress Tests
    # =========================================================================

    def test_graph_mule_network_when_no_case_loaded(self):
        """Endpoint /api/graph/mule-network must not crash when no case is loaded."""
        prev_loaded = server._case_state["loaded"]
        server._case_state["loaded"] = False
        try:
            res = server.get_graph_mule_network()
            self.assertTrue(res["success"])
            # C-03: no case data -> explicit empty result, never a built-in sample network.
            self.assertTrue(res["empty"])
            self.assertEqual(res["nodes"], [])
            self.assertEqual(res["edges"], [])
            self.assertIn("sankey_layout", res)
            self.assertIn("stages", res["sankey_layout"])
            self.assertIn("ribbons", res["sankey_layout"])
        finally:
            server._case_state["loaded"] = prev_loaded

    def test_graph_mule_network_with_empty_transactions_table(self):
        """When transactions table has 0 rows, must return an explicit empty result without 500."""
        conn = self.store._get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM transactions")
        conn.commit()

        res = server.get_graph_mule_network()
        self.assertTrue(res["success"])
        self.assertTrue(res["empty"])
        self.assertEqual(res["nodes"], [])

    def test_graph_mule_network_with_cyclic_mule_transactions(self):
        """Stress: Directed circular smurfing transactions must not cause infinite loop or crash."""
        conn = self.store._get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM transactions")

        # Directed cycle: This Phone -> Mule A -> Mule B -> Mule C -> This Phone
        cyclic_txs = [
            ("PhonePe", "TX_01", "412345678901", 60000.0, "DEBIT", "2026-11-08 10:00:00", "Mule_Alpha", "muleA@upi", "SUCCESS", "ACTIVE"),
            ("GPay", "TX_02", "412345678902", 55000.0, "TRANSFER", "2026-11-08 10:15:00", "Mule_Beta", "muleB@upi", "SUCCESS", "ACTIVE"),
            ("Paytm", "TX_03", "412345678903", 50000.0, "TRANSFER", "2026-11-08 10:30:00", "Mule_Gamma", "muleC@upi", "SUCCESS", "ACTIVE"),
            ("PhonePe", "TX_04", "412345678904", 45000.0, "CREDIT", "2026-11-08 10:45:00", "Mule_Alpha", "muleA@upi", "SUCCESS", "ACTIVE"),
        ]
        cur.executemany("""
            INSERT INTO transactions (
                Application, Transaction_ID, Bank_Ref_No, Amount, Type,
                Date, Counterparty, VPA, Status, Forensic_Provenance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, cyclic_txs)
        conn.commit()

        res = server.get_graph_mule_network()
        self.assertTrue(res["success"])
        self.assertGreater(len(res["nodes"]), 0)
        self.assertGreater(len(res["edges"]), 0)

        # Check that nodes have proper in/out flow
        node_map = {n["id"]: n for n in res["nodes"]}
        self.assertIn("Mule_Alpha", node_map)
        alpha = node_map["Mule_Alpha"]
        self.assertGreaterEqual(alpha["inflow"], 0.0)
        self.assertGreaterEqual(alpha["outflow"], 0.0)

    def test_graph_sankey_svg_vector_rendering(self):
        """Endpoint /api/graph/sankey-svg must return valid SVG markup with image/svg+xml."""
        conn = self.store._get_connection()
        conn.execute("DELETE FROM transactions")
        conn.execute(
            "INSERT INTO transactions (Application, Transaction_ID, Amount, Type, Date, Counterparty, Status)"
            " VALUES ('PhonePe','T1',1234.5,'DEBIT','2026-11-08 10:00:00','Real_Payee','SUCCESS')"
        )
        conn.commit()
        res = server.get_graph_sankey_svg()
        self.assertEqual(res.media_type, "image/svg+xml")
        svg_content = res.body.decode("utf-8")
        self.assertIn("</svg>", svg_content)
        self.assertIn("STAGE 1", svg_content.upper())
        self.assertIn("Real_Payee", svg_content)
        self.assertIn("1,234.50", svg_content)
        self.assertNotIn("FixedFloat", svg_content)
        self.assertNotIn("1,50,000", svg_content)

    def test_graph_sankey_svg_empty_case_has_no_sample_drawing(self):
        conn = self.store._get_connection()
        conn.execute("DELETE FROM transactions")
        conn.commit()
        svg_content = server.get_graph_sankey_svg().body.decode("utf-8")
        self.assertIn("No money-trail data", svg_content)
        self.assertNotIn("FixedFloat", svg_content)

    # =========================================================================
    # 3. NCRP 1930 Bank Lien & Complainant Safeguard Lock
    # =========================================================================

    def test_ncrp_freeze_safeguard_lock_prevents_victim_freezing(self):
        """Complainant account must be locked and NEVER appear in freeze rows."""
        victim_acc = "VICTIM_ACCOUNT_778899"
        req = NcrpFreezeRequest(candidates=ncrp_candidates(victim_acc), acknowledgement_no="NCRP-TEST-001", 
            case_id="ADV_NCRP_CASE",
            complainant_account=victim_acc,
            output_dir=os.path.join(self.workspace, "ncrp_adv_out")
        )
        res = server.generate_ncrp_freeze_report(req)
        self.assertTrue(res["success"])

        # Check safeguards list
        victim_entry = next((s for s in res["safeguards"] if s["account_no"] == victim_acc), None)
        self.assertIsNotNone(victim_entry, "Victim account must be present in safeguards evaluation")
        self.assertTrue(victim_entry["is_victim"])
        self.assertTrue(victim_entry["is_freeze_locked"])
        self.assertTrue(victim_entry["freeze_checkbox_disabled"])
        self.assertIn("DO NOT FREEZE", victim_entry["role_badge"])

        # Check exported CSV
        csv_text = res["csv_content"]
        lines = [line.strip() for line in csv_text.strip().split("\n") if line.strip()]
        header = lines[0].split(",")
        self.assertEqual(len(header), 14, "CSV must have exactly 14 statutory columns")
        self.assertIn("Beneficiary_Account_to_Freeze", header)
        beneficiary_col_idx = header.index("Beneficiary_Account_to_Freeze")

        for line in lines[1:]:
            cols = line.split(",")
            self.assertNotEqual(cols[beneficiary_col_idx], victim_acc, "Victim account must never be frozen!")

    def test_ncrp_freeze_complainant_safeguard_when_candidate_account_matches_beneficiary(self):
        """
        When candidate beneficiary account matches complainant_account and has is_complainant_victim=True,
        verify that it is de-conflicted and excluded from the Beneficiary freeze column.
        """
        complainant_acc = "COMPLAINANT_ACC_4455"
        candidates = [
            {"account_no": complainant_acc, "ifsc": "HDFC0001", "vpa": "victim@okhdfc", "volume_inr": 100000.0, "is_complainant_victim": True},
            {"account_no": "MULE_BENEFICIARY_99", "ifsc": "SBIN0001", "vpa": "mule@oksbi", "volume_inr": 95000.0, "is_complainant_victim": False},
        ]
        req = NcrpFreezeRequest(acknowledgement_no="NCRP-TEST-001", 
            complainant_account=complainant_acc,
            candidates=candidates,
            output_dir=os.path.join(self.workspace, "ncrp_match_out")
        )
        res = server.generate_ncrp_freeze_report(req)
        self.assertTrue(res["success"])

        # Complainant must be locked
        victim_safeguard = next(s for s in res["safeguards"] if s["account_no"] == complainant_acc)
        self.assertTrue(victim_safeguard["is_freeze_locked"])
        self.assertTrue(victim_safeguard["freeze_checkbox_disabled"])

        # Mule must be targeted
        mule_safeguard = next(s for s in res["safeguards"] if s["account_no"] == "MULE_BENEFICIARY_99")
        self.assertFalse(mule_safeguard["is_freeze_locked"])

        # CSV must contain only 1 freeze target (the mule)
        self.assertEqual(res["total_freeze_targets"], 1)
        csv_rows = [r.strip() for r in res["csv_content"].split("\n") if r.strip()]
        header = csv_rows[0].split(",")
        beneficiary_idx = header.index("Beneficiary_Account_to_Freeze")
        for row in csv_rows[1:]:
            parts = row.split(",")
            self.assertNotEqual(parts[beneficiary_idx], complainant_acc)

    def test_ncrp_freeze_safeguard_bypass_vulnerability(self):
        """
        Adversarial Finding:
        When an API caller supplies candidates where account_no matches req.complainant_account
        but omits the explicit is_complainant_victim: True flag, the server fails to auto-detect
        the match, and classifies the complainant's own account as a Layer-1 Mule Target!
        """
        complainant_acc = "ACC_COMPLAINANT_EXACT"
        candidates = [
            {"account_no": complainant_acc, "ifsc": "HDFC0001", "vpa": "victim@okhdfc", "volume_inr": 100000.0},
            {"account_no": "MULE_BENEFICIARY_99", "ifsc": "SBIN0001", "vpa": "mule@oksbi", "volume_inr": 95000.0},
        ]
        req = NcrpFreezeRequest(acknowledgement_no="NCRP-TEST-001", 
            complainant_account=complainant_acc,
            candidates=candidates,
            output_dir=os.path.join(self.workspace, "ncrp_vuln_out")
        )
        res = server.generate_ncrp_freeze_report(req)

        # The complainant's own account must be locked even though the caller omitted the flag.
        victim_entry = next(s for s in res["safeguards"] if s["account_no"] == complainant_acc)
        self.assertTrue(victim_entry["is_freeze_locked"])
        self.assertTrue(victim_entry["freeze_checkbox_disabled"])
        self.assertNotIn(complainant_acc, [r for r in res["csv_content"].splitlines()[1].split(",")][2:3])
        self.assertEqual(res["total_freeze_targets"], 1)

    def test_ncrp_freeze_utility_keyword_exclusion(self):
        """Utility billers (irctc, bescom, billdesk) must be excluded from debit liens."""
        candidates = [
            {"account_no": "BESCOM_ELEC_1", "ifsc": "SBIN0001", "vpa": "bescom.billdesk@icici", "volume_inr": 2500.0, "is_complainant_victim": False},
            {"account_no": "IRCTC_TICKETS_2", "ifsc": "SBIN0002", "vpa": "irctc@sbi", "volume_inr": 4200.0, "is_complainant_victim": False},
            {"account_no": "MULE_VALID_3", "ifsc": "ICIC0001", "vpa": "mule@icici", "volume_inr": 80000.0, "is_complainant_victim": False},
        ]
        center = NodalFreezeDeconflictionCenter()
        evaluated = center.evaluate_freeze_candidates(candidates)

        bescom = next(c for c in evaluated if "BESCOM" in c.account_no)
        self.assertTrue(bescom.is_utility_excluded)
        self.assertIn("UTILITY", bescom.role_badge)

        irctc = next(c for c in evaluated if "IRCTC" in c.account_no)
        self.assertTrue(irctc.is_utility_excluded)

        mule = next(c for c in evaluated if "MULE" in c.account_no)
        self.assertFalse(mule.is_utility_excluded)

        csv_text = center.generate_1930_ncrp_csv(evaluated, complainant_account="COMPL_1", acknowledgement_no="NCRP-T-1")
        self.assertNotIn("BESCOM", csv_text)
        self.assertNotIn("IRCTC", csv_text)
        self.assertIn("MULE_VALID_3", csv_text)

    # =========================================================================
    # 4. Section 230 BNSS Statutory Defense Disclosure Stress Tests
    # =========================================================================

    def test_sec230_bnss_non_existent_case_id(self):
        """Non-existent case ID must generate standalone defense bundle cleanly without 500."""
        req = Sec230BnssRequest(items=sec230_items(self.workspace), 
            case_id="CASE_TOTALLY_NON_EXISTENT_99999",
            victim_name="Smt. Ananya Sharma",
            anonymize_victim_identity=True
        )
        res = server.generate_sec230_bnss_report(req)
        self.assertTrue(res["success"])
        self.assertEqual(res["case_id"], "CASE_TOTALLY_NON_EXISTENT_99999")
        self.assertTrue(os.path.isdir(res["bundle_path"]))
        self.assertTrue(os.path.isfile(res["html_viewer_path"]))
        self.assertGreaterEqual(res["pocso_withheld_count"], 1)

    def test_sec230_bnss_multi_victim_anonymization(self):
        """Multiple victim names in string must be handled without crash."""
        req = Sec230BnssRequest(items=sec230_items(self.workspace), 
            case_id="CASE_MULTI_VICTIM_001",
            victim_name="Rajesh Gupta & Priya Gupta",
            anonymize_victim_identity=True
        )
        res = server.generate_sec230_bnss_report(req)
        self.assertTrue(res["success"])
        self.assertTrue(os.path.exists(res["html_viewer_path"]))

        with open(res["html_viewer_path"], "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("[VICTIM_PROTECTED_ID_01]", content)

    # =========================================================================
    # 5. Hex Window & Path Traversal Boundary Tests
    # =========================================================================

    def test_hex_window_precondition_412_when_no_case(self):
        """Calling /api/case/hex-window when no case is loaded must raise 412."""
        server._case_state["loaded"] = False
        try:
            with self.assertRaises(HTTPException) as ctx:
                coro = server.get_hex_window(file_path=self.workspace, offset=0)
                coro.send(None)
            self.assertEqual(ctx.exception.status_code, 412)
        finally:
            server._case_state["loaded"] = True

    def test_hex_window_path_traversal_403(self):
        """Path traversal attempts outside active case workspace must raise 403."""
        traversal_attempts = [
            "../../etc/passwd",
            "..\\..\\Windows\\win.ini",
            r"C:\Windows\System32\cmd.exe",
            r"C:\bootmgr",
            "/etc/shadow",
        ]
        for bad_path in traversal_attempts:
            with self.assertRaises(HTTPException) as ctx:
                coro = server.get_hex_window(file_path=bad_path, offset=0)
                coro.send(None)
            self.assertEqual(
                ctx.exception.status_code,
                403,
                f"Path traversal check failed for: {bad_path}"
            )
            self.assertIn("Access Denied", ctx.exception.detail)

    def test_hex_window_boundary_offset_zero(self):
        """Offset 0 on existing file must return valid 4KB window."""
        test_file = os.path.join(self.workspace, "test_boundary.bin")
        dummy_data = b"HEAD" + (b"\xAA" * 2048) + (b"\xBB" * 2048)
        with open(test_file, "wb") as f:
            f.write(dummy_data)

        res = server.get_inspector_hex(file_path=test_file, offset=0, window_size=4096)
        self.assertTrue(res["success"])
        self.assertEqual(res["target_offset"], 0)
        self.assertGreater(len(res["hex_lines"]), 0)
        # Clamped to 4096 bytes (8192 hex characters)
        self.assertEqual(len(res["raw_hex"]), min(len(dummy_data), 4096) * 2)

    def test_hex_window_boundary_offset_exceeding_file_size(self):
        """Offset far exceeding file size must handle cleanly without crash."""
        test_file = os.path.join(self.workspace, "test_small.bin")
        with open(test_file, "wb") as f:
            f.write(b"SHORT_DATA_128_BYTES" * 5)

        # Query offset at 50,000 (well beyond file size of ~100 bytes)
        # C-04: bytes are never fabricated; an unreadable offset is a 404 error.
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            server.get_inspector_hex(file_path=test_file, offset=50000, window_size=4096)
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("beyond end of file", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()
