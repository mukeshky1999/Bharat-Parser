"""
Milestone 5 Adversarial Challenger Verification Suite.
Statutory Mandate: Section 63 BSA 2023 & Section 230 BNSS Compliant.

Verifies:
1. Complainant account normalization in NCRP freeze requisitions cannot be bypassed by custom candidates.
2. Hex window returns HTTP 412 when store is not loaded (and 403 on path traversals).
3. Myers redline diffing escapes all XSS payloads and preserves Indic/financial semantics.
"""

import asyncio
import hashlib
import html
import os
import shutil
import tempfile
import unittest
from fastapi import HTTPException

import parsers.api_server as server
from parsers.api_server import (
    ChatRedlineRequest,
    NcrpFreezeRequest,
    compute_chat_redline,
    generate_ncrp_freeze_report,
    get_hex_window,
    get_inspector_hex,
)
from parsers.ui_fts5_paginator import CaseUIPaginatorStore


class TestM5ChallengerAdversarial(unittest.TestCase):
    """Adversarial stress harness for Milestone 5 backend and E2E verification."""

    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp(prefix="m5_challenger_")
        cls.workspace = os.path.join(cls.test_dir, "case_workspace")
        os.makedirs(cls.workspace, exist_ok=True)
        cls.store = CaseUIPaginatorStore(case_workspace=cls.workspace, db_name="challenger_case.db")

        # Save initial global states
        cls._orig_store = server._active_store
        cls._orig_case_state = dict(server._case_state)

    @classmethod
    def tearDownClass(cls):
        server._active_store = cls._orig_store
        server._case_state = cls._orig_case_state
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def setUp(self):
        # Reset state to clean loaded case by default
        server._active_store = self.store
        server._case_state = {
            "loaded": True,
            "case_id": "M5_CHALLENGER_CASE",
            "case_name": "Empirical Challenge Verification",
            "evidence_path": self.workspace,
            "extractions": [],
            "counts": {},
            "owner_dossier": None,
            "hashes": {},
            "mule_alerts": [],
            "syndicate_roles": [],
            "device_metadata": {},
            "pyvis_html": "",
            "charge_sheet_chain": {},
        }

    # =========================================================================
    # Edge Case 1: Complainant Account Normalization in NCRP Freeze Requisitions
    # =========================================================================

    def test_ncrp_normalization_cannot_be_bypassed_by_custom_victim_flag_false(self):
        """Adversary provides candidate with victim account number but sets is_complainant_victim=False."""
        victim_acc = "VICTIM_ACCOUNT_7788"
        custom_candidates = [
            {
                "account_no": victim_acc,
                "ifsc": "HDFC0001234",
                "vpa": "victim@okhdfc",
                "is_complainant_victim": False,  # Adversarial attempt to freeze victim
                "volume_inr": 750000.0,
            },
            {
                "account_no": "MULE_ACCOUNT_1122",
                "ifsc": "SBIN0005678",
                "vpa": "mule@oksbi",
                "is_complainant_victim": False,
                "volume_inr": 720000.0,
            },
        ]

        req = NcrpFreezeRequest(
            case_id="M5_CHALLENGE_NCRP",
            acknowledgement_no="NCRP-CHALLENGE-001",
            complainant_account=victim_acc,
            candidates=custom_candidates,
            output_dir=self.workspace,
        )

        res = generate_ncrp_freeze_report(req)
        self.assertTrue(res["success"])

        # Check safeguards list returned
        safeguards = {s["account_no"]: s for s in res["safeguards"]}
        self.assertIn(victim_acc, safeguards)
        victim_safeguard = safeguards[victim_acc]
        self.assertTrue(victim_safeguard["is_victim"])
        self.assertTrue(victim_safeguard["is_freeze_locked"])
        self.assertTrue(victim_safeguard["freeze_checkbox_disabled"])
        self.assertIn("VICTIM", victim_safeguard["role_badge"])

        # Check that victim account was NOT counted in total freeze targets
        self.assertEqual(res["total_freeze_targets"], 1)
        self.assertEqual(res["total_lien_amount_inr"], 720000.0)

        # Check CSV content strictly omits victim account
        csv_text = res["csv_content"]
        lines = csv_text.strip().split("\n")
        self.assertEqual(len(lines), 2)  # Header + 1 mule row
        self.assertNotIn("VICTIM_ACCOUNT_7788", lines[1].split(",")[2])
        self.assertEqual(lines[1].split(",")[2], "MULE_ACCOUNT_1122")

    def test_ncrp_normalization_whitespace_and_type_coercion_bypass(self):
        """Adversary attempts bypass using leading/trailing whitespaces or integer types."""
        cases = [
            # (complainant_account, candidate_account_no)
            ("987654321098", "  987654321098  "),
            ("  987654321098  ", "987654321098"),
            ("987654321098", 987654321098),
            ("123456789012", "123456789012\t\n"),
        ]

        for idx, (comp_acc, cand_acc) in enumerate(cases):
            custom_candidates = [
                {
                    "account_no": cand_acc,
                    "ifsc": "ICIC0001111",
                    "vpa": f"user_{idx}@icici",
                    "is_complainant_victim": False,
                    "volume_inr": 100000.0,
                },
                {
                    "account_no": "REAL_MULE_9999",
                    "ifsc": "KKBK0002222",
                    "vpa": "mule@kotak",
                    "is_complainant_victim": False,
                    "volume_inr": 90000.0,
                },
            ]

            req = NcrpFreezeRequest(acknowledgement_no="NCRP-TEST-001", 
                case_id=f"M5_NCRP_WS_{idx}",
                complainant_account=comp_acc,
                candidates=custom_candidates,
                output_dir=self.workspace,
            )

            res = generate_ncrp_freeze_report(req)
            self.assertTrue(res["success"])

            # Verify that the candidate account was normalized and locked
            matched_safeguards = [
                s for s in res["safeguards"]
                if str(s["account_no"]).strip() == str(cand_acc).strip()
            ]
            self.assertEqual(len(matched_safeguards), 1)
            self.assertTrue(matched_safeguards[0]["is_victim"])
            self.assertTrue(matched_safeguards[0]["is_freeze_locked"])
            self.assertTrue(matched_safeguards[0]["freeze_checkbox_disabled"])

            # Ensure victim account was excluded from CSV freeze actions
            csv_lines = [l for l in res["csv_content"].splitlines() if l.strip()]
            for row in csv_lines[1:]:
                fields = row.split(",")
                self.assertNotEqual(fields[2].strip(), str(cand_acc).strip())
                self.assertEqual(fields[2].strip(), "REAL_MULE_9999")

    def test_ncrp_multiple_matching_candidates_all_locked(self):
        """Adversary submits multiple candidate accounts sharing the complainant number."""
        victim_acc = "COMPLAINANT_REPEATED_3344"
        custom_candidates = [
            {"account_no": victim_acc, "ifsc": "HDFC0001", "vpa": "v1@hdfc", "is_complainant_victim": False, "volume_inr": 50000.0},
            {"account_no": victim_acc, "ifsc": "HDFC0002", "vpa": "v2@hdfc", "is_complainant_victim": False, "volume_inr": 60000.0},
            {"account_no": "MULE_LEGIT_123", "ifsc": "SBIN0001", "vpa": "m@sbi", "is_complainant_victim": False, "volume_inr": 40000.0},
        ]
        req = NcrpFreezeRequest(acknowledgement_no="NCRP-TEST-001", 
            case_id="M5_NCRP_MULTI",
            complainant_account=victim_acc,
            candidates=custom_candidates,
            output_dir=self.workspace,
        )
        res = generate_ncrp_freeze_report(req)
        self.assertTrue(res["success"])
        self.assertEqual(res["total_freeze_targets"], 1)
        self.assertEqual(res["total_lien_amount_inr"], 40000.0)

        locked = [s for s in res["safeguards"] if s["is_freeze_locked"]]
        self.assertEqual(len(locked), 2)
        for s in locked:
            self.assertEqual(s["account_no"], victim_acc)
            self.assertTrue(s["freeze_checkbox_disabled"])

    def test_ncrp_malformed_and_boundary_candidates(self):
        """Stress-tests missing, None, and empty fields in freeze candidate objects."""
        custom_candidates = [
            {"account_no": None, "ifsc": "HDFC0001", "vpa": "none@hdfc", "volume_inr": 1000.0},
            {"ifsc": "HDFC0002", "vpa": "missing_acc@hdfc", "volume_inr": 2000.0},
            {"account_no": "", "ifsc": "HDFC0003", "vpa": "empty_acc@hdfc", "volume_inr": 3000.0},
            {"account_no": "VALID_MULE_001", "ifsc": "ICIC0001", "vpa": "mule1@icici", "volume_inr": 50000.0},
        ]
        req = NcrpFreezeRequest(acknowledgement_no="NCRP-TEST-001", 
            case_id="M5_NCRP_MALFORMED",
            complainant_account="VICTIM_MAIN",
            candidates=custom_candidates,
            output_dir=self.workspace,
        )
        res = generate_ncrp_freeze_report(req)
        self.assertTrue(res["success"])
        self.assertEqual(res["total_accounts_evaluated"], 4)

    def test_ncrp_utility_billers_auto_exclusion(self):
        """Verifies statutory exclusion of utility billers (BESCOM, IRCTC, BILLDESK) from freeze requisitions."""
        custom_candidates = [
            {"account_no": "BESCOM_BANGALORE_ELECTRIC", "ifsc": "SBIN0001", "vpa": "bescom.bills@icici", "volume_inr": 1200.0},
            {"account_no": "IRCTC_TICKETING_ESCROW", "ifsc": "SBIN0002", "vpa": "irctc@sbi", "volume_inr": 4500.0},
            {"account_no": "REAL_MULE_FRAUDULENT", "ifsc": "PUNB0001", "vpa": "fraud@pnb", "volume_inr": 250000.0},
        ]
        req = NcrpFreezeRequest(acknowledgement_no="NCRP-TEST-001", 
            case_id="M5_NCRP_UTILITY",
            complainant_account="VICTIM_ACCOUNT_99",
            candidates=custom_candidates,
            output_dir=self.workspace,
        )
        res = generate_ncrp_freeze_report(req)
        self.assertTrue(res["success"])
        # Only the real mule should be targeted for debit freeze
        self.assertEqual(res["total_freeze_targets"], 1)
        self.assertEqual(res["total_lien_amount_inr"], 250000.0)

        # Utility accounts must NOT appear in generated CSV rows
        csv_rows = res["csv_content"].strip().split("\n")
        self.assertEqual(len(csv_rows), 2)  # Header + 1 real mule
        self.assertIn("REAL_MULE_FRAUDULENT", csv_rows[1])
        self.assertNotIn("BESCOM", csv_rows[1])
        self.assertNotIn("IRCTC", csv_rows[1])

    # =========================================================================
    # Edge Case 2: Hex Window Returns HTTP 412 When Store Is Not Loaded
    # =========================================================================

    def test_hex_inspector_endpoint_raises_412_when_store_is_none(self):
        """Direct test of /api/inspector/hex when _active_store is None."""
        server._active_store = None
        try:
            with self.assertRaises(HTTPException) as ctx:
                get_inspector_hex(file_path=os.path.join(self.workspace, "dummy.bin"), offset=0)
            self.assertEqual(ctx.exception.status_code, 412)
            self.assertIn("Precondition Failed: No forensic case is currently loaded", ctx.exception.detail)
        finally:
            server._active_store = self.store

    def test_case_hex_window_endpoint_raises_412_when_case_not_loaded(self):
        """Direct test of /api/case/hex-window when _case_state['loaded'] is False."""
        server._case_state["loaded"] = False
        try:
            with self.assertRaises(HTTPException) as ctx:
                coro = get_hex_window(file_path=os.path.join(self.workspace, "dummy.bin"), offset=0, window_size=4096)
                coro.send(None)
            self.assertEqual(ctx.exception.status_code, 412)
            self.assertIn("Precondition Failed: No forensic case is currently loaded", ctx.exception.detail)
        finally:
            server._case_state["loaded"] = True

    def test_hex_window_path_traversal_blocking_403(self):
        """Verifies get_hex_window strictly denies path traversals with HTTP 403."""
        traversal_attempts = [
            "../../etc/shadow",
            r"..\..\Windows\win.ini",
            "..",
            r"C:\Windows\System32\cmd.exe",
            r"\\127.0.0.1\c$\bootmgr",
        ]
        for bad_path in traversal_attempts:
            with self.assertRaises(HTTPException) as ctx:
                coro = get_hex_window(file_path=bad_path, offset=0)
                coro.send(None)
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertIn("Access Denied", ctx.exception.detail)

    def test_hex_window_valid_read_when_case_is_loaded(self):
        """Verifies hex extraction succeeds and verifies SHA-256 and 4KB windowing when loaded."""
        test_file = os.path.join(self.workspace, "target_forensic.bin")
        test_data = b"FORENSIC_HEADER_" + (b"\xaa\xbb\xcc\xdd" * 2048)  # 8208 bytes
        with open(test_file, "wb") as f:
            f.write(test_data)

        res = get_inspector_hex(file_path=test_file, offset=64, window_size=4096)
        self.assertTrue(res["success"])
        self.assertEqual(res["target_offset"], 64)
        self.assertGreater(len(res["hex_lines"]), 0)

        # Verify raw_hex matches SHA-256
        raw_bytes = bytes.fromhex(res["raw_hex"])
        expected_sha = hashlib.sha256(raw_bytes).hexdigest()
        self.assertEqual(res["sha256"], expected_sha)

    # =========================================================================
    # Edge Case 3: Myers Redline Diffing Escapes XSS Payloads
    # =========================================================================

    def test_myers_redline_diffing_escapes_xss_payloads(self):
        """Exhaustive test of adversarial XSS injection payloads into compute_chat_redline."""
        adversarial_vectors = [
            # Standard tags
            ("<script>alert('XSS_ATTACK_1')</script>", "Safe replacement"),
            ("Normal original text", "<script src='https://evil.attacker/xss.js'></script>"),
            # Image & media event handlers
            ("<img src=x onerror=alert('IMG_XSS')>", "<svg onload=alert('SVG_XSS')>"),
            ("<body onload=alert('BODY_XSS')>", "<iframe src='javascript:alert(1)'></iframe>"),
            # Input and autofocus triggers
            ("<input type='text' autofocus onfocus='alert(1)'>", "<video><source onerror='alert(2)'></video>"),
            # Broken / malformed tags designed to bypass regex sanitizers
            ("<<SCRIPT>alert('BROKEN')//<</SCRIPT>", "<svg/onload=confirm('MALFORMED')>"),
            ("<a href=\"javascript:alert('CLICK_XSS')\">Click here</a>", "<details open ontoggle=alert(1)>"),
            # Polyglots and entities
            ("jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a", "<div><span>safe</span></div>"),
            ("₹50000 sent to victim", "<script>alert('₹50000 stolen')</script> @mule_upi"),
        ]

        for orig, edit in adversarial_vectors:
            req = ChatRedlineRequest(original_text=orig, edited_text=edit)
            res = compute_chat_redline(req)
            self.assertTrue(res.success)

            markup = res.rendered_markup

            # 1. Ensure no raw unescaped executable HTML tags exist in the output
            lower = markup.lower()
            raw_dangerous_tags = [
                "<script", "</script",
                "<img", "<svg", "<iframe",
                "<input", "<video", "<body",
                "<details", "<a ", "<form", "<style"
            ]
            for danger in raw_dangerous_tags:
                self.assertNotIn(danger, lower, f"Vulnerability detected! Found unescaped tag {danger} in: {markup}")

            # 2. Strict HTML escaping invariant:
            # When stripping authorized styling tags (<del>, </del>, <ins>, </ins>),
            # there must be ZERO '<' and ZERO '>' characters remaining in rendered_markup.
            stripped = (
                markup.replace("<del>", "")
                .replace("</del>", "")
                .replace("<ins>", "")
                .replace("</ins>", "")
            )
            self.assertNotIn("<", stripped, f"Unescaped '<' character found in markup: {markup}")
            self.assertNotIn(">", stripped, f"Unescaped '>' character found in markup: {markup}")

    def test_myers_redline_diffing_financial_token_detection_with_xss(self):
        """Ensures XSS payloads containing financial indicators detect financial tokens while escaping."""
        req = ChatRedlineRequest(
            original_text="Received ₹10,000 from victim",
            edited_text="Transferred ₹50,000 to <script>alert('MULE')</script> at mule@okhdfc",
        )
        res = compute_chat_redline(req)
        self.assertTrue(res.success)
        self.assertTrue(res.has_financial_or_crypto_token)
        self.assertNotIn("<script>", res.rendered_markup)
        self.assertIn("&lt;script&gt;", res.rendered_markup)
        self.assertIn("&lt;/script&gt;", res.rendered_markup)

    def test_myers_redline_indic_and_emoji_with_financial_detection(self):
        """Ensures Hindi / Indic scripts and emojis are preserved and diffed accurately."""
        orig = "मैंने ₹50,000 ट्रांसफ़र किए थे 💸🏦"
        edit = "मैंने ₹75,000 ट्रांसफ़र किए थे 💰🏦"
        req = ChatRedlineRequest(original_text=orig, edited_text=edit)
        res = compute_chat_redline(req)
        self.assertTrue(res.success)
        self.assertTrue(res.has_financial_or_crypto_token)
        self.assertIn("मैंने", res.rendered_markup)
        self.assertIn("<del>₹50,000</del><ins>₹75,000</ins>", res.rendered_markup)
        self.assertIn("<del>💸🏦</del><ins>💰🏦</ins>", res.rendered_markup)


if __name__ == "__main__":
    unittest.main()
