"""
Unit Tests for tools/forensic_benchmark_recorder.py
Tests the 5-Stage Forensic Diagnostic Pipeline, PII Sanitization,
Container Ingestion, Differential Audit, and Report Generation.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile
from typing import Dict, Any

from tools.forensic_benchmark_recorder import (
    ForensicBenchmarkRecorder,
    mask_phone_number,
    mask_vpa_address,
    sanitize_dict_or_list,
    sanitize_pii,
)


class TestPIISanitization(unittest.TestCase):
    """Verifies strict privacy preservation and PII masking."""

    def test_mask_phone_number(self):
        # 10-digit Indian numbers with and without +91 prefix
        self.assertEqual(mask_phone_number("+91 9876543210"), "+91 98XXXXXX10")
        self.assertEqual(mask_phone_number("+91-9876543210"), "+91-98XXXXXX10")
        self.assertEqual(mask_phone_number("9876543210"), "98XXXXXX10")
        self.assertEqual(mask_phone_number("8888888888"), "88XXXXXX88")

        # Non-phone string
        self.assertEqual(mask_phone_number("hello_world"), "hello_world")
        self.assertEqual(mask_phone_number(""), "")

    def test_mask_vpa_address(self):
        self.assertEqual(mask_vpa_address("user123@oksbi"), "us***@oksbi")
        self.assertEqual(mask_vpa_address("merchant.fraud@ybl"), "me***@ybl")
        self.assertEqual(mask_vpa_address("ab@paytm"), "ab***@paytm")
        self.assertEqual(mask_vpa_address("a@upi"), "a***@upi")
        self.assertEqual(mask_vpa_address("not_a_vpa"), "not_a_vpa")

    def test_sanitize_pii(self):
        # Aadhaar numbers (with spaces, hyphens, or contiguous)
        text_with_aadhaar = "Suspect Aadhaar is 1234 5678 9012 and alternate 9876-5432-1098 or 112233445566."
        sanitized = sanitize_pii(text_with_aadhaar)
        self.assertNotIn("1234 5678 9012", sanitized)
        self.assertNotIn("9876-5432-1098", sanitized)
        self.assertNotIn("112233445566", sanitized)
        self.assertIn("[Aadhaar Redacted]", sanitized)

        # Phone numbers inside text
        text_with_phone = "Contact suspect at +91 9876543210 or 8765432109 immediately."
        sanitized_phone = sanitize_pii(text_with_phone)
        self.assertNotIn("9876543210", sanitized_phone)
        self.assertNotIn("8765432109", sanitized_phone)
        self.assertIn("98XXXXXX10", sanitized_phone)
        self.assertIn("87XXXXXX09", sanitized_phone)

        # VPAs inside text
        text_with_vpa = "Money sent to victim.account@okhdfcbank via UPI."
        sanitized_vpa = sanitize_pii(text_with_vpa)
        self.assertNotIn("victim.account@okhdfcbank", sanitized_vpa)
        self.assertIn("vi***@okhdfcbank", sanitized_vpa)

    def test_sanitize_dict_or_list(self):
        raw_data = {
            "case_id": "CRIME-2026-99",
            "evidence": [
                {
                    "aadhaar": "4444 5555 6666",
                    "phone": "+91 9123456789",
                    "vpa": "scammer99@axl",
                    "nested": {
                        "secret_card": "1234-5678-9012",
                    }
                }
            ],
            "note": "Payment of 5000 sent from 9876543210 to test@upi",
        }

        sanitized = sanitize_dict_or_list(raw_data)
        serialized = json.dumps(sanitized)

        # Verify no sensitive PII leaked
        self.assertNotIn("4444 5555 6666", serialized)
        self.assertNotIn("1234-5678-9012", serialized)
        self.assertNotIn("9123456789", serialized)
        self.assertNotIn("9876543210", serialized)
        self.assertNotIn("scammer99@axl", serialized)

        # Verify redactions / masks present
        self.assertIn("[Aadhaar Redacted]", serialized)
        self.assertIn("91XXXXXX89", serialized)
        self.assertIn("98XXXXXX10", serialized)
        self.assertIn("sc***@axl", serialized)


class TestForensicBenchmarkPipeline(unittest.TestCase):
    """Verifies the 5-Stage Automated Benchmark and Compatibility Tester."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_benchmark_harness_")
        self.dump_zip_path = os.path.join(self.test_dir, "synthetic_evidence_dump.ufdr")
        self.output_dir = os.path.join(self.test_dir, "benchmark_output")

        # Build synthetic evidence container (.ufdr / .zip)
        self._build_synthetic_dump(self.dump_zip_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _build_synthetic_dump(self, zip_path: str):
        """Creates a realistic .ufdr container with WhatsApp, PhonePe, custom DB, and report.xml."""
        staging_dir = os.path.join(self.test_dir, "staging")
        os.makedirs(staging_dir, exist_ok=True)

        # 1. WhatsApp DB: msgstore.db
        wa_dir = os.path.join(staging_dir, "data", "data", "com.whatsapp", "databases")
        os.makedirs(wa_dir, exist_ok=True)
        wa_db = os.path.join(wa_dir, "msgstore.db")
        conn_wa = sqlite3.connect(wa_db)
        cur_wa = conn_wa.cursor()
        cur_wa.execute("""
            CREATE TABLE message (
                _id INTEGER PRIMARY KEY,
                key_remote_jid TEXT,
                key_from_me INTEGER,
                data TEXT,
                timestamp INTEGER
            )
        """)
        cur_wa.executemany(
            "INSERT INTO message VALUES (?, ?, ?, ?, ?)",
            [
                (1, "919876543210@s.whatsapp.net", 0, "Aadhaar is 1234 5678 9012 transfer fast", 1700000000000),
                (2, "919876543210@s.whatsapp.net", 1, "Send to scammer@ybl 5000 rs", 1700000010000),
                (3, "918765432109@s.whatsapp.net", 0, "Meeting at Connaught Place", 1700000020000),
            ]
        )
        conn_wa.commit()
        conn_wa.close()

        # 2. PhonePe DB: TransactionsStore.sqlite
        phonepe_dir = os.path.join(staging_dir, "data", "data", "com.phonepe.app", "databases")
        os.makedirs(phonepe_dir, exist_ok=True)
        ppe_db = os.path.join(phonepe_dir, "TransactionsStore.sqlite")
        conn_ppe = sqlite3.connect(ppe_db)
        cur_ppe = conn_ppe.cursor()
        cur_ppe.execute("""
            CREATE TABLE transactions (
                transaction_id TEXT PRIMARY KEY,
                amount INTEGER,
                payee_vpa TEXT,
                status TEXT,
                utr_number TEXT,
                timestamp INTEGER
            )
        """)
        cur_ppe.executemany(
            "INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("TX2026110112000001", 500000, "merchant@okhdfcbank", "COMPLETED", "431234567890", 1700000000000),
                ("TX2026110112000002", 150000, "target@paytm", "FAILED", "431234567891", 1700000050000),
            ]
        )
        conn_ppe.commit()
        conn_ppe.close()

        # 3. Unparsed Database with BLOB column (Stage 3 test)
        custom_dir = os.path.join(staging_dir, "data", "data", "com.darknet.spillover", "databases")
        os.makedirs(custom_dir, exist_ok=True)
        custom_db = os.path.join(custom_dir, "custom_vault.db")
        conn_custom = sqlite3.connect(custom_db)
        cur_custom = conn_custom.cursor()
        cur_custom.execute("""
            CREATE TABLE hidden_payloads (
                session_id TEXT PRIMARY KEY,
                user_note TEXT, /* Target Aadhaar 1234 5678 9012 Phone +91 9876543210 */
                raw_wire_blob BLOB,
                json_meta TEXT
            )
        """)
        # Synthetic Protobuf wire blob: field 1 varint 150 (0x08 0x96 0x01) + field 2 length-delimited string
        raw_proto = b"\x08\x96\x01\x12\x07payload"
        json_data = '{"imei": "860123456789012", "operator": "Jio"}'
        cur_custom.execute(
            "INSERT INTO hidden_payloads VALUES (?, ?, ?, ?)",
            ("SESS-001", "Confidential packet", sqlite3.Binary(raw_proto), json_data)
        )
        conn_custom.commit()
        conn_custom.close()

        # 4. Vendor Export XML: report.xml
        report_xml = os.path.join(staging_dir, "report.xml")
        xml_content = """<?xml version="1.0" encoding="utf-8"?>
<report>
    <model type="Chat">
        <field name="Application">WhatsApp</field>
        <field name="Body">Aadhaar is 1234 5678 9012 transfer fast</field>
        <field name="Timestamp">2026-11-01T10:00:00Z</field>
    </model>
    <model type="Chat">
        <field name="Application">WhatsApp</field>
        <field name="Body">Send to scammer@ybl 5000 rs</field>
        <field name="Timestamp">2026-11-01T10:05:00Z</field>
    </model>
    <model type="Transaction">
        <field name="Application">PhonePe</field>
        <field name="Amount">5000</field>
        <field name="Payee">merchant@okhdfcbank</field>
    </model>
</report>
"""
        with open(report_xml, "w", encoding="utf-8") as f_xml:
            f_xml.write(xml_content)

        # 5. Pack into ZIP (.ufdr)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(staging_dir):
                for f in files:
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, staging_dir)
                    zf.write(full_p, rel_p)

    def test_full_pipeline_execution(self):
        """Tests the full 5-stage benchmark execution on the synthetic dump."""
        recorder = ForensicBenchmarkRecorder(
            dump_path=self.dump_zip_path,
            output_dir=self.output_dir,
            verbose=False,
        )

        telemetry = recorder.run_full_pipeline()
        self.assertIsNotNone(telemetry)

        # STAGE 1 CHECKS
        s1 = telemetry.get("stage1_vfs_stress_test", {})
        self.assertEqual(s1.get("container_type"), "UFDR")
        self.assertGreater(s1.get("indexing_time_ms", 0), 0)
        self.assertGreaterEqual(s1.get("file_type_breakdown", {}).get("sqlite_databases", 0), 3)
        self.assertGreaterEqual(s1.get("file_type_breakdown", {}).get("xml_manifests", 0), 1)

        # STAGE 2 CHECKS
        matrix = telemetry.get("stage2_db_execution_matrix", [])
        self.assertGreaterEqual(len(matrix), 2)
        apps_scores = telemetry.get("stage2_app_completeness_scores", {})
        self.assertTrue(len(apps_scores) > 0)

        # STAGE 3 CHECKS (Unparsed schema cataloger)
        unparsed = telemetry.get("stage3_unparsed_schema_catalog", [])
        # hidden_payloads should be detected in custom_vault.db
        unparsed_table_names = [u.get("table_name") for u in unparsed]
        self.assertIn("hidden_payloads", unparsed_table_names)
        target_entry = next(u for u in unparsed if u.get("table_name") == "hidden_payloads")
        blob_sigs = target_entry.get("sampled_blob_signatures", {})
        self.assertIn("raw_wire_blob", blob_sigs)
        self.assertEqual(blob_sigs["raw_wire_blob"][0]["type"], "PROTOBUF_WIRE_FORMAT")
        self.assertIn("json_meta", blob_sigs)
        self.assertEqual(blob_sigs["json_meta"][0]["type"], "JSON_OBJECT")

        # STAGE 4 CHECKS (Vendor differential)
        s4 = telemetry.get("stage4_vendor_differential", {})
        self.assertTrue(s4.get("vendor_xml_found"))
        comp = s4.get("comparison_matrix", {})
        self.assertIn("WhatsApp", comp)
        self.assertEqual(comp["WhatsApp"]["verdict"], "MORE RECORDS THAN VENDOR (count only, correctness not checked)")
        self.assertIn("PhonePe", comp)
        self.assertEqual(comp["PhonePe"]["verdict"], "MORE RECORDS THAN VENDOR (count only, correctness not checked)")

        # STAGE 5 CHECKS (Report generation & PII Sanitization)
        json_path = os.path.join(self.output_dir, "benchmark_telemetry_ledger.json")
        md_path = os.path.join(self.output_dir, "PARITY_GAP_REPORT.md")
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(md_path))

        with open(json_path, "r", encoding="utf-8") as f:
            ledger_text = f.read()

        with open(md_path, "r", encoding="utf-8") as f:
            report_text = f.read()

        # Strict PII verification in output files
        self.assertNotIn("1234 5678 9012", ledger_text)
        self.assertNotIn("1234 5678 9012", report_text)
        self.assertIn("[Aadhaar Redacted]", ledger_text)
        self.assertIn("[Aadhaar Redacted]", report_text)

        # Phone masking verification
        self.assertNotIn("9876543210", ledger_text)
        self.assertNotIn("9876543210", report_text)

        # Markdown structure verification
        self.assertIn("# BHARAT-PA FORENSIC PARSER COMPATIBILITY & PARITY GAP REPORT", report_text)
        self.assertIn("EXECUTIVE SUMMARY", report_text)
        self.assertIn("HEAD-TO-HEAD VENDOR DIFFERENTIAL MATRIX", report_text)
        self.assertIn("UNPARSED TABLES & BLOB SCHEMA BLUEPRINTS", report_text)

    def test_cli_execution(self):
        """Tests command-line interface execution."""
        cli_out_dir = os.path.join(self.test_dir, "cli_output")
        cmd = [
            sys.executable,
            "-m",
            "tools.forensic_benchmark_recorder",
            "--input",
            self.dump_zip_path,
            "--output-dir",
            cli_out_dir,
            "--verbose",
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0, f"CLI exited with error: {res.stderr}")
        self.assertTrue(os.path.exists(os.path.join(cli_out_dir, "benchmark_telemetry_ledger.json")))
        self.assertTrue(os.path.exists(os.path.join(cli_out_dir, "PARITY_GAP_REPORT.md")))


if __name__ == "__main__":
    unittest.main()
