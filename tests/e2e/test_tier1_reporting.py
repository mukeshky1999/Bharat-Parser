import os
import sys
import tempfile
import unittest
import sqlite3
import hashlib
from pathlib import Path

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup  # noqa: F401 - Sanitizes path and environment

from src.legal_and_bsa.models import (
    DeponentDetails,
    DeviceMetadata,
    ForensicExpertDetails,
    WorkstationEnvironment,
    IntegrityAuditDisclosure,
    HashTier,
    StatutoryRegimeMode,
    ImmutabilityStatus,
    Section63BsaCertificateRecord,
)
from src.legal_and_bsa.bsa_certificate_generator import Section63BsaCertificateGenerator
from src.legal_and_bsa.chain_of_custody import (
    MerkleChainOfCustodyLedger,
    ChainOfCustodyTamperException,
)
from src.legal_and_bsa.hash_manifest import HierarchicalHashManifestManager
from src.legal_and_bsa.engine import LegalComplianceAndBsaEngine


class TestTier1Reporting(unittest.TestCase):
    """Tier 1: Statutory Court Reporting & Section 63 BSA 2023 compliance tests."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="e2e_reporting_")
        self.scratch_dir = self.tmp_dir.name

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_section_63_bsa_statutory_certificate_generation(self):
        """Validates statutory Part A (IO) and Part B (Forensic Expert) certificate generation."""
        generator = Section63BsaCertificateGenerator()

        deponent = DeponentDetails(
            name="Vikram Rathore",
            designation="Inspector of Police / Cyber Crime Branch",
            father_name="Devendra Rathore",
            age=44,
            police_station="Cyber Police Station, Connaught Place",
            district="New Delhi",
            state="Delhi",
            fir_number="FIR-2026/0441",
            sections_of_law="Sections 316, 318(4) BNS 2023 & Section 66D IT Act",
            custody_mode="SEIZED_OFFICIAL_CUSTODY",
            seizure_memo_ref="SM-2026-DEL-089",
        )

        device = DeviceMetadata(
            device_type="Smartphone",
            make_and_brand="Samsung",
            model_name="Galaxy S23 Ultra (SM-S918B)",
            imei_1="358234112233445",
            imei_2="358234112233446",
            serial_number="R5CW203XYZ",
            chipset_details="Qualcomm Snapdragon 8 Gen 2",
            operating_system="Android 14 (OneUI 6.0)",
            sim_iccids=["8991871234567890123F"],
            phone_numbers=["+919876543210"],
        )

        expert = ForensicExpertDetails(
            name="Dr. Aditi Sharma",
            designation="Senior Assistant Director / Cyber Forensics",
            laboratory_unit="Central Forensic Science Laboratory (CFSL)",
            qualifications="M.Tech (Information Security), PhD (Digital Forensics), EnCE",
        )

        workstation = WorkstationEnvironment(
            workstation_hostname="CFSL-DF-WS-09",
            os_version="Windows 11 Pro 64-bit Forensic Image",
            engine_version="BharatForensics-2026.1.0-PROD",
            git_commit_hash="c3a4f8b91e07",
            vfs_mount_mode="READ_ONLY_IMMUTABLE",
            processing_start_ist="2026-11-09 09:30:00 IST (+05:30)",
            processing_completion_ist="2026-11-09 10:15:00 IST (+05:30)",
        )

        integrity_audit = IntegrityAuditDisclosure(
            root_or_jailbreak_detected=False,
            clock_tampering_detected=False,
            malware_or_overlay_detected=False,
        )

        dummy_master_sha256 = "a" * 64
        dummy_master_md5 = "b" * 32
        dummy_merkle_root = "c" * 64

        cert_record, cert_text = generator.generate_section_63_certificate(
            certificate_reference_no="CERT/DEL/CYBER/2026/0091",
            statutory_mode=StatutoryRegimeMode.BSA_2023_SECTION_63_4_C_SCHEDULE,
            deponent=deponent,
            device=device,
            expert=expert,
            workstation=workstation,
            integrity_audit=integrity_audit,
            master_image_sha256=dummy_master_sha256,
            master_image_md5=dummy_master_md5,
            case_merkle_root_sha256=dummy_merkle_root,
        )

        self.assertEqual(cert_record.certificate_reference_no, "CERT/DEL/CYBER/2026/0091")
        self.assertEqual(cert_record.case_fir_or_rc_number, "FIR-2026/0441")
        self.assertEqual(cert_record.tier1_master_image_sha256, dummy_master_sha256)
        self.assertEqual(cert_record.case_merkle_root_sha256, dummy_merkle_root)

        # Statutory textual requirements
        self.assertIn("PART A", cert_text)
        self.assertIn("PART B", cert_text)
        self.assertIn("Vikram Rathore", cert_text)
        self.assertIn("Dr. Aditi Sharma", cert_text)
        self.assertIn("Samsung", cert_text)
        self.assertIn("Galaxy S23 Ultra", cert_text)
        self.assertIn("Section 63(4)(c)", cert_text)

    def test_section_63_2_c_anomaly_compensation_auto_drafting(self):
        """Verifies Section 63(2)(c) statutory disclosure and compensation clauses when anomalies are present."""
        audit_tampered = IntegrityAuditDisclosure(
            root_or_jailbreak_detected=True,
            root_details="Magisk v26.4 root daemon active with zygisk hook",
            clock_tampering_detected=True,
            clock_tampering_details="Manual system clock rollback of -48.5 hours detected",
            monotonic_counter_bounds="database sequence counters (ROWID) and sqlite WAL commit sequence",
            malware_or_overlay_detected=False,
        )

        clause = Section63BsaCertificateGenerator.synthesize_sec63_2_c_clause(audit_tampered)

        self.assertIn("Section 63(2)(c) of the Bharatiya Sakshya Adhiniyam, 2023", clause)
        self.assertIn("Magisk v26.4 root daemon active", clause)
        self.assertIn("Manual system clock rollback of -48.5 hours", clause)
        self.assertIn("mathematically isolated", clause)
        self.assertIn("not such as to affect the integrity of the remaining electronic records", clause)

    def test_merkle_chain_of_custody_append_and_tamper_detection(self):
        """Verifies append-only hash chain linking and tamper detection."""
        ledger = MerkleChainOfCustodyLedger()
        case_uuid = "CASE-2026-DEL-101"
        master_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        genesis = ledger.initialize_chain(case_uuid, master_sha256)
        self.assertIsInstance(genesis, str)
        self.assertEqual(len(genesis), 64)

        # Append 5 events
        events = [
            ("OPERATOR_01", "INGEST_STARTED", {"action": "mount_vfs", "target": "case.zip"}),
            ("PARSER_UPI", "PHONEPE_PARSED", {"records_found": 142, "db": "phonepe.db"}),
            ("PARSER_CHAT", "WHATSAPP_PARSED", {"messages": 1250, "db": "msgstore.db"}),
            ("CORROBORATOR", "TRANSACTIONS_HEALED", {"cross_matches": 38}),
            ("REPORTER", "BSA_CERT_GENERATED", {"cert_id": "CERT-001"}),
        ]

        for actor, action, payload in events:
            entry = ledger.append_entry(actor=actor, event_action_type=action, payload_dict=payload)
            self.assertEqual(len(entry.current_entry_hash_hex), 64)

        self.assertEqual(len(ledger.entries), 5)
        # Should verify without error
        self.assertTrue(ledger.verify_chain_integrity())

        # Now simulate tampering in event 3 payload
        original_payload = ledger.entries[2].canonical_payload_json
        ledger.entries[2].canonical_payload_json = '{"messages": 9999, "db": "tampered.db"}'

        with self.assertRaises(ChainOfCustodyTamperException):
            ledger.verify_chain_integrity()

        # Restore payload but tamper hash
        ledger.entries[2].canonical_payload_json = original_payload
        ledger.entries[2].current_entry_hash_hex = "0" * 64

        with self.assertRaises(ChainOfCustodyTamperException):
            ledger.verify_chain_integrity()

    def test_pre_post_ingest_source_immutability_and_hash_manifest(self):
        """Verifies hierarchical hash manifest registration and Merkle root calculation."""
        manager = HierarchicalHashManifestManager()

        # Create dummy physical files
        f1_path = os.path.join(self.scratch_dir, "master_raw.dd")
        with open(f1_path, "wb") as f:
            f.write(b"RAW_DISK_FORENSIC_ACQUISITION_EVIDENCE_BYTES" * 100)

        f2_path = os.path.join(self.scratch_dir, "extracted_msgstore.db")
        with open(f2_path, "wb") as f:
            f.write(b"SQLITE_FORMAT_3\x00_EXTRACTED_WHATSAPP_DATABASE" * 50)

        item1 = manager.register_manifest_item(
            hash_tier=HashTier.TIER_1_MASTER_ACQUISITION_SOURCE,
            canonical_path_or_exhibit_name="/evidence/master_raw.dd",
            artifact_description="Bitstream Physical Image",
            file_path=f1_path,
        )

        item2 = manager.register_manifest_item(
            hash_tier=HashTier.TIER_2A_VFS_ORIGINAL_CONTAINER,
            canonical_path_or_exhibit_name="/data/data/com.whatsapp/databases/msgstore.db",
            artifact_description="Extracted SQLite container",
            file_path=f2_path,
            parent_manifest_item_uid=item1.manifest_item_uid,
        )

        item3 = manager.register_synthetic_manifest_item(
            hash_tier=HashTier.TIER_3_EXPORTED_COURT_EXHIBIT,
            canonical_path_or_exhibit_name="EXHIBIT_A_TRANSACTION_SUMMARY.pdf",
            artifact_description="Section 63 court exhibit PDF",
            byte_size=2048,
            sha256_hex=hashlib.sha256(b"court_exhibit").hexdigest(),
            md5_hex=hashlib.md5(b"court_exhibit").hexdigest(),
        )

        self.assertEqual(len(manager.items), 3)
        self.assertEqual(item1.post_run_reverified_status, ImmutabilityStatus.IMMUTABILITY_VERIFIED_IDENTICAL)

        merkle_root = manager.compute_case_merkle_root()
        self.assertEqual(len(merkle_root), 64)

        # Determinism check: recalculating with same items produces exact same root
        merkle_root_2 = manager.compute_case_merkle_root()
        self.assertEqual(merkle_root, merkle_root_2)

    def test_master_legal_sqlite_database_export(self):
        """Verifies master SQLite database export conforming to the canonical 3-table schema."""
        engine = LegalComplianceAndBsaEngine()

        # Populate sample manifest item
        item = engine.manifest_manager.register_synthetic_manifest_item(
            hash_tier=HashTier.TIER_1_MASTER_ACQUISITION_SOURCE,
            canonical_path_or_exhibit_name="/evidence/image.dd",
            artifact_description="Master bitstream acquisition image",
            byte_size=1024 * 1024,
            sha256_hex="1" * 64,
            md5_hex="2" * 32,
        )

        # Populate sample certificate
        cert_record = Section63BsaCertificateRecord(
            certificate_reference_no="CERT-2026-001",
            statutory_regime_mode=StatutoryRegimeMode.BSA_2023_SECTION_63_4_C_SCHEDULE,
            case_fir_or_rc_number="FIR-2026/001",
            part_a_deponent_details_json='{"name": "Vikram Rathore"}',
            part_a_device_metadata_json='{"make": "Samsung"}',
            part_b_expert_details_json='{"name": "Dr. Sharma"}',
            part_b_workstation_env_json='{"hostname": "CFSL-01"}',
            sec63_2_c_integrity_clause_text="Device operated normally at all material times.",
            tier1_master_image_sha256="1" * 64,
            case_merkle_root_sha256="3" * 64,
            generated_at_ist_iso="2026-11-09 10:00:00 IST (+05:30)",
        )

        # Populate custody audit chain
        engine.custody_ledger.initialize_chain("CASE-001", "1" * 64)
        engine.custody_ledger.append_entry("OPERATOR", "HASH_VERIFY", {"status": "SUCCESS"})

        out_db = os.path.join(self.scratch_dir, "legal_bsa_master.sqlite")
        engine.export_master_database(
            output_db_path=out_db,
            manifest_items=engine.manifest_manager.items,
            certificates=[cert_record],
            audit_entries=engine.custody_ledger.entries,
        )

        self.assertTrue(os.path.exists(out_db))

        # Check tables inside SQLite
        conn = sqlite3.connect(out_db)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        self.assertIn("evidentiary_hash_manifest_ledger", tables)
        self.assertIn("section63_bsa_certificates_registry", tables)
        self.assertIn("chain_of_custody_merkle_ledger", tables)

        cursor.execute("SELECT COUNT(*) FROM evidentiary_hash_manifest_ledger")
        self.assertEqual(cursor.fetchone()[0], 1)

        cursor.execute("SELECT COUNT(*) FROM section63_bsa_certificates_registry")
        self.assertEqual(cursor.fetchone()[0], 1)

        cursor.execute("SELECT COUNT(*) FROM chain_of_custody_merkle_ledger")
        self.assertEqual(cursor.fetchone()[0], 1)

        conn.close()


if __name__ == "__main__":
    unittest.main()
