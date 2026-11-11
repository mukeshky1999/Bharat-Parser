"""
Tier 4 Real-World Application Scenarios.
Simulates end-to-end complex investigative cases:
1. Multi-hop mule syndicate tracing across UPI, CBS IMPS, Binance P2P, and TRC-20 crypto cashout.
2. Dirty acquisition cross-app healing (recovering damaged / orphan records via SMS DLT & multi-app corroboration).
3. Anti-forensics clock tampering and root evasion audit with Section 63(2)(c) statutory compensation drafting.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import sys
import unittest
from pathlib import Path
import pandas as pd

# Ensure root directory is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup as env_setup
from parsers.corroboration_engine import heal_counterparties_across_apps
from parsers.graph_intelligence import (
    build_transaction_graph,
    classify_syndicate_roles,
    detect_mule_behavior,
)
from src.web3.tronlink import base58check_to_hex41, hex41_to_base58check
from src.legal_and_bsa.models import (
    DeponentDetails,
    DeviceMetadata,
    ForensicExpertDetails,
    WorkstationEnvironment,
    IntegrityAuditDisclosure,
    HashTier,
    StatutoryRegimeMode,
)
from src.legal_and_bsa.bsa_certificate_generator import Section63BsaCertificateGenerator
from src.legal_and_bsa.chain_of_custody import MerkleChainOfCustodyLedger
from src.legal_and_bsa.hash_manifest import HierarchicalHashManifestManager
from src.legal_and_bsa.engine import LegalComplianceAndBsaEngine


class TestTier4RealWorld(unittest.TestCase):
    """Tier 4: Comprehensive real-world investigative scenarios."""

    def setUp(self):
        self.sandbox = env_setup.create_isolated_sandbox(prefix="t4_real_world_")

    def tearDown(self):
        if self.sandbox.exists():
            shutil.rmtree(self.sandbox, ignore_errors=True)

    def test_scenario_multi_hop_mule_syndicate_tracing(self):
        """
        Scenario 1: Full Financial Crime Simulation.
        Traces a 5-hop laundering syndicate:
        Victim (GPay) -> Mule 1 (PhonePe) -> Mule 2 & Mule 3 (CBS IMPS) ->
        Mule 4 (Binance P2P Escrow) -> Cashout Wallet (TRC-20 USDT).
        Exports final court-admissible Section 63 BSA evidence package.
        """
        # Step 1: Synthesize multi-app syndicate transactions
        victim_tx = {
            "Transaction_ID": "630911000001",
            "Date": "2024-05-04",
            "Timestamp_IST": "2024-05-04 10:00:00",
            "Amount": 100000.0,
            "Counterparty": "Mule 1 (mule1@okaxis)",
            "Application": "Google Pay",
            "Status": "SUCCESS",
            "Type": "DEBIT",
        }
        mule1_layer1 = {
            "Transaction_ID": "630911000002",
            "Date": "2024-05-04",
            "Timestamp_IST": "2024-05-04 10:15:00",
            "Amount": 49000.0,
            "Counterparty": "Mule 2 (mule2@ybl)",
            "Application": "PhonePe",
            "Status": "SUCCESS",
            "Type": "DEBIT",
        }
        mule1_layer2 = {
            "Transaction_ID": "630911000003",
            "Date": "2024-05-04",
            "Timestamp_IST": "2024-05-04 10:16:00",
            "Amount": 49000.0,
            "Counterparty": "Mule 3 (mule3@ybl)",
            "Application": "PhonePe",
            "Status": "SUCCESS",
            "Type": "DEBIT",
        }
        mule2_to_mule4 = {
            "Transaction_ID": "630911000004",
            "Date": "2024-05-04",
            "Timestamp_IST": "2024-05-04 11:00:00",
            "Amount": 45000.0,
            "Counterparty": "Mule 4 (Consolidator)",
            "Application": "IMPS",
            "Status": "SUCCESS",
            "Type": "DEBIT",
        }
        mule3_to_mule4 = {
            "Transaction_ID": "630911000005",
            "Date": "2024-05-04",
            "Timestamp_IST": "2024-05-04 11:05:00",
            "Amount": 45000.0,
            "Counterparty": "Mule 4 (Consolidator)",
            "Application": "IMPS",
            "Status": "SUCCESS",
            "Type": "DEBIT",
        }
        mule4_p2p_escrow = {
            "Transaction_ID": "630911000006",
            "Date": "2024-05-04",
            "Timestamp_IST": "2024-05-04 12:00:00",
            "Amount": 90000.0,
            "Counterparty": "Crypto Merchant (Binance P2P)",
            "Application": "Binance P2P",
            "Status": "SUCCESS",
            "Type": "DEBIT",
        }

        all_txs = [
            victim_tx, mule1_layer1, mule1_layer2,
            mule2_to_mule4, mule3_to_mule4, mule4_p2p_escrow
        ]
        df_syndicate = pd.DataFrame(all_txs)

        # Step 2: Build NetworkX graph and perform graph intelligence analysis
        graph = build_transaction_graph(df_syndicate)
        self.assertGreaterEqual(len(graph.nodes), 5)

        roles_df = classify_syndicate_roles(graph, df_syndicate)
        self.assertFalse(roles_df.empty)

        alerts = detect_mule_behavior(graph, df_syndicate)
        self.assertIsInstance(alerts, list)

        # Step 3: Validate TRC-20 Crypto Destination Address Conversion
        usdt_trc20_base58 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
        hex41_address = base58check_to_hex41(usdt_trc20_base58)
        self.assertTrue(hex41_address.startswith("41"))
        self.assertEqual(len(hex41_address), 42)

        # Roundtrip conversion check
        reconstructed_base58 = hex41_to_base58check(hex41_address)
        self.assertEqual(reconstructed_base58, usdt_trc20_base58)

        # Step 4: Build Merkle Custody Ledger for the Syndicate Case
        custody_ledger = MerkleChainOfCustodyLedger()
        master_img_sha256 = "d" * 64
        custody_ledger.initialize_chain("CASE-MULE-SYNDICATE-01", master_img_sha256)
        custody_ledger.append_entry("ANALYZER", "GRAPH_BUILT", {"node_count": len(graph.nodes)})
        custody_ledger.append_entry("MULE_DETECTOR", "LAYERING_DETECTED", {"total_hops": 5})
        custody_ledger.append_entry("CRYPTO_SOLVER", "TRC20_RESOLVED", {"address": usdt_trc20_base58})
        self.assertTrue(custody_ledger.verify_chain_integrity())

        # Step 5: Generate Statutory Section 63 BSA 2023 Certificate
        manifest_mgr = HierarchicalHashManifestManager()
        t1_item = manifest_mgr.register_synthetic_manifest_item(
            hash_tier=HashTier.TIER_1_MASTER_ACQUISITION_SOURCE,
            canonical_path_or_exhibit_name="suspect_syndicate_phone.dd",
            artifact_description="Bitstream Physical Forensic Extraction",
            byte_size=128 * 1024 * 1024,
            sha256_hex=master_img_sha256,
            md5_hex="e" * 32,
        )
        case_merkle_root = manifest_mgr.compute_case_merkle_root()

        bsa_gen = Section63BsaCertificateGenerator()
        deponent = DeponentDetails(
            name="Rajesh Verma",
            designation="Deputy Superintendent of Police, STF Cyber Unit",
            fir_number="FIR-STF-2026-088",
            police_station="Special Task Force Cyber Cell",
        )
        device = DeviceMetadata(
            make_and_brand="OnePlus",
            model_name="12R (CPH2585)",
            imei_1="862019482910482",
        )
        expert = ForensicExpertDetails(
            name="Dr. Aditi Sharma",
            designation="Forensic Director",
            laboratory_unit="CFSL Cyber Division",
            qualifications="PhD Digital Forensics",
        )
        workstation = WorkstationEnvironment(
            workstation_hostname="CFSL-STF-WS-04",
            os_version="Windows 11 Forensic",
            engine_version="2026.1",
            git_commit_hash="c3a4f8b91e07",
        )
        audit = IntegrityAuditDisclosure()

        cert_record, cert_text = bsa_gen.generate_section_63_certificate(
            certificate_reference_no="CERT-BSA-STF-2026-088",
            statutory_mode=StatutoryRegimeMode.BSA_2023_SECTION_63_4_C_SCHEDULE,
            deponent=deponent,
            device=device,
            expert=expert,
            workstation=workstation,
            integrity_audit=audit,
            master_image_sha256=master_img_sha256,
            master_image_md5=t1_item.md5_hex,
            case_merkle_root_sha256=case_merkle_root,
        )

        self.assertIn("PART A", cert_text)
        self.assertIn("Rajesh Verma", cert_text)
        self.assertIn("OnePlus", cert_text)
        self.assertIn("Section 63(4)(c)", cert_text)

        # Step 6: Export master legal SQLite database
        master_sqlite_path = self.sandbox / "syndicate_master_report.sqlite"
        engine = LegalComplianceAndBsaEngine()
        engine.export_master_database(
            output_db_path=str(master_sqlite_path),
            manifest_items=manifest_mgr.items,
            certificates=[cert_record],
            audit_entries=custody_ledger.entries,
        )
        self.assertTrue(master_sqlite_path.exists())

    def test_scenario_dirty_acquisition_cross_app_healing(self):
        """
        Scenario 2: Dirty Acquisition Cross-App Healing.
        Simulates an extraction where PhonePe database records are partially damaged
        (counterparty is a placeholder 'UPI / Bank Transfer' or carved 'Unknown').
        Cross-app corroboration matches Google Pay records and heals the records with
        verified VPA and transaction direction.
        """
        # App 1: Damaged PhonePe transactions with placeholder and carved records
        phonepe_txs = pd.DataFrame([
            {
                "Transaction_ID": "630911445566",
                "Date": "2024-05-04",
                "Amount": 15000.0,
                "Counterparty": "UPI / Bank Transfer",  # Placeholder from damaged PhonePe table
                "Type": "TRANSFER",
                "Linked_Reference_IDs": "630911445566",
            },
            {
                "Transaction_ID": "CARVED_01",
                "Date": "2024-05-04",
                "Amount": 25000.0,
                "Counterparty": "Unknown",  # Damaged carved record missing counterparty
                "Type": "TRANSFER",
                "Linked_Reference_IDs": "N/A",
            }
        ])

        # App 2: Google Pay containing verified VPA and Direction for the same UTR and Amount+Date
        gpay_txs = pd.DataFrame([
            {
                "Transaction_ID": "630911445566",
                "Date": "2024-05-04",
                "Amount": 15000.0,
                "Counterparty": "mule_account@okaxis",  # Known VPA for UTR 630911445566
                "Type": "DEBIT",
                "Linked_Reference_IDs": "630911445566",
            },
            {
                "Transaction_ID": "630911998877",
                "Date": "2024-05-04",
                "Amount": 25000.0,
                "Counterparty": "victim_mule@ybl",  # Known VPA for Amount ₹25,000 + Date 2024-05-04
                "Type": "DEBIT",
                "Linked_Reference_IDs": "630911998877",
            }
        ])

        app_artifacts = {
            "PhonePe": {"transactions": phonepe_txs},
            "Google Pay": {"transactions": gpay_txs},
        }

        # Run cross-app healing
        healed_artifacts = heal_counterparties_across_apps(app_artifacts)

        healed_phonepe_txs = healed_artifacts["PhonePe"]["transactions"]

        # Row 0: Placeholder 'UPI / Bank Transfer' must be healed to mule_account@okaxis and DEBIT
        row0 = healed_phonepe_txs[healed_phonepe_txs["Transaction_ID"] == "630911445566"].iloc[0]
        self.assertEqual(row0["Counterparty"], "mule_account@okaxis")
        self.assertEqual(row0["Type"], "DEBIT")

        # Row 1: Damaged carved record must be healed to victim_mule@ybl and DEBIT via Amount+Date compatibility
        row1 = healed_phonepe_txs[healed_phonepe_txs["Transaction_ID"] == "CARVED_01"].iloc[0]
        self.assertEqual(row1["Counterparty"], "victim_mule@ybl")
        self.assertEqual(row1["Type"], "DEBIT")

    def test_scenario_anti_forensics_clock_tampering_audit(self):
        """
        Scenario 3: Anti-Forensics Clock Tampering Audit.
        Simulates an adversary who manipulated the device clock backwards by 48.5 hours
        and left Magisk zygisk root binaries on the filesystem.
        Validates automatic detection, mathematical bounding, and Section 63(2)(c)
        anomaly compensation drafting in the statutory BSA 2023 certificate.
        """
        audit_tampered = IntegrityAuditDisclosure(
            root_or_jailbreak_detected=True,
            root_details="Magisk zygisk daemon active in /data/adb/modules",
            clock_tampering_detected=True,
            clock_tampering_details="Manual system clock rollback of -48.5 hours detected via monotonic GPS delta",
            monotonic_counter_bounds="hardware monotonic clock, database ROWID sequence, and sqlite WAL checkpoint tags",
            malware_or_overlay_detected=True,
            malware_details="Sideloaded accessibility keylogger trojan package com.sys.service",
        )

        generator = Section63BsaCertificateGenerator()
        sec63_clause = generator.synthesize_sec63_2_c_clause(audit_tampered)

        # Statutory Clause Validation
        self.assertIn("Section 63(2)(c) of the Bharatiya Sakshya Adhiniyam, 2023", sec63_clause)
        self.assertIn("Magisk zygisk daemon active", sec63_clause)
        self.assertIn("Manual system clock rollback of -48.5 hours", sec63_clause)
        self.assertIn("Sideloaded accessibility keylogger trojan", sec63_clause)
        self.assertIn("mathematically isolated", sec63_clause)
        self.assertIn("not such as to affect the integrity of the remaining electronic records", sec63_clause)

        # Complete statutory certificate creation with anomaly disclosure
        deponent = DeponentDetails(
            name="Vikram Rathore",
            designation="Inspector of Police",
            fir_number="FIR-2026/0441",
            police_station="Cyber Police Station",
        )
        device = DeviceMetadata(
            make_and_brand="Xiaomi",
            model_name="Redmi Note 12",
            imei_1="861928471928374",
        )
        expert = ForensicExpertDetails(
            name="Dr. Aditi Sharma",
            designation="Forensic Director",
            laboratory_unit="CFSL",
            qualifications="PhD Forensics",
        )
        workstation = WorkstationEnvironment(
            workstation_hostname="CFSL-WS-02",
            os_version="Windows 11",
            engine_version="2026.1",
            git_commit_hash="c3a4f8b91e07",
        )

        cert_record, cert_text = generator.generate_section_63_certificate(
            certificate_reference_no="CERT-BSA-ANOMALY-01",
            statutory_mode=StatutoryRegimeMode.BSA_2023_SECTION_63_4_C_SCHEDULE,
            deponent=deponent,
            device=device,
            expert=expert,
            workstation=workstation,
            integrity_audit=audit_tampered,
            master_image_sha256="f" * 64,
            master_image_md5="0" * 32,
            case_merkle_root_sha256="1" * 64,
        )

        # Verify that the generated statutory text incorporates the full anomaly compensation clause
        self.assertIn("Section 63(2)(c)", cert_text)
        self.assertIn("Magisk zygisk daemon", cert_text)
        self.assertIn("Manual system clock rollback", cert_text)


if __name__ == "__main__":
    unittest.main()
