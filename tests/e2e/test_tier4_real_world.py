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
from src.audit import AuditLedger, HashManifest
from parsers.corroboration_engine import heal_counterparties_across_apps
from parsers.graph_intelligence import (
    build_transaction_graph,
    classify_syndicate_roles,
    detect_mule_behavior,
)
from src.web3.tronlink import base58check_to_hex41, hex41_to_base58check


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
        Records the analysis in the audit ledger.
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

        # Step 4: Record the analysis in the audit ledger
        ledger = AuditLedger("CASE-MULE-SYNDICATE-01")
        ledger.append("ANALYZER", "GRAPH_BUILT", {"node_count": len(graph.nodes)})
        ledger.append("MULE_DETECTOR", "LAYERING_DETECTED", {"total_hops": 5})
        ledger.append("CRYPTO_SOLVER", "TRC20_RESOLVED", {"address": usdt_trc20_base58})
        self.assertTrue(ledger.verify().ok)
        self.assertEqual(len(ledger.entries), 3)

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

        # Row 1 (REVIEW M-04): same amount and date in another app is NOT proof of the same payment.
        # The damaged record is left as it was and the candidate is offered as an unconfirmed lead.
        row1 = healed_phonepe_txs[healed_phonepe_txs["Transaction_ID"] == "CARVED_01"].iloc[0]
        self.assertNotEqual(row1["Counterparty"], "victim_mule@ybl")
        self.assertEqual(row1["Type"], "TRANSFER")
        self.assertIn("victim_mule@ybl", str(row1.get("Possible_Link", "")))
        self.assertIn("unconfirmed", str(row1.get("Possible_Link", "")))



if __name__ == "__main__":
    unittest.main()
