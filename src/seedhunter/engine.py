"""
Master Sub-Engine 4.4: Seed Hunter, HD Derivation & Rupee-to-Crypto Correlator Engine.
Coordinates seed discovery, deterministic address derivation, and cross-phase laundering
reconstruction, exporting all evidentiary data into bip39_derivation_and_rupee_usdt_correlator.sqlite.
Complies with Section 7 of Phase 4 Module 4.4 Specification.
"""

import os
import sqlite3
from typing import List

from src.seedhunter.models import (
    RecoveredSeedRecord,
    HDDerivedAddressRecord,
    LaunderingChainRecord,
)


class SeedHunterCorrelatorEngine:
    """Master engine for mnemonic seed hunting, HD address derivation, and laundering correlation."""

    def __init__(self) -> None:
        self.recovered_seeds: List[RecoveredSeedRecord] = []
        self.hd_addresses: List[HDDerivedAddressRecord] = []
        self.laundering_chains: List[LaunderingChainRecord] = []

    def register_recovered_seeds(self, seeds: List[RecoveredSeedRecord]) -> None:
        """Appends recovered seed, private key, and vault records to master registry."""
        self.recovered_seeds.extend(seeds)

    def register_hd_addresses(self, addresses: List[HDDerivedAddressRecord]) -> None:
        """Appends derived HD public address records to master registry."""
        self.hd_addresses.extend(addresses)

    def register_laundering_chains(self, chains: List[LaunderingChainRecord]) -> None:
        """Appends reconstructed end-to-end money laundering chains to master registry."""
        self.laundering_chains.extend(chains)

    def export_to_master_db(self, export_db_path: str) -> str:
        """
        Creates the standardized schema and inserts all parsed secrets, derived addresses,
        and laundering chains into the target SQLite database.
        """
        os.makedirs(os.path.dirname(os.path.abspath(export_db_path)), exist_ok=True)
        conn = sqlite3.connect(export_db_path)
        cur = conn.cursor()

        # Table 1: recovered_seeds_private_keys_and_unwrapped_vaults
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS recovered_seeds_private_keys_and_unwrapped_vaults (
                seed_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_type TEXT NOT NULL,
                discovery_source_detail TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                checksum_validation_status TEXT NOT NULL,
                plaintext_mnemonic_or_privkey TEXT,
                unlocked_with_password TEXT,
                raw_encrypted_vault_json TEXT,
                recovery_classification TEXT NOT NULL
            )
            """
        )

        # Table 2: hd_derived_public_addresses_from_seeds
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS hd_derived_public_addresses_from_seeds (
                derived_addr_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                seed_record_uid INTEGER NOT NULL,
                blockchain_network TEXT NOT NULL,
                derivation_path TEXT NOT NULL,
                derived_public_address TEXT NOT NULL,
                matches_on_device_activity INTEGER DEFAULT 0,
                FOREIGN KEY (seed_record_uid) REFERENCES recovered_seeds_private_keys_and_unwrapped_vaults(seed_record_uid)
            )
            """
        )

        # Table 3: end_to_end_rupee_to_crypto_laundering_chains
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS end_to_end_rupee_to_crypto_laundering_chains (
                laundering_chain_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_pattern_classification TEXT NOT NULL,
                hop1_phase3_tx_master_uids_json TEXT NOT NULL,
                hop1_total_fiat_outflow_inr REAL NOT NULL,
                hop2_cex_p2p_order_uid INTEGER,
                hop2_acquired_crypto_amount TEXT NOT NULL,
                hop3_cex_withdrawal_or_pay_uid INTEGER,
                hop4_self_custody_or_swap_json TEXT,
                hop5_chat_confirmation_msg_uid TEXT,
                chain_start_utc_iso TEXT NOT NULL,
                chain_completion_utc_iso TEXT
            )
            """
        )

        # Insert Table 1 Records
        for s in self.recovered_seeds:
            cur.execute(
                """
                INSERT INTO recovered_seeds_private_keys_and_unwrapped_vaults (
                    secret_type,
                    discovery_source_detail,
                    source_vfs_file_id,
                    checksum_validation_status,
                    plaintext_mnemonic_or_privkey,
                    unlocked_with_password,
                    raw_encrypted_vault_json,
                    recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    s.secret_type.value if hasattr(s.secret_type, "value") else str(s.secret_type),
                    s.discovery_source_detail,
                    s.source_vfs_file_id,
                    s.checksum_validation_status,
                    s.plaintext_mnemonic_or_privkey,
                    s.unlocked_with_password,
                    s.raw_encrypted_vault_json,
                    s.recovery_classification.value if hasattr(s.recovery_classification, "value") else str(s.recovery_classification),
                ),
            )

        # Insert Table 2 Records
        for h in self.hd_addresses:
            cur.execute(
                """
                INSERT INTO hd_derived_public_addresses_from_seeds (
                    seed_record_uid,
                    blockchain_network,
                    derivation_path,
                    derived_public_address,
                    matches_on_device_activity
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    h.seed_record_uid,
                    h.blockchain_network.value if hasattr(h.blockchain_network, "value") else str(h.blockchain_network),
                    h.derivation_path,
                    h.derived_public_address,
                    h.matches_on_device_activity,
                ),
            )

        # Insert Table 3 Records
        for c in self.laundering_chains:
            cur.execute(
                """
                INSERT INTO end_to_end_rupee_to_crypto_laundering_chains (
                    chain_pattern_classification,
                    hop1_phase3_tx_master_uids_json,
                    hop1_total_fiat_outflow_inr,
                    hop2_cex_p2p_order_uid,
                    hop2_acquired_crypto_amount,
                    hop3_cex_withdrawal_or_pay_uid,
                    hop4_self_custody_or_swap_json,
                    hop5_chat_confirmation_msg_uid,
                    chain_start_utc_iso,
                    chain_completion_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    c.chain_pattern_classification.value if hasattr(c.chain_pattern_classification, "value") else str(c.chain_pattern_classification),
                    c.hop1_phase3_tx_master_uids_json,
                    c.hop1_total_fiat_outflow_inr,
                    c.hop2_cex_p2p_order_uid,
                    c.hop2_acquired_crypto_amount,
                    c.hop3_cex_withdrawal_or_pay_uid,
                    c.hop4_self_custody_or_swap_json,
                    c.hop5_chat_confirmation_msg_uid,
                    c.chain_start_utc_iso,
                    c.chain_completion_utc_iso,
                ),
            )

        conn.commit()
        conn.close()
        return export_db_path
