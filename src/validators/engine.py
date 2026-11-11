"""
Master Sub-Engine 4.3: Address Validators, ABI Unpacker & WalletConnect Engine.
Coordinates address checksumming, smart contract ABI parsing, and WalletConnect audits,
and exports all verified data into address_validators_abi_and_walletconnect.sqlite.
"""

import os
import sqlite3
from typing import List

from src.validators.models import (
    UnpackedSmartContractABIRecord,
    ValidatedCryptoAddressRecord,
    WalletConnectAuditRecord,
)
from src.validators.address_validators import validate_crypto_address
from src.validators.abi_unpacker import SmartContractABIUnpacker
from src.validators.walletconnect import WalletConnectDecoder


class ValidatorsAndABIEngine:
    """Master engine for mathematical address validation, ABI call decoding, and WalletConnect audits."""

    def __init__(self) -> None:
        self.validated_addresses: List[ValidatedCryptoAddressRecord] = []
        self.abi_calls: List[UnpackedSmartContractABIRecord] = []
        self.walletconnect_records: List[WalletConnectAuditRecord] = []

        self.abi_unpacker = SmartContractABIUnpacker()
        self.wc_decoder = WalletConnectDecoder()

    def register_validated_addresses(
        self, addresses: List[ValidatedCryptoAddressRecord]
    ) -> None:
        """Appends validated cryptocurrency address records to master registry."""
        self.validated_addresses.extend(addresses)

    def register_unpacked_abi_calls(
        self, calls: List[UnpackedSmartContractABIRecord]
    ) -> None:
        """Appends unpacked Smart Contract ABI call records to master registry."""
        self.abi_calls.extend(calls)

    def register_walletconnect_records(
        self, records: List[WalletConnectAuditRecord]
    ) -> None:
        """Appends WalletConnect audit records to master registry."""
        self.walletconnect_records.extend(records)

    def export_to_master_db(self, export_db_path: str) -> str:
        """
        Creates address_validators_abi_and_walletconnect.sqlite schema and inserts
        all validated addresses, unpacked ABI calls, and WalletConnect audits.
        """
        os.makedirs(os.path.dirname(os.path.abspath(export_db_path)), exist_ok=True)

        conn = sqlite3.connect(export_db_path)
        cursor = conn.cursor()

        # Table 1: validated_crypto_addresses_global_index
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS validated_crypto_addresses_global_index (
                addr_index_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                blockchain_ecosystem TEXT NOT NULL,
                canonical_address TEXT NOT NULL,
                checksum_verification_method TEXT NOT NULL,
                discovered_in_module_and_app TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                associated_actor_or_context TEXT,
                first_seen_utc_iso TEXT,
                recovery_classification TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_val_addr ON validated_crypto_addresses_global_index(canonical_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_val_eco ON validated_crypto_addresses_global_index(blockchain_ecosystem)")

        # Table 2: unpacked_smart_contract_abi_calls
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS unpacked_smart_contract_abi_calls (
                abi_call_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                linked_web3_tx_uid INTEGER,
                tx_hash_hex TEXT,
                blockchain_network TEXT NOT NULL,
                outer_contract_address TEXT NOT NULL,
                resolved_token_or_protocol TEXT,
                selector_4byte_hex TEXT NOT NULL,
                decoded_function_name TEXT NOT NULL,
                unpacked_true_sender TEXT,
                unpacked_true_recipient_or_spender TEXT NOT NULL,
                unpacked_raw_uint256_amount TEXT,
                unpacked_human_token_amount TEXT,
                is_unlimited_approval_or_drainer INTEGER DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_abi_recip ON unpacked_smart_contract_abi_calls(unpacked_true_recipient_or_spender)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_abi_outer ON unpacked_smart_contract_abi_calls(outer_contract_address)")

        # Table 3: walletconnect_v2_sessions_and_rpc_audit
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS walletconnect_v2_sessions_and_rpc_audit (
                wc_audit_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_instance_id INTEGER NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                wc_record_type TEXT NOT NULL,
                session_topic_hex TEXT,
                dapp_peer_name TEXT,
                dapp_peer_url TEXT NOT NULL,
                exposed_caip10_accounts_json TEXT,
                rpc_method_and_params_json TEXT,
                is_phishing_permit_drainer_sig INTEGER DEFAULT 0,
                session_paired_utc_iso TEXT,
                session_expiry_utc_iso TEXT,
                recovery_classification TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_wc_topic ON walletconnect_v2_sessions_and_rpc_audit(session_topic_hex)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_wc_url ON walletconnect_v2_sessions_and_rpc_audit(dapp_peer_url)")

        # Insert addresses
        for a in self.validated_addresses:
            cursor.execute("""
                INSERT INTO validated_crypto_addresses_global_index (
                    blockchain_ecosystem, canonical_address, checksum_verification_method,
                    discovered_in_module_and_app, source_vfs_file_id, associated_actor_or_context,
                    first_seen_utc_iso, recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a.blockchain_ecosystem.value if hasattr(a.blockchain_ecosystem, "value") else str(a.blockchain_ecosystem),
                a.canonical_address,
                a.checksum_verification_method,
                a.discovered_in_module_and_app,
                a.source_vfs_file_id,
                a.associated_actor_or_context,
                a.first_seen_utc_iso,
                a.recovery_classification.value if hasattr(a.recovery_classification, "value") else str(a.recovery_classification),
            ))
            a.addr_index_uid = cursor.lastrowid

        # Insert ABI calls
        for c in self.abi_calls:
            cursor.execute("""
                INSERT INTO unpacked_smart_contract_abi_calls (
                    linked_web3_tx_uid, tx_hash_hex, blockchain_network,
                    outer_contract_address, resolved_token_or_protocol,
                    selector_4byte_hex, decoded_function_name, unpacked_true_sender,
                    unpacked_true_recipient_or_spender, unpacked_raw_uint256_amount,
                    unpacked_human_token_amount, is_unlimited_approval_or_drainer
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                c.linked_web3_tx_uid,
                c.tx_hash_hex,
                c.blockchain_network,
                c.outer_contract_address,
                c.resolved_token_or_protocol,
                c.selector_4byte_hex,
                c.decoded_function_name,
                c.unpacked_true_sender,
                c.unpacked_true_recipient_or_spender,
                c.unpacked_raw_uint256_amount,
                c.unpacked_human_token_amount,
                c.is_unlimited_approval_or_drainer,
            ))
            c.abi_call_uid = cursor.lastrowid

        # Insert WalletConnect audit records
        for w in self.walletconnect_records:
            cursor.execute("""
                INSERT INTO walletconnect_v2_sessions_and_rpc_audit (
                    app_instance_id, source_vfs_file_id, wc_record_type,
                    session_topic_hex, dapp_peer_name, dapp_peer_url,
                    exposed_caip10_accounts_json, rpc_method_and_params_json,
                    is_phishing_permit_drainer_sig, session_paired_utc_iso,
                    session_expiry_utc_iso, recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                w.app_instance_id,
                w.source_vfs_file_id,
                w.wc_record_type.value if hasattr(w.wc_record_type, "value") else str(w.wc_record_type),
                w.session_topic_hex,
                w.dapp_peer_name,
                w.dapp_peer_url,
                w.exposed_caip10_accounts_json,
                w.rpc_method_and_params_json,
                w.is_phishing_permit_drainer_sig,
                w.session_paired_utc_iso,
                w.session_expiry_utc_iso,
                w.recovery_classification.value if hasattr(w.recovery_classification, "value") else str(w.recovery_classification),
            ))
            w.wc_audit_uid = cursor.lastrowid

        conn.commit()
        conn.close()
        return export_db_path
