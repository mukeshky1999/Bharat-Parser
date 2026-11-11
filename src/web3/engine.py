"""
Master Sub-Engine 4.1: Web3 Self-Custody Wallets Engine & Master SQLite Exporter.
Coordinates TronLink, MetaMask, Trust Wallet, Cake Wallet, and Ledger Live decoders
and exports unified accounts, transactions, and cross-chain swaps into web3_self_custody_wallets_engine.sqlite.
"""

from datetime import datetime, timezone
import os
import sqlite3
from typing import Any, Dict, List, Optional

from src.core.enums import ForensicGroup, ResidualConfidence
from src.core.timestamps import ForensicTimestamp
from src.web3.models import (
    Web3CrossChainSwapRecord,
    Web3TransactionRecord,
    Web3WalletAccountRecord,
)
from src.web3.tronlink import TronLinkDecoder
from src.web3.metamask import MetaMaskDecoder
from src.web3.trustwallet import TrustWalletDecoder
from src.web3.cakewallet import CakeWalletDecoder
from src.web3.ledgerlive import LedgerLiveDecoder


class Web3SelfCustodyWalletsEngine:
    """Master engine orchestrating wallet decoders and exporting to SQLite."""

    def __init__(self) -> None:
        self.accounts: List[Web3WalletAccountRecord] = []
        self.transactions: List[Web3TransactionRecord] = []
        self.swaps: List[Web3CrossChainSwapRecord] = []

        self.tronlink_decoder = TronLinkDecoder()
        self.metamask_decoder = MetaMaskDecoder()
        self.trustwallet_decoder = TrustWalletDecoder()
        self.cakewallet_decoder = CakeWalletDecoder()
        self.ledgerlive_decoder = LedgerLiveDecoder()

    def register_accounts(self, accounts: List[Web3WalletAccountRecord]) -> None:
        """Appends discovered wallet accounts to the master registry."""
        self.accounts.extend(accounts)

    def register_transactions(self, transactions: List[Web3TransactionRecord]) -> None:
        """Appends discovered transactions to the master registry."""
        self.transactions.extend(transactions)

    def register_swaps(self, swaps: List[Web3CrossChainSwapRecord]) -> None:
        """Appends discovered cross-chain swap orders to the master registry."""
        self.swaps.extend(swaps)

    def process_sandbox_target(
        self,
        app_name: str,
        target_path: str,
        source_vfs_file_id: int = 0
    ) -> Dict[str, Any]:
        """Dispatches target path to appropriate decoder and registers extracted records."""
        norm_name = app_name.lower()
        result: Dict[str, Any] = {"accounts": [], "transactions": [], "swaps": []}

        if "tronlink" in norm_name:
            res = self.tronlink_decoder.decode_sandbox(target_path, source_vfs_file_id)
            self.register_accounts(res.get("accounts", []))
            self.register_transactions(res.get("transactions", []))
            result = res
        elif "metamask" in norm_name:
            res = self.metamask_decoder.decode_sandbox(target_path, source_vfs_file_id)
            self.register_accounts(res.get("accounts", []))
            self.register_transactions(res.get("transactions", []))
            result = res
        elif "trust" in norm_name:
            res = self.trustwallet_decoder.decode_sandbox(target_path, source_vfs_file_id)
            self.register_accounts(res.get("accounts", []))
            self.register_transactions(res.get("transactions", []))
            result = res
        elif "cake" in norm_name or "monero" in norm_name:
            res = self.cakewallet_decoder.decode_sandbox(target_path, source_vfs_file_id)
            self.register_swaps(res.get("swaps", []))
            self.register_accounts(res.get("accounts", []))
            self.register_transactions(res.get("transactions", []))
            result = res
        elif "ledger" in norm_name:
            res = self.ledgerlive_decoder.decode_sandbox(target_path, source_vfs_file_id)
            self.register_accounts(res.get("accounts", []))
            self.register_transactions(res.get("transactions", []))
            result = res

        return result

    def export_to_master_db(self, export_db_path: str) -> str:
        """
        Creates web3_self_custody_wallets_engine.sqlite schema and inserts all
        registered accounts, transactions, and cross-chain swaps.
        """
        os.makedirs(os.path.dirname(os.path.abspath(export_db_path)), exist_ok=True)

        conn = sqlite3.connect(export_db_path)
        cursor = conn.cursor()

        # Table 1: web3_wallet_instances_and_accounts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS web3_wallet_instances_and_accounts (
                web3_account_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_instance_id INTEGER NOT NULL,
                wallet_app_name TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                account_control_mode TEXT NOT NULL,
                blockchain_network TEXT NOT NULL,
                public_address_canonical TEXT NOT NULL,
                tron_hex41_representation TEXT,
                extended_public_key_xpub TEXT,
                bip44_derivation_path TEXT,
                user_assigned_wallet_label TEXT,
                paired_hardware_device_info TEXT,
                cached_token_balances_json TEXT,
                is_vault_unwrapped INTEGER DEFAULT 0
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_web3_acc_addr ON web3_wallet_instances_and_accounts(public_address_canonical)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_web3_acc_net ON web3_wallet_instances_and_accounts(blockchain_network)")

        # Table 2: web3_wallet_transactions_ledger
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS web3_wallet_transactions_ledger (
                web3_tx_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                web3_account_uid INTEGER NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                tx_hash_hex TEXT NOT NULL,
                blockchain_network TEXT NOT NULL,
                tx_operation_type TEXT NOT NULL,
                token_symbol TEXT NOT NULL,
                token_contract_address TEXT,
                from_address TEXT,
                to_recipient_address TEXT,
                raw_bigint_amount_str TEXT NOT NULL,
                token_decimals INTEGER NOT NULL,
                human_amount_decimal_str TEXT NOT NULL,
                monero_secret_tx_key TEXT,
                tx_status TEXT NOT NULL,
                tx_utc_ns INTEGER NOT NULL,
                tx_utc_iso TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_web3_tx_hash ON web3_wallet_transactions_ledger(tx_hash_hex)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_web3_tx_recip ON web3_wallet_transactions_ledger(to_recipient_address)")

        # Table 3: web3_cross_chain_bridge_and_swap_orders
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS web3_cross_chain_bridge_and_swap_orders (
                swap_order_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_instance_id INTEGER NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                swap_aggregator_provider TEXT NOT NULL,
                provider_order_or_trade_id TEXT NOT NULL,
                input_chain_and_asset TEXT NOT NULL,
                input_amount_decimal TEXT NOT NULL,
                input_deposit_txid TEXT,
                output_chain_and_asset TEXT NOT NULL,
                output_amount_decimal TEXT,
                destination_payout_address TEXT NOT NULL,
                output_payout_txid TEXT,
                swap_created_utc_iso TEXT NOT NULL,
                recovery_classification TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_web3_swap_trade_id ON web3_cross_chain_bridge_and_swap_orders(provider_order_or_trade_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_web3_swap_dest ON web3_cross_chain_bridge_and_swap_orders(destination_payout_address)")

        # Insert accounts
        for acc in self.accounts:
            cursor.execute("""
                INSERT INTO web3_wallet_instances_and_accounts (
                    app_instance_id, wallet_app_name, source_vfs_file_id, recovery_classification,
                    account_control_mode, blockchain_network, public_address_canonical,
                    tron_hex41_representation, extended_public_key_xpub, bip44_derivation_path,
                    user_assigned_wallet_label, paired_hardware_device_info,
                    cached_token_balances_json, is_vault_unwrapped
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                acc.app_instance_id,
                acc.wallet_app_name,
                acc.source_vfs_file_id,
                acc.recovery_classification.value if hasattr(acc.recovery_classification, "value") else str(acc.recovery_classification),
                acc.account_control_mode.value if hasattr(acc.account_control_mode, "value") else str(acc.account_control_mode),
                acc.blockchain_network.value if hasattr(acc.blockchain_network, "value") else str(acc.blockchain_network),
                acc.public_address_canonical,
                acc.tron_hex41_representation,
                acc.extended_public_key_xpub,
                acc.bip44_derivation_path,
                acc.user_assigned_wallet_label,
                acc.paired_hardware_device_info,
                acc.cached_token_balances_json,
                acc.is_vault_unwrapped,
            ))
            acc.web3_account_uid = cursor.lastrowid

        # Insert transactions
        for tx in self.transactions:
            ts_iso = tx.tx_timestamp.utc_iso8601 if tx.tx_timestamp else datetime.now(timezone.utc).isoformat()
            # Calculate nanoseconds
            try:
                dt_obj = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
                ns_val = int(dt_obj.timestamp() * 1_000_000_000)
            except Exception:
                ns_val = 0

            cursor.execute("""
                INSERT INTO web3_wallet_transactions_ledger (
                    web3_account_uid, source_vfs_file_id, recovery_classification,
                    tx_hash_hex, blockchain_network, tx_operation_type, token_symbol,
                    token_contract_address, from_address, to_recipient_address,
                    raw_bigint_amount_str, token_decimals, human_amount_decimal_str,
                    monero_secret_tx_key, tx_status, tx_utc_ns, tx_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tx.web3_account_uid or 1,
                tx.source_vfs_file_id,
                tx.recovery_classification.value if hasattr(tx.recovery_classification, "value") else str(tx.recovery_classification),
                tx.tx_hash_hex,
                tx.blockchain_network.value if hasattr(tx.blockchain_network, "value") else str(tx.blockchain_network),
                tx.tx_operation_type.value if hasattr(tx.tx_operation_type, "value") else str(tx.tx_operation_type),
                tx.token_symbol,
                tx.token_contract_address,
                tx.from_address,
                tx.to_recipient_address,
                tx.raw_bigint_amount_str,
                tx.token_decimals,
                tx.human_amount_decimal_str,
                tx.monero_secret_tx_key,
                tx.tx_status,
                ns_val,
                ts_iso,
            ))
            tx.web3_tx_uid = cursor.lastrowid

        # Insert cross-chain swap orders
        for sw in self.swaps:
            sw_iso = sw.swap_timestamp.utc_iso8601 if sw.swap_timestamp else datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO web3_cross_chain_bridge_and_swap_orders (
                    app_instance_id, source_vfs_file_id, swap_aggregator_provider,
                    provider_order_or_trade_id, input_chain_and_asset, input_amount_decimal,
                    input_deposit_txid, output_chain_and_asset, output_amount_decimal,
                    destination_payout_address, output_payout_txid, swap_created_utc_iso,
                    recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sw.app_instance_id,
                sw.source_vfs_file_id,
                sw.swap_aggregator_provider,
                sw.provider_order_or_trade_id,
                sw.input_chain_and_asset,
                sw.input_amount_decimal,
                sw.input_deposit_txid,
                sw.output_chain_and_asset,
                sw.output_amount_decimal,
                sw.destination_payout_address,
                sw.output_payout_txid,
                sw_iso,
                sw.recovery_classification.value if hasattr(sw.recovery_classification, "value") else str(sw.recovery_classification),
            ))
            sw.swap_order_uid = cursor.lastrowid

        conn.commit()
        conn.close()
        return export_db_path
