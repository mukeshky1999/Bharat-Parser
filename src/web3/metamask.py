"""
Sub-Engine 4.1C: MetaMask Mobile Deep Decoder.
Unpacks double-stringified Redux-Persist JSON in RKStorage (catalystLocalStorage).
Preserves arbitrary-precision uint256 balances/transfers and extracts accounts, transactions, and DApps.
"""

import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryState,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.core.timestamps import ForensicTimestamp
from src.web3.address_utils import format_bigint_decimal
from src.web3.models import (
    BlockchainNetwork,
    Web3AccountControlMode,
    Web3TransactionRecord,
    Web3TxOperationType,
    Web3WalletAccountRecord,
)


def recursive_json_unpack(obj: Any) -> Any:
    """Recursively unpacks double-serialized or escaped JSON strings."""
    if isinstance(obj, str):
        stripped = obj.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                nested = json.loads(stripped)
                return recursive_json_unpack(nested)
            except Exception:
                return obj
        return obj
    elif isinstance(obj, dict):
        return {k: recursive_json_unpack(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [recursive_json_unpack(elem) for elem in obj]
    return obj


class MetaMaskDecoder:
    """Decodes MetaMask RKStorage database and extracts accounts, balances, and txs."""

    def __init__(self) -> None:
        self.default_chain_id = "0x1"

    def decode_sandbox(
        self,
        rk_db_path: str,
        source_vfs_file_id: int = 0
    ) -> Dict[str, Any]:
        """
        Parses MetaMask RKStorage SQLite file.
        Returns dict containing 'accounts', 'transactions', 'dapp_sessions', 'vault'.
        """
        accounts: List[Web3WalletAccountRecord] = []
        transactions: List[Web3TransactionRecord] = []
        dapp_sessions: List[Dict[str, Any]] = []
        vault_payload: Optional[str] = None

        if not os.path.exists(rk_db_path):
            return {
                "accounts": accounts,
                "transactions": transactions,
                "dapp_sessions": dapp_sessions,
                "vault": vault_payload,
            }

        conn = sqlite3.connect(rk_db_path)
        cursor = conn.cursor()

        raw_persist_root: Optional[str] = None
        try:
            cursor.execute(
                "SELECT value FROM catalystLocalStorage WHERE key = 'persist:root' LIMIT 1"
            )
            row = cursor.fetchone()
            if row:
                raw_persist_root = row[0]
        except Exception:
            # Fallback search across any table with key/value
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tbls = [r[0] for r in cursor.fetchall()]
                for t in tbls:
                    try:
                        cursor.execute(f"SELECT value FROM {t} WHERE key = 'persist:root' LIMIT 1")
                        r = cursor.fetchone()
                        if r:
                            raw_persist_root = r[0]
                            break
                    except Exception:
                        continue
            except Exception:
                raw_persist_root = None
        finally:
            conn.close()

        if not raw_persist_root:
            return {
                "accounts": accounts,
                "transactions": transactions,
                "dapp_sessions": dapp_sessions,
                "vault": vault_payload,
            }

        try:
            root_data = json.loads(raw_persist_root)
            unpacked = recursive_json_unpack(root_data)
        except Exception:
            return {
                "accounts": accounts,
                "transactions": transactions,
                "dapp_sessions": dapp_sessions,
                "vault": vault_payload,
            }

        engine_data = unpacked.get("engine", {})
        bg_state = engine_data.get("backgroundState", {})

        # 1. Extract Vault
        keyring_ctrl = bg_state.get("KeyringController", {})
        if "vault" in keyring_ctrl:
            vault_payload = json.dumps(keyring_ctrl["vault"]) if isinstance(keyring_ctrl["vault"], (dict, list)) else str(keyring_ctrl["vault"])

        # 2. Extract Accounts & Balances
        acc_tracker = bg_state.get("AccountTrackerController", {})
        tracked_accounts = acc_tracker.get("accounts", {})

        pref_ctrl = bg_state.get("PreferencesController", {})
        identities = pref_ctrl.get("identities", {})

        # Combine all discovered addresses
        all_addrs = set(tracked_accounts.keys()) | set(identities.keys())
        for addr in all_addrs:
            canon_addr = addr.lower()
            name_val = "MetaMask Account"
            if addr in identities:
                name_val = identities[addr].get("name", name_val)

            cached_bal_dict = {}
            if addr in tracked_accounts:
                raw_bal_hex = tracked_accounts[addr].get("balance", "0x0")
                raw_bigint_str, human_bal_str = format_bigint_decimal(raw_bal_hex, 18)
                cached_bal_dict["ETH"] = human_bal_str

            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                provenance_pointer=f"{rk_db_path}::persist:root::AccountTrackerController::{addr}",
                forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
            )

            acc_rec = Web3WalletAccountRecord(
                wallet_app_name="MetaMask",
                source_vfs_file_id=source_vfs_file_id,
                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                account_control_mode=Web3AccountControlMode.FULL_PRIVATE_KEY_OR_SEED,
                blockchain_network=BlockchainNetwork.ETHEREUM_ERC20,
                public_address_canonical=canon_addr,
                user_assigned_wallet_label=name_val,
                cached_token_balances_json=json.dumps(cached_bal_dict) if cached_bal_dict else None,
                evidentiary_state=ev_state,
            )
            accounts.append(acc_rec)

        # 3. Extract Transactions
        tx_ctrl = bg_state.get("TransactionController", {})
        tx_list = tx_ctrl.get("transactions", [])
        for tx_obj in tx_list:
            tx_id = tx_obj.get("id", "")
            tx_hash = tx_obj.get("hash", "")
            chain_id = tx_obj.get("chainId", "0x1")
            raw_time = tx_obj.get("time", 0)
            status_str = str(tx_obj.get("status", "CONFIRMED")).upper()

            tx_params = tx_obj.get("txParams", {})
            from_addr = tx_params.get("from")
            to_addr = tx_params.get("to")
            raw_val_str = tx_params.get("value", "0x0")
            raw_bigint_str, human_amount_str = format_bigint_decimal(raw_val_str, 18)

            network = BlockchainNetwork.ETHEREUM_ERC20
            if str(chain_id) in ["0x38", "56"]:
                network = BlockchainNetwork.BSC_BEP20
            elif str(chain_id) in ["0x89", "137"]:
                network = BlockchainNetwork.POLYGON_POS

            time_val = int(raw_time) if raw_time else 0
            if time_val > 10_000_000_000:
                forensic_ts = ForensicTimestamp.from_unix_milliseconds(time_val)
            else:
                forensic_ts = ForensicTimestamp.from_unix_seconds(time_val)

            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                provenance_pointer=f"{rk_db_path}::persist:root::TransactionController::{tx_hash or tx_id}",
                forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
            )

            tx_rec = Web3TransactionRecord(
                source_vfs_file_id=source_vfs_file_id,
                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                tx_hash_hex=tx_hash if tx_hash else tx_id,
                blockchain_network=network,
                tx_operation_type=Web3TxOperationType.NATIVE_COIN_TRANSFER,
                token_symbol="ETH" if network == BlockchainNetwork.ETHEREUM_ERC20 else "BNB",
                from_address=from_addr,
                to_recipient_address=to_addr,
                raw_bigint_amount_str=raw_bigint_str,
                token_decimals=18,
                human_amount_decimal_str=human_amount_str,
                tx_status=status_str,
                tx_timestamp=forensic_ts,
                evidentiary_state=ev_state,
            )
            transactions.append(tx_rec)

        # 4. Extract Connected DApps & Browser History
        browser_data = unpacked.get("browser", {})
        hist_list = browser_data.get("history", [])
        for h in hist_list:
            if isinstance(h, dict) and "url" in h:
                dapp_sessions.append(h)

        return {
            "accounts": accounts,
            "transactions": transactions,
            "dapp_sessions": dapp_sessions,
            "vault": vault_payload,
        }
