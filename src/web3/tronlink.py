"""
Sub-Engine 4.1B: TronLink Pro Deep Sandbox Decoder.
Decodes TronLink Pro SQLite databases, MMKV, and shared_prefs.
Converts 21-byte 41... hex strings to 34-char 'T' Base58Check, identifies watch-only wallets,
and extracts TRC-20 USDT and Energy Delegation transactions.
"""

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
from src.web3.address_utils import (
    hex41_to_base58check,
    base58check_to_hex41,
    format_bigint_decimal,
)
from src.web3.models import (
    BlockchainNetwork,
    Web3AccountControlMode,
    Web3TransactionRecord,
    Web3TxOperationType,
    Web3WalletAccountRecord,
)

TRON_USDT_CONTRACT_B58 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_USDT_CONTRACT_HEX = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"


class TronLinkDecoder:
    """Decodes TronLink Pro artifacts and extracts accounts and transaction ledgers."""

    def __init__(self) -> None:
        self.target_network = BlockchainNetwork.TRON_TRC20

    def decode_sandbox(
        self,
        db_path: str,
        source_vfs_file_id: int = 0
    ) -> Dict[str, Any]:
        """
        Parses TronLink Pro SQLite database file.
        Returns dictionary with 'accounts' and 'transactions'.
        """
        accounts: List[Web3WalletAccountRecord] = []
        transactions: List[Web3TransactionRecord] = []

        if not os.path.exists(db_path):
            return {"accounts": accounts, "transactions": transactions}

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Step 1: Detect tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row["name"] for row in cursor.fetchall()]

        # Step 2: Extract Accounts
        account_tables = [t for t in tables if any(k in t.lower() for k in ["wallet", "account", "user"])]
        for tbl in account_tables:
            cursor.execute(f"PRAGMA table_info([{tbl}])")
            cols = {col["name"].lower(): col["name"] for col in cursor.fetchall()}

            addr_col = cols.get("address") or cols.get("pubkey") or cols.get("owner_address")
            if not addr_col:
                continue

            name_col = cols.get("name") or cols.get("wallet_name") or cols.get("account_name")
            watch_col = cols.get("iswatchonly") or cols.get("is_watch_only") or cols.get("coldwallet")
            type_col = cols.get("create_type") or cols.get("type") or cols.get("wallet_type")

            query = f"SELECT * FROM [{tbl}]"
            cursor.execute(query)
            for row in cursor.fetchall():
                raw_addr = str(row[addr_col] or "").strip()
                if not raw_addr:
                    continue

                if raw_addr.startswith("41") or len(raw_addr) == 42:
                    canon_addr = hex41_to_base58check(raw_addr)
                    hex41_addr = raw_addr.lower()
                elif raw_addr.startswith("T"):
                    canon_addr = raw_addr
                    hex41_addr = base58check_to_hex41(raw_addr)
                else:
                    canon_addr = raw_addr
                    hex41_addr = None

                user_label = str(row[name_col]) if name_col and row[name_col] is not None else None

                is_watch = 0
                if watch_col and row[watch_col]:
                    is_watch = int(row[watch_col])

                create_type = 0
                if type_col and row[type_col] is not None:
                    create_type = int(row[type_col])

                if is_watch == 1 or create_type == 3:
                    mode = Web3AccountControlMode.WATCH_ONLY_OBSERVED_WALLET
                elif create_type == 4:
                    mode = Web3AccountControlMode.PAIRED_HARDWARE_COLD_WALLET
                else:
                    mode = Web3AccountControlMode.FULL_PRIVATE_KEY_OR_SEED

                ev_state = EvidentiaryState(
                    existence=EvidentiaryExistence.OBSERVED,
                    access=EvidentiaryAccess.PLAINTEXT,
                    storage_layer=EvidentiaryStorage.LIVE_RECORD,
                    provenance_pointer=f"{db_path}::{tbl}::row_{row['id'] if 'id' in cols else '0'}",
                    forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
                )

                acc_record = Web3WalletAccountRecord(
                    wallet_app_name="TronLink Pro",
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    account_control_mode=mode,
                    blockchain_network=BlockchainNetwork.TRON_TRC20,
                    public_address_canonical=canon_addr,
                    tron_hex41_representation=hex41_addr,
                    user_assigned_wallet_label=user_label,
                    evidentiary_state=ev_state,
                )
                accounts.append(acc_record)

        # Step 3: Extract Transactions
        tx_tables = [t for t in tables if any(k in t.lower() for k in ["trans", "transfer", "trc20", "tx"])]
        for tbl in tx_tables:
            cursor.execute(f"PRAGMA table_info([{tbl}])")
            cols = {col["name"].lower(): col["name"] for col in cursor.fetchall()}

            tx_hash_col = cols.get("tx_id") or cols.get("txid") or cols.get("hash")
            if not tx_hash_col:
                continue

            owner_col = cols.get("owner_address") or cols.get("from_address") or cols.get("from")
            to_col = cols.get("to_address") or cols.get("to") or cols.get("recipient_address")
            contract_col = cols.get("contract_address") or cols.get("contract")
            type_col = cols.get("contract_type") or cols.get("type")
            amount_col = cols.get("amount") or cols.get("quant") or cols.get("value")
            ts_col = cols.get("block_timestamp") or cols.get("timestamp") or cols.get("time")

            query = f"SELECT * FROM [{tbl}]"
            cursor.execute(query)
            for row in cursor.fetchall():
                tx_hash = str(row[tx_hash_col] or "").strip()
                if not tx_hash:
                    continue

                raw_owner = str(row[owner_col] or "").strip() if owner_col else ""
                raw_to = str(row[to_col] or "").strip() if to_col else ""
                raw_contract = str(row[contract_col] or "").strip() if contract_col else ""
                contract_type_val = int(row[type_col]) if type_col and row[type_col] is not None else 0
                raw_amount_val = row[amount_col] if amount_col and row[amount_col] is not None else 0
                raw_ts = row[ts_col] if ts_col and row[ts_col] is not None else 0

                from_addr = hex41_to_base58check(raw_owner) if raw_owner else None
                to_addr = hex41_to_base58check(raw_to) if raw_to else None

                contract_addr_b58 = hex41_to_base58check(raw_contract) if raw_contract else None

                # Determine operation type and token parameters
                if contract_type_val == 57:
                    # DelegateResourceContract (Energy Delegation)
                    op_type = Web3TxOperationType.TRON_ENERGY_DELEGATION
                    token_symbol = "ENERGY"
                    decimals = 0
                    raw_bigint_str, human_amount_str = format_bigint_decimal(raw_amount_val, 0)
                elif contract_type_val == 31 or raw_contract:
                    # Smart contract call (e.g., TRC-20 USDT)
                    op_type = Web3TxOperationType.SMART_CONTRACT_TOKEN_TRANSFER
                    if contract_addr_b58 == TRON_USDT_CONTRACT_B58 or raw_contract.lower() == TRON_USDT_CONTRACT_HEX:
                        token_symbol = "USDT"
                        decimals = 6
                    else:
                        token_symbol = "TRC20_TOKEN"
                        decimals = 6
                    raw_bigint_str, human_amount_str = format_bigint_decimal(raw_amount_val, decimals)
                else:
                    # Native TRX transfer
                    op_type = Web3TxOperationType.NATIVE_COIN_TRANSFER
                    token_symbol = "TRX"
                    decimals = 6
                    raw_bigint_str, human_amount_str = format_bigint_decimal(raw_amount_val, decimals)

                # Parse timestamp
                ts_int = int(raw_ts) if raw_ts else 0
                if ts_int > 10_000_000_000:
                    forensic_ts = ForensicTimestamp.from_unix_milliseconds(ts_int)
                else:
                    forensic_ts = ForensicTimestamp.from_unix_seconds(ts_int)

                ev_state = EvidentiaryState(
                    existence=EvidentiaryExistence.OBSERVED,
                    access=EvidentiaryAccess.PLAINTEXT,
                    storage_layer=EvidentiaryStorage.LIVE_RECORD,
                    provenance_pointer=f"{db_path}::{tbl}::{tx_hash}",
                    forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
                )

                tx_record = Web3TransactionRecord(
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    tx_hash_hex=tx_hash,
                    blockchain_network=BlockchainNetwork.TRON_TRC20,
                    tx_operation_type=op_type,
                    token_symbol=token_symbol,
                    token_contract_address=contract_addr_b58,
                    from_address=from_addr,
                    to_recipient_address=to_addr,
                    raw_bigint_amount_str=raw_bigint_str,
                    token_decimals=decimals,
                    human_amount_decimal_str=human_amount_str,
                    tx_status="CONFIRMED",
                    tx_timestamp=forensic_ts,
                    evidentiary_state=ev_state,
                )
                transactions.append(tx_record)

        conn.close()
        return {"accounts": accounts, "transactions": transactions}
