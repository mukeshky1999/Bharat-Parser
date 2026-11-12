"""
Sub-Engine 4.1D: Ledger Live Hardware Companion Decoder.
Parses /files/app.json and RKStorage caches from Ledger Live.
Extracts BLE hardware device pairings (Nano X/S Plus), extended public keys (xpub/ypub/zpub),
derivation paths, cached balances, and historical cold-wallet operations.
"""

from datetime import datetime, timezone
import json
import os
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

CURRENCY_SPECS = {
    "bitcoin": (BlockchainNetwork.BITCOIN, "BTC", 8),
    "ethereum": (BlockchainNetwork.ETHEREUM_ERC20, "ETH", 18),
    "tron": (BlockchainNetwork.TRON_TRC20, "TRX", 6),
    "bsc": (BlockchainNetwork.BSC_BEP20, "BNB", 18),
    "polygon": (BlockchainNetwork.POLYGON_POS, "MATIC", 18),
    "solana": (BlockchainNetwork.SOLANA, "SOL", 9),
}


class LedgerLiveDecoder:
    """Decodes Ledger Live companion app data from app.json and database stores."""

    def __init__(self) -> None:
        self.supported_devices = ("nanoX", "nanoS", "nanoSP", "stax", "flex")

    def decode_sandbox(
        self,
        app_json_path: str,
        source_vfs_file_id: int = 0
    ) -> Dict[str, Any]:
        """
        Parses Ledger Live app.json file.
        Returns dict containing 'accounts', 'transactions', and 'known_devices'.
        """
        accounts: List[Web3WalletAccountRecord] = []
        transactions: List[Web3TransactionRecord] = []
        known_devices: List[Dict[str, Any]] = []

        if not os.path.exists(app_json_path):
            return {
                "accounts": accounts,
                "transactions": transactions,
                "known_devices": known_devices,
            }

        try:
            with open(app_json_path, "r", encoding="utf-8") as fh:
                app_data = json.load(fh)
        except Exception:
            return {
                "accounts": accounts,
                "transactions": transactions,
                "known_devices": known_devices,
            }

        root_data = app_data.get("data", {})

        # Extract BLE Known Devices
        ble_section = root_data.get("ble", {})
        known_devs = ble_section.get("knownDevices", [])
        device_descriptions = []
        for dev in known_devs:
            known_devices.append(dev)
            m_id = dev.get("modelId", "ledger_hardware")
            d_name = dev.get("name", "Ledger Hardware Device")
            b_id = dev.get("id", "")
            device_descriptions.append(f"{m_id} ({d_name}, MAC/ID: {b_id})")

        hardware_device_summary = "; ".join(device_descriptions) if device_descriptions else "Ledger Hardware Cold Wallet"

        # Extract Accounts
        raw_accounts = root_data.get("accounts", [])
        for acc in raw_accounts:
            acc_id = acc.get("id", "")
            xpub = acc.get("xpub")
            name = acc.get("name", "Ledger Cold Account")
            fresh_addr = acc.get("freshAddress", "")
            fresh_path = acc.get("freshAddressPath")
            raw_balance = acc.get("balance", "0")
            currency_id = str(acc.get("currencyId", "bitcoin")).lower()

            net_info = CURRENCY_SPECS.get(
                currency_id, (BlockchainNetwork.BITCOIN, "BTC", 8)
            )
            network, symbol, decimals = net_info

            raw_bigint_str, human_bal_str = format_bigint_decimal(raw_balance, decimals)
            cached_bal_dict = {symbol: human_bal_str}

            ev_state = EvidentiaryState(
                existence=EvidentiaryExistence.OBSERVED,
                access=EvidentiaryAccess.PLAINTEXT,
                storage_layer=EvidentiaryStorage.LIVE_RECORD,
                provenance_pointer=f"{app_json_path}::data.accounts::{acc_id}",
                forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
            )

            acc_rec = Web3WalletAccountRecord(
                wallet_app_name="Ledger Live",
                source_vfs_file_id=source_vfs_file_id,
                recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                account_control_mode=Web3AccountControlMode.PAIRED_HARDWARE_COLD_WALLET,
                blockchain_network=network,
                public_address_canonical=fresh_addr,
                extended_public_key_xpub=xpub,
                bip44_derivation_path=fresh_path,
                user_assigned_wallet_label=name,
                paired_hardware_device_info=hardware_device_summary,
                cached_token_balances_json=json.dumps(cached_bal_dict),
                evidentiary_state=ev_state,
            )
            accounts.append(acc_rec)

            # Extract Operations (historical transactions)
            ops = acc.get("operations", [])
            for op in ops:
                op_id = op.get("id", "")
                tx_hash = op.get("hash", op_id)
                op_type = op.get("type", "IN")
                raw_val = op.get("value", "0")
                senders = op.get("senders", [])
                recipients = op.get("recipients", [])
                date_str = op.get("date", "")

                from_addr = senders[0] if senders else None
                to_addr = recipients[0] if recipients else None

                raw_val_str, human_op_amt = format_bigint_decimal(raw_val, decimals)

                try:
                    if date_str.endswith("Z"):
                        clean_dt = date_str[:-1] + "+00:00"
                    else:
                        clean_dt = date_str
                    dt = datetime.fromisoformat(clean_dt)
                    forensic_ts = ForensicTimestamp.from_unix_seconds(dt.timestamp())
                except Exception:
                    forensic_ts = ForensicTimestamp.from_unix_seconds(0)

                op_ev_state = EvidentiaryState(
                    existence=EvidentiaryExistence.OBSERVED,
                    access=EvidentiaryAccess.PLAINTEXT,
                    storage_layer=EvidentiaryStorage.LIVE_RECORD,
                    provenance_pointer=f"{app_json_path}::data.accounts::{acc_id}::operations::{tx_hash}",
                    forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
                )

                tx_rec = Web3TransactionRecord(
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    tx_hash_hex=tx_hash,
                    blockchain_network=network,
                    tx_operation_type=Web3TxOperationType.NATIVE_COIN_TRANSFER,
                    token_symbol=symbol,
                    from_address=from_addr,
                    to_recipient_address=to_addr,
                    raw_bigint_amount_str=raw_val_str,
                    token_decimals=decimals,
                    human_amount_decimal_str=human_op_amt,
                    tx_status="UNVERIFIED_LOCAL_RECORD",  # a wallet cache is not proof of on-chain confirmation
                    tx_timestamp=forensic_ts,
                    evidentiary_state=op_ev_state,
                )
                transactions.append(tx_rec)

        return {
            "accounts": accounts,
            "transactions": transactions,
            "known_devices": known_devices,
        }
