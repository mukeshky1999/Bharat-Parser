"""
Sub-Engine 4.1C: Trust Wallet Multi-Coin Keystore & Sandbox Decoder.
Parses /files/keystore/*.json keystore files, extracting unencrypted activeAccounts
across SLIP-0044 coin types (TRON 195, Ethereum 60, Bitcoin 0, Solana 501, TON 607)
alongside derivation paths and extended public keys (xpub/zpub).
"""

import json
import logging
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
from src.web3.address_utils import hex41_to_base58check, base58check_to_hex41
from src.web3.models import (
    BlockchainNetwork,
    Web3AccountControlMode,
    Web3TransactionRecord,
    Web3WalletAccountRecord,
)

SLIP0044_COIN_MAP = {
    195: BlockchainNetwork.TRON_TRC20,
    60: BlockchainNetwork.ETHEREUM_ERC20,
    20000714: BlockchainNetwork.BSC_BEP20,
    714: BlockchainNetwork.BSC_BEP20,
    966: BlockchainNetwork.POLYGON_POS,
    0: BlockchainNetwork.BITCOIN,
    501: BlockchainNetwork.SOLANA,
    607: BlockchainNetwork.TON_NETWORK,
}

logger = logging.getLogger(__name__)


class TrustWalletDecoder:
    """Decodes Trust Wallet keystores and sandbox databases."""

    def __init__(self) -> None:
        self.default_wallet_type = "mnemonic"

    def decode_sandbox(
        self,
        file_or_dir_path: str,
        source_vfs_file_id: int = 0
    ) -> Dict[str, Any]:
        """
        Parses Trust Wallet keystore JSON file or directory of keystores.
        Returns dict containing 'accounts' and 'transactions'.
        """
        accounts: List[Web3WalletAccountRecord] = []
        transactions: List[Web3TransactionRecord] = []

        if not os.path.exists(file_or_dir_path):
            return {"accounts": accounts, "transactions": transactions}

        files_to_parse: List[str] = []
        if os.path.isfile(file_or_dir_path):
            files_to_parse.append(file_or_dir_path)
        else:
            for root, _, files in os.walk(file_or_dir_path):
                for f in files:
                    if f.endswith(".json"):
                        files_to_parse.append(os.path.join(root, f))

        for file_path in files_to_parse:
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    keystore_data = json.load(fh)
            except Exception as exc:
                logger.warning("could not read keystore %s: %s", file_path, exc)
                continue
            if not isinstance(keystore_data, dict):
                continue

            wallet_id = keystore_data.get("id", "")
            wallet_name = keystore_data.get("name") or ""
            wallet_type = str(keystore_data.get("type") or "").lower()

            # No "type" in the file means the control mode is not known, not "the app holds the seed".
            if wallet_type in ["address", "watch-only", "watch_only"]:
                mode = Web3AccountControlMode.WATCH_ONLY_OBSERVED_WALLET
            elif wallet_type:
                mode = Web3AccountControlMode.FULL_PRIVATE_KEY_OR_SEED
            else:
                mode = Web3AccountControlMode.UNKNOWN

            active_accounts = keystore_data.get("activeAccounts", [])
            if not isinstance(active_accounts, list):
                continue
            for item in active_accounts:
                if not isinstance(item, dict):
                    continue
                raw_addr = str(item.get("address", "")).strip()
                derivation_path = item.get("derivationPath")
                xpub = item.get("extendedPublicKey")

                # A missing or unlisted coin type is an unknown chain, not Ethereum.
                try:
                    coin_type = int(item["coin"])
                    network = SLIP0044_COIN_MAP.get(coin_type, BlockchainNetwork.UNKNOWN)
                except (KeyError, ValueError, TypeError):
                    coin_type = -1
                    network = BlockchainNetwork.UNKNOWN

                hex41_repr: Optional[str] = None
                canon_addr = raw_addr
                if network == BlockchainNetwork.TRON_TRC20:
                    if raw_addr.startswith("41"):
                        canon_addr = hex41_to_base58check(raw_addr)
                        hex41_repr = raw_addr.lower()
                    elif raw_addr.startswith("T"):
                        canon_addr = raw_addr
                        hex41_repr = base58check_to_hex41(raw_addr)

                ev_state = EvidentiaryState(
                    existence=EvidentiaryExistence.OBSERVED,
                    access=EvidentiaryAccess.PLAINTEXT,
                    storage_layer=EvidentiaryStorage.LIVE_RECORD,
                    provenance_pointer=f"{file_path}::activeAccounts::coin_{coin_type}",
                    forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
                )

                acc_rec = Web3WalletAccountRecord(
                    wallet_app_name="Trust Wallet",
                    source_vfs_file_id=source_vfs_file_id,
                    recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                    account_control_mode=mode,
                    blockchain_network=network,
                    public_address_canonical=canon_addr,
                    tron_hex41_representation=hex41_repr,
                    extended_public_key_xpub=xpub,
                    bip44_derivation_path=derivation_path,
                    user_assigned_wallet_label=wallet_name,
                    evidentiary_state=ev_state,
                )
                accounts.append(acc_rec)

        return {"accounts": accounts, "transactions": transactions}
