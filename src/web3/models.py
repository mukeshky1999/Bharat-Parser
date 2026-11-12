"""
Models, Enums, and Evidentiary State Containers for Web3 Self-Custody Wallets.
Phase 4, Module 4.1. Complies with Sections 4 & 5 of AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from enum import Enum, unique
from typing import Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryState,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.core.timestamps import ForensicTimestamp


@unique
class Web3AccountControlMode(str, Enum):
    """Classification of wallet control level and key custody."""
    FULL_PRIVATE_KEY_OR_SEED = "FULL_PRIVATE_KEY_OR_SEED"
    WATCH_ONLY_OBSERVED_WALLET = "WATCH_ONLY_OBSERVED_WALLET"
    PAIRED_HARDWARE_COLD_WALLET = "PAIRED_HARDWARE_COLD_WALLET"


@unique
class BlockchainNetwork(str, Enum):
    """Supported blockchain ecosystems and networks."""
    TRON_TRC20 = "TRON_TRC20"
    ETHEREUM_ERC20 = "ETHEREUM_ERC20"
    BSC_BEP20 = "BSC_BEP20"
    POLYGON_POS = "POLYGON_POS"
    BITCOIN = "BITCOIN"
    SOLANA = "SOLANA"
    TON_NETWORK = "TON_NETWORK"
    MONERO_XMR = "MONERO_XMR"


@unique
class Web3TxOperationType(str, Enum):
    """Operation types inside self-custody wallet ledgers."""
    NATIVE_COIN_TRANSFER = "NATIVE_COIN_TRANSFER"
    SMART_CONTRACT_TOKEN_TRANSFER = "SMART_CONTRACT_TOKEN_TRANSFER"
    TOKEN_APPROVAL_ALLOWANCE = "TOKEN_APPROVAL_ALLOWANCE"
    TRON_ENERGY_DELEGATION = "TRON_ENERGY_DELEGATION"
    DEX_SWAP_EXECUTION = "DEX_SWAP_EXECUTION"


@dataclass(slots=True)
class Web3WalletAccountRecord:
    """Discovered self-custody, watch-only, or hardware companion account."""
    web3_account_uid: Optional[int] = None
    app_instance_id: int = 0
    wallet_app_name: str = ""
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    account_control_mode: Web3AccountControlMode = Web3AccountControlMode.FULL_PRIVATE_KEY_OR_SEED
    blockchain_network: BlockchainNetwork = BlockchainNetwork.ETHEREUM_ERC20
    public_address_canonical: str = ""
    tron_hex41_representation: Optional[str] = None
    extended_public_key_xpub: Optional[str] = None
    bip44_derivation_path: Optional[str] = None
    user_assigned_wallet_label: Optional[str] = None
    paired_hardware_device_info: Optional[str] = None
    cached_token_balances_json: Optional[str] = None
    is_vault_unwrapped: int = 0
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
        )
    )


@dataclass(slots=True)
class Web3TransactionRecord:
    """Historical or pending blockchain transaction extracted from local wallet sandbox."""
    web3_tx_uid: Optional[int] = None
    web3_account_uid: Optional[int] = None
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    tx_hash_hex: str = ""
    blockchain_network: BlockchainNetwork = BlockchainNetwork.ETHEREUM_ERC20
    tx_operation_type: Web3TxOperationType = Web3TxOperationType.NATIVE_COIN_TRANSFER
    token_symbol: str = "ETH"
    token_contract_address: Optional[str] = None
    from_address: Optional[str] = None
    to_recipient_address: Optional[str] = None
    raw_bigint_amount_str: str = "0"
    token_decimals: int = 18
    human_amount_decimal_str: str = "0.0"
    monero_secret_tx_key: Optional[str] = None
    tx_status: str = "UNVERIFIED_LOCAL_RECORD"  # set from the record, never assumed
    tx_timestamp: ForensicTimestamp = field(
        default_factory=lambda: ForensicTimestamp.from_unix_seconds(0)
    )
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
        )
    )


@dataclass(slots=True)
class Web3CrossChainSwapRecord:
    """Cross-chain bridge or DEX swap order connecting different blockchain rails."""
    swap_order_uid: Optional[int] = None
    app_instance_id: int = 0
    source_vfs_file_id: int = 0
    swap_aggregator_provider: str = ""
    provider_order_or_trade_id: str = ""
    input_chain_and_asset: str = ""
    input_amount_decimal: str = ""
    input_deposit_txid: Optional[str] = None
    output_chain_and_asset: str = ""
    output_amount_decimal: Optional[str] = None
    destination_payout_address: str = ""
    output_payout_txid: Optional[str] = None
    swap_timestamp: ForensicTimestamp = field(
        default_factory=lambda: ForensicTimestamp.from_unix_seconds(0)
    )
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
        )
    )
