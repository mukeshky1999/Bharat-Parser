"""
Data models and canonical enums for Phase 4, Module 4.4:
Cross-System BIP-39 Seed Hunter, HD Derivation Engine & Rupee-to-Crypto Correlator.
Complies with Section 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


class SecretType(str, Enum):
    """Cryptographic secret classification."""
    BIP39_MNEMONIC_12_TO_24_WORDS = "BIP39_MNEMONIC_12_TO_24_WORDS"
    MONERO_25_WORD_SEED = "MONERO_25_WORD_SEED"
    WIF_PRIVATE_KEY = "WIF_PRIVATE_KEY"
    RAW_64_HEX_PRIVATE_KEY = "RAW_64_HEX_PRIVATE_KEY"
    UNWRAPPED_METAMASK_OR_WEB3_VAULT = "UNWRAPPED_METAMASK_OR_WEB3_VAULT"
    LOCKED_WEB3_VAULT_EXPORT = "LOCKED_WEB3_VAULT_EXPORT"


class BlockchainNetwork(str, Enum):
    """Target blockchain networks for HD address derivation."""
    TRON_TRC20 = "TRON_TRC20"
    ETHEREUM_EVM_0X = "ETHEREUM_EVM_0X"
    BITCOIN_SEGWIT_BIP84 = "BITCOIN_SEGWIT_BIP84"
    BITCOIN_LEGACY_BIP44 = "BITCOIN_LEGACY_BIP44"
    SOLANA_SLIP0010 = "SOLANA_SLIP0010"


class LaunderingPattern(str, Enum):
    """Reconstructed fiat-to-crypto money laundering pattern."""
    SINGLE_UPI_TO_P2P_USDT = "SINGLE_UPI_TO_P2P_USDT"
    SPLIT_UPI_SMURFING_TO_P2P_USDT = "SPLIT_UPI_SMURFING_TO_P2P_USDT"
    THIRD_PARTY_TRIANGULATION_P2P = "THIRD_PARTY_TRIANGULATION_P2P"
    DIRECT_INDIAN_FIU_CEX_ONRAMP = "DIRECT_INDIAN_FIU_CEX_ONRAMP"
    P2P_TO_SELF_CUSTODY_AND_MONERO_SWAP = "P2P_TO_SELF_CUSTODY_AND_MONERO_SWAP"


@dataclass
class RecoveredSeedRecord:
    """Recovered seed phrase, private key, or wallet vault record."""
    secret_type: SecretType
    discovery_source_detail: str
    source_vfs_file_id: int
    checksum_validation_status: str
    plaintext_mnemonic_or_privkey: Optional[str] = None
    unlocked_with_password: Optional[str] = None
    raw_encrypted_vault_json: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS
    evidentiary_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    evidentiary_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    evidentiary_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    raw_byte_offset: int = 0
    corroboration_score: float = 1.0
    product_a_sha256: str = ""
    product_b_sha256: str = ""
    seed_record_uid: Optional[int] = None


@dataclass
class HDDerivedAddressRecord:
    """Hierarchically derived public address record."""
    seed_record_uid: int
    blockchain_network: BlockchainNetwork
    derivation_path: str
    derived_public_address: str
    matches_on_device_activity: int = 0
    derived_addr_uid: Optional[int] = None


@dataclass
class LaunderingChainRecord:
    """End-to-end money laundering reconstructed chain record."""
    chain_pattern_classification: LaunderingPattern
    hop1_phase3_tx_master_uids_json: str
    hop1_total_fiat_outflow_inr: float
    hop2_cex_p2p_order_uid: Optional[int] = None
    hop2_acquired_crypto_amount: str = ""
    hop3_cex_withdrawal_or_pay_uid: Optional[int] = None
    hop4_self_custody_or_swap_json: Optional[str] = None
    hop5_chat_confirmation_msg_uid: Optional[str] = None
    chain_start_utc_iso: str = ""
    chain_completion_utc_iso: Optional[str] = None
    laundering_chain_uid: Optional[int] = None


@dataclass
class Phase3UPIPayment:
    """Normalized Phase 3 UPI payment transaction for correlation."""
    tx_master_uid: int
    utr_reference: str
    amount_inr: float
    counterparty_vpa: str
    counterparty_name: str
    source_app: str
    timestamp_utc_iso: str


@dataclass
class Phase4P2POrder:
    """Normalized Phase 4.2 CEX P2P order for correlation."""
    p2p_order_uid: int
    order_number: str
    exchange_name: str
    order_side: str
    crypto_quantity: float
    crypto_currency: str
    fiat_total_amount: float
    fiat_currency: str
    counterparty_vpa: str
    order_status: str
    created_utc_iso: str
    completed_utc_iso: str


@dataclass
class Phase4CryptoWithdrawal:
    """Normalized Phase 4.2 CEX withdrawal or Phase 4.1 transfer."""
    transfer_uid: int
    exchange_name: str
    currency: str
    amount: float
    blockchain_network: str
    destination_address: str
    txid: str
    timestamp_utc_iso: str
    matches_local_wallet: bool = False
