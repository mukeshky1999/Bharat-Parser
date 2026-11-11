"""
Models, Enums, and Evidentiary State Containers for Address Validators, ABI Unpacking & WalletConnect.
Phase 4, Module 4.3. Complies with Sections 4 & 5 of AGENTS.md Constitution.
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
class BlockchainEcosystem(str, Enum):
    """Supported blockchain address standards and checksum architectures."""
    TRON_TRC20 = "TRON_TRC20"
    BITCOIN_LEGACY_P2PKH_P2SH = "BITCOIN_LEGACY_P2PKH_P2SH"
    BITCOIN_SEGWIT_BECH32 = "BITCOIN_SEGWIT_BECH32"
    BITCOIN_TAPROOT_BECH32M = "BITCOIN_TAPROOT_BECH32M"
    ETHEREUM_EVM_0X = "ETHEREUM_EVM_0X"
    SOLANA_ED25519 = "SOLANA_ED25519"
    MONERO_XMR_CRYPTONOTE = "MONERO_XMR_CRYPTONOTE"
    TON_CRC16 = "TON_CRC16"


@unique
class WalletConnectRecordType(str, Enum):
    """Categorization of WalletConnect v2 audit records."""
    WC_V2_PAIRING_OR_SESSION = "WC_V2_PAIRING_OR_SESSION"
    WC_V2_JSON_RPC_TRANSACTION = "WC_V2_JSON_RPC_TRANSACTION"
    WC_V2_EIP712_PERMIT_SIGNATURE = "WC_V2_EIP712_PERMIT_SIGNATURE"


@dataclass(slots=True)
class ValidatedCryptoAddressRecord:
    """Discovered, validated, and normalized cryptocurrency address record."""
    addr_index_uid: Optional[int] = None
    blockchain_ecosystem: BlockchainEcosystem = BlockchainEcosystem.ETHEREUM_EVM_0X
    canonical_address: str = ""
    checksum_verification_method: str = ""
    discovered_in_module_and_app: str = ""
    source_vfs_file_id: int = 0
    associated_actor_or_context: Optional[str] = None
    first_seen_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
        )
    )


@dataclass(slots=True)
class UnpackedSmartContractABIRecord:
    """Decoded Smart Contract call payload showing true sender, recipient, and amount."""
    abi_call_uid: Optional[int] = None
    linked_web3_tx_uid: Optional[int] = None
    tx_hash_hex: Optional[str] = None
    blockchain_network: str = "ETHEREUM_ERC20"
    outer_contract_address: str = ""
    resolved_token_or_protocol: Optional[str] = None
    selector_4byte_hex: str = ""
    decoded_function_name: str = ""
    unpacked_true_sender: Optional[str] = None
    unpacked_true_recipient_or_spender: str = ""
    unpacked_raw_uint256_amount: Optional[str] = None
    unpacked_human_token_amount: Optional[str] = None
    is_unlimited_approval_or_drainer: int = 0
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
        )
    )


@dataclass(slots=True)
class WalletConnectAuditRecord:
    """WalletConnect v2 pairing, approved session, or JSON-RPC phishing audit record."""
    wc_audit_uid: Optional[int] = None
    app_instance_id: int = 0
    source_vfs_file_id: int = 0
    wc_record_type: WalletConnectRecordType = WalletConnectRecordType.WC_V2_PAIRING_OR_SESSION
    session_topic_hex: Optional[str] = None
    dapp_peer_name: Optional[str] = None
    dapp_peer_url: str = ""
    exposed_caip10_accounts_json: Optional[str] = None
    rpc_method_and_params_json: Optional[str] = None
    is_phishing_permit_drainer_sig: int = 0
    session_paired_utc_iso: Optional[str] = None
    session_expiry_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G05_CRYPTO_SELF_CUSTODY_WALLETS,
        )
    )
