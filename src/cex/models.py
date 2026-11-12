"""
Models, Enums, and Evidentiary State Containers for Centralized Exchanges & P2P Escrow Forensics.
Phase 4, Module 4.2. Complies with Sections 4 & 5 of AGENTS.md Constitution.
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
class CEXComplianceTier(str, Enum):
    """FIU-IND Registration and Compliance Classification."""
    INDIAN_DOMESTIC_FIU_REGISTERED = "INDIAN_DOMESTIC_FIU_REGISTERED"
    GLOBAL_FIU_REGISTERED_VASP = "GLOBAL_FIU_REGISTERED_VASP"
    OFFSHORE_UNREGISTERED_CEX_OR_P2P = "OFFSHORE_UNREGISTERED_CEX_OR_P2P"


@unique
class CEXP2PTradeDirection(str, Enum):
    """P2P Fiat-to-Crypto Trading Direction."""
    BUY_CRYPTO_PAID_FIAT = "BUY_CRYPTO_PAID_FIAT"
    SELL_CRYPTO_RECEIVED_FIAT = "SELL_CRYPTO_RECEIVED_FIAT"
    UNKNOWN = "UNKNOWN"  # tradeType missing from the record


@unique
class CEXP2POrderStatus(str, Enum):
    """P2P Escrow Lifecycle State."""
    COMPLETED_RELEASED = "COMPLETED_RELEASED"
    CANCELLED = "CANCELLED"
    APPEAL_DISPUTED = "APPEAL_DISPUTED"
    IN_ESCROW_PENDING = "IN_ESCROW_PENDING"
    UNKNOWN = "UNKNOWN"  # orderStatus missing from the record


@unique
class CEXTransferCategory(str, Enum):
    """Categorization of On-Chain, Off-Chain Pay, and Fiat Movements."""
    ONCHAIN_CRYPTO_WITHDRAWAL = "ONCHAIN_CRYPTO_WITHDRAWAL"
    ONCHAIN_CRYPTO_DEPOSIT = "ONCHAIN_CRYPTO_DEPOSIT"
    OFFCHAIN_BINANCE_PAY_OR_UID_TRANSFER = "OFFCHAIN_BINANCE_PAY_OR_UID_TRANSFER"
    CRYPTO_BOX_RED_PACKET = "CRYPTO_BOX_RED_PACKET"
    INDIAN_FIAT_INR_DEPOSIT_WITHDRAWAL = "INDIAN_FIAT_INR_DEPOSIT_WITHDRAWAL"
    VDA_SPOT_TRADE_WITH_1PCT_TDS = "VDA_SPOT_TRADE_WITH_1PCT_TDS"


@dataclass(slots=True)
class CEXAccountProfileRecord:
    """Discovered CEX account profile, KYC identity, and linked fiat accounts."""
    cex_account_uid: Optional[int] = None
    exchange_name: str = ""
    fiu_ind_compliance_tier: CEXComplianceTier = CEXComplianceTier.GLOBAL_FIU_REGISTERED_VASP
    app_instance_id: Optional[int] = None
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    cex_user_uid: str = ""
    binance_pay_id_or_nick: Optional[str] = None
    kyc_verified_full_name: Optional[str] = None
    indian_pan_10_char: Optional[str] = None
    aadhaar_or_passport_id: Optional[str] = None
    registered_email: Optional[str] = None
    registered_mobile_phone: Optional[str] = None
    linked_indian_banks_vpas_json: Optional[str] = None
    cached_spot_funding_balances: Optional[str] = None
    last_active_utc_iso: Optional[str] = None
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
        )
    )


@dataclass(slots=True)
class CEXP2PEscrowOrderRecord:
    """P2P (C2C) Escrow Order connecting Indian Rupee banking to cryptocurrency."""
    p2p_order_uid: Optional[int] = None
    cex_account_uid: Optional[int] = None
    exchange_name: str = ""
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    p2p_order_number: str = ""
    trade_direction: CEXP2PTradeDirection = CEXP2PTradeDirection.BUY_CRYPTO_PAID_FIAT
    order_status: CEXP2POrderStatus = CEXP2POrderStatus.UNKNOWN
    crypto_asset: str = "USDT"
    crypto_quantity_decimal: float = 0.0
    fiat_currency: str = "INR"
    fiat_total_amount: float = 0.0
    unit_exchange_rate: Optional[float] = None
    counterparty_cex_uid_nick: Optional[str] = None
    counterparty_verified_kyc_name: Optional[str] = None
    fiat_payment_rail: Optional[str] = None
    counterparty_vpa_or_bank_ifsc: Optional[str] = None
    extracted_utr_or_giftcard_code: Optional[str] = None
    is_third_party_payer_mismatch: int = 0
    order_created_utc_iso: str = ""
    order_completed_utc_iso: Optional[str] = None
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
        )
    )


@dataclass(slots=True)
class CEXP2PChatMessageRecord:
    """In-order escrow chat message exchanged between Buyer and Seller."""
    p2p_chat_uid: Optional[int] = None
    p2p_order_number: str = ""
    exchange_name: str = ""
    sender_uid_and_nickname: Optional[str] = None
    message_type: str = "TEXT"
    message_text_or_image_url: str = ""
    extracted_phone_utr_or_vpa: Optional[str] = None
    sent_utc_iso: str = ""
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
        )
    )


@dataclass(slots=True)
class CEXTransferRecord:
    """On-chain withdrawal/deposit, off-chain Binance Pay, or domestic TDS record."""
    cex_transfer_uid: Optional[int] = None
    cex_account_uid: Optional[int] = None
    exchange_name: str = ""
    source_vfs_file_id: int = 0
    transfer_category: CEXTransferCategory = CEXTransferCategory.ONCHAIN_CRYPTO_WITHDRAWAL
    asset_or_currency: str = "USDT"
    network_or_rail: Optional[str] = None
    amount_decimal: float = 0.0
    tds_1pct_deducted_inr: Optional[float] = None
    txid_or_internal_pay_order_id: str = ""
    destination_wallet_or_peer_uid: Optional[str] = None
    matches_local_web3_wallet_uid: Optional[int] = None
    transfer_utc_iso: str = ""
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    evidentiary_state: EvidentiaryState = field(
        default_factory=lambda: EvidentiaryState(
            existence=EvidentiaryExistence.OBSERVED,
            access=EvidentiaryAccess.PLAINTEXT,
            storage_layer=EvidentiaryStorage.LIVE_RECORD,
            forensic_group=ForensicGroup.G06_CRYPTO_EXCHANGES_AND_SEEDS,
        )
    )
