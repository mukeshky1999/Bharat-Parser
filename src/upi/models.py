"""
Domain Models and Enums for Indian UPI Super-App Forensic Extraction.
Adheres strictly to Specification Section 8 and AGENTS.md Forensic Invariants.
"""

from dataclasses import dataclass
from enum import Enum, unique
from typing import Optional

from src.core.enums import ResidualConfidence


@unique
class UPIInstrumentMode(str, Enum):
    """Payment instrument modes supported across Indian UPI Super-Apps."""
    UPI_BANK_ACCOUNT = "UPI_BANK_ACCOUNT"
    UPI_LITE_ON_DEVICE = "UPI_LITE_ON_DEVICE"
    UPI_CIRCLE_DELEGATED = "UPI_CIRCLE_DELEGATED"
    RUPAY_CREDIT_ON_UPI = "RUPAY_CREDIT_ON_UPI"
    PREPAID_WALLET = "PREPAID_WALLET"
    POCKET_UPI = "POCKET_UPI"


@unique
class UPITransactionDirection(str, Enum):
    """Transaction flow direction."""
    DEBIT_SENT = "DEBIT_SENT"
    CREDIT_RECEIVED = "CREDIT_RECEIVED"
    COLLECT_REQUEST_SENT = "COLLECT_REQUEST_SENT"
    COLLECT_REQUEST_RECEIVED = "COLLECT_REQUEST_RECEIVED"
    SELF_TRANSFER = "SELF_TRANSFER"
    UNKNOWN = "UNKNOWN"  # the app database does not say which way the money moved


@unique
class UPITransactionStatus(str, Enum):
    """Application-recorded settlement status."""
    SUCCESS = "SUCCESS"
    PENDING = "PENDING"
    INITIATED = "INITIATED"
    FAILED = "FAILED"
    DECLINED = "DECLINED"
    EXPIRED = "EXPIRED"
    REFUNDED = "REFUNDED"


@unique
class QRArtifactType(str, Enum):
    """QR code and VPA resolution lookup classification."""
    SCANNED_UPI_URI_QR = "SCANNED_UPI_URI_QR"
    SCANNED_BHARATQR_EMVCO_TLV = "SCANNED_BHARATQR_EMVCO_TLV"
    VPA_NAME_VERIFICATION_CACHE = "VPA_NAME_VERIFICATION_CACHE"
    SAVED_BENEFICIARY = "SAVED_BENEFICIARY"


@unique
class DelegationFeatureType(str, Enum):
    """UPI Lite on-device wallet or delegated circle spending features."""
    UPI_LITE_WALLET = "UPI_LITE_WALLET"
    UPI_CIRCLE_DELEGATION = "UPI_CIRCLE_DELEGATION"
    POCKET_UPI_WALLET = "POCKET_UPI_WALLET"
    UPI_AUTOPAY_MANDATE = "UPI_AUTOPAY_MANDATE"


@dataclass(slots=True)
class UPIAppSandboxTransaction:
    """Normalized transaction extracted from a UPI Super-App sandbox."""
    app_instance_id: int
    source_vfs_file_id: int
    source_subsystem: str
    recovery_classification: ResidualConfidence
    amount_inr_decimal: float
    raw_amount_value: str = ""
    instrument_mode: str = "UPI_BANK_ACCOUNT"
    tx_direction: str = "DEBIT_SENT"
    app_recorded_status: str = "SUCCESS"
    utr_12_digit: Optional[str] = None
    app_order_or_tx_id: Optional[str] = None
    payer_vpa: Optional[str] = None
    payee_vpa: Optional[str] = None
    counterparty_display_name: Optional[str] = None
    counterparty_verified_cbs_name: Optional[str] = None
    counterparty_phone_number: Optional[str] = None
    counterparty_bank_acct_ifsc: Optional[str] = None
    payment_note_remarks: Optional[str] = None
    created_utc_iso: Optional[str] = None
    completed_utc_iso: Optional[str] = None
    raw_json_or_proto_dump: Optional[str] = None
    sandbox_tx_uid: Optional[int] = None


@dataclass(slots=True)
class UPITransactionRecord:
    """Convenience alias and carrier record for UPI app transaction events."""
    app_instance_id: int = 1
    source_vfs_file_id: int = 101
    app_name: str = "UPI"
    payer_vpa: Optional[str] = None
    payee_vpa: Optional[str] = None
    amount_inr_decimal: float = 0.0
    npci_utr_or_rrn: Optional[str] = None
    transaction_status: str = "SUCCESS"
    initiated_timestamp_utc_iso: Optional[str] = None
    settled_timestamp_utc_iso: Optional[str] = None
    source_record_rowid: Optional[int] = None
    payee_name: Optional[str] = None
    utr_12_digit: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD


@dataclass(slots=True)
class UPIInAppP2PChat:
    """Chat message or split-bill note exchanged inside a UPI payment thread."""
    app_instance_id: int
    source_vfs_file_id: int
    recovery_classification: ResidualConfidence
    message_text: str
    thread_or_topic_id: Optional[str] = None
    sender_vpa_or_phone: Optional[str] = None
    receiver_vpa_or_phone: Optional[str] = None
    counterparty_verified_cbs_name: Optional[str] = None
    linked_utr_or_tx_id: Optional[str] = None
    sent_utc_iso: Optional[str] = None
    upi_chat_uid: Optional[int] = None


@dataclass(slots=True)
class UPIScannedQRAndVPALookup:
    """Decoded BharatQR/EMVCo TLV string, upi://pay URI, or VPA name verification."""
    app_instance_id: int
    source_vfs_file_id: int
    artifact_type: str
    raw_qr_or_uri_string: Optional[str] = None
    extracted_payee_vpa: Optional[str] = None
    verified_merchant_or_cbs_name: Optional[str] = None
    mcc_4_digit: Optional[str] = None
    merchant_city: Optional[str] = None
    merchant_pincode_6_digit: Optional[str] = None
    terminal_or_store_id: Optional[str] = None
    scan_gps_lat_lon_json: Optional[str] = None
    was_name_verified_without_tx: int = 0
    event_utc_iso: Optional[str] = None
    lookup_uid: Optional[int] = None


@dataclass(slots=True)
class UPILiteAndCircleDelegation:
    """On-device UPI Lite wallet ledger or UPI Circle delegated payment registry."""
    app_instance_id: int
    feature_type: str
    status: str = "ACTIVE"
    lite_lrn_or_mandate_umn: Optional[str] = None
    primary_holder_vpa: Optional[str] = None
    secondary_delegate_vpa_phone: Optional[str] = None
    delegation_role_on_this_device: Optional[str] = None
    balance_or_limit_inr: Optional[float] = None
    updated_utc_iso: Optional[str] = None
    record_uid: Optional[int] = None


_OUT_HINTS = {"debit", "dr", "pay", "paid", "sent", "send", "outgoing", "out", "p2p_pay", "1", "true"}
_IN_HINTS = {"credit", "cr", "receive", "received", "incoming", "in", "collect_received", "0", "false"}
_DIRECTION_KEYS = ("direction", "txn_type", "txnType", "tx_type", "transactionType", "type", "txn_direction")
_BOOL_OUT_KEYS = ("is_outgoing", "isSender", "is_sender", "from_me", "isDebit")


def infer_direction(row: dict, payer_vpa=None, payee_vpa=None, owner_vpas=()) -> str:
    """Direction of a UPI record from evidence, never by default.

    Order: an explicit flag/type column in the record, then a match of the payer/payee VPA against the
    device owner's VPAs, otherwise UNKNOWN. Returns a UPITransactionDirection value.
    """
    for k in _BOOL_OUT_KEYS:
        if k in row and row[k] is not None:
            return (UPITransactionDirection.DEBIT_SENT if str(row[k]).strip().lower() in {"1", "true"}
                    else UPITransactionDirection.CREDIT_RECEIVED).value
    for k in _DIRECTION_KEYS:
        v = row.get(k)
        if v is None:
            continue
        t = str(v).strip().lower()
        if t in _OUT_HINTS and t not in {"1", "0", "true", "false"}:
            return UPITransactionDirection.DEBIT_SENT.value
        if t in _IN_HINTS and t not in {"1", "0", "true", "false"}:
            return UPITransactionDirection.CREDIT_RECEIVED.value
    owners = {str(v).strip().lower() for v in owner_vpas if v}
    if owners:
        payer = str(payer_vpa or "").strip().lower()
        payee = str(payee_vpa or "").strip().lower()
        if payer in owners and payee in owners:
            return UPITransactionDirection.SELF_TRANSFER.value
        if payer in owners:
            return UPITransactionDirection.DEBIT_SENT.value
        if payee in owners:
            return UPITransactionDirection.CREDIT_RECEIVED.value
    return UPITransactionDirection.UNKNOWN.value
