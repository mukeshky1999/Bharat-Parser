"""
Domain Models and Enums for Phase 3, Module 3.4:
The Indian TRAI DLT Financial SMS & System Notification Parser.
Adheres strictly to AGENTS.md Forensic Invariants and Section 7 of Module 3.4 Spec.
"""

from dataclasses import dataclass
from enum import Enum, unique
from typing import Optional

from src.core.enums import ResidualConfidence


@unique
class FinancialSMSCategory(str, Enum):
    """The 10-Category Indian Financial SMS classification scheme."""
    TX_DEBIT_OUTFLOW = "TX_DEBIT_OUTFLOW"
    TX_CREDIT_INFLOW = "TX_CREDIT_INFLOW"
    ATM_CASH_WITHDRAWAL = "ATM_CASH_WITHDRAWAL"
    BENEFICIARY_ADDITION_ALERT = "BENEFICIARY_ADDITION_ALERT"
    OTP_AUTHENTICATION_CODE = "OTP_AUTHENTICATION_CODE"
    LIEN_HOLD_OR_FREEZE_ALERT = "LIEN_HOLD_OR_FREEZE_ALERT"
    UPI_DEVICE_BINDING_OR_MPIN = "UPI_DEVICE_BINDING_OR_MPIN"
    UPI_AUTOPAY_OR_MANDATE = "UPI_AUTOPAY_OR_MANDATE"
    FAILED_OR_DECLINED_TX = "FAILED_OR_DECLINED_TX"
    PROMOTIONAL_SPAM_IGNORED = "PROMOTIONAL_SPAM_IGNORED"


@unique
class SourceDBType(str, Enum):
    """Database source layer of the SMS message."""
    ANDROID_MMSSMS_DE = "ANDROID_MMSSMS_DE"
    ANDROID_BUGLE_CE = "ANDROID_BUGLE_CE"
    IOS_SMS_DB_TEXT = "IOS_SMS_DB_TEXT"
    IOS_SMS_DB_ATTRIBUTED_BODY = "IOS_SMS_DB_ATTRIBUTED_BODY"


@unique
class NotificationSubsystem(str, Enum):
    """Operating-system notification persistence subsystem."""
    IOS_DUET_EXPERT_CENTER = "IOS_DUET_EXPERT_CENTER"
    IOS_BIOME_SEGB = "IOS_BIOME_SEGB"
    ANDROID_NOTIF_HISTORY_PROTO = "ANDROID_NOTIF_HISTORY_PROTO"
    ANDROID_BUGREPORT_DUMP = "ANDROID_BUGREPORT_DUMP"
    SMARTWATCH_COMPANION_DB = "SMARTWATCH_COMPANION_DB"


@dataclass(slots=True)
class DLTHeaderInfo:
    """Parsed Indian TRAI Distributed Ledger Technology (DLT) header details."""
    raw_sender: str
    operator_char: Optional[str] = None
    operator_name: Optional[str] = None
    circle_char: Optional[str] = None
    circle_name: Optional[str] = None
    entity_code: Optional[str] = None
    category_suffix: Optional[str] = None
    resolved_institution: str = "Unknown Institution"
    operator_and_circle: Optional[str] = None
    is_promotional_dlt: bool = False


@dataclass(slots=True)
class ParsedFinancialSMSFields:
    """Extracted financial values from a message body."""
    sms_event_category: str
    amount_inr_decimal: Optional[float] = None
    post_tx_available_balance_inr: Optional[float] = None
    masked_account_or_card: Optional[str] = None
    account_tail_digits: Optional[str] = None
    payment_rail: Optional[str] = None
    utr_or_rrn_reference: Optional[str] = None
    counterparty_vpa_or_name: Optional[str] = None
    atm_location_or_otp_digits: Optional[str] = None


@dataclass(slots=True)
class DLTFinancialSMSLedgerRecord:
    """Extracted Layer-2 financial or OTP SMS record matching canonical Table 1 schema."""
    source_vfs_file_id: int
    source_db_type: str
    raw_sender_address: str
    resolved_institution_name: str
    sms_event_category: str
    full_sms_body_text: str
    received_utc_ns: int
    received_utc_iso: str
    fin_sms_uid: Optional[int] = None
    original_sms_rowid: Optional[int] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    dlt_operator_and_circle: Optional[str] = None
    dlt_entity_code: Optional[str] = None
    dlt_category_suffix: Optional[str] = None
    masked_account_or_card: Optional[str] = None
    account_tail_digits: Optional[str] = None
    payment_rail: Optional[str] = None
    utr_or_rrn_reference: Optional[str] = None
    amount_inr_decimal: Optional[float] = None
    post_tx_available_balance_inr: Optional[float] = None
    counterparty_vpa_or_name: Optional[str] = None
    atm_location_or_otp_digits: Optional[str] = None
    android_sub_id: Optional[int] = None
    receiving_sim_iccid: Optional[str] = None
    carrier_smsc_number: Optional[str] = None
    is_spoofed_sms_suspected: int = 0


@dataclass(slots=True)
class OSFinancialNotificationRecord:
    """Extracted Layer-3 OS push notification record matching canonical Table 2 schema."""
    source_vfs_file_id: int
    notification_subsystem: str
    target_app_bundle_or_pkg: str
    delivered_utc_iso: str
    fin_notif_uid: Optional[int] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    is_metadata_only_no_body: int = 0
    notif_title_text: Optional[str] = None
    notif_body_text: Optional[str] = None
    extracted_amount_inr: Optional[float] = None
    extracted_utr_reference: Optional[str] = None
    user_interaction_state: Optional[str] = None
