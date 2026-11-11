"""
Domain Models and Enums for Phase 3, Module 3.5:
The 4-Way UTR Correlator, VPA Handle Resolver & Mule-Account Fraud Detector.
Adheres strictly to AGENTS.md Forensic Invariants and Section 7 of Module 3.5 Spec.
"""

from dataclasses import dataclass
from enum import Enum, unique
from typing import Optional

from src.core.enums import ResidualConfidence


@unique
class CorroborationLevel(str, Enum):
    """Multi-layer evidentiary corroboration level for fused financial transactions."""
    SETTLED_BANK_AND_APP_VERIFIED = "SETTLED_BANK_AND_APP_VERIFIED"
    SETTLED_BANK_SMS_ONLY = "SETTLED_BANK_SMS_ONLY"
    SETTLED_BANK_PASSBOOK_ONLY = "SETTLED_BANK_PASSBOOK_ONLY"
    APP_INITIATED_UNCONFIRMED = "APP_INITIATED_UNCONFIRMED"
    UNVERIFIED_OR_DISCREPANT = "UNVERIFIED_OR_DISCREPANT"


@unique
class FraudFlagCategory(str, Enum):
    """Automated fraud, balance-gap, and mule-account detection categories."""
    DELETED_SMS_BALANCE_GAP = "DELETED_SMS_BALANCE_GAP"
    MULE_HIGH_VELOCITY_PASSTHROUGH = "MULE_HIGH_VELOCITY_PASSTHROUGH"
    REMOTE_APP_LOCAL_SIM_OTP_RELAY = "REMOTE_APP_LOCAL_SIM_OTP_RELAY"
    LOCAL_APP_EXTERNAL_SIM_CARD = "LOCAL_APP_EXTERNAL_SIM_CARD"
    CONCURRENT_TROJAN_OR_SCREENSHARE_DURING_TX = "CONCURRENT_TROJAN_OR_SCREENSHARE_DURING_TX"
    NCRP_1930_LIEN_AND_POST_FREEZE_ACTIVITY = "NCRP_1930_LIEN_AND_POST_FREEZE_ACTIVITY"
    MINOR_BANK_FEE_OR_SMS_CHARGE_DELTA = "MINOR_BANK_FEE_OR_SMS_CHARGE_DELTA"


@unique
class FlagSeverity(str, Enum):
    """Severity level of forensic fraud alerts."""
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass(slots=True)
class UTRValidationResult:
    """Disambiguation result between 12-digit Julian NPCI UTR and UIDAI Aadhaar ID."""
    candidate_number: str
    is_aadhaar_number: bool
    utr_validation_status: str
    extracted_year_digit: Optional[int] = None
    extracted_julian_day: Optional[int] = None


@dataclass(slots=True)
class VPAResolutionResult:
    """Resolved Indian VPA handle metadata, owning TPAP, sponsor bank, and phone number."""
    raw_vpa: str
    owning_tpap_app: str
    sponsor_psp_bank: str
    inferred_mobile_number: Optional[str] = None
    is_direct_account_ifsc_vpa: bool = False
    direct_account_number: Optional[str] = None
    direct_ifsc_code: Optional[str] = None


@dataclass(slots=True)
class UnifiedTransactionRecord:
    """Fused, multi-layer master financial transaction record."""
    master_tx_uid: Optional[int] = None
    utr_or_rrn: Optional[str] = None
    account_tail_digits: Optional[str] = None
    local_bank_account_number: Optional[str] = None
    local_bank_institution: Optional[str] = None
    sender_vpa: Optional[str] = None
    receiver_vpa: Optional[str] = None
    counterparty_cbs_name: Optional[str] = None
    counterparty_ifsc: Optional[str] = None
    inferred_counterparty_mobile: Optional[str] = None
    tx_direction: str = "DEBIT"
    payment_rail: str = "UPI"
    amount_inr_decimal: float = 0.0
    post_tx_balance_inr: Optional[float] = None
    settlement_status: str = "SETTLED_SUCCESS"
    corroboration_level: str = "SETTLED_BANK_AND_APP_VERIFIED"
    source_records_lineage_json: str = "{}"
    tx_utc_iso: str = "1970-01-01T00:00:00.000000Z"
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD


@dataclass(slots=True)
class FinancialFraudFlagRecord:
    """Automated balance-gap, high-velocity mule, and fraud detection alert."""
    flag_category: str
    severity: str = "CRITICAL"
    flag_uid: Optional[int] = None
    master_tx_uid: Optional[int] = None
    account_tail_digits: Optional[str] = None
    discrepancy_amount_inr: Optional[float] = None
    narrative_summary: str = ""
    flagged_utc_iso: str = "1970-01-01T00:00:00.000000Z"


@dataclass(slots=True)
class CounterpartyCommsCrosslinkRecord:
    """Cross-group bridge linking financial counterparties to cellular/chat communications."""
    vpa_entry_uid: int
    counterparty_vpa_or_acct: str
    matched_mobile_number: str
    crosslink_uid: Optional[int] = None
    counterparty_cbs_name: Optional[str] = None
    local_contact_saved_name: Optional[str] = None
    voice_calls_count: int = 0
    chat_messages_count: int = 0
    shortest_chat_to_tx_delta_sec: Optional[int] = None
