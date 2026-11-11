"""
Domain Models and Enums for Phase 3, Module 3.3:
Indian Retail, Payments, AePS & Corporate Banking App Decoders.
Adheres strictly to AGENTS.md Forensic Invariants and Section 9 of Module 3.3 Spec.
"""

from dataclasses import dataclass
from enum import Enum, unique
from typing import Optional

from src.core.enums import ResidualConfidence


@unique
class AppTierCategory(str, Enum):
    """Classification of the banking / payment application tier."""
    PSU_RETAIL = "PSU_RETAIL"
    PRIVATE_RETAIL = "PRIVATE_RETAIL"
    NEO_BANK_WRAPPER = "NEO_BANK_WRAPPER"
    PAYMENTS_BANK = "PAYMENTS_BANK"
    CORPORATE_SME_BANKING = "CORPORATE_SME_BANKING"
    AEPS_BC_AGENT_APP = "AEPS_BC_AGENT_APP"
    BIOMETRIC_RD_SERVICE = "BIOMETRIC_RD_SERVICE"


@unique
class CorporateRole(str, Enum):
    """User operational role inside a retail or corporate banking application."""
    RETAIL_INDIVIDUAL = "RETAIL_INDIVIDUAL"
    CORPORATE_MAKER = "CORPORATE_MAKER"
    CORPORATE_CHECKER_APPROVER = "CORPORATE_CHECKER_APPROVER"
    CORPORATE_SUPER_ADMIN = "CORPORATE_SUPER_ADMIN"
    BC_CASH_AGENT = "BC_CASH_AGENT"


@unique
class SourceArtifactType(str, Enum):
    """Source artifact layer where banking transactions were recovered."""
    OFFLINE_MPASSBOOK_DB = "OFFLINE_MPASSBOOK_DB"
    WEBVIEW_JSON_STATEMENT = "WEBVIEW_JSON_STATEMENT"
    AEPS_AGENT_LEDGER = "AEPS_AGENT_LEDGER"
    CORPORATE_BATCH_QUEUE = "CORPORATE_BATCH_QUEUE"
    UNLOCKED_PDF_STATEMENT = "UNLOCKED_PDF_STATEMENT"


@unique
class PaymentRail(str, Enum):
    """Underlying Indian core-banking payment clearing rail."""
    IMPS = "IMPS"
    NEFT = "NEFT"
    RTGS = "RTGS"
    UPI = "UPI"
    INTERNAL_TRANSFER = "INTERNAL_TRANSFER"
    YONO_CARDLESS_ATM = "YONO_CARDLESS_ATM"
    AEPS_BIOMETRIC_CASHOUT = "AEPS_BIOMETRIC_CASHOUT"
    DMT_REMITTANCE = "DMT_REMITTANCE"
    POSB_SWEEP = "POSB_SWEEP"
    CHEQUE = "CHEQUE"


@unique
class TxDirection(str, Enum):
    """Transaction money movement direction."""
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"
    CORPORATE_BATCH_PENDING = "CORPORATE_BATCH_PENDING"


@unique
class SpecialArtifactCategory(str, Enum):
    """Category of specialized banking artifacts (Cardless ATM or Unlocked PDFs)."""
    YONO_CASH_CARDLESS_ATM = "YONO_CASH_CARDLESS_ATM"
    ICICI_CARDLESS_ATM = "ICICI_CARDLESS_ATM"
    AXIS_BOI_IMT_ATM = "AXIS_BOI_IMT_ATM"
    BARODA_CASH_ON_MOBILE = "BARODA_CASH_ON_MOBILE"
    UNLOCKED_BANK_STATEMENT_PDF = "UNLOCKED_BANK_STATEMENT_PDF"


@dataclass(slots=True)
class IFSCBranchInfo:
    """Resolved Indian bank branch and geographic jurisdiction details from IFSC."""
    ifsc_code: str
    bank_name: str
    branch_name: str
    address: str
    city: str
    district: str
    state: str
    formatted_location: str


@dataclass(slots=True)
class ParsedNarration:
    """Structured fields parsed from Indian core-banking narration strings."""
    utr_or_rrn: Optional[str] = None
    direction: str = "DEBIT"
    counterparty_name: Optional[str] = None
    counterparty_vpa: Optional[str] = None
    counterparty_acct: Optional[str] = None
    counterparty_ifsc: Optional[str] = None
    payment_rail: str = "UPI"
    remarks: Optional[str] = None


@dataclass(slots=True)
class PDFUnlockResult:
    """Result from the deterministic Indian bank statement PDF unlocker."""
    is_unlocked: bool
    unlocked_password: Optional[str] = None
    extracted_rows_count: int = 0
    pdf_bytes: Optional[bytes] = None


@dataclass(slots=True)
class BankingAppProfileRecord:
    """Discovered customer profile, CIF, corporate credentials, or AePS agent metadata."""
    app_instance_id: int
    source_vfs_file_id: int
    bank_institution_name: str
    app_tier_category: str
    bank_profile_uid: Optional[int] = None
    corporate_id_code: Optional[str] = None
    customer_id_cif_crn: Optional[str] = None
    corporate_role: Optional[str] = None
    account_holder_name: Optional[str] = None
    registered_mobile_no: Optional[str] = None
    linked_account_numbers_json: Optional[str] = None
    attached_biometric_scanner_sn: Optional[str] = None
    last_login_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD


@dataclass(slots=True)
class BankMPassbookLedgerRecord:
    """Normalized ledger entry extracted from offline mPassbook, WebView JSON, or AePS store."""
    source_vfs_file_id: int
    source_artifact_type: str
    payment_rail: str
    tx_direction: str
    amount_inr_decimal: float
    tx_utc_iso: str
    bank_tx_uid: Optional[int] = None
    bank_profile_uid: Optional[int] = None
    local_account_number: Optional[str] = None
    utr_or_rrn_reference: Optional[str] = None
    running_balance_inr: Optional[float] = None
    raw_narration_text: Optional[str] = None
    extracted_counterparty_name: Optional[str] = None
    extracted_counterparty_acct_vpa: Optional[str] = None
    extracted_counterparty_ifsc: Optional[str] = None
    resolved_branch_city_state: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD


@dataclass(slots=True)
class BankBeneficiaryCoolingRecord:
    """IMPS/NEFT/RTGS beneficiary addition and cooling-period audit entry."""
    source_vfs_file_id: int
    beneficiary_holder_name: str
    beneficiary_account_no: str
    beneficiary_uid: Optional[int] = None
    app_instance_id: Optional[int] = None
    beneficiary_ifsc_11_char: Optional[str] = None
    resolved_bank_and_branch_loc: Optional[str] = None
    added_utc_iso: Optional[str] = None
    cooling_period_end_utc_iso: Optional[str] = None
    first_transfer_utc_iso: Optional[str] = None
    post_cooling_latency_minutes: Optional[float] = None
    is_rapid_mule_drain_flagged: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD


@dataclass(slots=True)
class CardlessATMOrPDFRecord:
    """YONO Cash / IMT cardless ATM withdrawal token or unlocked statement PDF entry."""
    source_vfs_file_id: int
    artifact_category: str
    bank_institution_name: str
    cardless_ref_id_or_pdf_name: str
    event_utc_iso: str
    special_artifact_uid: Optional[int] = None
    amount_inr_or_row_count: Optional[float] = None
    unlocked_pdf_password: Optional[str] = None
    linked_runner_chat_recipient: Optional[str] = None
