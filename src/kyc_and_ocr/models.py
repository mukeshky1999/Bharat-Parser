"""
Data Models and Canonical Enums for Phase 7, Module 7.4:
Offline Multilingual OCR, Indian KYC Document Classifier, Financial Instrument Extractor & Grid-Aware BIP-39 Seed Hunter.
Adheres strictly to AGENTS.md Forensic Invariants and Module 7.4 Specification.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class VisualDocumentClassification(str, Enum):
    """Classification of visual document or image content."""
    INDIAN_PAN_CARD = "INDIAN_PAN_CARD"
    UIDAI_AADHAAR_CARD = "UIDAI_AADHAAR_CARD"
    INDIAN_GST_CERTIFICATE = "INDIAN_GST_CERTIFICATE"
    PASSPORT_MRZ_BIO_PAGE = "PASSPORT_MRZ_BIO_PAGE"
    VOTER_ID_EPIC = "VOTER_ID_EPIC"
    DRIVING_LICENCE_DL = "DRIVING_LICENCE_DL"
    CANCELLED_CHEQUE_OR_PASSBOOK = "CANCELLED_CHEQUE_OR_PASSBOOK"
    DEBIT_OR_CREDIT_CARD = "DEBIT_OR_CREDIT_CARD"
    HAWALA_CURRENCY_TOKEN_NOTE = "HAWALA_CURRENCY_TOKEN_NOTE"
    CRYPTO_BIP39_SEED_SCREENSHOT = "CRYPTO_BIP39_SEED_SCREENSHOT"
    UPI_OR_BANK_PAYMENT_RECEIPT = "UPI_OR_BANK_PAYMENT_RECEIPT"
    CHAT_CONVERSATION_SCREENSHOT = "CHAT_CONVERSATION_SCREENSHOT"
    GENERAL_TEXT_IMAGE = "GENERAL_TEXT_IMAGE"


class KYCDocumentType(str, Enum):
    """Specific Indian or international identity document types."""
    PAN_CARD = "PAN_CARD"
    AADHAAR_CARD = "AADHAAR_CARD"
    GSTIN_CERTIFICATE = "GSTIN_CERTIFICATE"
    PASSPORT_MRZ = "PASSPORT_MRZ"
    VOTER_ID_EPIC = "VOTER_ID_EPIC"
    DRIVING_LICENCE = "DRIVING_LICENCE"
    VEHICLE_RC = "VEHICLE_RC"


class FinancialInstrumentCategory(str, Enum):
    """Classification of photographed banking instruments and bearer tokens."""
    CANCELLED_CHEQUE_LEAF = "CANCELLED_CHEQUE_LEAF"
    BANK_PASSBOOK_FRONT_PAGE = "BANK_PASSBOOK_FRONT_PAGE"
    PHYSICAL_DEBIT_OR_CREDIT_CARD = "PHYSICAL_DEBIT_OR_CREDIT_CARD"
    HAWALA_CURRENCY_NOTE_TOKEN = "HAWALA_CURRENCY_NOTE_TOKEN"


class ResidualRecoveryConfidence(str, Enum):
    """Standard 6-tier evidentiary recovery confidence classification."""
    ORIGINAL_RECORD = "ORIGINAL_RECORD"
    HISTORICAL_COMMITTED_RECORD = "HISTORICAL_COMMITTED_RECORD"
    RESIDUAL_RECORD = "RESIDUAL_RECORD"
    PARTIAL_RECORD = "PARTIAL_RECORD"
    RECONSTRUCTED_RECORD = "RECONSTRUCTED_RECORD"
    UNVERIFIED_FRAGMENT = "UNVERIFIED_FRAGMENT"


@dataclass
class OCRTokenBoundingBox:
    """Represents a single recognized text token with spatial 2D coordinates."""
    text: str
    x_min: float
    y_min: float
    x_max: float
    y_max: float
    confidence: float = 1.0


@dataclass
class VisualOCRRecord:
    """Master ledger entry for an image processed by OCR or Apple Live Text."""
    ocr_record_uid: Optional[int] = None
    source_vfs_file_id: int = 0
    visual_source_category: str = "GALLERY_SCREENSHOT"
    visual_document_classification: str = VisualDocumentClassification.GENERAL_TEXT_IMAGE.value
    full_extracted_text: str = ""
    detected_scripts_and_langs: Optional[str] = "Latin/English"
    mean_ocr_confidence: Optional[float] = 1.0
    image_captured_or_mtime_utc: Optional[str] = None
    recovery_classification: str = ResidualRecoveryConfidence.ORIGINAL_RECORD.value
    forensic_group: str = "G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS"


@dataclass
class KYCDocumentRecord:
    """Structured identity document extracted and mathematically verified from an image."""
    kyc_doc_uid: Optional[int] = None
    ocr_record_uid: int = 0
    source_vfs_file_id: int = 0
    document_type: str = KYCDocumentType.PAN_CARD.value
    document_id_number: str = ""
    mathematical_validation_status: str = ""
    holder_full_name: Optional[str] = None
    father_or_guardian_name: Optional[str] = None
    date_of_birth_or_incorp: Optional[str] = None
    entity_type_or_state: Optional[str] = None
    extracted_address_and_pin: Optional[str] = None
    shared_in_chat_or_app_context: Optional[str] = None
    forensic_group: str = "G18_DOCUMENTS_APKS_AND_OCR_INDEX"


@dataclass
class FinancialInstrumentRecord:
    """Structured banking instrument or hawala token extracted from an image."""
    fin_instrument_uid: Optional[int] = None
    ocr_record_uid: int = 0
    source_vfs_file_id: int = 0
    instrument_category: str = FinancialInstrumentCategory.CANCELLED_CHEQUE_LEAF.value
    bank_name_and_branch: Optional[str] = None
    account_or_card_number: Optional[str] = None
    ifsc_and_micr_code: Optional[str] = None
    account_or_card_holder_name: Optional[str] = None
    card_expiry_and_cvv: Optional[str] = None
    hawala_note_denomination_serial: Optional[str] = None
    linked_phase3_account_uid: Optional[int] = None
    forensic_group: str = "G02_UPI_AND_WALLETS"


@dataclass
class PANValidationResult:
    """Detailed validation outcome for an Indian PAN card."""
    is_valid: bool = False
    pan_number: str = ""
    entity_type: str = ""
    holder_name: Optional[str] = None
    father_name: Optional[str] = None
    dob: Optional[str] = None
    validation_status: str = ""
    is_forged: bool = False


@dataclass
class PassportMRZValidationResult:
    """Detailed validation outcome for an ICAO Doc 9303 TD3 2-line Passport MRZ."""
    is_valid: bool = False
    passport_number: str = ""
    nationality: str = ""
    date_of_birth_iso: str = ""
    expiry_date_iso: str = ""
    gender: str = ""
    surname: str = ""
    given_names: str = ""
    validation_status: str = ""
    is_forged: bool = False
    check_digits_verified: Dict[str, bool] = field(default_factory=dict)


@dataclass
class FinancialExtractionResult:
    """Outcome of financial instrument parsing from text."""
    instrument_category: str = ""
    ifsc_code: Optional[str] = None
    account_number: Optional[str] = None
    micr_code: Optional[str] = None
    bank_name_and_branch: Optional[str] = None
    holder_name: Optional[str] = None
    hawala_note_serial: Optional[str] = None
    hawala_note_description: Optional[str] = None
    account_or_card_number: Optional[str] = None
    card_expiry: Optional[str] = None


@dataclass
class ReconstructedSeedResult:
    """Outcome of multi-column BIP-39 recovery seed reconstruction."""
    is_valid_bip39: bool = False
    word_count: int = 0
    mnemonic_phrase: str = ""
    reconstruction_method: str = ""
    derived_addresses: Dict[str, str] = field(default_factory=dict)
