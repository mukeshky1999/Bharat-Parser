"""
Data Models and Canonical Enums for Phase 7, Module 7.3:
Offline Universal Barcode/QR Decoder, UIDAI Aadhaar Secure QR Unpacker & Forged Payment Receipt Detector.
Adheres strictly to AGENTS.md Forensic Invariants and Module 7.3 Specification.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class BarcodeSymbology(str, Enum):
    """Supported 1D and 2D barcode symbologies."""
    QR_CODE = "QR_CODE"
    MICRO_QR = "MICRO_QR"
    AZTEC = "AZTEC"
    PDF417 = "PDF417"
    DATAMATRIX = "DATAMATRIX"
    CODE_128 = "CODE_128"


class VisualSourceLayer(str, Enum):
    """Source visual origin layer where barcode or screenshot was located."""
    CAMERA_OR_GALLERY_IMAGE = "CAMERA_OR_GALLERY_IMAGE"
    MESSENGER_MEDIA_IMAGE = "MESSENGER_MEDIA_IMAGE"
    APP_SWITCHER_SNAPSHOT = "APP_SWITCHER_SNAPSHOT"
    RECONSTRUCTED_THUMBNAIL_OR_CACHE = "RECONSTRUCTED_THUMBNAIL_OR_CACHE"
    UNMASKED_VAULT_FILE = "UNMASKED_VAULT_FILE"
    PDF_DOCUMENT_PAGE = "PDF_DOCUMENT_PAGE"


class PreprocessingPass(str, Enum):
    """4-Pass preprocessing pipeline stage that successfully resolved the barcode."""
    PASS1_NATIVE = "PASS1_NATIVE"
    PASS2_DARKMODE_INVERTED = "PASS2_DARKMODE_INVERTED"
    PASS3_ADAPTIVE_GLARE = "PASS3_ADAPTIVE_GLARE"
    PASS4_DEWARP_UPSCALED = "PASS4_DEWARP_UPSCALED"


class PayloadCategory(str, Enum):
    """Canonical 10-category forensic classification of barcode payloads."""
    UIDAI_AADHAAR_SECURE_QR = "UIDAI_AADHAAR_SECURE_QR"
    NPCI_UPI_PAYMENT_QR = "NPCI_UPI_PAYMENT_QR"
    EMVCO_BHARATQR_MERCHANT = "EMVCO_BHARATQR_MERCHANT"
    CRYPTO_WALLET_URI_OR_ADDRESS = "CRYPTO_WALLET_URI_OR_ADDRESS"
    WALLETCONNECT_PAIRING_QR = "WALLETCONNECT_PAIRING_QR"
    GSMA_ESIM_ACTIVATION_QR = "GSMA_ESIM_ACTIVATION_QR"
    MESSENGER_COMPANION_OR_OPSEC_INVITE_QR = "MESSENGER_COMPANION_OR_OPSEC_INVITE_QR"
    WIFI_CREDENTIALS_SHARE_QR = "WIFI_CREDENTIALS_SHARE_QR"
    IATA_BOARDING_PASS_BCBP_OR_IRCTC_QR = "IATA_BOARDING_PASS_BCBP_OR_IRCTC_QR"
    DIGILOCKER_OR_GOVT_JWT_QR = "DIGILOCKER_OR_GOVT_JWT_QR"


class ResidualRecoveryConfidence(str, Enum):
    """Standard 6-tier evidentiary recovery confidence classification."""
    ORIGINAL_RECORD = "ORIGINAL_RECORD"
    HISTORICAL_COMMITTED_RECORD = "HISTORICAL_COMMITTED_RECORD"
    RESIDUAL_RECORD = "RESIDUAL_RECORD"
    PARTIAL_RECORD = "PARTIAL_RECORD"
    RECONSTRUCTED_RECORD = "RECONSTRUCTED_RECORD"
    UNVERIFIED_FRAGMENT = "UNVERIFIED_FRAGMENT"


class AadhaarTamperStatus(str, Enum):
    """UIDAI Aadhaar physical card face vs signed QR cryptographic consistency status."""
    AUTHENTIC_MATCH = "AUTHENTIC_MATCH"
    PHOTOSHOPPED_AADHAAR_CARD_DETECTED = "CRITICAL: PHOTOSHOPPED_AADHAAR_CARD_DETECTED (Printed Name/DOB/Last-4 differs from signed QR payload!)"


class ReceiptJulianStatus(str, Enum):
    """NPCI 12-digit UTR YDDD Julian day vs printed receipt date consistency status."""
    VALID_YDDD_DATE_MATCH = "VALID_YDDD_DATE_MATCH"
    FORGED_UTR_JULIAN_DATE_MISMATCH = "FORGED_UTR_JULIAN_DATE_MISMATCH"


class ReceiptCorroborationStatus(str, Enum):
    """Cross-layer corroboration of receipt against seized device Phase 3 financial databases."""
    CORROBORATED_IN_PHASE3_LEDGER = "CORROBORATED_IN_PHASE3_LEDGER"
    UNCORROBORATED_EXTERNAL_SCREENSHOT = "UNCORROBORATED_EXTERNAL_SCREENSHOT"
    CRITICAL_LOCAL_SCREENSHOT_MISSING_FROM_LEDGER = "CRITICAL_LOCAL_SCREENSHOT_MISSING_FROM_LEDGER"


@dataclass
class DecodedBarcodeRecord:
    """Master record representing any 1D/2D barcode or QR code extracted across the device."""
    barcode_uid: Optional[int] = None
    source_vfs_file_id: int = 0
    source_visual_layer: str = VisualSourceLayer.CAMERA_OR_GALLERY_IMAGE.value
    symbology_type: str = BarcodeSymbology.QR_CODE.value
    preprocessing_pass_used: str = PreprocessingPass.PASS1_NATIVE.value
    payload_category: str = PayloadCategory.UIDAI_AADHAAR_SECURE_QR.value
    raw_decoded_text: str = ""
    structured_unpacked_json: str = "{}"
    linked_phase3_or_phase4_id: Optional[str] = None
    image_created_utc_iso: Optional[str] = None
    recovery_classification: str = ResidualRecoveryConfidence.ORIGINAL_RECORD.value
    forensic_group: str = "G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS"


@dataclass
class AadhaarUnpackedRecord:
    """Detailed unpacked record from UIDAI Aadhaar Secure QR code."""
    aadhaar_qr_uid: Optional[int] = None
    barcode_uid: int = 0
    source_vfs_file_id: int = 0
    qr_format_version: str = "SECURE_QR_V2_V3_BIGINT_GZIP"
    aadhaar_last_4_digits: str = ""
    qr_generation_timestamp_str: Optional[str] = None
    signed_full_name: str = ""
    signed_dob_and_gender: str = ""
    signed_care_of_guardian: Optional[str] = None
    signed_full_address_and_pin: str = ""
    extracted_jp2_photo_staging_id: Optional[int] = None
    unmasked_registered_mobile: Optional[str] = None
    unmasked_registered_email: Optional[str] = None
    rsa_2048_signature_hex: Optional[str] = None
    visual_vs_qr_tamper_status: str = AadhaarTamperStatus.AUTHENTIC_MATCH.value
    extracted_jp2_bytes: Optional[bytes] = None
    mobile_sha256_hash_hex: Optional[str] = None
    email_sha256_hash_hex: Optional[str] = None
    forensic_group: str = "G18_DOCUMENTS_APKS_AND_OCR_INDEX"


@dataclass
class PaymentReceiptAuditRecord:
    """Authenticity audit record for payment receipt screenshots."""
    receipt_audit_uid: Optional[int] = None
    source_vfs_file_id: int = 0
    claimed_payment_app: str = ""
    ocr_extracted_utr_12_digit: Optional[str] = None
    ocr_extracted_amount_inr: Optional[float] = None
    ocr_extracted_payee_and_vpa: Optional[str] = None
    ocr_displayed_date_str: Optional[str] = None
    utr_yddd_julian_check_status: str = ReceiptJulianStatus.VALID_YDDD_DATE_MATCH.value
    phase3_corroboration_status: str = ReceiptCorroborationStatus.UNCORROBORATED_EXTERNAL_SCREENSHOT.value
    is_forged_receipt_flagged: int = 0
    forgery_proof_reasons_json: Optional[str] = None
    forgery_proof_reasons: List[str] = field(default_factory=list)
    forensic_group: str = "G02_UPI_AND_WALLETS"
