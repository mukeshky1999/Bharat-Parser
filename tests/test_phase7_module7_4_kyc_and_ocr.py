"""
Acceptance Test Suite for Phase 7, Module 7.4:
Offline Multilingual OCR, Indian KYC Document Classifier, Financial Instrument Extractor & Grid-Aware BIP-39 Seed Hunter.

Test Scope (5 Acceptance Tests):
1. test_indian_pan_card_validation_and_forgery_detection:
   Validates 10-character PAN structure, 4th-character entity code filter (P, C, H, F, A, T, B, L, J, G),
   5th-character cardholder surname initial cross-check, positional homoglyph repairs, and detects forged cards.
2. test_icao_doc_9303_passport_mrz_7_3_1_modulo10_verification:
   Parses 2-line TD3 MRZ, extracts passport number, DOB, expiry, nationality, surname, given names,
   and verifies all 5 ICAO Doc 9303 7-3-1 Modulo-10 check digits; flags forged MRZs.
3. test_cancelled_cheque_and_financial_instrument_extraction:
   Extracts and repairs homoglyph IFSC codes from cancelled cheques (SBINO004821 -> SBIN0004821),
   resolves bank/branch, validates MICR 9-digit code and unmasked bank account numbers,
   extracts Luhn-verified cards and Indian hawala currency note bearer tokens (45B 829104).
4. test_bip39_multi_column_seed_grid_reconstruction:
   Reconstructs multi-column vertical wallet recovery phrase screenshots using bounding-box spatial clustering
   and number badges to defeat row-major scanline distortion and validate BIP-39 SHA-256 checksums.
5. test_ocr_kyc_and_visual_intelligence_sqlite_export:
   Validates export of all 3 canonical forensic tables to ocr_indian_kyc_and_visual_intelligence.sqlite.
"""

import os
import sqlite3
import pytest

from src.kyc_and_ocr.models import (
    VisualDocumentClassification,
    KYCDocumentType,
    FinancialInstrumentCategory,
    ResidualRecoveryConfidence,
    OCRTokenBoundingBox,
    VisualOCRRecord,
    KYCDocumentRecord,
    FinancialInstrumentRecord,
)
from src.kyc_and_ocr.homoglyph_normalizer import PositionalHomoglyphNormalizer
from src.kyc_and_ocr.kyc_validator import IndianKYCValidator
from src.kyc_and_ocr.financial_instrument_extractor import FinancialInstrumentExtractor
from src.kyc_and_ocr.seed_grid_reconstructor import BIP39SeedGridReconstructor
from src.kyc_and_ocr.engine import VisualKYCAndOCREngine


def test_indian_pan_card_validation_and_forgery_detection():
    """Acceptance Test 1: Indian PAN card 4th-char entity status, 5th-char surname cross-check & homoglyph repair."""
    validator = IndianKYCValidator()

    # Case A: Authentic Individual PAN card with surname match
    text_authentic = (
        "INCOME TAX DEPARTMENT\n"
        "GOVT. OF INDIA\n"
        "Permanent Account Number Card\n"
        "RAHUL KUMAR SHARMA\n"
        "RAMESH SHARMA\n"
        "15/08/1995\n"
        "ABCPS1234K"
    )
    result_a = validator.validate_pan_card(text_authentic)
    assert result_a is not None
    assert result_a.is_valid is True
    assert result_a.pan_number == "ABCPS1234K"
    assert result_a.entity_type == "Individual (P)"
    assert result_a.holder_name == "RAHUL KUMAR SHARMA"
    assert result_a.validation_status == "PAN_4TH_CHAR_AND_SURNAME_VERIFIED"
    assert result_a.is_forged is False

    # Case B: Invalid 4th character entity code ('Z' is not a valid PAN entity)
    text_invalid_entity = "INCOME TAX DEPARTMENT\nABCZS1234K"
    result_b = validator.validate_pan_card(text_invalid_entity)
    assert result_b is None

    # Case C: Suspected Forged PAN (5th char 'S' contradicts surname 'VERMA' where 'V' is expected)
    text_forged_surname = (
        "INCOME TAX DEPARTMENT\n"
        "Permanent Account Number\n"
        "RAHUL KUMAR VERMA\n"
        "01/01/1990\n"
        "ABCPS1234K"
    )
    result_c = validator.validate_pan_card(text_forged_surname)
    assert result_c is not None
    assert result_c.is_forged is True
    assert result_c.validation_status == "SUSPECTED_FORGED_PAN_SURNAME_MISMATCH"

    # Case D: Positional Homoglyph Repair (letter 'O' in digit position, letter 'I' in digit position)
    text_homoglyph = "INCOME TAX DEPARTMENT\nRAHUL SHARMA\nABCPSo234I"
    result_d = validator.validate_pan_card(text_homoglyph)
    assert result_d is not None
    assert result_d.pan_number == "ABCPS02341"
    assert result_d.is_valid is True


def test_icao_doc_9303_passport_mrz_7_3_1_modulo10_verification():
    """Acceptance Test 2: ICAO Doc 9303 TD3 2-line Passport MRZ parsing & 5-check-digit 7-3-1 modulo-10 validation."""
    validator = IndianKYCValidator()

    # Authentic Indian Passport TD3 MRZ (2 lines of 44 chars)
    line1 = "P<INDSHARMA<<RAHUL<KUMAR<<<<<<<<<<<<<<<<<<<<"
    line2 = "Z4829104<9IND9508152M3211049<<<<<<<<<<<<<<02"
    mrz_text = f"{line1}\n{line2}"

    result = validator.validate_passport_mrz(mrz_text)
    assert result is not None
    assert result.is_valid is True
    assert result.passport_number == "Z4829104"
    assert result.surname == "SHARMA"
    assert result.given_names == "RAHUL KUMAR"
    assert result.date_of_birth_iso == "1995-08-15"
    assert result.expiry_date_iso == "2032-11-04"
    assert result.nationality == "IND"
    assert result.gender == "M"
    assert result.validation_status == "ICAO_9303_MRZ_5_CHECKDIGITS_VERIFIED"
    assert result.is_forged is False

    # Tampered Passport MRZ (altered check digit or expiry date)
    line2_tampered = "Z4829104<9IND9508152M3211048<<<<<<<<<<<<<<02"  # cd 8 instead of 9
    result_tampered = validator.validate_passport_mrz(f"{line1}\n{line2_tampered}")
    assert result_tampered is not None
    assert result_tampered.is_valid is False
    assert result_tampered.is_forged is True
    assert result_tampered.validation_status == "FORGED_OR_ALTERED_PASSPORT_MRZ"


def test_cancelled_cheque_and_financial_instrument_extraction():
    """Acceptance Test 3: Cancelled cheques with homoglyph IFSC repair, MICR code, Hawala currency note tokens & cards."""
    extractor = FinancialInstrumentExtractor()

    # 1. Cancelled Cheque Leaf with 'SBINO004821' ('O' in position 5)
    cheque_text = (
        "STATE BANK OF INDIA\n"
        "VARANASI MAIN BRANCH\n"
        "A/c No: 30984718291\n"
        "IFSC: SBINO004821\n"
        "MICR: 221002014\n"
        "CANCELLED\n"
        "RAHUL KUMAR SHARMA"
    )
    result_cheque = extractor.extract_from_text(cheque_text)
    assert result_cheque is not None
    assert result_cheque.instrument_category == FinancialInstrumentCategory.CANCELLED_CHEQUE_LEAF.value
    assert result_cheque.ifsc_code == "SBIN0004821"
    assert result_cheque.account_number == "30984718291"
    assert result_cheque.micr_code == "221002014"
    assert "State Bank of India" in result_cheque.bank_name_and_branch
    assert "Varanasi" in result_cheque.bank_name_and_branch
    assert result_cheque.holder_name == "RAHUL KUMAR SHARMA"

    # 2. Hawala Currency-Note Bearer Token
    hawala_text = (
        "RESERVE BANK OF INDIA\n"
        "GUARANTEED BY THE CENTRAL GOVERNMENT\n"
        "I PROMISE TO PAY THE BEARER THE SUM OF TEN RUPEES\n"
        "45B 829104"
    )
    result_hawala = extractor.extract_from_text(hawala_text)
    assert result_hawala is not None
    assert result_hawala.instrument_category == FinancialInstrumentCategory.HAWALA_CURRENCY_NOTE_TOKEN.value
    assert result_hawala.hawala_note_serial == "45B 829104"
    assert "₹10" in result_hawala.hawala_note_description

    # 3. Physical Payment Card with Luhn Mod-10 Checksum
    card_text = "STATE BANK OF INDIA\n4532 0150 1234 5674\nVALID THRU 12/28\nRAHUL SHARMA"
    result_card = extractor.extract_from_text(card_text)
    assert result_card is not None
    assert result_card.instrument_category == FinancialInstrumentCategory.PHYSICAL_DEBIT_OR_CREDIT_CARD.value
    assert result_card.account_or_card_number == "4532015012345674"
    assert result_card.card_expiry == "12/28"


def test_bip39_multi_column_seed_grid_reconstruction():
    """Acceptance Test 4: Multi-column BIP-39 recovery seed screenshot spatial reconstruction."""
    reconstructor = BIP39SeedGridReconstructor()

    # The 12 authentic BIP-39 words:
    # legal, winner, thank, year, wave, sausage, worth, useful, legal, winner, thank, yellow
    # Arranged in 2 vertical columns of 6 words:
    # Column 1 (Left, x=100): 1. legal, 2. winner, 3. thank, 4. year, 5. wave, 6. sausage
    # Column 2 (Right, x=300): 7. worth, 8. useful, 9. legal, 10. winner, 11. thank, 12. yellow
    tokens = [
        # Left Column
        OCRTokenBoundingBox("1.", 70, 100, 95, 125),
        OCRTokenBoundingBox("legal", 100, 100, 180, 125),
        OCRTokenBoundingBox("2.", 70, 150, 95, 175),
        OCRTokenBoundingBox("winner", 100, 150, 180, 175),
        OCRTokenBoundingBox("3.", 70, 200, 95, 225),
        OCRTokenBoundingBox("thank", 100, 200, 180, 225),
        OCRTokenBoundingBox("4.", 70, 250, 95, 275),
        OCRTokenBoundingBox("year", 100, 250, 180, 275),
        OCRTokenBoundingBox("5.", 70, 300, 95, 325),
        OCRTokenBoundingBox("wave", 100, 300, 180, 325),
        OCRTokenBoundingBox("6.", 70, 350, 95, 375),
        OCRTokenBoundingBox("sausage", 100, 350, 180, 375),
        # Right Column
        OCRTokenBoundingBox("7.", 270, 100, 295, 125),
        OCRTokenBoundingBox("worth", 300, 100, 380, 125),
        OCRTokenBoundingBox("8.", 270, 150, 295, 175),
        OCRTokenBoundingBox("useful", 300, 150, 380, 175),
        OCRTokenBoundingBox("9.", 270, 200, 295, 225),
        OCRTokenBoundingBox("legal", 300, 200, 380, 225),
        OCRTokenBoundingBox("10.", 270, 250, 295, 275),
        OCRTokenBoundingBox("winner", 300, 250, 380, 275),
        OCRTokenBoundingBox("11.", 270, 300, 295, 325),
        OCRTokenBoundingBox("thank", 300, 300, 380, 325),
        OCRTokenBoundingBox("12.", 270, 350, 295, 375),
        OCRTokenBoundingBox("yellow", 300, 350, 380, 375),
    ]

    result = reconstructor.reconstruct_seed_phrase(tokens)
    assert result is not None
    assert result.is_valid_bip39 is True
    assert result.word_count == 12
    assert result.reconstruction_method in {"BADGE_INDEXED", "COLUMN_MAJOR_2COL"}
    assert result.mnemonic_phrase == "legal winner thank year wave sausage worth useful legal winner thank yellow"


def test_ocr_kyc_and_visual_intelligence_sqlite_export():
    """Acceptance Test 5: Verify SQLite export into ocr_indian_kyc_and_visual_intelligence.sqlite across 3 tables."""
    db_path = os.path.join(".", ".workspace_tmp", "ocr_indian_kyc_and_visual_intelligence.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    ocr_records = [
        VisualOCRRecord(
            ocr_record_uid=1,
            source_vfs_file_id=501,
            visual_source_category="GALLERY_SCREENSHOT",
            visual_document_classification=VisualDocumentClassification.INDIAN_PAN_CARD.value,
            full_extracted_text="INCOME TAX DEPARTMENT / RAHUL SHARMA / ABCPS1234K",
            detected_scripts_and_langs="Latin/English",
            mean_ocr_confidence=0.95,
            image_captured_or_mtime_utc="2026-11-05T14:30:00.000000Z",
            recovery_classification=ResidualRecoveryConfidence.ORIGINAL_RECORD.value,
        )
    ]

    kyc_records = [
        KYCDocumentRecord(
            kyc_doc_uid=1,
            ocr_record_uid=1,
            source_vfs_file_id=501,
            document_type=KYCDocumentType.PAN_CARD.value,
            document_id_number="ABCPS1234K",
            mathematical_validation_status="PAN_4TH_CHAR_AND_SURNAME_VERIFIED",
            holder_full_name="RAHUL SHARMA",
            father_or_guardian_name="RAMESH SHARMA",
            date_of_birth_or_incorp="15/08/1995",
            entity_type_or_state="Individual (P)",
            extracted_address_and_pin=None,
            shared_in_chat_or_app_context="WhatsApp Mule Group (+919876543210)",
        )
    ]

    fin_records = [
        FinancialInstrumentRecord(
            fin_instrument_uid=1,
            ocr_record_uid=1,
            source_vfs_file_id=501,
            instrument_category=FinancialInstrumentCategory.CANCELLED_CHEQUE_LEAF.value,
            bank_name_and_branch="State Bank of India, Varanasi Branch",
            account_or_card_number="30984718291",
            ifsc_and_micr_code="IFSC: SBIN0004821 | MICR: 221002014",
            account_or_card_holder_name="RAHUL KUMAR SHARMA",
            card_expiry_and_cvv=None,
            hawala_note_denomination_serial=None,
            linked_phase3_account_uid=12,
        )
    ]

    engine = VisualKYCAndOCREngine()
    engine.export_case_database(
        db_path=db_path,
        ocr_records=ocr_records,
        kyc_records=kyc_records,
        financial_records=fin_records,
    )

    assert os.path.exists(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM visual_ocr_master_index")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT count(*) FROM indian_kyc_and_identity_documents_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT count(*) FROM visual_financial_instruments_and_hawala_tokens")
    assert cur.fetchone()[0] == 1

    # Verify column presence in visual_ocr_master_index
    cur.execute("PRAGMA table_info(visual_ocr_master_index)")
    cols_ocr = [r[1] for r in cur.fetchall()]
    assert "ocr_record_uid" in cols_ocr
    assert "visual_source_category" in cols_ocr
    assert "visual_document_classification" in cols_ocr
    assert "full_extracted_text" in cols_ocr

    # Verify column presence in indian_kyc_and_identity_documents_ledger
    cur.execute("PRAGMA table_info(indian_kyc_and_identity_documents_ledger)")
    cols_kyc = [r[1] for r in cur.fetchall()]
    assert "kyc_doc_uid" in cols_kyc
    assert "document_type" in cols_kyc
    assert "document_id_number" in cols_kyc
    assert "mathematical_validation_status" in cols_kyc
    assert "holder_full_name" in cols_kyc

    # Verify column presence in visual_financial_instruments_and_hawala_tokens
    cur.execute("PRAGMA table_info(visual_financial_instruments_and_hawala_tokens)")
    cols_fin = [r[1] for r in cur.fetchall()]
    assert "fin_instrument_uid" in cols_fin
    assert "instrument_category" in cols_fin
    assert "account_or_card_number" in cols_fin
    assert "ifsc_and_micr_code" in cols_fin

    conn.close()
