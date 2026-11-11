"""
Sub-Engine 7.4 Master Coordinator: Visual KYC & Offline OCR Forensic Engine.
Coordinates Apple Live Text harvesting, tiered multilingual OCR, KYC classification,
financial instrument extraction, multi-column BIP-39 recovery, and case database storage.
Adheres strictly to AGENTS.md Forensic Invariants and Section 7 of Module 7.4 Specification.
"""

import os
import sqlite3
from typing import List, Optional

from src.kyc_and_ocr.models import (
    FinancialInstrumentRecord,
    KYCDocumentRecord,
    VisualOCRRecord,
)


class VisualKYCAndOCREngine:
    """Master engine orchestrating OCR analysis, KYC document validation, and SQLite case storage."""

    SCHEMA_DDL = """
    CREATE TABLE IF NOT EXISTS visual_ocr_master_index (
        ocr_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        source_vfs_file_id INTEGER NOT NULL,
        visual_source_category TEXT NOT NULL,
        visual_document_classification TEXT NOT NULL,
        full_extracted_text TEXT NOT NULL,
        detected_scripts_and_langs TEXT NULL,
        mean_ocr_confidence REAL NULL,
        image_captured_or_mtime_utc TEXT NULL,
        recovery_classification TEXT NOT NULL,
        forensic_group TEXT DEFAULT 'G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS'
    );

    CREATE TABLE IF NOT EXISTS indian_kyc_and_identity_documents_ledger (
        kyc_doc_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        ocr_record_uid INTEGER NOT NULL,
        source_vfs_file_id INTEGER NOT NULL,
        document_type TEXT NOT NULL,
        document_id_number TEXT NOT NULL,
        mathematical_validation_status TEXT NOT NULL,
        holder_full_name TEXT NULL,
        father_or_guardian_name TEXT NULL,
        date_of_birth_or_incorp TEXT NULL,
        entity_type_or_state TEXT NULL,
        extracted_address_and_pin TEXT NULL,
        shared_in_chat_or_app_context TEXT NULL,
        forensic_group TEXT DEFAULT 'G18_DOCUMENTS_APKS_AND_OCR_INDEX',
        FOREIGN KEY (ocr_record_uid) REFERENCES visual_ocr_master_index(ocr_record_uid)
    );

    CREATE TABLE IF NOT EXISTS visual_financial_instruments_and_hawala_tokens (
        fin_instrument_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        ocr_record_uid INTEGER NOT NULL,
        source_vfs_file_id INTEGER NOT NULL,
        instrument_category TEXT NOT NULL,
        bank_name_and_branch TEXT NULL,
        account_or_card_number TEXT NULL,
        ifsc_and_micr_code TEXT NULL,
        account_or_card_holder_name TEXT NULL,
        card_expiry_and_cvv TEXT NULL,
        hawala_note_denomination_serial TEXT NULL,
        linked_phase3_account_uid INTEGER NULL,
        forensic_group TEXT DEFAULT 'G02_UPI_AND_WALLETS',
        FOREIGN KEY (ocr_record_uid) REFERENCES visual_ocr_master_index(ocr_record_uid)
    );

    CREATE INDEX IF NOT EXISTS idx_ocr_vfs_id ON visual_ocr_master_index(source_vfs_file_id);
    CREATE INDEX IF NOT EXISTS idx_kyc_id_num ON indian_kyc_and_identity_documents_ledger(document_id_number);
    CREATE INDEX IF NOT EXISTS idx_fin_acct_num ON visual_financial_instruments_and_hawala_tokens(account_or_card_number);
    """

    def export_case_database(
        self,
        db_path: str,
        ocr_records: Optional[List[VisualOCRRecord]] = None,
        kyc_records: Optional[List[KYCDocumentRecord]] = None,
        financial_records: Optional[List[FinancialInstrumentRecord]] = None,
    ) -> str:
        """Exports all OCR, identity document, and financial records into the case database."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.executescript(self.SCHEMA_DDL)

        # 1. Insert Visual OCR Master Records
        if ocr_records:
            cur.executemany(
                """
                INSERT INTO visual_ocr_master_index (
                    ocr_record_uid, source_vfs_file_id, visual_source_category,
                    visual_document_classification, full_extracted_text,
                    detected_scripts_and_langs, mean_ocr_confidence,
                    image_captured_or_mtime_utc, recovery_classification, forensic_group
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        r.ocr_record_uid,
                        r.source_vfs_file_id,
                        r.visual_source_category,
                        r.visual_document_classification,
                        r.full_extracted_text,
                        r.detected_scripts_and_langs,
                        r.mean_ocr_confidence,
                        r.image_captured_or_mtime_utc,
                        r.recovery_classification,
                        r.forensic_group,
                    )
                    for r in ocr_records
                ],
            )

        # 2. Insert Indian KYC Identity Documents
        if kyc_records:
            cur.executemany(
                """
                INSERT INTO indian_kyc_and_identity_documents_ledger (
                    kyc_doc_uid, ocr_record_uid, source_vfs_file_id, document_type,
                    document_id_number, mathematical_validation_status, holder_full_name,
                    father_or_guardian_name, date_of_birth_or_incorp, entity_type_or_state,
                    extracted_address_and_pin, shared_in_chat_or_app_context, forensic_group
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        k.kyc_doc_uid,
                        k.ocr_record_uid,
                        k.source_vfs_file_id,
                        k.document_type,
                        k.document_id_number,
                        k.mathematical_validation_status,
                        k.holder_full_name,
                        k.father_or_guardian_name,
                        k.date_of_birth_or_incorp,
                        k.entity_type_or_state,
                        k.extracted_address_and_pin,
                        k.shared_in_chat_or_app_context,
                        k.forensic_group,
                    )
                    for k in kyc_records
                ],
            )

        # 3. Insert Visual Financial Instruments & Hawala Tokens
        if financial_records:
            cur.executemany(
                """
                INSERT INTO visual_financial_instruments_and_hawala_tokens (
                    fin_instrument_uid, ocr_record_uid, source_vfs_file_id,
                    instrument_category, bank_name_and_branch, account_or_card_number,
                    ifsc_and_micr_code, account_or_card_holder_name, card_expiry_and_cvv,
                    hawala_note_denomination_serial, linked_phase3_account_uid, forensic_group
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        f.fin_instrument_uid,
                        f.ocr_record_uid,
                        f.source_vfs_file_id,
                        f.instrument_category,
                        f.bank_name_and_branch,
                        f.account_or_card_number,
                        f.ifsc_and_micr_code,
                        f.account_or_card_holder_name,
                        f.card_expiry_and_cvv,
                        f.hawala_note_denomination_serial,
                        f.linked_phase3_account_uid,
                        f.forensic_group,
                    )
                    for f in financial_records
                ],
            )

        conn.commit()
        conn.close()
        return db_path
