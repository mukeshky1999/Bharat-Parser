"""
Sub-Engine 7.3 Master Coordinator: Barcode, Aadhaar Secure QR & Payment Receipt Forensic Engine.
Coordinates multi-pass pre-processing, payload classification, Aadhaar demographic/biometric extraction,
payment receipt authenticity auditing, and schema generation for qr_aadhaar_and_forged_receipt_engine.sqlite.
Adheres strictly to AGENTS.md Forensic Invariants and Section 7 of Module 7.3 Specification.
"""

import json
import os
import sqlite3
from typing import List, Optional

from src.qr_and_receipts.models import (
    AadhaarUnpackedRecord,
    DecodedBarcodeRecord,
    PaymentReceiptAuditRecord,
)


class BarcodeAndReceiptForensicEngine:
    """Master engine orchestrating barcode decoding, Aadhaar unpacking, receipt auditing, and SQLite case storage."""

    SCHEMA_DDL = """
    CREATE TABLE IF NOT EXISTS decoded_barcodes_and_qr_master_ledger (
        barcode_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        source_vfs_file_id INTEGER NOT NULL,
        source_visual_layer TEXT NOT NULL,
        symbology_type TEXT NOT NULL,
        preprocessing_pass_used TEXT NOT NULL,
        payload_category TEXT NOT NULL,
        raw_decoded_text TEXT NOT NULL,
        structured_unpacked_json TEXT NOT NULL,
        linked_phase3_or_phase4_id TEXT NULL,
        image_created_utc_iso TEXT NULL,
        recovery_classification TEXT NOT NULL,
        forensic_group TEXT DEFAULT 'G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS'
    );

    CREATE TABLE IF NOT EXISTS uidai_aadhaar_secure_qr_unpacked_ledger (
        aadhaar_qr_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        barcode_uid INTEGER NOT NULL,
        source_vfs_file_id INTEGER NOT NULL,
        qr_format_version TEXT NOT NULL,
        aadhaar_last_4_digits TEXT NOT NULL,
        qr_generation_timestamp_str TEXT NULL,
        signed_full_name TEXT NOT NULL,
        signed_dob_and_gender TEXT NOT NULL,
        signed_care_of_guardian TEXT NULL,
        signed_full_address_and_pin TEXT NOT NULL,
        extracted_jp2_photo_staging_id INTEGER NULL,
        unmasked_registered_mobile TEXT NULL,
        unmasked_registered_email TEXT NULL,
        rsa_2048_signature_hex TEXT NULL,
        visual_vs_qr_tamper_status TEXT NOT NULL,
        forensic_group TEXT DEFAULT 'G18_DOCUMENTS_APKS_AND_OCR_INDEX',
        FOREIGN KEY (barcode_uid) REFERENCES decoded_barcodes_and_qr_master_ledger(barcode_uid)
    );

    CREATE TABLE IF NOT EXISTS payment_receipt_screenshots_authenticity_audit (
        receipt_audit_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        source_vfs_file_id INTEGER NOT NULL,
        claimed_payment_app TEXT NOT NULL,
        ocr_extracted_utr_12_digit TEXT NULL,
        ocr_extracted_amount_inr REAL NULL,
        ocr_extracted_payee_and_vpa TEXT NULL,
        ocr_displayed_date_str TEXT NULL,
        utr_yddd_julian_check_status TEXT NOT NULL,
        phase3_corroboration_status TEXT NOT NULL,
        is_forged_receipt_flagged INTEGER DEFAULT 0,
        forgery_proof_reasons_json TEXT NULL,
        forensic_group TEXT DEFAULT 'G02_UPI_AND_WALLETS'
    );

    CREATE INDEX IF NOT EXISTS idx_barcodes_vfs_id ON decoded_barcodes_and_qr_master_ledger(source_vfs_file_id);
    CREATE INDEX IF NOT EXISTS idx_barcodes_category ON decoded_barcodes_and_qr_master_ledger(payload_category);
    CREATE INDEX IF NOT EXISTS idx_aadhaar_last_4 ON uidai_aadhaar_secure_qr_unpacked_ledger(aadhaar_last_4_digits);
    CREATE INDEX IF NOT EXISTS idx_receipt_utr ON payment_receipt_screenshots_authenticity_audit(ocr_extracted_utr_12_digit);
    CREATE INDEX IF NOT EXISTS idx_receipt_flagged ON payment_receipt_screenshots_authenticity_audit(is_forged_receipt_flagged);
    """

    def export_case_database(
        self,
        db_path: str,
        barcode_records: Optional[List[DecodedBarcodeRecord]] = None,
        aadhaar_records: Optional[List[AadhaarUnpackedRecord]] = None,
        receipt_records: Optional[List[PaymentReceiptAuditRecord]] = None,
    ) -> str:
        """Exports all extracted records into the canonical SQLite case ledger."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.executescript(self.SCHEMA_DDL)

        # 1. Insert Decoded Barcodes
        if barcode_records:
            cur.executemany(
                """
                INSERT INTO decoded_barcodes_and_qr_master_ledger (
                    barcode_uid, source_vfs_file_id, source_visual_layer, symbology_type,
                    preprocessing_pass_used, payload_category, raw_decoded_text,
                    structured_unpacked_json, linked_phase3_or_phase4_id,
                    image_created_utc_iso, recovery_classification, forensic_group
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        b.barcode_uid,
                        b.source_vfs_file_id,
                        b.source_visual_layer,
                        b.symbology_type,
                        b.preprocessing_pass_used,
                        b.payload_category,
                        b.raw_decoded_text,
                        b.structured_unpacked_json,
                        b.linked_phase3_or_phase4_id,
                        b.image_created_utc_iso,
                        b.recovery_classification,
                        b.forensic_group,
                    )
                    for b in barcode_records
                ],
            )

        # 2. Insert Aadhaar Records
        if aadhaar_records:
            cur.executemany(
                """
                INSERT INTO uidai_aadhaar_secure_qr_unpacked_ledger (
                    aadhaar_qr_uid, barcode_uid, source_vfs_file_id, qr_format_version,
                    aadhaar_last_4_digits, qr_generation_timestamp_str, signed_full_name,
                    signed_dob_and_gender, signed_care_of_guardian, signed_full_address_and_pin,
                    extracted_jp2_photo_staging_id, unmasked_registered_mobile,
                    unmasked_registered_email, rsa_2048_signature_hex,
                    visual_vs_qr_tamper_status, forensic_group
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        a.aadhaar_qr_uid,
                        a.barcode_uid,
                        a.source_vfs_file_id,
                        a.qr_format_version,
                        a.aadhaar_last_4_digits,
                        a.qr_generation_timestamp_str,
                        a.signed_full_name,
                        a.signed_dob_and_gender,
                        a.signed_care_of_guardian,
                        a.signed_full_address_and_pin,
                        a.extracted_jp2_photo_staging_id,
                        a.unmasked_registered_mobile,
                        a.unmasked_registered_email,
                        a.rsa_2048_signature_hex,
                        a.visual_vs_qr_tamper_status,
                        a.forensic_group,
                    )
                    for a in aadhaar_records
                ],
            )

        # 3. Insert Payment Receipt Audits
        if receipt_records:
            cur.executemany(
                """
                INSERT INTO payment_receipt_screenshots_authenticity_audit (
                    receipt_audit_uid, source_vfs_file_id, claimed_payment_app,
                    ocr_extracted_utr_12_digit, ocr_extracted_amount_inr,
                    ocr_extracted_payee_and_vpa, ocr_displayed_date_str,
                    utr_yddd_julian_check_status, phase3_corroboration_status,
                    is_forged_receipt_flagged, forgery_proof_reasons_json, forensic_group
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        r.receipt_audit_uid,
                        r.source_vfs_file_id,
                        r.claimed_payment_app,
                        r.ocr_extracted_utr_12_digit,
                        r.ocr_extracted_amount_inr,
                        r.ocr_extracted_payee_and_vpa,
                        r.ocr_displayed_date_str,
                        r.utr_yddd_julian_check_status,
                        r.phase3_corroboration_status,
                        r.is_forged_receipt_flagged,
                        r.forgery_proof_reasons_json or json.dumps(r.forgery_proof_reasons),
                        r.forensic_group,
                    )
                    for r in receipt_records
                ],
            )

        conn.commit()
        conn.close()
        return db_path
