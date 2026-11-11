"""
Acceptance Test Suite for Phase 7, Module 7.3:
Offline Universal Barcode/QR Decoder, UIDAI Aadhaar Secure QR Unpacker & Forged Payment Receipt Detector.

Test Scope (5 Acceptance Tests):
1. test_uidai_aadhaar_secure_qr_bigint_gzip_and_mobile_unmasking:
   Unpacks real BigInt decimal string -> Big-Endian bytes -> Gzip decompression ->
   0xFF-delimited demographic fields, embedded .jp2 biometric photo carving,
   and iterative SHA-256 mobile unmasking based on reference_id[3] count.
2. test_photoshopped_aadhaar_card_tamper_detection:
   Cross-compares signed Aadhaar QR payload against OCR printed text on card face
   to detect photoshopped / forged Aadhaar cards.
3. test_npci_upi_and_bharatqr_tlv_unpacker:
   Unpacks and validates upi://pay query parameters and BharatQR EMVCo TLV streams
   (including nested merchant VPAs and CRC-16 CCITT validation) plus GSMA eSIM & Wi-Fi barcodes.
4. test_forged_upi_receipt_yddd_julian_mismatch_and_duplicate_utr:
   Applies the 5-point mathematical authenticity checks on payment receipt screenshots
   (YDDD Julian date mismatch, generator APK provenance, missing local DB records,
   duplicate UTR with altered amount, fabricated VPA handles).
5. test_qr_and_receipts_master_sqlite_export:
   Validates export of all 3 canonical forensic tables to qr_aadhaar_and_forged_receipt_engine.sqlite.
"""

import gzip
import hashlib
import os
import sqlite3
import pytest

from src.qr_and_receipts.models import (
    BarcodeSymbology,
    VisualSourceLayer,
    PreprocessingPass,
    PayloadCategory,
    ResidualRecoveryConfidence,
    AadhaarTamperStatus,
    ReceiptJulianStatus,
    ReceiptCorroborationStatus,
    DecodedBarcodeRecord,
    AadhaarUnpackedRecord,
    PaymentReceiptAuditRecord,
)
from src.qr_and_receipts.aadhaar_unpacker import AadhaarSecureQRUnpacker
from src.qr_and_receipts.upi_bharatqr_unpacker import UPIAndBharatQRUnpacker
from src.qr_and_receipts.forged_receipt_detector import ForgedReceiptDetector
from src.qr_and_receipts.barcode_qr_engine import BarcodeAndReceiptForensicEngine


def _build_synthetic_aadhaar_bigint_qr(
    version="V2",
    indicator="2",  # mobile only
    ref_id="482120261105143000000",  # ref_id[3] == '1' -> 1 iteration
    name="RAHUL SHARMA",
    dob="15-08-1995",
    gender="M",
    care_of="S/O: Ramesh Sharma",
    district="Varanasi",
    landmark="Near Dashashwamedh Ghat",
    house="42/B",
    locality="Godowlia",
    pin="221001",
    po="Varanasi H.O.",
    state="Uttar Pradesh",
    street="Ghat Road",
    sub_district="Varanasi",
    vtc="Varanasi",
    mobile_num="9876543210",
    email_str="rahul.sharma@example.com",
    include_dummy_sig=True,
):
    """Constructs a real binary Aadhaar Secure QR BigInt decimal string."""
    fields = [
        version.encode("utf-8"),
        indicator.encode("utf-8"),
        ref_id.encode("utf-8"),
        name.encode("utf-8"),
        dob.encode("utf-8"),
        gender.encode("utf-8"),
        care_of.encode("utf-8"),
        district.encode("utf-8"),
        landmark.encode("utf-8"),
        house.encode("utf-8"),
        locality.encode("utf-8"),
        pin.encode("utf-8"),
        po.encode("utf-8"),
        state.encode("utf-8"),
        street.encode("utf-8"),
        sub_district.encode("utf-8"),
        vtc.encode("utf-8"),
    ]
    demographic_bytes = b"\xff".join(fields) + b"\xff"

    # Synthetic JP2 header and facial image bytes
    jp2_bytes = b"\x00\x00\x00\x0c\x6a\x50\x20\x20\r\n\x87\n" + (b"FACE_PIXELS_BINARY_RAW_JP2_" * 8)

    # Compute iterative mobile hash based on ref_id[3]
    d4 = int(ref_id[3])
    n_iter = 1 if d4 == 0 else d4

    # Mobile hash (32 bytes)
    curr_mob = mobile_num
    for _ in range(n_iter):
        curr_mob = hashlib.sha256(curr_mob.encode("ascii")).hexdigest()
    mob_hash_bytes = bytes.fromhex(curr_mob)

    # Email hash (32 bytes)
    curr_email = email_str
    for _ in range(n_iter):
        curr_email = hashlib.sha256(curr_email.encode("ascii")).hexdigest()
    email_hash_bytes = bytes.fromhex(curr_email)

    hashes = b""
    if indicator == "3":
        hashes = email_hash_bytes + mob_hash_bytes
    elif indicator == "2":
        hashes = mob_hash_bytes
    elif indicator == "1":
        hashes = email_hash_bytes

    sig_bytes = (b"\x77" * 256) if include_dummy_sig else b""

    decompressed = demographic_bytes + jp2_bytes + hashes + sig_bytes
    compressed = gzip.compress(decompressed)
    big_int = int.from_bytes(compressed, byteorder="big")
    return str(big_int), mob_hash_bytes, jp2_bytes


def test_uidai_aadhaar_secure_qr_bigint_gzip_and_mobile_unmasking():
    """Acceptance Test 1: Mathematical unpacking of UIDAI Aadhaar Secure QR BigInt & iterative mobile hash unmasking."""
    qr_num_str, expected_mob_hash, expected_jp2 = _build_synthetic_aadhaar_bigint_qr(
        version="V2",
        indicator="2",
        ref_id="482120261105143000000",
        name="RAHUL SHARMA",
        dob="15-08-1995",
        gender="M",
        mobile_num="9876543210",
    )

    unpacker = AadhaarSecureQRUnpacker()
    candidate_mobiles = ["9111222333", "9876543210", "9988776655"]

    record = unpacker.unpack_secure_qr(
        qr_numeric_string=qr_num_str,
        candidate_mobiles=candidate_mobiles,
    )

    assert isinstance(record, AadhaarUnpackedRecord)
    assert record.qr_format_version == "SECURE_QR_V2_V3_BIGINT_GZIP"
    assert record.aadhaar_last_4_digits == "4821"
    assert record.signed_full_name == "RAHUL SHARMA"
    assert "15-08-1995" in record.signed_dob_and_gender
    assert "(M)" in record.signed_dob_and_gender
    assert "S/O: Ramesh Sharma" in record.signed_care_of_guardian
    assert "221001" in record.signed_full_address_and_pin
    assert "Varanasi" in record.signed_full_address_and_pin
    assert "Uttar Pradesh" in record.signed_full_address_and_pin

    # Verify extracted .jp2 biometric photo contains valid JPEG 2000 box magic
    assert record.extracted_jp2_bytes is not None
    assert record.extracted_jp2_bytes.startswith(b"\x00\x00\x00\x0c\x6a\x50\x20\x20")

    # Verify iterative mobile unmasking mathematically matched the correct candidate phone
    assert record.unmasked_registered_mobile == "9876543210"
    assert record.mobile_sha256_hash_hex == expected_mob_hash.hex().lower()

    # Verify RSA 2048-bit (256 bytes = 512 hex characters) signature extraction
    assert record.rsa_2048_signature_hex is not None
    assert len(record.rsa_2048_signature_hex) == 512
    assert record.rsa_2048_signature_hex == ("77" * 256)


def test_photoshopped_aadhaar_card_tamper_detection():
    """Acceptance Test 2: Photoshopped / forged Aadhaar card detection comparing signed QR vs printed OCR."""
    qr_num_str, _, _ = _build_synthetic_aadhaar_bigint_qr(
        ref_id="482120261105143000000",
        name="RAHUL SHARMA",
        dob="15-08-1995",
        mobile_num="9876543210",
    )

    unpacker = AadhaarSecureQRUnpacker()
    unpacked_record = unpacker.unpack_secure_qr(qr_numeric_string=qr_num_str)

    # Case A: Genuine Authentic Card
    status_genuine = unpacker.detect_aadhaar_card_tamper(
        unpacked=unpacked_record,
        printed_name="RAHUL SHARMA",
        printed_dob="15-08-1995",
        printed_last_4="4821",
    )
    assert status_genuine == AadhaarTamperStatus.AUTHENTIC_MATCH.value

    # Case B: Photoshopped Card (Criminal edited printed name and last 4 on card face, but QR has genuine owner)
    status_forged = unpacker.detect_aadhaar_card_tamper(
        unpacked=unpacked_record,
        printed_name="AMIT KUMAR",
        printed_dob="01-01-1990",
        printed_last_4="9988",
    )
    assert status_forged == AadhaarTamperStatus.PHOTOSHOPPED_AADHAAR_CARD_DETECTED.value


def test_npci_upi_and_bharatqr_tlv_unpacker():
    """Acceptance Test 3: Unpacking UPI URIs, BharatQR EMVCo TLV streams, and barcode classification."""
    unpacker = UPIAndBharatQRUnpacker()

    # 1. Test UPI URI parsing
    upi_uri = "upi://pay?pa=merchant99@ybl&pn=Quick%20Mart&mc=5411&am=1250.50&tr=TXN987654321&cu=INR&mode=02"
    cat_upi, data_upi = unpacker.classify_and_unpack(upi_uri)
    assert cat_upi == PayloadCategory.NPCI_UPI_PAYMENT_QR.value
    assert data_upi["pa"] == "merchant99@ybl"
    assert data_upi["pn"] == "Quick Mart"
    assert data_upi["mc"] == "5411"
    assert float(data_upi["am"]) == 1250.50
    assert data_upi["tr"] == "TXN987654321"

    # 2. Test BharatQR EMVCo TLV parsing with CRC-16 CCITT
    # Tag 00: 01 (Format indicator)
    # Tag 01: 12 (Dynamic QR)
    # Tag 26: Merchant Account Info -> sub-tag 00 (A000000524), sub-tag 01 (bharatqr@hdfcbank)
    # Tag 52: 5411 (MCC)
    # Tag 53: 356 (Currency INR)
    # Tag 58: IN (Country)
    # Tag 59: SUPER STORE (Merchant Name)
    # Tag 60: MUMBAI (City)
    # Tag 61: 400001 (Postal Code)
    # Tag 63: 04 + CRC16
    emvco_body = (
        "000201"
        "010212"
        "26360010A0000005240118bharatqr@hdfcbank"
        "52045411"
        "5303356"
        "5802IN"
        "5911SUPER STORE"
        "6006MUMBAI"
        "6106400001"
        "6304"
    )
    crc_hex = unpacker.compute_crc16_ccitt(emvco_body)
    full_bharatqr = emvco_body + crc_hex

    cat_bqr, data_bqr = unpacker.classify_and_unpack(full_bharatqr)
    assert cat_bqr == PayloadCategory.EMVCO_BHARATQR_MERCHANT.value
    assert data_bqr["crc_valid"] is True
    assert data_bqr["merchant_vpa"] == "bharatqr@hdfcbank"
    assert data_bqr["mcc"] == "5411"
    assert data_bqr["merchant_name"] == "SUPER STORE"
    assert data_bqr["city"] == "MUMBAI"
    assert data_bqr["postal_code"] == "400001"

    # 3. Test GSMA eSIM barcode
    esim_qr = "LPA:1$smdp.carrier.com$CONF-MATCH-889900$1.3.6.1$1"
    cat_esim, data_esim = unpacker.classify_and_unpack(esim_qr)
    assert cat_esim == PayloadCategory.GSMA_ESIM_ACTIVATION_QR.value
    assert data_esim["smdp_server"] == "smdp.carrier.com"
    assert data_esim["matching_id"] == "CONF-MATCH-889900"

    # 4. Test Wi-Fi QR
    wifi_qr = "WIFI:S:ForensicHub;T:WPA;P:SuperSecret123;;;;"
    cat_wifi, data_wifi = unpacker.classify_and_unpack(wifi_qr)
    assert cat_wifi == PayloadCategory.WIFI_CREDENTIALS_SHARE_QR.value
    assert data_wifi["ssid"] == "ForensicHub"
    assert data_wifi["password"] == "SuperSecret123"


def test_forged_upi_receipt_yddd_julian_mismatch_and_duplicate_utr():
    """Acceptance Test 4: 5-Point Forged Payment Receipt Screenshot Detector."""
    detector = ForgedReceiptDetector()

    # Case 1: Julian YDDD Mismatch & Generator APK
    # Printed receipt says 05 Nov 2026 (Julian Day 309 of 2026 -> YDDD = 6309)
    # But UTR starts with 4120 (Year 2024, Day 120 = April 29, 2024)
    ocr_case1 = {
        "displayed_date_str": "05 Nov 2026, 02:35 PM",
        "utr_12_digit": "412014829104",
        "amount_inr": 75000.0,
        "payee_vpa": "fraudster@fakebanknotexist",
        "payee_name": "Quick Cash Outlet",
        "app_name": "PhonePe",
    }
    meta_case1 = {
        "source_vfs_file_id": 101,
        "provenance_classification": "OS_SCREENSHOT_OR_SCREEN_RECORDING",
        "owner_package_name": "com.fake.gpayreceipt",
        "exif_software": "PicsArt",
        "is_local_screenshot": True,
    }

    result1 = detector.audit_receipt(
        screenshot_meta=meta_case1,
        ocr_data=ocr_case1,
        local_ledger_utrs={"630999999999"},  # The fake UTR is not in local DB
    )

    assert result1.is_forged_receipt_flagged == 1
    assert result1.utr_yddd_julian_check_status == ReceiptJulianStatus.FORGED_UTR_JULIAN_DATE_MISMATCH.value
    assert result1.phase3_corroboration_status == ReceiptCorroborationStatus.CRITICAL_LOCAL_SCREENSHOT_MISSING_FROM_LEDGER.value
    assert "FORGED_UTR_JULIAN_DATE_MISMATCH" in result1.forgery_proof_reasons
    assert "GENERATOR_APK_OR_EDITOR_PROVENANCE" in result1.forgery_proof_reasons
    assert "INVALID_FABRICATED_VPA_OR_IFSC_ON_RECEIPT" in result1.forgery_proof_reasons

    # Case 2: Duplicate UTR reuse across screenshots with altered amounts
    ocr_case2_a = {
        "displayed_date_str": "05 Nov 2026, 10:00 AM",
        "utr_12_digit": "630914829104",
        "amount_inr": 500.0,
        "payee_vpa": "vendor@ybl",
        "payee_name": "Grocery Store",
        "app_name": "Google Pay",
    }
    ocr_case2_b = {
        "displayed_date_str": "05 Nov 2026, 11:30 AM",
        "utr_12_digit": "630914829104",
        "amount_inr": 50000.0,
        "payee_vpa": "club@okaxis",
        "payee_name": "VIP Lounge",
        "app_name": "Google Pay",
    }
    meta_case2 = {
        "source_vfs_file_id": 102,
        "provenance_classification": "CAMERA_OR_GALLERY_IMAGE",
        "owner_package_name": "com.google.android.apps.nbu.paisa.user",
        "exif_software": None,
        "is_local_screenshot": False,
    }

    known_utrs = {}
    detector.audit_receipt(meta_case2, ocr_case2_a, known_utrs_map=known_utrs)
    result2_b = detector.audit_receipt(meta_case2, ocr_case2_b, known_utrs_map=known_utrs)

    assert result2_b.is_forged_receipt_flagged == 1
    assert "DUPLICATE_UTR_WITH_ALTERED_AMOUNT_OR_PAYEE" in result2_b.forgery_proof_reasons


def test_qr_and_receipts_master_sqlite_export():
    """Acceptance Test 5: Verify SQLite export into qr_aadhaar_and_forged_receipt_engine.sqlite across 3 tables."""
    db_path = os.path.join(".", ".workspace_tmp", "qr_aadhaar_and_forged_receipt_engine.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    # Create dummy records
    barcodes = [
        DecodedBarcodeRecord(
            barcode_uid=1,
            source_vfs_file_id=101,
            source_visual_layer=VisualSourceLayer.CAMERA_OR_GALLERY_IMAGE.value,
            symbology_type=BarcodeSymbology.QR_CODE.value,
            preprocessing_pass_used=PreprocessingPass.PASS1_NATIVE.value,
            payload_category=PayloadCategory.UIDAI_AADHAAR_SECURE_QR.value,
            raw_decoded_text="9876543210...",
            structured_unpacked_json='{"name": "RAHUL SHARMA", "last_4": "4821"}',
            linked_phase3_or_phase4_id=None,
            image_created_utc_iso="2026-11-05T14:30:00.000000Z",
            recovery_classification=ResidualRecoveryConfidence.ORIGINAL_RECORD.value,
        )
    ]

    aadhaar_records = [
        AadhaarUnpackedRecord(
            aadhaar_qr_uid=1,
            barcode_uid=1,
            source_vfs_file_id=101,
            qr_format_version="SECURE_QR_V2_V3_BIGINT_GZIP",
            aadhaar_last_4_digits="4821",
            qr_generation_timestamp_str="2026-11-05 14:30:00",
            signed_full_name="RAHUL SHARMA",
            signed_dob_and_gender="15-08-1995 (M)",
            signed_care_of_guardian="S/O: Ramesh Sharma",
            signed_full_address_and_pin="42/B, Godowlia, Varanasi, Uttar Pradesh - 221001",
            extracted_jp2_photo_staging_id=9001,
            unmasked_registered_mobile="9876543210",
            unmasked_registered_email=None,
            rsa_2048_signature_hex="77" * 256,
            visual_vs_qr_tamper_status=AadhaarTamperStatus.AUTHENTIC_MATCH.value,
            extracted_jp2_bytes=b"\x00\x00\x00\x0c\x6a\x50\x20\x20",
            mobile_sha256_hash_hex="a" * 64,
        )
    ]

    receipt_records = [
        PaymentReceiptAuditRecord(
            receipt_audit_uid=1,
            source_vfs_file_id=202,
            claimed_payment_app="PhonePe",
            ocr_extracted_utr_12_digit="412014829104",
            ocr_extracted_amount_inr=75000.0,
            ocr_extracted_payee_and_vpa="Quick Cash (fraudster@fakebanknotexist)",
            ocr_displayed_date_str="05 Nov 2026, 02:35 PM",
            utr_yddd_julian_check_status=ReceiptJulianStatus.FORGED_UTR_JULIAN_DATE_MISMATCH.value,
            phase3_corroboration_status=ReceiptCorroborationStatus.CRITICAL_LOCAL_SCREENSHOT_MISSING_FROM_LEDGER.value,
            is_forged_receipt_flagged=1,
            forgery_proof_reasons_json='["FORGED_UTR_JULIAN_DATE_MISMATCH", "GENERATOR_APK_OR_EDITOR_PROVENANCE"]',
            forgery_proof_reasons=["FORGED_UTR_JULIAN_DATE_MISMATCH", "GENERATOR_APK_OR_EDITOR_PROVENANCE"],
        )
    ]

    engine = BarcodeAndReceiptForensicEngine()
    engine.export_case_database(
        db_path=db_path,
        barcode_records=barcodes,
        aadhaar_records=aadhaar_records,
        receipt_records=receipt_records,
    )

    assert os.path.exists(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM decoded_barcodes_and_qr_master_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT count(*) FROM uidai_aadhaar_secure_qr_unpacked_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT count(*) FROM payment_receipt_screenshots_authenticity_audit")
    assert cur.fetchone()[0] == 1

    # Verify column presence in decoded_barcodes_and_qr_master_ledger
    cur.execute("PRAGMA table_info(decoded_barcodes_and_qr_master_ledger)")
    cols = [r[1] for r in cur.fetchall()]
    assert "barcode_uid" in cols
    assert "source_vfs_file_id" in cols
    assert "source_visual_layer" in cols
    assert "symbology_type" in cols
    assert "preprocessing_pass_used" in cols
    assert "payload_category" in cols
    assert "raw_decoded_text" in cols
    assert "structured_unpacked_json" in cols

    # Verify column presence in uidai_aadhaar_secure_qr_unpacked_ledger
    cur.execute("PRAGMA table_info(uidai_aadhaar_secure_qr_unpacked_ledger)")
    cols_aadhaar = [r[1] for r in cur.fetchall()]
    assert "aadhaar_qr_uid" in cols_aadhaar
    assert "signed_full_name" in cols_aadhaar
    assert "aadhaar_last_4_digits" in cols_aadhaar
    assert "unmasked_registered_mobile" in cols_aadhaar
    assert "visual_vs_qr_tamper_status" in cols_aadhaar

    # Verify column presence in payment_receipt_screenshots_authenticity_audit
    cur.execute("PRAGMA table_info(payment_receipt_screenshots_authenticity_audit)")
    cols_receipt = [r[1] for r in cur.fetchall()]
    assert "receipt_audit_uid" in cols_receipt
    assert "ocr_extracted_utr_12_digit" in cols_receipt
    assert "utr_yddd_julian_check_status" in cols_receipt
    assert "phase3_corroboration_status" in cols_receipt
    assert "is_forged_receipt_flagged" in cols_receipt

    conn.close()
