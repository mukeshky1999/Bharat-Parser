"""
Acceptance Test Suite for Phase 8, Module 8.2:
The Zero-Omission (UNK) Unparsed File Audit, Binary Entropy Triage,
Generic Introspector & Dual SQLite FTS5 Search Engine.

Test Scope (6 Acceptance Tests):
1. test_vfs_zero_omission_accounting_invariant:
   Enforces mathematical conservation law N_total == N_State1 + N_State2 + N_State3 + N_State4;
   verifies UNCLAIMED_APP_SANDBOX_DATA_STORE alert generation for unclaimed app sandbox files.
2. test_magic_byte_extension_spoofing_detection:
   Inspects binary magic signatures of disguised SQLite, APK, and DEX files;
   verifies detected_magic_signature and is_extension_spoofed_mismatch flags.
3. test_shannon_entropy_and_chi_square_encryption_classifier:
   Disambiguates high-entropy compressed streams (chi^2 > 380) from true cryptographic
   SQLCipher / AES ciphertext (H(X) >= 7.980, 180 <= chi^2 <= 350, page-aligned).
4. test_universal_fallback_introspector_on_unk_database:
   Performs 3-stage schema and column heuristic introspection on uncataloged SQLite databases;
   validates 10-indicator forensic sweeper (UPI UTR, VPA, TRON, phone, timestamp conversion).
5. test_dual_fts5_and_roaring_bitmap_search:
   Evaluates custom-tokenized lexical FTS5 (tokenchars for VPAs, Indic NFC Devanagari),
   3-character trigram substring FTS5, and compressed 32-bit Roaring Bitmap facet filtering.
6. test_zero_omission_master_sqlite_export:
   Validates export of all 4 canonical tables and indexes into zero_omission_unk_and_fts5_engine.sqlite.
"""

import math
import os
import random
import sqlite3
import unicodedata
import pytest

from src.zero_omission_and_fts5.models import (
    AccountingState,
    DetectedMagicSignature,
    EntropyCryptoClassification,
    ContainerStructureType,
    DetectedIndicatorCategory,
    ResidualRecoveryConfidence,
    VfsAccountingRecord,
    UnkGenericFinding,
    SearchDocument,
    RoaringFacetEntry,
)
from src.zero_omission_and_fts5.vfs_auditor import VfsZeroOmissionAuditor
from src.zero_omission_and_fts5.magic_and_entropy import (
    MagicByteDiscrepancyDetector,
    EntropyAndChiSquareClassifier,
)
from src.zero_omission_and_fts5.fallback_introspector import UniversalFallbackIntrospector
from src.zero_omission_and_fts5.fts5_roaring_engine import (
    DualFts5AndRoaringEngine,
    RoaringBitmap32,
)
from src.zero_omission_and_fts5.engine import ZeroOmissionAndFts5Engine


def test_vfs_zero_omission_accounting_invariant():
    """Acceptance Test 1: Mathematical conservation law over VFS index + Unclaimed App alerts."""
    auditor = VfsZeroOmissionAuditor()

    records = [
        # State 1: Claimed & parsed by Phase 1-7 modules
        {
            "vfs_file_id": 1,
            "canonical_vfs_path": "/data/user/0/com.whatsapp/databases/msgstore.db",
            "file_byte_size": 204800,
            "consumed_by_modules": ["MOD_5_1_WHATSAPP", "MOD_2_1_SQLITE"],
            "extracted_records_count": 150,
            "is_blocked": False,
        },
        {
            "vfs_file_id": 2,
            "canonical_vfs_path": "/data/user/0/org.telegram.messenger/files/cache4.db",
            "file_byte_size": 102400,
            "consumed_by_modules": ["MOD_5_2_TELEGRAM"],
            "extracted_records_count": 85,
            "is_blocked": False,
        },
        {
            "vfs_file_id": 3,
            "canonical_vfs_path": "/data/user/0/com.phonepe.app/databases/phonepe.db",
            "file_byte_size": 81920,
            "consumed_by_modules": ["MOD_3_1_PHONEPE"],
            "extracted_records_count": 42,
            "is_blocked": False,
        },
        {
            "vfs_file_id": 4,
            "canonical_vfs_path": "/sdcard/DCIM/Camera/IMG_20261105_120000.jpg",
            "file_byte_size": 3145728,
            "consumed_by_modules": ["MOD_7_1_MEDIA", "MOD_7_3_QR"],
            "extracted_records_count": 2,
            "is_blocked": False,
        },
        # State 2: Blocked by password / corruption
        {
            "vfs_file_id": 5,
            "canonical_vfs_path": "/data/user/0/network.loki.messenger/databases/session.db",
            "file_byte_size": 65536,
            "consumed_by_modules": [],
            "extracted_records_count": 0,
            "is_blocked": True,
            "block_reason": "ENCRYPTED_GATED_MISSING_KEY",
        },
        # State 3: Static OS system / immutable resource
        {
            "vfs_file_id": 6,
            "canonical_vfs_path": "/system/bin/app_process64",
            "file_byte_size": 524288,
            "consumed_by_modules": [],
            "extracted_records_count": 0,
            "is_blocked": False,
        },
        {
            "vfs_file_id": 7,
            "canonical_vfs_path": "/system/fonts/Roboto-Regular.ttf",
            "file_byte_size": 300000,
            "consumed_by_modules": [],
            "extracted_records_count": 0,
            "is_blocked": False,
        },
        {
            "vfs_file_id": 8,
            "canonical_vfs_path": "/vendor/lib64/libaudio.so",
            "file_byte_size": 150000,
            "consumed_by_modules": [],
            "extracted_records_count": 0,
            "is_blocked": False,
        },
        # State 4: Unparsed user artifact (target queue!)
        {
            "vfs_file_id": 9,
            "canonical_vfs_path": "/data/user/0/com.unknown.muleapp/databases/mule_records.db",
            "file_byte_size": 49152,
            "consumed_by_modules": [],
            "extracted_records_count": 0,
            "is_blocked": False,
        },
        {
            "vfs_file_id": 10,
            "canonical_vfs_path": "/sdcard/Download/encrypted_payload.bin",
            "file_byte_size": 16384,
            "consumed_by_modules": [],
            "extracted_records_count": 0,
            "is_blocked": False,
        },
    ]

    accounting_ledger, alerts = auditor.audit_vfs_entries(records)

    # 1. Total count conservation
    assert len(accounting_ledger) == 10
    n_total = len(accounting_ledger)
    n_s1 = sum(1 for r in accounting_ledger if r.accounting_state == AccountingState.STATE_1_PARSED_AND_VERIFIED)
    n_s2 = sum(1 for r in accounting_ledger if r.accounting_state == AccountingState.STATE_2_RECOGNIZED_DECRYPTION_OR_CORRUPTION_BLOCKED)
    n_s3 = sum(1 for r in accounting_ledger if r.accounting_state == AccountingState.STATE_3_KNOWN_SYSTEM_OR_STATIC_ASSET_IMMUTABLE)
    n_s4 = sum(1 for r in accounting_ledger if r.accounting_state == AccountingState.STATE_4_UNK_UNPARSED_USER_ARTIFACT)

    assert n_s1 == 4
    assert n_s2 == 1
    assert n_s3 == 3
    assert n_s4 == 2
    assert n_total == n_s1 + n_s2 + n_s3 + n_s4

    # 2. Check alert for unclaimed user app sandbox file
    assert any(
        a["alert_type"] == "UNCLAIMED_APP_SANDBOX_DATA_STORE"
        and a["vfs_file_id"] == 9
        and "com.unknown.muleapp" in a["details"]
        for a in alerts
    )


def test_magic_byte_extension_spoofing_detection():
    """Acceptance Test 2: Detect disguised SQLite, APK, and DEX files by binary header."""
    detector = MagicByteDiscrepancyDetector()
    sandbox = os.path.join(".", ".workspace_tmp", "test_vfs_audit_sandbox")
    os.makedirs(sandbox, exist_ok=True)

    # 1. Disguised SQLite Database named "font_cache.ttf"
    sqlite_path = os.path.join(sandbox, "font_cache.ttf")
    with open(sqlite_path, "wb") as f:
        # SQLite 3 header: "SQLite format 3\0" + 84 bytes of page header
        f.write(b"SQLite format 3\x00" + b"\x10\x00\x01\x01\x00@  \x00\x00\x00\x01" + b"\x00" * 4070)

    # 2. Disguised ZIP/APK Archive named "avatar_thumb.png"
    zip_path = os.path.join(sandbox, "avatar_thumb.png")
    with open(zip_path, "wb") as f:
        # ZIP Local File Header: "PK\x03\x04"
        f.write(b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"\x00" * 50)

    # 3. Disguised Dalvik DEX named "classes.tmp"
    dex_path = os.path.join(sandbox, "classes.tmp")
    with open(dex_path, "wb") as f:
        # DEX header: "dex\n035\0"
        f.write(b"dex\n035\x00" + b"\x00" * 60)

    # 4. Legitimate PNG file
    png_path = os.path.join(sandbox, "real_photo.png")
    with open(png_path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 30)

    res_sqlite = detector.inspect_file(sqlite_path)
    assert res_sqlite.detected_magic_signature == DetectedMagicSignature.SQLITE_3_DATABASE
    assert res_sqlite.is_extension_spoofed_mismatch == 1

    res_zip = detector.inspect_file(zip_path)
    assert res_zip.detected_magic_signature == DetectedMagicSignature.ZIP_APK_JAR_DOCX_XLSX
    assert res_zip.is_extension_spoofed_mismatch == 1

    res_dex = detector.inspect_file(dex_path)
    assert res_dex.detected_magic_signature == DetectedMagicSignature.JAVA_DALVIK_DEX
    assert res_dex.is_extension_spoofed_mismatch == 1

    res_png = detector.inspect_file(png_path)
    assert res_png.detected_magic_signature == DetectedMagicSignature.JPEG_PNG_WEBP_HEIC_GIF
    assert res_png.is_extension_spoofed_mismatch == 0


def test_shannon_entropy_and_chi_square_encryption_classifier():
    """Acceptance Test 3: Disambiguate compressed media from SQLCipher/AES ciphertext via Chi-Square."""
    classifier = EntropyAndChiSquareClassifier()

    # File A: Compressed media mock (High entropy ~7.8 - 7.9, but non-uniform distribution -> chi^2 > 500)
    # Generated by biased frequency distribution
    rng = random.Random(42)
    compressed_bytes = bytearray()
    for _ in range(65536):
        # 80% uniform, 20% biased towards low bytes to simulate compression frequency tables
        if rng.random() < 0.20:
            compressed_bytes.append(rng.randint(0, 31))
        else:
            compressed_bytes.append(rng.randint(0, 255))

    analysis_a = classifier.analyze_bytes(bytes(compressed_bytes))
    assert analysis_a.shannon_entropy_bits >= 7.200
    assert analysis_a.chi_square_uniformity_score > 380.0
    assert analysis_a.classification == EntropyCryptoClassification.COMPRESSED_OR_PROPRIETARY_BINARY_STREAM

    # File B: True AES / SQLCipher ciphertext (64 KB = 16 x 4096-byte pages)
    # Truly uniform random bytes over all 256 byte bins
    crypto_rng = random.Random(1337)
    crypto_bytes = bytes(crypto_rng.randint(0, 255) for _ in range(65536))

    analysis_b = classifier.analyze_bytes(crypto_bytes)
    assert analysis_b.shannon_entropy_bits >= 7.980
    assert 180.0 <= analysis_b.chi_square_uniformity_score <= 350.0
    assert len(crypto_bytes) % 4096 == 0
    assert analysis_b.classification == EntropyCryptoClassification.UNCATALOGED_SQLCIPHER_OR_PAGE_ENCRYPTED_DB


def test_universal_fallback_introspector_on_unk_database():
    """Acceptance Test 4: Schema introspection & 10-indicator extraction on uncataloged SQLite DB."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_unk_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    db_path = os.path.join(sandbox, "custom_mule_ledger.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE custom_transactions (
            id INTEGER PRIMARY KEY,
            peer_contact TEXT,
            remittance_notes TEXT,
            payment_vpa TEXT,
            rrn_number TEXT,
            created_timestamp_ms INTEGER
        );
        """
    )
    # Insert row containing: Phone, TRON address, VPA, 12-digit UPI UTR, and timestamp in ms
    cur.execute(
        """
        INSERT INTO custom_transactions VALUES (
            1,
            '+919876543210',
            'Settled 50000 USDT to TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf via banking desk',
            'mule.king@ybl',
            '630914829104',
            1762348800000
        );
        """
    )
    conn.commit()
    conn.close()

    introspector = UniversalFallbackIntrospector()
    findings = introspector.introspect_sqlite_file(
        vfs_file_id=99,
        file_path=db_path,
        owning_package="com.unknown.muleapp",
    )

    # Must recover:
    # 1. Phone number
    phone_finding = next((f for f in findings if f.detected_indicator_category == DetectedIndicatorCategory.PHONE_NUMBER_E164), None)
    assert phone_finding is not None
    assert "+919876543210" in phone_finding.extracted_indicator_value

    # 2. TRON Crypto address
    crypto_finding = next((f for f in findings if f.detected_indicator_category == DetectedIndicatorCategory.VALIDATED_CRYPTO_ADDRESS), None)
    assert crypto_finding is not None
    assert "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf" in crypto_finding.extracted_indicator_value

    # 3. UPI VPA
    vpa_finding = next((f for f in findings if f.detected_indicator_category == DetectedIndicatorCategory.VALIDATED_UPI_VPA), None)
    assert vpa_finding is not None
    assert "mule.king@ybl" in vpa_finding.extracted_indicator_value

    # 4. 12-digit UPI UTR
    utr_finding = next((f for f in findings if f.detected_indicator_category == DetectedIndicatorCategory.VALIDATED_UPI_UTR_12_DIGIT), None)
    assert utr_finding is not None
    assert "630914829104" in utr_finding.extracted_indicator_value

    # 5. Converted UTC timestamp from 1762348800000 ms
    assert phone_finding.inferred_timestamp_utc_iso is not None
    assert "2025" in phone_finding.inferred_timestamp_utc_iso or "2026" in phone_finding.inferred_timestamp_utc_iso


def test_dual_fts5_and_roaring_bitmap_search():
    """Acceptance Test 5: Lexical FTS5 (tokenchars + Indic NFC), Trigram substring, and Roaring Bitmaps."""
    engine = DualFts5AndRoaringEngine()
    sandbox = os.path.join(".", ".workspace_tmp", "test_fts5_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    db_path = os.path.join(sandbox, "test_search.sqlite")

    engine.initialize_database(db_path)

    # Insert test documents
    docs = [
        SearchDocument(
            doc_uid=1,
            timeline_event_uid=101,
            originating_phase_module="PHASE_3_MOD_3_1",
            artifact_domain="FIAT_UPI_BANK_TX",
            app_package="com.phonepe.app",
            source_vfs_file_id=10,
            source_record_pointer="phonepe.db:tx:1",
            recovery_classification="ORIGINAL_RECORD",
            timestamp_utc_ns=1762348800000000000,
            actor_names_and_handles_nfc="merchant.99@okaxis",
            searchable_body_text_nfc="Paid Rs 50,000 to merchant.99@okaxis via UTR 630914829104",
        ),
        # Decomposed NFD Hindi text: "नोएडा"
        SearchDocument(
            doc_uid=2,
            timeline_event_uid=102,
            originating_phase_module="PHASE_5_MOD_5_1",
            artifact_domain="MESSAGING_CHAT",
            app_package="org.telegram.messenger",
            source_vfs_file_id=20,
            source_record_pointer="cache4.db:messages:55",
            recovery_classification="ORIGINAL_RECORD",
            timestamp_utc_ns=1762348810000000000,
            actor_names_and_handles_nfc="HawalaKing",
            searchable_body_text_nfc=unicodedata.normalize("NFD", "हवाला का पैसा नोएडा फ्लैट में है"),
        ),
        SearchDocument(
            doc_uid=3,
            timeline_event_uid=103,
            originating_phase_module="PHASE_4_MOD_4_1",
            artifact_domain="CRYPTO_WEB3_CEX_TX",
            app_package="com.binance.dev",
            source_vfs_file_id=30,
            source_record_pointer="binance.db:orders:9",
            recovery_classification="HISTORICAL_COMMITTED_RECORD",
            timestamp_utc_ns=1762348820000000000,
            actor_names_and_handles_nfc="+919876543210",
            searchable_body_text_nfc="+919876543210 transferred 5000 USDT to 0x71C85C2F37985Eb722F816692022d42e401E5E82",
        ),
    ]

    engine.index_documents(docs)

    # 1. Lexical FTS5 Query for intact VPA token
    res_vpa = engine.search_lexical("merchant.99@okaxis")
    assert len(res_vpa) == 1
    assert res_vpa[0].doc_uid == 1

    # 2. Trigram FTS5 Query for mid-string substring ("148291")
    res_sub = engine.search_trigram("148291")
    assert len(res_sub) == 1
    assert res_sub[0].doc_uid == 1

    # 3. Trigram FTS5 Query for EVM hex fragment ("71C85C2F")
    res_evm = engine.search_trigram("71C85C2F")
    assert len(res_evm) == 1
    assert res_evm[0].doc_uid == 3

    # 4. Lexical FTS5 Query with keyboard-typed NFC Devanagari "नोएडा"
    nfc_query = unicodedata.normalize("NFC", "नोएडा")
    res_hindi = engine.search_lexical(nfc_query)
    assert len(res_hindi) == 1
    assert res_hindi[0].doc_uid == 2

    # 5. Roaring Bitmap Facet Filtering in RAM
    # Filter: originating_phase_module == "PHASE_3_MOD_3_1" AND artifact_domain == "FIAT_UPI_BANK_TX"
    matching_uids = engine.query_facets(
        facet_filters={
            "originating_phase_module": "PHASE_3_MOD_3_1",
            "artifact_domain": "FIAT_UPI_BANK_TX",
        }
    )
    assert matching_uids == [1]


def test_zero_omission_master_sqlite_export():
    """Acceptance Test 6: Verify export of all 4 canonical tables into master database."""
    output_db = os.path.join(".", ".workspace_tmp", "zero_omission_unk_and_fts5_engine.sqlite")
    if os.path.exists(output_db):
        os.remove(output_db)

    engine = ZeroOmissionAndFts5Engine()

    vfs_records = [
        VfsAccountingRecord(
            vfs_file_id=1,
            canonical_vfs_path="/data/user/0/com.unknown.muleapp/databases/mule.db",
            owning_app_package_or_domain="com.unknown.muleapp",
            file_byte_size=65536,
            accounting_state=AccountingState.STATE_4_UNK_UNPARSED_USER_ARTIFACT,
            consumed_by_modules_json="[]",
            extracted_records_count=0,
            filename_extension=".db",
            detected_magic_signature="SQLITE_3_DATABASE",
            is_extension_spoofed_mismatch=0,
            shannon_entropy_bits=5.42,
            chi_square_uniformity_score=1250.0,
            entropy_crypto_classification="LOW_ENTROPY_PLAINTEXT_OR_STRUCTURED",
            unk_introspection_hit_count=3,
        )
    ]

    findings = [
        UnkGenericFinding(
            vfs_file_id=1,
            owning_app_package="com.unknown.muleapp",
            container_structure_type=ContainerStructureType.UNK_SQLITE_ACTIVE_ROW,
            table_or_object_path="mule_records:1",
            detected_indicator_category=DetectedIndicatorCategory.VALIDATED_UPI_UTR_12_DIGIT,
            extracted_indicator_value="630914829104",
            full_row_or_context_json='{"id": 1, "utr": "630914829104"}',
            inferred_timestamp_utc_iso="2026-11-05T13:20:00.000Z",
            recovery_classification=ResidualRecoveryConfidence.ORIGINAL_RECORD,
        )
    ]

    docs = [
        SearchDocument(
            doc_uid=1,
            timeline_event_uid=1001,
            originating_phase_module="PHASE_8_MOD_8_2",
            artifact_domain="GENERIC_UNK_RECORD",
            app_package="com.unknown.muleapp",
            source_vfs_file_id=1,
            source_record_pointer="mule_records:1",
            recovery_classification="ORIGINAL_RECORD",
            timestamp_utc_ns=1762348800000000000,
            actor_names_and_handles_nfc="mule_user",
            searchable_body_text_nfc="Transaction UTR 630914829104",
        )
    ]

    facets = [
        RoaringFacetEntry(
            target_table_scope="GLOBAL_SEARCH_DOCUMENTS",
            facet_dimension_name="artifact_domain",
            facet_value_key="GENERIC_UNK_RECORD",
            total_matching_cardinality=1,
            serialized_roaring_bitmap_blob=b"\x30\x3b\x01\x00\x00\x00\x01\x00",
        )
    ]

    engine.export_master_database(
        output_db_path=output_db,
        accounting_records=vfs_records,
        findings=findings,
        search_documents=docs,
        facets=facets,
    )

    assert os.path.exists(output_db)
    conn = sqlite3.connect(output_db)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM vfs_zero_omission_accounting_ledger;")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM unk_generic_introspection_findings;")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM global_search_documents_master;")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT COUNT(*) FROM roaring_bitmap_facet_index_store;")
    assert cur.fetchone()[0] == 1

    conn.close()
