"""
Master Orchestration Engine for Phase 8, Module 8.2:
ZeroOmissionAndFts5Engine coordinating VFS Accounting, Entropy Analysis, Fallback Introspection, and Dual FTS5.
"""

import json
import os
import sqlite3
from typing import Optional

from src.zero_omission_and_fts5.models import (
    AccountingState,
    DetectedMagicSignature,
    EntropyCryptoClassification,
    RoaringFacetEntry,
    SearchDocument,
    UnkGenericFinding,
    VfsAccountingRecord,
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


class ZeroOmissionAndFts5Engine:
    """Production coordinator for 100% VFS file accounting, entropy triage, UNK fallback introspection, and Dual FTS5 search."""

    def __init__(self):
        self.auditor = VfsZeroOmissionAuditor()
        self.magic_detector = MagicByteDiscrepancyDetector()
        self.entropy_classifier = EntropyAndChiSquareClassifier()
        self.fallback_introspector = UniversalFallbackIntrospector()
        self.fts5_engine = DualFts5AndRoaringEngine()

    def export_master_database(
        self,
        output_db_path: str,
        accounting_records: list[VfsAccountingRecord],
        findings: list[UnkGenericFinding],
        search_documents: list[SearchDocument],
        facets: list[RoaringFacetEntry],
    ) -> None:
        """Exports all 4 canonical tables and companion FTS5 virtual indexes into zero_omission_unk_and_fts5_engine.sqlite."""
        os.makedirs(os.path.dirname(os.path.abspath(output_db_path)), exist_ok=True)
        if os.path.exists(output_db_path):
            try:
                os.remove(output_db_path)
            except OSError as exc:
                _ = exc

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        # Table 1: vfs_zero_omission_accounting_ledger
        cur.execute(
            """
            CREATE TABLE vfs_zero_omission_accounting_ledger (
                vfs_file_id INTEGER PRIMARY KEY,
                canonical_vfs_path TEXT NOT NULL,
                owning_app_package_or_domain TEXT,
                file_byte_size INTEGER NOT NULL,
                accounting_state TEXT NOT NULL,
                consumed_by_modules_json TEXT,
                extracted_records_count INTEGER DEFAULT 0,
                filename_extension TEXT,
                detected_magic_signature TEXT NOT NULL,
                is_extension_spoofed_mismatch INTEGER DEFAULT 0,
                shannon_entropy_bits REAL,
                chi_square_uniformity_score REAL,
                entropy_crypto_classification TEXT,
                unk_introspection_hit_count INTEGER DEFAULT 0
            );
            """
        )
        cur.execute("CREATE INDEX idx_vfs_accounting_state ON vfs_zero_omission_accounting_ledger(accounting_state);")
        cur.execute("CREATE INDEX idx_vfs_spoofed_mismatch ON vfs_zero_omission_accounting_ledger(is_extension_spoofed_mismatch);")

        for r in accounting_records:
            cur.execute(
                """
                INSERT INTO vfs_zero_omission_accounting_ledger VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                );
                """,
                (
                    r.vfs_file_id,
                    r.canonical_vfs_path,
                    r.owning_app_package_or_domain,
                    r.file_byte_size,
                    r.accounting_state.value if isinstance(r.accounting_state, AccountingState) else str(r.accounting_state),
                    r.consumed_by_modules_json,
                    r.extracted_records_count,
                    r.filename_extension,
                    r.detected_magic_signature,
                    r.is_extension_spoofed_mismatch,
                    r.shannon_entropy_bits,
                    r.chi_square_uniformity_score,
                    r.entropy_crypto_classification,
                    r.unk_introspection_hit_count,
                ),
            )

        # Table 2: unk_generic_introspection_findings
        cur.execute(
            """
            CREATE TABLE unk_generic_introspection_findings (
                unk_finding_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                vfs_file_id INTEGER NOT NULL,
                owning_app_package TEXT NOT NULL,
                container_structure_type TEXT NOT NULL,
                table_or_object_path TEXT NOT NULL,
                detected_indicator_category TEXT NOT NULL,
                extracted_indicator_value TEXT NOT NULL,
                full_row_or_context_json TEXT NOT NULL,
                inferred_timestamp_utc_iso TEXT,
                recovery_classification TEXT NOT NULL,
                FOREIGN KEY (vfs_file_id) REFERENCES vfs_zero_omission_accounting_ledger(vfs_file_id)
            );
            """
        )
        cur.execute("CREATE INDEX idx_unk_vfs_file_id ON unk_generic_introspection_findings(vfs_file_id);")
        cur.execute("CREATE INDEX idx_unk_indicator_val ON unk_generic_introspection_findings(extracted_indicator_value);")

        for f in findings:
            cur.execute(
                """
                INSERT INTO unk_generic_introspection_findings (
                    vfs_file_id, owning_app_package, container_structure_type,
                    table_or_object_path, detected_indicator_category, extracted_indicator_value,
                    full_row_or_context_json, inferred_timestamp_utc_iso, recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    f.vfs_file_id,
                    f.owning_app_package,
                    f.container_structure_type.value if hasattr(f.container_structure_type, "value") else str(f.container_structure_type),
                    f.table_or_object_path,
                    f.detected_indicator_category.value if hasattr(f.detected_indicator_category, "value") else str(f.detected_indicator_category),
                    f.extracted_indicator_value,
                    f.full_row_or_context_json,
                    f.inferred_timestamp_utc_iso,
                    f.recovery_classification.value if hasattr(f.recovery_classification, "value") else str(f.recovery_classification),
                ),
            )

        # Table 3: global_search_documents_master + Dual FTS5
        cur.execute(
            """
            CREATE TABLE global_search_documents_master (
                doc_uid INTEGER PRIMARY KEY,
                timeline_event_uid INTEGER,
                originating_phase_module TEXT NOT NULL,
                artifact_domain TEXT NOT NULL,
                app_package TEXT,
                source_vfs_file_id INTEGER,
                source_record_pointer TEXT NOT NULL,
                recovery_classification TEXT NOT NULL,
                timestamp_utc_ns INTEGER,
                actor_names_and_handles_nfc TEXT,
                searchable_body_text_nfc TEXT
            );
            """
        )
        cur.execute(
            """
            CREATE VIRTUAL TABLE global_fts5_lexical_index USING fts5(
                actor_names_and_handles_nfc,
                searchable_body_text_nfc,
                content='global_search_documents_master',
                content_rowid='doc_uid',
                tokenize="unicode61 remove_diacritics 2 tokenchars '@._:-+/$#'"
            );
            """
        )
        cur.execute(
            """
            CREATE VIRTUAL TABLE global_fts5_trigram_index USING fts5(
                actor_names_and_handles_nfc,
                searchable_body_text_nfc,
                content='global_search_documents_master',
                content_rowid='doc_uid',
                tokenize="trigram case_sensitive 0"
            );
            """
        )
        cur.execute(
            """
            CREATE TRIGGER trg_master_docs_ai AFTER INSERT ON global_search_documents_master BEGIN
                INSERT INTO global_fts5_lexical_index(rowid, actor_names_and_handles_nfc, searchable_body_text_nfc)
                VALUES (new.doc_uid, new.actor_names_and_handles_nfc, new.searchable_body_text_nfc);
                INSERT INTO global_fts5_trigram_index(rowid, actor_names_and_handles_nfc, searchable_body_text_nfc)
                VALUES (new.doc_uid, new.actor_names_and_handles_nfc, new.searchable_body_text_nfc);
            END;
            """
        )

        for d in search_documents:
            norm_actor = DualFts5AndRoaringEngine.normalize_text(d.actor_names_and_handles_nfc)
            norm_body = DualFts5AndRoaringEngine.normalize_text(d.searchable_body_text_nfc)
            cur.execute(
                """
                INSERT INTO global_search_documents_master VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                );
                """,
                (
                    d.doc_uid,
                    d.timeline_event_uid,
                    d.originating_phase_module,
                    d.artifact_domain,
                    d.app_package,
                    d.source_vfs_file_id,
                    d.source_record_pointer,
                    d.recovery_classification,
                    d.timestamp_utc_ns,
                    norm_actor,
                    norm_body,
                ),
            )

        # Table 4: roaring_bitmap_facet_index_store
        cur.execute(
            """
            CREATE TABLE roaring_bitmap_facet_index_store (
                facet_bitmap_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                target_table_scope TEXT NOT NULL,
                facet_dimension_name TEXT NOT NULL,
                facet_value_key TEXT NOT NULL,
                total_matching_cardinality INTEGER NOT NULL,
                serialized_roaring_bitmap_blob BLOB NOT NULL
            );
            """
        )

        for fc in facets:
            cur.execute(
                """
                INSERT INTO roaring_bitmap_facet_index_store (
                    target_table_scope, facet_dimension_name, facet_value_key,
                    total_matching_cardinality, serialized_roaring_bitmap_blob
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (
                    fc.target_table_scope,
                    fc.facet_dimension_name,
                    fc.facet_value_key,
                    fc.total_matching_cardinality,
                    fc.serialized_roaring_bitmap_blob,
                ),
            )

        conn.commit()
        conn.close()
