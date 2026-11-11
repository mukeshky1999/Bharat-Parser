"""
Master Legal Evidentiary Compliance & Section 63 BSA Engine (Phase 8, Module 8.3).
Orchestrates Hierarchical Hash Manifests, Statutory Part A/B Certificate Generation,
and Merkle Chain-of-Custody verification with master SQLite database export.
"""

import os
import sqlite3
from typing import Optional

from src.legal_and_bsa.models import (
    ChainOfCustodyEntry,
    EvidentiaryHashManifestItem,
    HashTier,
    ImmutabilityStatus,
    Section63BsaCertificateRecord,
    StatutoryRegimeMode,
)
from src.legal_and_bsa.hash_manifest import HierarchicalHashManifestManager
from src.legal_and_bsa.bsa_certificate_generator import Section63BsaCertificateGenerator
from src.legal_and_bsa.chain_of_custody import (
    MerkleChainOfCustodyLedger,
    ChainOfCustodyTamperException,
)


class LegalComplianceAndBsaEngine:
    """Production coordinator for Indian Legal Compliance, Hash Manifests, and Section 63(4)(c) BSA Certification."""

    def __init__(self):
        self.manifest_manager = HierarchicalHashManifestManager()
        self.certificate_generator = Section63BsaCertificateGenerator()
        self.custody_ledger = MerkleChainOfCustodyLedger()

    def export_master_database(
        self,
        output_db_path: str,
        manifest_items: list[EvidentiaryHashManifestItem],
        certificates: list[Section63BsaCertificateRecord],
        audit_entries: list[ChainOfCustodyEntry],
    ) -> None:
        """Exports all 3 canonical tables and indexes into legal_compliance_and_section63_bsa.sqlite."""
        os.makedirs(os.path.dirname(os.path.abspath(output_db_path)), exist_ok=True)
        if os.path.exists(output_db_path):
            try:
                os.remove(output_db_path)
            except OSError as exc:
                _ = exc

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        # Table 1: evidentiary_hash_manifest_ledger
        cur.execute(
            """
            CREATE TABLE evidentiary_hash_manifest_ledger (
                manifest_item_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_tier TEXT NOT NULL,
                vfs_file_id_or_staging_id INTEGER,
                canonical_path_or_exhibit_name TEXT NOT NULL,
                artifact_description TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                sha256_hex TEXT NOT NULL,
                md5_hex TEXT NOT NULL,
                blake3_hex TEXT,
                parent_manifest_item_uid INTEGER,
                crypto_unwrap_provenance_note TEXT,
                post_run_reverified_status TEXT NOT NULL,
                hashed_at_utc_iso TEXT NOT NULL
            );
            """
        )
        cur.execute("CREATE INDEX idx_manifest_sha256 ON evidentiary_hash_manifest_ledger(sha256_hex);")
        cur.execute("CREATE INDEX idx_manifest_md5 ON evidentiary_hash_manifest_ledger(md5_hex);")
        cur.execute("CREATE INDEX idx_manifest_tier ON evidentiary_hash_manifest_ledger(hash_tier);")

        for item in manifest_items:
            tier_val = item.hash_tier.value if isinstance(item.hash_tier, HashTier) else str(item.hash_tier)
            immut_val = (
                item.post_run_reverified_status.value
                if isinstance(item.post_run_reverified_status, ImmutabilityStatus)
                else str(item.post_run_reverified_status)
            )
            cur.execute(
                """
                INSERT INTO evidentiary_hash_manifest_ledger (
                    manifest_item_uid, hash_tier, vfs_file_id_or_staging_id,
                    canonical_path_or_exhibit_name, artifact_description, byte_size,
                    sha256_hex, md5_hex, blake3_hex, parent_manifest_item_uid,
                    crypto_unwrap_provenance_note, post_run_reverified_status, hashed_at_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    item.manifest_item_uid,
                    tier_val,
                    item.vfs_file_id_or_staging_id,
                    item.canonical_path_or_exhibit_name,
                    item.artifact_description,
                    item.byte_size,
                    item.sha256_hex,
                    item.md5_hex,
                    item.blake3_hex,
                    item.parent_manifest_item_uid,
                    item.crypto_unwrap_provenance_note,
                    immut_val,
                    item.hashed_at_utc_iso,
                ),
            )

        # Table 2: section63_bsa_certificates_registry
        cur.execute(
            """
            CREATE TABLE section63_bsa_certificates_registry (
                certificate_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                certificate_reference_no TEXT NOT NULL,
                statutory_regime_mode TEXT NOT NULL,
                case_fir_or_rc_number TEXT NOT NULL,
                part_a_deponent_details_json TEXT NOT NULL,
                part_a_device_metadata_json TEXT NOT NULL,
                part_b_expert_details_json TEXT NOT NULL,
                part_b_workstation_env_json TEXT NOT NULL,
                sec63_2_c_integrity_clause_text TEXT NOT NULL,
                tier1_master_image_sha256 TEXT NOT NULL,
                case_merkle_root_sha256 TEXT NOT NULL,
                rendered_certificate_pdf_sha256 TEXT,
                generated_at_ist_iso TEXT NOT NULL
            );
            """
        )
        cur.execute(
            "CREATE UNIQUE INDEX idx_cert_ref_no ON section63_bsa_certificates_registry(certificate_reference_no);"
        )

        for cert in certificates:
            regime_val = (
                cert.statutory_regime_mode.value
                if isinstance(cert.statutory_regime_mode, StatutoryRegimeMode)
                else str(cert.statutory_regime_mode)
            )
            cur.execute(
                """
                INSERT INTO section63_bsa_certificates_registry (
                    certificate_uid, certificate_reference_no, statutory_regime_mode,
                    case_fir_or_rc_number, part_a_deponent_details_json, part_a_device_metadata_json,
                    part_b_expert_details_json, part_b_workstation_env_json, sec63_2_c_integrity_clause_text,
                    tier1_master_image_sha256, case_merkle_root_sha256, rendered_certificate_pdf_sha256,
                    generated_at_ist_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    cert.certificate_uid,
                    cert.certificate_reference_no,
                    regime_val,
                    cert.case_fir_or_rc_number,
                    cert.part_a_deponent_details_json,
                    cert.part_a_device_metadata_json,
                    cert.part_b_expert_details_json,
                    cert.part_b_workstation_env_json,
                    cert.sec63_2_c_integrity_clause_text,
                    cert.tier1_master_image_sha256,
                    cert.case_merkle_root_sha256,
                    cert.rendered_certificate_pdf_sha256,
                    cert.generated_at_ist_iso,
                ),
            )

        # Table 3: chain_of_custody_merkle_ledger
        cur.execute(
            """
            CREATE TABLE chain_of_custody_merkle_ledger (
                seq_no INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc_ns INTEGER NOT NULL,
                timestamp_ist_iso TEXT NOT NULL,
                actor_or_subsystem TEXT NOT NULL,
                event_action_type TEXT NOT NULL,
                canonical_payload_json TEXT NOT NULL,
                previous_entry_hash_hex TEXT NOT NULL,
                current_entry_hash_hex TEXT NOT NULL
            );
            """
        )
        cur.execute("CREATE INDEX idx_coc_action_type ON chain_of_custody_merkle_ledger(event_action_type);")

        for entry in audit_entries:
            cur.execute(
                """
                INSERT INTO chain_of_custody_merkle_ledger (
                    seq_no, timestamp_utc_ns, timestamp_ist_iso,
                    actor_or_subsystem, event_action_type, canonical_payload_json,
                    previous_entry_hash_hex, current_entry_hash_hex
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    entry.seq_no,
                    entry.timestamp_utc_ns,
                    entry.timestamp_ist_iso,
                    entry.actor_or_subsystem,
                    entry.event_action_type,
                    entry.canonical_payload_json,
                    entry.previous_entry_hash_hex,
                    entry.current_entry_hash_hex,
                ),
            )

        conn.commit()
        conn.close()
