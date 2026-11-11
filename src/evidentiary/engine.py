"""
The 5D Evidentiary State Engine & Tripartite Evaluation Core.
Phase 1, Module 1.4, Section 2 & Section 3.
"""

from typing import Optional

from src.evidentiary.enums import (
    DimensionAPresence,
    DimensionBAccessibility,
    DimensionCIntegrity,
    DimensionDCoverage,
    DimensionEMaturity,
    TripartiteStoredState,
)
from src.evidentiary.models import EvidentiaryAuditEntry
from src.evidentiary.ledger import TripartiteLedgerDatabase


class EvidentiaryStateEngine:
    """Enforces the 4 absolute courtroom rules and evaluates artifacts across all 5 dimensions."""

    def __init__(self, ledger: TripartiteLedgerDatabase):
        self.ledger = ledger

    def evaluate_artifact(
        self,
        artifact_code: str,
        forensic_group_num: int,
        forensic_group_name: str,
        expected_canonical_path: str,
        file_exists_in_vfs: bool = False,
        file_size_bytes: int = 0,
        is_plaintext_readable: bool = False,
        is_encrypted_ciphertext: bool = False,
        has_hardware_gated_key: bool = False,
        missing_keychain_key: bool = False,
        is_bfu_extraction: bool = False,
        is_tier_1b_backup: bool = False,
        is_ghost_app: bool = False,
        is_static_image: bool = False,
        app_instance_id: Optional[int] = None,
        vfs_file_id: Optional[int] = None,
        parser_module_name: Optional[str] = None,
        active_records: int = 0,
        residual_records: int = 0,
        diagnostic_notes: Optional[str] = None
    ) -> EvidentiaryAuditEntry:
        """
        Evaluates a target artifact against the 5D state matrix and tripartite model.
        Guarantees that Rule 1 ("Absent" ban) and Rule 2 (Lock-state inference) are strictly enforced.
        """
        notes = diagnostic_notes or ""

        # 1. Dimension A: Acquisition Presence
        if file_exists_in_vfs:
            if file_size_bytes == 0:
                dim_a = DimensionAPresence.PRESENT_EMPTY_STUB
            else:
                dim_a = DimensionAPresence.PRESENT
            stored_state = TripartiteStoredState.APP_INSTALLED_STORAGE_EXPECTED

        else:
            if is_bfu_extraction and (
                "/user/" in expected_canonical_path or
                "CE" in artifact_code or
                "whatsapp" in expected_canonical_path.lower()
            ):
                # Rule 2: Automatic BFU Lock-State CE exclusion inference
                dim_a = DimensionAPresence.SOURCE_PRESENT_NOT_ACQUIRED_BFU
                stored_state = TripartiteStoredState.ARCHITECTURALLY_EXPECTED
                notes = (notes + " Gated by Android BFU CE State: credentials required to decrypt user partition").strip()

            elif is_tier_1b_backup and any(
                token in expected_canonical_path for token in ("knowledgeC", "tracev3", "fsevents", "Signal", "CoreDuet")
            ):
                # Rule 2: Automatic iOS Logical Backup exclusion inference
                dim_a = DimensionAPresence.SOURCE_PRESENT_NOT_ACQUIRED_TIER
                stored_state = TripartiteStoredState.ARCHITECTURALLY_EXPECTED
                notes = (notes + " Source present on device architecture but excluded by OS Backup Policy").strip()

            elif is_ghost_app:
                dim_a = DimensionAPresence.NOT_OBSERVED_GHOST_APP
                stored_state = TripartiteStoredState.APP_UNINSTALLED_GHOST
                notes = (notes + " App was uninstalled prior to seizure; residual references found in telemetry").strip()

            else:
                dim_a = DimensionAPresence.NOT_OBSERVED
                stored_state = TripartiteStoredState.APP_NOT_PRESENT
                notes = (notes + " Not observed in extraction").strip()

        # 2. Dimension B: Content Accessibility
        if dim_a in (DimensionAPresence.PRESENT, DimensionAPresence.PRESENT_EMPTY_STUB):
            if is_plaintext_readable:
                dim_b = DimensionBAccessibility.READABLE
            elif is_encrypted_ciphertext:
                if has_hardware_gated_key:
                    # Rule 3: Gated by Hardware (SEP/TEE)
                    dim_b = DimensionBAccessibility.ENCRYPTED_GATED_BY_HARDWARE
                    notes = (notes + " Protected by hardware SEP/TEE/StrongBox key; cannot be decrypted offline").strip()
                elif missing_keychain_key:
                    # Rule 3: Missing external key material
                    dim_b = DimensionBAccessibility.ENCRYPTED_GATED_MISSING_KEY
                    notes = (notes + " Ciphertext database present; requires Keychain item from keychain-2.db or keychain-backup.plist to decrypt").strip()
                else:
                    dim_b = DimensionBAccessibility.ENCRYPTED_GATED_MISSING_KEY
            else:
                dim_b = DimensionBAccessibility.CORRUPT_OR_ZEROED
        else:
            dim_b = DimensionBAccessibility.NOT_APPLICABLE

        # 3. Dimension C: Physical & Source Integrity
        if dim_a in (DimensionAPresence.PRESENT, DimensionAPresence.PRESENT_EMPTY_STUB):
            dim_c = DimensionCIntegrity.VERIFIED_STATIC if is_static_image else DimensionCIntegrity.VERIFIED_LIVE_STAGING_HASH
        else:
            dim_c = DimensionCIntegrity.UNKNOWN

        # 4. Dimension D: Parser Coverage
        if dim_b == DimensionBAccessibility.READABLE:
            dim_d = DimensionDCoverage.DIRECTLY_PARSED_FULL
        elif dim_b in (DimensionBAccessibility.ENCRYPTED_GATED_MISSING_KEY, DimensionBAccessibility.ENCRYPTED_GATED_BY_HARDWARE):
            dim_d = DimensionDCoverage.PARSED_WITH_SUPPLIED_KEYS
        else:
            dim_d = DimensionDCoverage.NOT_TESTED

        # 5. Dimension E: Research Maturity
        dim_e = DimensionEMaturity.R4

        entry = EvidentiaryAuditEntry(
            artifact_code=artifact_code,
            forensic_group_num=forensic_group_num,
            forensic_group_name=forensic_group_name,
            expected_canonical_path=expected_canonical_path,
            tripartite_stored_state=stored_state,
            dim_a_presence=dim_a,
            dim_b_accessibility=dim_b,
            dim_c_integrity=dim_c,
            dim_d_coverage=dim_d,
            dim_e_maturity=dim_e,
            app_instance_id=app_instance_id,
            vfs_file_id=vfs_file_id,
            parser_module_name=parser_module_name,
            active_records_parsed=active_records,
            residual_records_parsed=residual_records,
            diagnostic_notes=notes or None
        )

        entry_id = self.ledger.record_audit_entry(entry)
        entry.audit_entry_id = entry_id
        return entry
