"""
Master Engine for Module 9.5: Interactive UNK Triage, Key-Broker Unlocker & Section 63 BSA Studio.
Coordinates sliding-window entropy, zero-code promotion, DAG hot-patching, freeze de-confliction, and report studio.
"""

from typing import Any

from src.unk_triage_and_bsa_studio.models import (
    BlockEntropyResult,
    BsaDossierDualPreview,
    ChiSquareHistogramResult,
    FreezeCandidateAccount,
    IncrementalHotPatchResult,
    PreFlightCheckResult,
    PromotedSchemaRecord,
    SemanticColumnRole,
)
from src.unk_triage_and_bsa_studio.entropy_profiler import (
    SlidingWindowEntropyProfiler,
)
from src.unk_triage_and_bsa_studio.schema_mapper import (
    ZeroCodeSchemaMapper,
)
from src.unk_triage_and_bsa_studio.key_broker_hotpatcher import (
    KeyBrokerHotPatcher,
)
from src.unk_triage_and_bsa_studio.freeze_deconfliction import (
    NodalFreezeDeconflictionCenter,
)
from src.unk_triage_and_bsa_studio.bsa_report_studio import (
    BsaReportStudioEngine,
)


class UnkTriageAndBsaStudioMasterEngine:
    """Master engine orchestrating UNK Triage, Key-Broker console, freeze de-confliction, and BSA studio."""

    def __init__(self):
        self.entropy_profiler = SlidingWindowEntropyProfiler()
        self.schema_mapper = ZeroCodeSchemaMapper()
        self.key_broker = KeyBrokerHotPatcher()
        self.freeze_deconfliction = NodalFreezeDeconflictionCenter()
        self.bsa_studio = BsaReportStudioEngine()

    def profile_file_entropy(self, file_bytes: bytes) -> BlockEntropyResult:
        """Profiles 4 KB sliding-window Shannon entropy curve across a file."""
        return self.entropy_profiler.compute_block_entropy_skyline(file_bytes)

    def compute_chi_squared(self, data_bytes: bytes) -> ChiSquareHistogramResult:
        """Calculates 256-bin Chi-Square uniformity statistic."""
        return self.entropy_profiler.compute_256bin_chi_squared(data_bytes)

    def promote_table(
        self,
        db_path: str,
        vfs_file_id: int,
        table_name: str,
        column_roles: dict[str, SemanticColumnRole],
        raw_rows: list[dict[str, Any]],
        examiner_name: str = "Examiner",
    ) -> PromotedSchemaRecord:
        """Promotes custom table into live case and records promotion ledger entry."""
        self.schema_mapper.initialize_triage_db(db_path)
        return self.schema_mapper.promote_table_to_case(
            db_path=db_path,
            vfs_file_id=vfs_file_id,
            table_name=table_name,
            column_roles=column_roles,
            raw_rows=raw_rows,
            examiner_name=examiner_name,
        )

    def execute_keybroker_hotpatch(
        self,
        vfs_file_id: int,
        secret: str,
        container_type: str,
        simulated_records: list[dict[str, Any]],
    ) -> IncrementalHotPatchResult:
        """Unwraps blocked container and hot-patches new records in < 3.0 seconds."""
        return self.key_broker.execute_incremental_hotpatch(
            vfs_file_id=vfs_file_id,
            secret=secret,
            container_type=container_type,
            simulated_unlocked_records=simulated_records,
        )

    def deconflict_freeze_candidates(
        self, candidates: list[dict[str, Any]]
    ) -> list[FreezeCandidateAccount]:
        """Evaluates freeze candidates with victim locks and utility biller safeguards."""
        return self.freeze_deconfliction.evaluate_freeze_candidates(candidates)

    def export_1930_ncrp_csv(
        self,
        evaluated_candidates: list[FreezeCandidateAccount],
        complainant_account: str,
        acknowledgement_no: str,
    ) -> str:
        """Exports 14-column 1930 NCRP bank lien CSV."""
        return self.freeze_deconfliction.generate_1930_ncrp_csv(
            evaluated_candidates=evaluated_candidates,
            complainant_account=complainant_account,
            acknowledgement_no=acknowledgement_no,
        )

    def run_preflight_gate(
        self, submission_data: dict[str, Any]
    ) -> PreFlightCheckResult:
        """Runs mandatory 6-point Section 63(4)(c) BSA compliance check."""
        return self.bsa_studio.run_preflight_statutory_gate(submission_data)

    def generate_dual_preview(
        self,
        exhibits: list[dict[str, Any]],
        include_dual_statutory_caption: bool = True,
    ) -> BsaDossierDualPreview:
        """Builds side-by-side synchronized preview of Master Court Copy and Defense Disclosure Copy."""
        return self.bsa_studio.generate_dual_preview_dossier(
            exhibits=exhibits,
            include_dual_statutory_caption=include_dual_statutory_caption,
        )
