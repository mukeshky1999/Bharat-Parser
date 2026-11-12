"""Master engine for the UNK triage workbench and key-broker console.
Coordinates sliding-window entropy, examiner-driven schema promotion and DAG hot-patching."""

from typing import Any

from src.unk_triage.models import (
    BlockEntropyResult,
    ChiSquareHistogramResult,
    IncrementalHotPatchResult,
    PromotedSchemaRecord,
    SemanticColumnRole,
)
from src.unk_triage.entropy_profiler import SlidingWindowEntropyProfiler
from src.unk_triage.schema_mapper import ZeroCodeSchemaMapper
from src.unk_triage.key_broker_hotpatcher import KeyBrokerHotPatcher


class UnkTriageMasterEngine:
    """Orchestrates UNK triage and the key-broker console."""

    def __init__(self):
        self.entropy_profiler = SlidingWindowEntropyProfiler()
        self.schema_mapper = ZeroCodeSchemaMapper()
        self.key_broker = KeyBrokerHotPatcher()

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
        examiner_name: str = "",
    ) -> PromotedSchemaRecord:
        """Promotes a custom table into the live case and records the promotion ledger entry."""
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
        """Unwraps a blocked container with an examiner-supplied secret and hot-patches the new records."""
        return self.key_broker.execute_incremental_hotpatch(
            vfs_file_id=vfs_file_id,
            secret=secret,
            container_type=container_type,
            simulated_unlocked_records=simulated_records,
        )
