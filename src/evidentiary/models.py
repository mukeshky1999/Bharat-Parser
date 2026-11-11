"""
Evidentiary Audit Models and Contracts.
Phase 1, Module 1.4, Section 5.
"""

from dataclasses import dataclass
from typing import Optional

from src.evidentiary.enums import (
    DimensionAPresence,
    DimensionBAccessibility,
    DimensionCIntegrity,
    DimensionDCoverage,
    DimensionEMaturity,
    TripartiteStoredState,
)


@dataclass(slots=True)
class EvidentiaryAuditEntry:
    """The complete 5D audit entry contract representing an evaluated target artifact."""
    artifact_code: str
    forensic_group_num: int
    forensic_group_name: str
    expected_canonical_path: str
    tripartite_stored_state: TripartiteStoredState
    dim_a_presence: DimensionAPresence
    dim_b_accessibility: DimensionBAccessibility
    dim_c_integrity: DimensionCIntegrity
    dim_d_coverage: DimensionDCoverage
    dim_e_maturity: DimensionEMaturity
    app_instance_id: Optional[int] = None
    vfs_file_id: Optional[int] = None
    parser_module_name: Optional[str] = None
    active_records_parsed: int = 0
    residual_records_parsed: int = 0
    diagnostic_notes: Optional[str] = None
    audit_entry_id: Optional[int] = None
