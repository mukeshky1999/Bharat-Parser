"""
Domain models and schema definitions for Forensic SQLite Engine.
Adheres to AGENTS.md Section 4: Forensic Invariants and Canonical Enums.
"""

import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from src.core.enums import (
    ResidualConfidence,
    EvidentiaryState,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
    ForensicGroup,
)


@dataclass(slots=True)
class ColumnSchema:
    """Represents a column in a parsed SQLite table definition."""
    name: str
    data_type: str
    affinity: str
    is_primary_key: bool = False
    not_null: bool = False


@dataclass(slots=True)
class TableSchema:
    """Represents a parsed SQLite table definition from sqlite_schema."""
    name: str
    rootpage: int
    sql: str
    columns: List[ColumnSchema] = field(default_factory=list)
    is_without_rowid: bool = False
    ipk_column_index: Optional[int] = None
    ipk_column_name: Optional[str] = None


@dataclass(slots=True)
class SQLiteDiagnostics:
    """Forensic diagnostic metrics for a parsed SQLite database."""
    staging_id: int
    canonical_db_path: str
    page_size_bytes: int
    usable_page_size_u: int
    text_encoding: str
    journal_mode_header: str
    auto_vacuum_mode: str
    secure_delete_suspected: int
    header_page_count: int
    physical_page_count: int
    freelist_page_count: int
    wal_frames_total: int = 0
    wal_historical_commits_recovered: int = 0
    carved_residual_rows_recovered: int = 0
    db_profile_id: Optional[int] = None


@dataclass(slots=True)
class RecoveredRecord:
    """Represents a forensic record recovered from live, WAL, journal, or carved zones."""
    table_name: str
    sqlite_rowid: Optional[int]
    recovery_classification: ResidualConfidence
    source_origin_zone: str
    source_page_number: int
    source_byte_offset: int
    columns_dict: Dict[str, Any]
    wal_frame_number: Optional[int] = None
    diff_vs_active: Optional[Dict[str, Any]] = None
    recovered_row_uid: Optional[int] = None
    db_profile_id: Optional[int] = None
    evidentiary_state: Optional[EvidentiaryState] = None
    # Names of columns whose bytes were cut off (value is None, meaning unknown). None = nothing was cut off.
    truncated_columns: Optional[List[str]] = None

    @property
    def columns_json(self) -> str:
        """Serializes column dictionary to deterministic JSON string."""
        return json.dumps(self.columns_dict, default=str, sort_keys=True)

    @property
    def diff_vs_active_json(self) -> Optional[str]:
        """Serializes difference dictionary to deterministic JSON string."""
        if self.diff_vs_active is None:
            return None
        return json.dumps(self.diff_vs_active, default=str, sort_keys=True)
