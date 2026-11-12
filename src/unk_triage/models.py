"""
Data models and canonical enums for Phase 9, Module 9.5:
Interactive UNK Triage Workbench, Key-Broker Console.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class SemanticColumnRole(str, Enum):
    """Semantic column mapping roles for promoting custom/unrecognized tables."""
    IGNORE_COLUMN = "IGNORE_COLUMN"
    TIMESTAMP_EPOCH_AUTO = "TIMESTAMP_EPOCH_AUTO"
    TIMESTAMP_EPOCH_S = "TIMESTAMP_EPOCH_S"
    TIMESTAMP_EPOCH_MS = "TIMESTAMP_EPOCH_MS"
    TIMESTAMP_EPOCH_US = "TIMESTAMP_EPOCH_US"
    TIMESTAMP_COCOA_S = "TIMESTAMP_COCOA_S"
    TIMESTAMP_ISO8601 = "TIMESTAMP_ISO8601"
    ACTOR_SOURCE_IDENTIFIER = "ACTOR_SOURCE_IDENTIFIER"
    ACTOR_TARGET_IDENTIFIER = "ACTOR_TARGET_IDENTIFIER"
    MESSAGE_OR_EVENT_BODY_TEXT = "MESSAGE_OR_EVENT_BODY_TEXT"
    FINANCIAL_OR_CRYPTO_AMOUNT = "FINANCIAL_OR_CRYPTO_AMOUNT"
    GPS_LATITUDE = "GPS_LATITUDE"
    GPS_LONGITUDE = "GPS_LONGITUDE"


@dataclass
class BlockByteComposition:
    """Per-block percentage breakdown across 4 byte classes."""
    null_zero_pct: float
    printable_ascii_pct: float
    high_bit_structured_pct: float
    all_ones_erase_pct: float


@dataclass
class BlockEntropyResult:
    """Block-by-block sliding-window entropy skyline profile."""
    block_size_bytes: int
    total_file_bytes: int
    block_count: int
    block_entropies: list[float]
    block_compositions: list[BlockByteComposition]


@dataclass
class ChiSquareHistogramResult:
    """256-bin byte frequency histogram and Chi-Square goodness-of-fit statistic."""
    observed_counts: list[int]
    ideal_uniform_reference: float
    chi_squared_statistic: float
    is_likely_uniform_ciphertext: bool


@dataclass
class PromotedSchemaRecord:
    """Audit record for a custom table promoted into the live case."""
    vfs_file_id: int
    table_name: str
    promoted_rows_count: int
    column_roles_json: str
    promoted_by_examiner: str
    promoted_at_ist_iso: str
    mapping_uid: int = 0


@dataclass
class CandidateSecretRecord:
    """Auto-harvested password or key candidate for the Key-Broker Console."""
    secret_value: str
    source_origin: str
    confidence_score: float
    candidate_type: str = "PASSPHRASE"


@dataclass
class IncrementalHotPatchResult:
    """Output of the 5-step targeted incremental DAG hot-patching pipeline."""
    is_unlocked: bool
    unwrapped_records_count: int
    derivative_vfs_id: int
    merkle_audit_entry_created: bool
    merkle_event_type: str
    elapsed_seconds: float = 0.0
