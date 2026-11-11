"""
Data models and canonical enums for Phase 9, Module 9.5:
Interactive UNK Triage Workbench, Key-Broker Console & Section 63(4)(c) BSA 2023 Report Studio.
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


@dataclass
class FreezeCandidateAccount:
    """Account or VPA evaluated in the Golden-Hour Freeze De-Confliction Center."""
    account_no: str
    ifsc: str
    vpa: str
    is_complainant_victim: bool
    volume_inr: float
    is_freeze_locked: bool = False
    freeze_checkbox_disabled: bool = False
    is_utility_excluded: bool = False
    role_badge: str = ""


@dataclass
class PreFlightCheckResult:
    """Output of the mandatory 6-point Section 63(4)(c) BSA pre-flight statutory gate."""
    is_passed: bool
    failure_reasons: list[str]
    checks_passed_count: int = 0
    checks_total_count: int = 6


@dataclass
class BsaDossierDualPreview:
    """WYSIWYG side-by-side comparison between Master Court copy and Defense Disclosure copy."""
    statutory_header_caption: str
    master_court_html: str
    defense_disclosure_html: str
    withheld_exhibits_count: int = 0
    redacted_victims_count: int = 0

    @property
    def master_court_preview_html(self) -> str:
        return self.master_court_html

    @property
    def defense_redacted_preview_html(self) -> str:
        return self.defense_disclosure_html

    @property
    def sec230_bnss_defense_preview_html(self) -> str:
        return self.defense_disclosure_html
