"""
Canonical Enums for 5-Dimensional Evidentiary State and Tripartite Model.
Phase 1, Module 1.4, Section 3 & Section 5.
"""

from enum import Enum, unique


@unique
class DimensionAPresence(str, Enum):
    """Dimension A: Acquisition Presence Logic."""
    PRESENT = "PRESENT"
    PRESENT_EMPTY_STUB = "PRESENT_EMPTY_STUB"
    SOURCE_PRESENT_NOT_ACQUIRED_TIER = "SOURCE_PRESENT_NOT_ACQUIRED_TIER"
    SOURCE_PRESENT_NOT_ACQUIRED_BFU = "SOURCE_PRESENT_NOT_ACQUIRED_BFU"
    SOURCE_PRESENT_NOT_ACQUIRED_LUN = "SOURCE_PRESENT_NOT_ACQUIRED_LUN"
    NOT_OBSERVED_GHOST_APP = "NOT_OBSERVED_GHOST_APP"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_ASSESSED = "NOT_ASSESSED"


@unique
class DimensionBAccessibility(str, Enum):
    """Dimension B: Content Accessibility Logic."""
    READABLE = "READABLE"
    READABLE_DECRYPTED = "READABLE_DECRYPTED"
    PARTIALLY_READABLE_METADATA_ONLY = "PARTIALLY_READABLE_METADATA_ONLY"
    ENCRYPTED_GATED_BY_HARDWARE = "ENCRYPTED_GATED_BY_HARDWARE"
    ENCRYPTED_GATED_MISSING_KEY = "ENCRYPTED_GATED_MISSING_KEY"
    CORRUPT_OR_ZEROED = "CORRUPT_OR_ZEROED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@unique
class DimensionCIntegrity(str, Enum):
    """Dimension C: Physical & Source Integrity Logic."""
    VERIFIED_STATIC = "VERIFIED_STATIC"
    VERIFIED_LIVE_STAGING_HASH = "VERIFIED_LIVE_STAGING_HASH"
    PARTIALLY_VERIFIED_READ_ERRORS = "PARTIALLY_VERIFIED_READ_ERRORS"
    MODIFIED_SOURCE_BY_PROCEDURE = "MODIFIED_SOURCE_BY_PROCEDURE"
    POTENTIAL_TOOL_ANOMALY = "POTENTIAL_TOOL_ANOMALY"
    UNKNOWN = "UNKNOWN"


@unique
class DimensionDCoverage(str, Enum):
    """Dimension D: Parser & Acquisition Coverage Logic."""
    DIRECTLY_PARSED_FULL = "DIRECTLY_PARSED_FULL"
    PARSED_WITH_SUPPLIED_KEYS = "PARSED_WITH_SUPPLIED_KEYS"
    PARTIALLY_PARSED = "PARTIALLY_PARSED"
    SCHEMA_MISMATCH_REQUIRES_MANUAL = "SCHEMA_MISMATCH_REQUIRES_MANUAL"
    STRUCTURALLY_IDENTIFIED_UNSUPPORTED = "STRUCTURALLY_IDENTIFIED_UNSUPPORTED"
    NOT_TESTED = "NOT_TESTED"


@unique
class DimensionEMaturity(str, Enum):
    """Dimension E: Laboratory Research Validation Maturity (R1-R6)."""
    R1 = "R1"  # Path Identified
    R2 = "R2"  # Schema Documented
    R3 = "R3"  # Partially Decoded
    R4 = "R4"  # Semantically Interpreted
    R5 = "R5"  # Experimentally Validated on Controlled Corpus
    R6 = "R6"  # Independently Corroborated & Peer-Reviewed


@unique
class TripartiteStoredState(str, Enum):
    """Tripartite Model: Stored device state."""
    ARCHITECTURALLY_EXPECTED = "ARCHITECTURALLY_EXPECTED"
    APP_INSTALLED_STORAGE_EXPECTED = "APP_INSTALLED_STORAGE_EXPECTED"
    APP_UNINSTALLED_GHOST = "APP_UNINSTALLED_GHOST"
    APP_NOT_PRESENT = "APP_NOT_PRESENT"


@unique
class UnclassifiedStorageFormat(str, Enum):
    """Format detected by Unclassified Artifacts Sweeper."""
    SQLITE3 = "SQLITE3"
    MMKV = "MMKV"
    LEVELDB = "LEVELDB"
    REALM = "REALM"
    PROTOBUF_RAW = "PROTOBUF_RAW"
    BPLIST = "BPLIST"
    HIGH_ENTROPY_ENCRYPTED = "HIGH_ENTROPY_ENCRYPTED"
    UNKNOWN_BINARY = "UNKNOWN_BINARY"


@unique
class ExaminerReviewStatus(str, Enum):
    """Workflow state for unclassified artifacts in the workbench."""
    PENDING_REVIEW = "PENDING_REVIEW"
    MANUALLY_INSPECTED = "MANUALLY_INSPECTED"
    BOOKMARKED_RELEVANT = "BOOKMARKED_RELEVANT"
    IGNORED_BENIGN = "IGNORED_BENIGN"
