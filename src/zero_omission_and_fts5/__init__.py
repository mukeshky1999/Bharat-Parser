"""
Phase 8, Module 8.2: Zero-Omission Audit, Binary Entropy Triage, Generic Introspection & Dual FTS5.
"""

from src.zero_omission_and_fts5.models import (
    AccountingState,
    DetectedMagicSignature,
    EntropyCryptoClassification,
    ContainerStructureType,
    DetectedIndicatorCategory,
    ResidualRecoveryConfidence,
    MagicInspectionResult,
    EntropyAnalysisResult,
    VfsAccountingRecord,
    UnkGenericFinding,
    SearchDocument,
    RoaringFacetEntry,
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
from src.zero_omission_and_fts5.engine import ZeroOmissionAndFts5Engine

__all__ = [
    "AccountingState",
    "DetectedMagicSignature",
    "EntropyCryptoClassification",
    "ContainerStructureType",
    "DetectedIndicatorCategory",
    "ResidualRecoveryConfidence",
    "MagicInspectionResult",
    "EntropyAnalysisResult",
    "VfsAccountingRecord",
    "UnkGenericFinding",
    "SearchDocument",
    "RoaringFacetEntry",
    "VfsZeroOmissionAuditor",
    "MagicByteDiscrepancyDetector",
    "EntropyAndChiSquareClassifier",
    "UniversalFallbackIntrospector",
    "DualFts5AndRoaringEngine",
    "RoaringBitmap32",
    "ZeroOmissionAndFts5Engine",
]
