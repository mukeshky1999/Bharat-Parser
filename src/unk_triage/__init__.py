"""Interactive Zero-Omission (UNK) triage workbench and cryptographic key-broker unlocker:
sliding-window entropy, examiner-driven schema promotion of unknown tables, and incremental hot-patching
after an examiner supplies a key."""

from src.unk_triage.models import (
    SemanticColumnRole,
    BlockByteComposition,
    BlockEntropyResult,
    ChiSquareHistogramResult,
    PromotedSchemaRecord,
    CandidateSecretRecord,
    IncrementalHotPatchResult,
)
from src.unk_triage.entropy_profiler import SlidingWindowEntropyProfiler
from src.unk_triage.schema_mapper import ZeroCodeSchemaMapper
from src.unk_triage.key_broker_hotpatcher import KeyBrokerHotPatcher
from src.unk_triage.engine import UnkTriageMasterEngine

__all__ = [
    "SemanticColumnRole",
    "BlockByteComposition",
    "BlockEntropyResult",
    "ChiSquareHistogramResult",
    "PromotedSchemaRecord",
    "CandidateSecretRecord",
    "IncrementalHotPatchResult",
    "SlidingWindowEntropyProfiler",
    "ZeroCodeSchemaMapper",
    "KeyBrokerHotPatcher",
    "UnkTriageMasterEngine",
]
