"""
Phase 8, Module 8.1: The Cross-Phase Entity Resolution, Master Identity Graph & Unified Super-Timeline Engine.
"""

from src.entity_and_timeline.models import (
    EntityClassification,
    GraphEdgeVerb,
    ArtifactDomainCategory,
    ClockIntegrityStatus,
    ActionBurstSignature,
    ActionBurstSeverity,
    ResidualRecoveryConfidence,
    AtomicObservation,
    MasterEntityProfile,
    GraphEdgeRecord,
    SuperTimelineEvent,
    ActionBurstStoryRecord,
)
from src.entity_and_timeline.entity_resolver import ConstrainedEntityResolver
from src.entity_and_timeline.edge_synthesizer import GraphEdgeSynthesizer
from src.entity_and_timeline.super_timeline import SuperTimelineNormalizer
from src.entity_and_timeline.action_burst_correlator import ActionBurstCorrelator
from src.entity_and_timeline.engine import EntityGraphAndTimelineEngine

__all__ = [
    "EntityClassification",
    "GraphEdgeVerb",
    "ArtifactDomainCategory",
    "ClockIntegrityStatus",
    "ActionBurstSignature",
    "ActionBurstSeverity",
    "ResidualRecoveryConfidence",
    "AtomicObservation",
    "MasterEntityProfile",
    "GraphEdgeRecord",
    "SuperTimelineEvent",
    "ActionBurstStoryRecord",
    "ConstrainedEntityResolver",
    "GraphEdgeSynthesizer",
    "SuperTimelineNormalizer",
    "ActionBurstCorrelator",
    "EntityGraphAndTimelineEngine",
]
