"""
Sub-Engine 8.1C: Nanosecond-Normalized Unified Super-Timeline.
Normalizes heterogeneous cross-phase timestamps into a unified 64-bit UTC nanosecond ledger.
Precomputes Indian Standard Time (+05:30) strings and populates 5D evidentiary attributes.
Adheres strictly to AGENTS.md Forensic Invariants and Section 5 of Module 8.1 Specification.
"""

from datetime import datetime, timezone
from typing import Optional

from src.entity_and_timeline.models import (
    ArtifactDomainCategory,
    ClockIntegrityStatus,
    ResidualRecoveryConfidence,
    SuperTimelineEvent,
)


class SuperTimelineNormalizer:
    """Normalizes heterogeneous timeline events to signed 64-bit UTC nanoseconds and IST strings."""

    def __init__(self):
        self._next_event_uid = 1

    def create_event(
        self,
        timestamp_utc_ns: int,
        originating_phase_and_module: str,
        artifact_domain_category: str,
        app_package_or_subsystem: str,
        event_title_badge: str,
        event_detailed_summary: str,
        source_vfs_file_id: int,
        source_table_and_record_uid: str,
        android_user_profile_or_locality: str = "User 0 (Main)",
        actor_source_entity_uid: Optional[int] = None,
        actor_target_entity_uid: Optional[int] = None,
        clock_integrity_status: str = ClockIntegrityStatus.VERIFIED_NORMAL_CLOCK.value,
        timestamp_type_and_precision: str = "OCCURRENCE_MS",
        recovery_classification: str = ResidualRecoveryConfidence.ORIGINAL_RECORD.value,
    ) -> SuperTimelineEvent:
        """Constructs a normalized SuperTimelineEvent with dual UTC and IST timestamps."""
        # 1. Compute UTC ISO-8601 string
        sec_utc = timestamp_utc_ns // 1_000_000_000
        nsec_utc = timestamp_utc_ns % 1_000_000_000
        dt_utc = datetime.fromtimestamp(sec_utc, timezone.utc)
        utc_iso = dt_utc.strftime("%Y-%m-%dT%H:%M:%S") + f".{nsec_utc:09d}Z"

        # 2. Compute IST (+05:30) string (+19,800,000,000,000 ns)
        ist_ns = timestamp_utc_ns + 19_800_000_000_000
        sec_ist = ist_ns // 1_000_000_000
        nsec_ist = ist_ns % 1_000_000_000
        dt_ist = datetime.fromtimestamp(sec_ist, timezone.utc)
        msec_ist = nsec_ist // 1_000_000
        ist_iso = dt_ist.strftime("%Y-%m-%d %H:%M:%S") + f".{msec_ist:03d} IST (+05:30)"

        event = SuperTimelineEvent(
            timeline_event_uid=self._next_event_uid,
            timestamp_utc_ns=timestamp_utc_ns,
            timestamp_utc_iso=utc_iso,
            timestamp_ist_iso=ist_iso,
            timestamp_type_and_precision=timestamp_type_and_precision,
            clock_integrity_status=clock_integrity_status,
            originating_phase_and_module=originating_phase_and_module,
            artifact_domain_category=artifact_domain_category,
            app_package_or_subsystem=app_package_or_subsystem,
            android_user_profile_or_locality=android_user_profile_or_locality,
            actor_source_entity_uid=actor_source_entity_uid,
            actor_target_entity_uid=actor_target_entity_uid,
            event_title_badge=event_title_badge,
            event_detailed_summary=event_detailed_summary,
            recovery_classification=recovery_classification,
            source_vfs_file_id=source_vfs_file_id,
            source_table_and_record_uid=source_table_and_record_uid,
            action_burst_story_uid=None,
        )
        self._next_event_uid += 1
        return event
