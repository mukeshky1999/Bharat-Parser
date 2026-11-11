"""
Data Models and Canonical Enums for Phase 8, Module 8.1:
Cross-Phase Entity Resolution, Master Identity Graph & Unified Super-Timeline Engine.
Adheres strictly to AGENTS.md Forensic Invariants and Module 8.1 Specification.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class EntityClassification(str, Enum):
    """Classification of an identity node in the Master Entity Graph."""
    DEVICE_OWNER_SELF = "DEVICE_OWNER_SELF"
    EXTERNAL_PERSON_ACTOR = "EXTERNAL_PERSON_ACTOR"
    SHARED_MULE_OR_ESCROW_INSTRUMENT = "SHARED_MULE_OR_ESCROW_INSTRUMENT"
    PHYSICAL_HIDEOUT_LOCATION = "PHYSICAL_HIDEOUT_LOCATION"
    THREAT_APK_OR_C2_ENDPOINT = "THREAT_APK_OR_C2_ENDPOINT"


class GraphEdgeVerb(str, Enum):
    """8 Canonical relationship verbs connecting nodes in the forensic graph."""
    COMMUNICATED_WITH = "COMMUNICATED_WITH"
    TRANSFERRED_FIAT_TO = "TRANSFERRED_FIAT_TO"
    SETTLED_P2P_ESCROW_WITH = "SETTLED_P2P_ESCROW_WITH"
    TRANSFERRED_CRYPTO_TO = "TRANSFERRED_CRYPTO_TO"
    OWNS_OR_CONTROLS_INSTRUMENT = "OWNS_OR_CONTROLS_INSTRUMENT"
    POSSESSED_KYC_DOCUMENT_OF = "POSSESSED_KYC_DOCUMENT_OF"
    VISITED_OR_ORDERED_AT_LOCATION = "VISITED_OR_ORDERED_AT_LOCATION"
    COMPROMISED_OR_CONTROLLED_BY = "COMPROMISED_OR_CONTROLLED_BY"


class ArtifactDomainCategory(str, Enum):
    """Domain category for unified super-timeline events."""
    MESSAGING_CHAT = "MESSAGING_CHAT"
    VOICE_VIDEO_CALL = "VOICE_VIDEO_CALL"
    FIAT_UPI_BANK_TX = "FIAT_UPI_BANK_TX"
    CRYPTO_WEB3_CEX_TX = "CRYPTO_WEB3_CEX_TX"
    OS_APP_LIFECYCLE = "OS_APP_LIFECYCLE"
    SCREEN_LOCK_BIOMETRIC = "SCREEN_LOCK_BIOMETRIC"
    SENSOR_CAMERA_MIC_STEP = "SENSOR_CAMERA_MIC_STEP"
    GEOLOCATION_RADIO_FIX = "GEOLOCATION_RADIO_FIX"
    HYPERLOCAL_RIDE_TRAVEL = "HYPERLOCAL_RIDE_TRAVEL"
    DATING_MATRIMONIAL = "DATING_MATRIMONIAL"
    MEDIA_SNAPSHOT_OCR_QR = "MEDIA_SNAPSHOT_OCR_QR"
    FILESYSTEM_FSEVENT = "FILESYSTEM_FSEVENT"
    TAMPER_OR_MALWARE_ALERT = "TAMPER_OR_MALWARE_ALERT"


class ClockIntegrityStatus(str, Enum):
    """Evidentiary clock tamper badge for super-timeline events."""
    VERIFIED_NORMAL_CLOCK = "VERIFIED_NORMAL_CLOCK"
    BRACKETED_WINDOW = "BRACKETED_WINDOW"
    CRITICAL_CLOCK_ROLLBACK_SUSPECTED = "CRITICAL_CLOCK_ROLLBACK_SUSPECTED"


class ActionBurstSignature(str, Enum):
    """Master signatures for multi-phase action burst crime sequences."""
    ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW = "ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW"
    TROJAN_OR_REMOTE_ACCESS_SILENT_DRAIN = "TROJAN_OR_REMOTE_ACCESS_SILENT_DRAIN"
    CROSS_APP_COVERT_HANDOFF_AND_DELETION = "CROSS_APP_COVERT_HANDOFF_AND_DELETION"
    PAYMENT_SCREENSHOT_PROOF_TO_HANDLER = "PAYMENT_SCREENSHOT_PROOF_TO_HANDLER"
    P2P_ESCROW_TO_SELF_CUSTODY_VELOCITY_HOP = "P2P_ESCROW_TO_SELF_CUSTODY_VELOCITY_HOP"
    PANIC_MASS_WIPE_PRIOR_TO_SEIZURE = "PANIC_MASS_WIPE_PRIOR_TO_SEIZURE"


class ActionBurstSeverity(str, Enum):
    """Severity classification of an action burst sequence."""
    CRITICAL_SMOKING_GUN = "CRITICAL_SMOKING_GUN"
    HIGH_CORRELATION = "HIGH_CORRELATION"
    MEDIUM_BEHAVIORAL = "MEDIUM_BEHAVIORAL"


class ResidualRecoveryConfidence(str, Enum):
    """6-Tier evidentiary confidence classification."""
    ORIGINAL_RECORD = "ORIGINAL_RECORD"
    HISTORICAL_COMMITTED_RECORD = "HISTORICAL_COMMITTED_RECORD"
    RESIDUAL_RECORD = "RESIDUAL_RECORD"
    PARTIAL_RECORD = "PARTIAL_RECORD"
    RECONSTRUCTED_RECORD = "RECONSTRUCTED_RECORD"
    UNVERIFIED_FRAGMENT = "UNVERIFIED_FRAGMENT"


@dataclass
class AtomicObservation:
    """Individual identity-bearing record extracted from any phase."""
    observation_id: str
    hard_keys: Set[str] = field(default_factory=set)
    soft_attributes: Dict[str, Any] = field(default_factory=dict)
    observed_name: Optional[str] = None
    source_phase_module: str = ""
    source_table_record: str = ""
    handoff_proof: Optional[str] = None


@dataclass
class MasterEntityProfile:
    """Consolidated 360-degree identity profile in the Master Entity Graph."""
    entity_master_uid: Optional[int] = None
    entity_classification: str = EntityClassification.EXTERNAL_PERSON_ACTOR.value
    canonical_display_name: str = "Unknown Actor"
    all_observed_names_json: str = "{}"
    tier1_hard_keys_json: str = "[]"
    phones_e164_json: Optional[str] = None
    messaging_handles_json: Optional[str] = None
    bank_accounts_and_vpas_json: Optional[str] = None
    crypto_addresses_and_uids_json: Optional[str] = None
    kyc_documents_and_biometrics_json: Optional[str] = None
    linked_locations_and_addresses_json: Optional[str] = None
    risk_and_typology_flags_json: Optional[str] = None
    deterministic_merge_proof_json: str = "[]"
    tier1_hard_keys: Set[str] = field(default_factory=set)
    deterministic_merge_proof: List[str] = field(default_factory=list)
    all_observed_names: Dict[str, str] = field(default_factory=dict)


@dataclass
class GraphEdgeRecord:
    """Typed directed relationship edge connecting two entity nodes."""
    graph_edge_uid: Optional[int] = None
    source_entity_uid: int = 0
    target_entity_uid: int = 0
    edge_verb: str = GraphEdgeVerb.COMMUNICATED_WITH.value
    interaction_count: int = 1
    total_fiat_value_inr: float = 0.0
    total_crypto_value_summary: Optional[str] = None
    platforms_and_rails_json: str = "[]"
    has_deleted_or_hidden_evidence: int = 0
    supporting_record_pointers_json: str = "[]"
    first_interaction_utc_iso: Optional[str] = None
    last_interaction_utc_iso: Optional[str] = None
    platforms_and_rails: List[str] = field(default_factory=list)
    supporting_record_pointers: List[str] = field(default_factory=list)


@dataclass
class SuperTimelineEvent:
    """Nanosecond-normalized chronological record in the master super-timeline."""
    timeline_event_uid: Optional[int] = None
    timestamp_utc_ns: int = 0
    timestamp_utc_iso: str = ""
    timestamp_ist_iso: str = ""
    timestamp_type_and_precision: str = "OCCURRENCE_MS"
    clock_integrity_status: str = ClockIntegrityStatus.VERIFIED_NORMAL_CLOCK.value
    originating_phase_and_module: str = ""
    artifact_domain_category: str = ArtifactDomainCategory.OS_APP_LIFECYCLE.value
    app_package_or_subsystem: str = ""
    android_user_profile_or_locality: str = "User 0 (Main)"
    actor_source_entity_uid: Optional[int] = None
    actor_target_entity_uid: Optional[int] = None
    event_title_badge: str = ""
    event_detailed_summary: str = ""
    recovery_classification: str = ResidualRecoveryConfidence.ORIGINAL_RECORD.value
    source_vfs_file_id: int = 0
    source_table_and_record_uid: str = ""
    action_burst_story_uid: Optional[int] = None


@dataclass
class ActionBurstStoryRecord:
    """Automatically detected multi-phase action-burst crime sequence."""
    story_uid: Optional[int] = None
    story_signature_code: str = ""
    severity_level: str = ActionBurstSeverity.CRITICAL_SMOKING_GUN.value
    burst_start_utc_iso: str = ""
    burst_end_utc_iso: str = ""
    burst_duration_seconds: float = 0.0
    involved_entity_uids_json: str = "[]"
    involved_timeline_event_uids: str = "[]"
    automated_courtroom_narrative: str = ""
    involved_entity_uids: List[int] = field(default_factory=list)
    involved_timeline_event_uids_list: List[int] = field(default_factory=list)
