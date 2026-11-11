"""
Data models and canonical enums for Phase 8, Module 8.3:
Indian Legal Compliance, Hierarchical Hash Manifest, and Section 63(4)(c) BSA Statutory Certificates.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class HashTier(str, Enum):
    """The 3-Tier Provenance Hash Hierarchy."""
    TIER_1_MASTER_ACQUISITION_SOURCE = "TIER_1_MASTER_ACQUISITION_SOURCE"
    TIER_2A_VFS_ORIGINAL_CONTAINER = "TIER_2A_VFS_ORIGINAL_CONTAINER"
    TIER_2B_UNWRAPPED_OR_CARVED_DERIVATIVE = "TIER_2B_UNWRAPPED_OR_CARVED_DERIVATIVE"
    TIER_3_EXPORTED_COURT_EXHIBIT = "TIER_3_EXPORTED_COURT_EXHIBIT"
    TIER_3_SEC230_BNSS_DEFENSE_COPY = "TIER_3_SEC230_BNSS_DEFENSE_COPY"


class StatutoryRegimeMode(str, Enum):
    """Statutory legal regimes governing electronic evidence certificates."""
    BSA_2023_SECTION_63_4_C_SCHEDULE = "BSA_2023_SECTION_63_4_C_SCHEDULE"
    DUAL_BSA_SEC_63_AND_IEA_SEC_65B_LEGACY = "DUAL_BSA_SEC_63_AND_IEA_SEC_65B_LEGACY"


class ImmutabilityStatus(str, Enum):
    """Post-processing source file immutability verification status."""
    IMMUTABILITY_VERIFIED_IDENTICAL = "IMMUTABILITY_VERIFIED_IDENTICAL"
    IMMUTABILITY_VIOLATED_MODIFIED = "IMMUTABILITY_VIOLATED_MODIFIED"
    NOT_REVERIFIED = "NOT_REVERIFIED"


@dataclass
class DeponentDetails:
    """Investigating Officer / Lawful Device Custodian details for Part A."""
    name: str
    designation: str
    father_name: Optional[str] = None
    age: Optional[int] = None
    police_station: Optional[str] = None
    district: Optional[str] = None
    state: Optional[str] = None
    fir_number: Optional[str] = None
    sections_of_law: Optional[str] = None
    custody_mode: str = "SEIZED_OFFICIAL_CUSTODY"
    seizure_memo_ref: Optional[str] = None


@dataclass
class DeviceMetadata:
    """Device identification details extracted from the seized hardware."""
    device_type: str = "Smartphone"
    make_and_brand: str = ""
    model_name: str = ""
    imei_1: Optional[str] = None
    imei_2: Optional[str] = None
    serial_number: Optional[str] = None
    chipset_details: Optional[str] = None
    operating_system: Optional[str] = None
    sim_iccids: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)


@dataclass
class ForensicExpertDetails:
    """Forensic Examiner / FSL Scientist credentials for Part B."""
    name: str
    designation: str
    laboratory_unit: str
    qualifications: str


@dataclass
class WorkstationEnvironment:
    """Forensic workstation technical environment and execution timestamps."""
    workstation_hostname: str
    os_version: str
    engine_version: str
    git_commit_hash: str
    vfs_mount_mode: str = "READ_ONLY_IMMUTABLE"
    processing_start_ist: Optional[str] = None
    processing_completion_ist: Optional[str] = None


@dataclass
class IntegrityAuditDisclosure:
    """OS integrity findings from Phase 6, Module 6.5 feeding Section 63(2)(c) clauses."""
    root_or_jailbreak_detected: bool = False
    root_details: Optional[str] = None
    clock_tampering_detected: bool = False
    clock_tampering_details: Optional[str] = None
    monotonic_counter_bounds: Optional[str] = None
    malware_or_overlay_detected: bool = False
    malware_details: Optional[str] = None


@dataclass
class EvidentiaryHashManifestItem:
    """A cryptographic lineage item for Table 1: evidentiary_hash_manifest_ledger."""
    hash_tier: HashTier
    canonical_path_or_exhibit_name: str
    artifact_description: str
    byte_size: int
    sha256_hex: str
    md5_hex: str
    blake3_hex: Optional[str] = None
    manifest_item_uid: Optional[int] = None
    vfs_file_id_or_staging_id: Optional[int] = None
    parent_manifest_item_uid: Optional[int] = None
    crypto_unwrap_provenance_note: Optional[str] = None
    post_run_reverified_status: ImmutabilityStatus = ImmutabilityStatus.IMMUTABILITY_VERIFIED_IDENTICAL
    hashed_at_utc_iso: str = ""


@dataclass
class Section63BsaCertificateRecord:
    """Statutory Certificate record for Table 2: section63_bsa_certificates_registry."""
    certificate_reference_no: str
    statutory_regime_mode: StatutoryRegimeMode
    case_fir_or_rc_number: str
    part_a_deponent_details_json: str
    part_a_device_metadata_json: str
    part_b_expert_details_json: str
    part_b_workstation_env_json: str
    sec63_2_c_integrity_clause_text: str
    tier1_master_image_sha256: str
    case_merkle_root_sha256: str
    certificate_uid: Optional[int] = None
    rendered_certificate_pdf_sha256: Optional[str] = None
    generated_at_ist_iso: str = ""


@dataclass
class ChainOfCustodyEntry:
    """Append-only Merkle hash chain entry for Table 3: chain_of_custody_merkle_ledger."""
    seq_no: int
    timestamp_utc_ns: int
    timestamp_ist_iso: str
    actor_or_subsystem: str
    event_action_type: str
    canonical_payload_json: str
    previous_entry_hash_hex: str
    current_entry_hash_hex: str
