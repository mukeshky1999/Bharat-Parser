"""
Domain Models and Enums for NPCI Common Library & Physical SIM Binding Forensics.
Adheres strictly to Specification Section 7 and AGENTS.md Forensic Invariants.
"""

from dataclasses import dataclass
from enum import Enum, unique
from typing import Optional

from src.core.enums import ResidualConfidence


@unique
class SIMFormFactor(str, Enum):
    """Physical SIM vs. embedded eSIM classification."""
    PHYSICAL_SIM = "PHYSICAL_SIM"
    EMBEDDED_ESIM = "EMBEDDED_ESIM"


@unique
class SeizureSlotState(str, Enum):
    """SIM card state at the time of handset seizure."""
    ACTIVE_SLOT_1 = "ACTIVE_SLOT_1"
    ACTIVE_SLOT_2 = "ACTIVE_SLOT_2"
    EJECTED_HISTORICAL_SIM = "EJECTED_HISTORICAL_SIM"


@unique
class BindingAttributionVerdict(str, Enum):
    """3-Point correlation verdict on whether binding was local or hijacked."""
    VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING = "VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING"
    COMPROMISED_REMOTE_GHOST_SIM_BINDING_VIA_TROJAN = "COMPROMISED_REMOTE_GHOST_SIM_BINDING_VIA_TROJAN"
    UNVERIFIED_OR_FAILED_BINDING = "UNVERIFIED_OR_FAILED_BINDING"


@dataclass(slots=True)
class DeviceSIMCardHistoryRecord:
    """Historical SIM / eSIM card entry from telephony.db or iOS CommCenter."""
    os_platform: str = "ANDROID"
    android_sub_id: Optional[int] = None
    iccid_20_digit: Optional[str] = None
    imsi_number: Optional[str] = None
    msisdn_phone_number: Optional[str] = None
    carrier_display_name: Optional[str] = None
    mcc_mnc_code: Optional[str] = None
    sim_form_factor: str = "PHYSICAL_SIM"
    seizure_slot_state: str = "ACTIVE_SLOT_1"
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    first_observed_utc_iso: Optional[str] = None
    last_observed_utc_iso: Optional[str] = None
    sim_record_uid: Optional[int] = None


@dataclass(slots=True)
class UPIOutboundBindingSMSAudit:
    """Audit entry for an outbound VMN silent SMS verification attempt."""
    source_vfs_file_id: int
    destination_vmn_number: str
    sms_payload_raw: str
    delivery_status: str = "SENT_SUCCESS"
    binding_attribution_verdict: str = "VERIFIED_LOCAL_HANDSET_AND_SIM_BINDING"
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    sms_row_id: Optional[int] = None
    inferred_target_psp_or_bank: Optional[str] = None
    android_sub_id: Optional[int] = None
    resolved_sim_iccid: Optional[str] = None
    resolved_sim_msisdn: Optional[str] = None
    creator_package_name: Optional[str] = None
    sent_utc_iso: Optional[str] = None
    binding_sms_uid: Optional[int] = None


@dataclass(slots=True)
class NPCICommonLibraryVaultRecord:
    """Credential and binding parameter record from an embedded NPCI CL vault."""
    app_instance_id: int
    source_vfs_file_id: int
    bound_sim_iccid_in_app: Optional[str] = None
    bound_sim_sub_id_in_app: Optional[int] = None
    bound_mobile_msisdn: Optional[str] = None
    bound_hardware_device_id: Optional[str] = None
    cl_k0_token_present: int = 0
    matched_keystore_alias: Optional[str] = None
    binding_registered_utc_iso: Optional[str] = None
    cl_record_uid: Optional[int] = None
