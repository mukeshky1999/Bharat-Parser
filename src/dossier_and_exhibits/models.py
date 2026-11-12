"""
Data models and canonical enums for Phase 8, Module 8.4:
Crime-Typology Dossier Builder, Nodal Freeze Packets, Section 94 BNSS Requisitions & Courtroom Packaging.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional


def ist_now_str() -> str:
    """Current time in IST (+05:30), independent of the machine's time zone."""
    ist = timezone(timedelta(hours=5, minutes=30))
    return datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S IST (+05:30)")


class DossierProfileType(str, Enum):
    """The 4 Statutory Indian Crime-Typology Investigation Dossier Profiles."""
    PROFILE_1_CYBER_FRAUD_MULE_AND_USDT_LAUNDERING = "PROFILE_1_CYBER_FRAUD_MULE_AND_USDT_LAUNDERING"
    PROFILE_2_ORGANIZED_CRIME_NDPS_HAWALA = "PROFILE_2_ORGANIZED_CRIME_NDPS_HAWALA"
    PROFILE_3_HONEYTRAP_SEXTORTION_POCSO = "PROFILE_3_HONEYTRAP_SEXTORTION_POCSO"
    PROFILE_4_MALWARE_APK_ANYDESK_AND_TAMPERING = "PROFILE_4_MALWARE_APK_ANYDESK_AND_TAMPERING"
    CUSTOM_INVESTIGATOR_SELECTION = "CUSTOM_INVESTIGATOR_SELECTION"


class ExportAudienceScope(str, Enum):
    """Audience and legal disclosure boundaries for generated dossiers."""
    IO_AND_COURT_UNREDACTED_MASTER = "IO_AND_COURT_UNREDACTED_MASTER"
    SECTION_230_BNSS_DEFENSE_DISCLOSURE_COPY = "SECTION_230_BNSS_DEFENSE_DISCLOSURE_COPY"
    PUBLIC_VICTIM_ANONYMIZED_BNS_SEC72 = "PUBLIC_VICTIM_ANONYMIZED_BNS_SEC72"


class NodalAgencyTarget(str, Enum):
    """Nodal agencies and freeze portals for Golden-Hour asset preservation."""
    I4C_NCRP_1930_CFCFRMS_BANK_LIEN = "I4C_NCRP_1930_CFCFRMS_BANK_LIEN"
    FIU_IND_AND_CEX_LERP_FREEZE = "FIU_IND_AND_CEX_LERP_FREEZE"
    TETHER_USDT_SMART_CONTRACT_FREEZE = "TETHER_USDT_SMART_CONTRACT_FREEZE"


class RecipientNodalCategory(str, Enum):
    """Categories of external intermediaries subject to Section 94 BNSS requisitions."""
    TELECOM_TSP_NODAL = "TELECOM_TSP_NODAL"
    BANK_NODAL_OFFICER = "BANK_NODAL_OFFICER"
    CRYPTO_CEX_OR_SWAP_COMPLIANCE = "CRYPTO_CEX_OR_SWAP_COMPLIANCE"
    HYPERLOCAL_DELIVERY_OR_RIDE_NODAL = "HYPERLOCAL_DELIVERY_OR_RIDE_NODAL"
    SOCIAL_OR_MESSAGING_INTERMEDIARY = "SOCIAL_OR_MESSAGING_INTERMEDIARY"


class RedactionTag(str, Enum):
    """Statutory redaction tags under POCSO Act, 2012 and Section 72 BNS, 2023."""
    CSAM_POCSO = "CSAM_POCSO"
    NON_CONSENSUAL_INTIMATE_MEDIA = "NON_CONSENSUAL_INTIMATE_MEDIA"
    SEXUAL_ASSAULT_FOOTAGE = "SEXUAL_ASSAULT_FOOTAGE"
    UNRELIED_PRIVATE_DATA = "UNRELIED_PRIVATE_DATA"
    PROTECTED_VICTIM_IDENTITY = "PROTECTED_VICTIM_IDENTITY"
    # Explicit examiner decision that the item may be released. There is no implicit default:
    # an item with no tag is "unclassified" and the packager refuses it.
    DISCLOSABLE = "DISCLOSABLE"


@dataclass
class MuleTransactionEntry:
    """A standardized fraudulent transaction or mule account entry for NCRP 1930 14-column CSV."""
    s_no: int
    transaction_layer: str
    payment_rail: str
    utr_or_rrn_12_digit: str
    transaction_timestamp_ist: str
    transaction_amount_inr: float
    payer_account_or_vpa: str
    beneficiary_bank_name: str
    beneficiary_account_number: str
    beneficiary_ifsc_11_char: str
    beneficiary_upi_vpa: str
    beneficiary_verified_cbs_name: str
    linked_mobile_number_e164: str
    forensic_source_artifact_and_sha256: str


@dataclass
class CryptoFreezeEntry:
    """A centralized exchange (CEX) account or on-chain wallet entry for FIU-IND/CEX freeze packets."""
    category: str  # "CEX_ACCOUNT" or "ONCHAIN_WALLET"
    exchange_or_network: str
    target_identifier: str
    kyc_name_or_control: str
    fiat_or_token_balance: str
    associated_txids_or_orders: list[str] = field(default_factory=list)
    requested_action: str = "Immediate Account Freeze & Production of KYC, Counterparty UIDs & Login IPs under Sec 94 BNSS"


@dataclass
class SensitiveMediaItem:
    """An evidentiary visual asset subjected to the Statutory Redaction Gate."""
    canonical_path: str
    file_name: str
    sha256_hex: str
    md5_hex: str
    raw_bytes: bytes
    redaction_tag: Optional[RedactionTag] = None
    timestamps_utc: str = ""
    exif_metadata: str = ""


@dataclass
class CrimeDossierRecord:
    """Compiled Crime-Typology Dossier for Table 1: compiled_crime_dossiers_registry."""
    dossier_profile_type: DossierProfileType
    dossier_title: str
    export_audience_scope: ExportAudienceScope
    included_entity_uids_json: str
    linked_sec63_certificate_uid: int
    exported_pdf_path_and_sha256: str
    dossier_uid: Optional[int] = None
    included_story_uids_json: Optional[str] = None
    pocso_or_intimate_media_withheld_count: int = 0
    exported_html5_bundle_sha256: Optional[str] = None
    compiled_at_ist_iso: str = ""


@dataclass
class NodalFreezePacketRecord:
    """Generated Golden-Hour Freeze Packet for Table 2: nodal_freeze_and_lien_exports_ledger."""
    target_agency_or_portal: NodalAgencyTarget
    total_accounts_or_wallets_count: int
    total_utrs_or_txids_count: int
    exported_csv_xlsx_path: str
    exported_file_sha256: str
    freeze_packet_uid: Optional[int] = None
    total_disputed_fiat_inr: float = 0.0
    total_disputed_crypto_summary: Optional[str] = None
    generated_at_ist_iso: str = ""


@dataclass
class Section94BnssRequisitionRecord:
    """Auto-drafted Section 94 BNSS Legal Notice for Table 3: section94_bnss_requisitions_queue."""
    recipient_nodal_category: RecipientNodalCategory
    recipient_organization_name: str
    target_identifiers_json: str
    requested_records_checklist: str
    rendered_notice_doc_path: str
    requisition_uid: Optional[int] = None
    statutory_provision: str = "Section 94 of the Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023 [erstwhile Sec 91 CrPC]"


@dataclass
class DefenseBundleResult:
    """Result of packaging an air-gapped Section 230 BNSS defense disclosure package."""
    bundle_path: str
    pocso_withheld_count: int
    html_viewer_path: str
