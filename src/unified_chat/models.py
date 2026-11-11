"""
Data models and canonical enums for Regional Messengers, Covert Dead-Drops, and Unified Correlator.
Covers Truecaller, ShareChat, Moj, JioChat, Arattai, OLX, IndiaMART, Betting/Gaming, Google Keep/Docs, and Actor Stitching.
Complies with Section 8 of Phase 5 Module 5.5 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


@unique
class SpecialChannelCategory(str, Enum):
    """Categorization of special communication channels."""
    TRUECALLER_IM_OR_FLASH = "TRUECALLER_IM_OR_FLASH"
    SHARECHAT_MOJ_DM_OR_AUDIOROOM = "SHARECHAT_MOJ_DM_OR_AUDIOROOM"
    JIOCHAT_ARATTAI = "JIOCHAT_ARATTAI"
    OLX_INDIAMART_MARKETPLACE = "OLX_INDIAMART_MARKETPLACE"
    BETTING_BOOKIE_LIVECHAT = "BETTING_BOOKIE_LIVECHAT"
    MULTIPLAYER_GAME_CHAT = "MULTIPLAYER_GAME_CHAT"
    GOOGLE_DOCS_KEEP_DEADDROP = "GOOGLE_DOCS_KEEP_DEADDROP"
    APPLE_NOTES_SHARED_DEADDROP = "APPLE_NOTES_SHARED_DEADDROP"
    EMAIL_DRAFT_DEADDROP = "EMAIL_DRAFT_DEADDROP"


@unique
class UnifiedActorRole(str, Enum):
    """Role classification of a resolved cross-platform actor."""
    SUSPECT_COUNTERPARTY = "SUSPECT_COUNTERPARTY"
    COVERT_HANDLER = "COVERT_HANDLER"
    FINANCIAL_MULE = "FINANCIAL_MULE"
    MARKETPLACE_FRAUD_VICTIM = "MARKETPLACE_FRAUD_VICTIM"
    BETTING_AGENT = "BETTING_AGENT"


def canonical_phone_10_and_e164(phone: str) -> Tuple[str, str]:
    """
    Normalizes phone numbers and handles into canonical (E.164, 10-digit subscriber tail).
    Strips @s.whatsapp.net, @lid, whitespace, dashes, and country code prefixes.
    """
    if not phone or not isinstance(phone, str):
        return "", ""

    # Remove app suffixes
    cleaned = phone.split("@")[0].strip()
    digits = re.sub(r"\D", "", cleaned)

    if not digits:
        return "", ""

    # Indian 10-digit mobile (starts with 6, 7, 8, 9)
    if len(digits) == 10 and digits[0] in "6789":
        return f"+91{digits}", digits

    # Indian with country code 91 (12 digits)
    if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
        tail = digits[2:]
        return f"+91{tail}", tail

    # Indian with leading 0 (11 digits)
    if len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
        tail = digits[1:]
        return f"+91{tail}", tail

    # US/Canada with country code 1 (11 digits)
    if len(digits) == 11 and digits.startswith("1"):
        tail = digits[1:]
        return f"+{digits}", tail

    # Other international numbers
    tail = digits[-10:] if len(digits) >= 10 else digits
    prefix = "+" if not phone.strip().startswith("+") else ""
    return f"{prefix}{cleaned}", tail


@dataclass
class TruecallerEnrichmentRecord:
    """Model for Table 1: truecaller_global_enrichment_cache."""
    normalized_e164_phone: str = ""
    subscriber_10_tail: Optional[str] = None
    tc_resolved_name: str = ""
    is_saved_in_device_contacts: int = 0
    tc_spam_score: int = 0
    tc_carrier_and_circle: Optional[str] = None
    tc_extracted_email_or_vpa: Optional[str] = None
    was_manually_searched_by_user: int = 0
    last_lookup_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    tc_enrich_uid: Optional[int] = None


@dataclass
class RegionalMarketplaceRecord:
    """Model for Table 2: regional_marketplace_betting_and_deaddrop_ledger."""
    channel_category: SpecialChannelCategory = SpecialChannelCategory.TRUECALLER_IM_OR_FLASH
    app_name: str = ""
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    thread_or_document_id: str = ""
    thread_or_listing_title: Optional[str] = None
    sender_or_author_id: Optional[str] = None
    collaborators_or_peers_json: Optional[str] = None
    message_or_mutation_text: str = ""
    extracted_utr_vpa_or_phone_json: Optional[str] = None
    event_utc_ns: int = 0
    event_utc_iso: str = ""
    special_comm_uid: Optional[int] = None


@dataclass
class UnifiedActorRecord:
    """Model for Table 3: unified_cross_platform_actors."""
    primary_display_name: str = ""
    phonebook_saved_name: Optional[str] = None
    truecaller_unmasked_name: Optional[str] = None
    verified_bank_cbs_name: Optional[str] = None
    phone_numbers_e164_json: Optional[str] = None
    whatsapp_jids_and_lids_json: Optional[str] = None
    telegram_ids_and_handles_json: Optional[str] = None
    signal_and_opsec_handles_json: Optional[str] = None
    social_and_marketplace_ids_json: Optional[str] = None
    linked_upi_vpas_and_banks_json: Optional[str] = None
    linked_crypto_addresses_json: Optional[str] = None
    deterministic_join_proof_json: str = "[]"
    unified_actor_uid: Optional[int] = None


@dataclass
class StitchedTimelineEventRecord:
    """Model for Table 4: unified_stitched_conversation_timeline."""
    unified_actor_uid: int = 1
    source_platform: str = ""
    is_platform_switch_hop: int = 0
    direction: str = "INCOMING"
    event_summary_text: str = ""
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    event_utc_ns: int = 0
    event_utc_iso: str = ""
    timeline_event_uid: Optional[int] = None
