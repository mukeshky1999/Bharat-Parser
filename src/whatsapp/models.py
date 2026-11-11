"""
Data models and canonical enums for Phase 5, Module 5.1:
The WhatsApp Ecosystem Deep Decoder.
Complies with Section 4 of PRODUCTION FORENSIC PARSER - AGENT CONSTITUTION.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


class IdentityType(str, Enum):
    """WhatsApp identity classification."""
    USER = "USER"
    GROUP_CHAT = "GROUP_CHAT"
    COMMUNITY = "COMMUNITY"
    NEWSLETTER_CHANNEL = "NEWSLETTER_CHANNEL"
    BROADCAST_STATUS = "BROADCAST_STATUS"


class MessageDirection(str, Enum):
    """Message direction enum."""
    OUTGOING_SENT = "OUTGOING_SENT"
    INCOMING_RECEIVED = "INCOMING_RECEIVED"
    SYSTEM_EVENT = "SYSTEM_EVENT"


class MessageTypeCategory(str, Enum):
    """Normalized WhatsApp message type category."""
    TEXT = "TEXT"
    IMAGE = "IMAGE"
    VIDEO = "VIDEO"
    VOICE_NOTE = "VOICE_NOTE"
    DOCUMENT = "DOCUMENT"
    LOCATION_STATIC = "LOCATION_STATIC"
    LOCATION_LIVE = "LOCATION_LIVE"
    VCARD = "VCARD"
    POLL = "POLL"
    VIEW_ONCE_IMAGE = "VIEW_ONCE_IMAGE"
    VIEW_ONCE_VIDEO = "VIEW_ONCE_VIDEO"
    VIEW_ONCE_AUDIO = "VIEW_ONCE_AUDIO"
    REVOKED_DELETED_FOR_EVERYONE = "REVOKED_DELETED_FOR_EVERYONE"
    UPI_PAYMENT = "UPI_PAYMENT"


@dataclass
class WhatsAppIdentityRecord:
    """Resolved WhatsApp contact, group, channel, or privacy LID identity record."""
    app_instance_id: int
    jid_row_id: Optional[int] = None
    phone_jid_string: Optional[str] = None
    linked_lid_string: Optional[str] = None
    extracted_phone_e164: Optional[str] = None
    address_book_display_name: Optional[str] = None
    remote_profile_push_name: Optional[str] = None
    status_about_text: Optional[str] = None
    identity_type: IdentityType = IdentityType.USER
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    evidentiary_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    evidentiary_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    evidentiary_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    raw_byte_offset: int = 0
    corroboration_score: float = 1.0
    product_a_sha256: str = ""
    product_b_sha256: str = ""
    wa_identity_uid: Optional[int] = None


@dataclass
class WhatsAppMessageRecord:
    """Normalized WhatsApp message record across Android, iOS, WAL, and Backups."""
    app_instance_id: int
    source_vfs_file_id: int
    chat_jid: str
    message_key_id: str
    sent_utc_ns: int
    sent_utc_iso: str
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    recovery_source_detail: str = "LIVE_ACTIVE_TABLE"
    chat_display_title: Optional[str] = None
    direction: MessageDirection = MessageDirection.INCOMING_RECEIVED
    sender_resolved_phone_jid: Optional[str] = None
    sender_raw_lid: Optional[str] = None
    sender_push_and_saved_name: Optional[str] = None
    message_type_category: MessageTypeCategory = MessageTypeCategory.TEXT
    message_text_or_caption: Optional[str] = None
    is_revoked_deleted_for_everyone: int = 0
    recovered_pre_revoke_or_edit_text: Optional[str] = None
    quoted_parent_key_id: Optional[str] = None
    quoted_parent_text_preview: Optional[str] = None
    forwarding_hop_score: int = 0
    ephemeral_timer_seconds: int = 0
    media_metadata_json: Optional[str] = None
    reactions_json: Optional[str] = None
    delivered_utc_iso: Optional[str] = None
    read_blue_tick_utc_iso: Optional[str] = None
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    evidentiary_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    evidentiary_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    evidentiary_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    raw_byte_offset: int = 0
    corroboration_score: float = 1.0
    product_a_sha256: str = ""
    product_b_sha256: str = ""
    wa_msg_uid: Optional[int] = None


@dataclass
class WhatsAppCompanionDeviceRecord:
    """Linked WhatsApp Web / Desktop / Companion phone audit record."""
    app_instance_id: int
    companion_device_jid: str
    companion_os_and_browser: Optional[str] = None
    paired_login_utc_iso: Optional[str] = None
    last_active_utc_iso: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    evidentiary_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    evidentiary_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    evidentiary_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    raw_byte_offset: int = 0
    corroboration_score: float = 1.0
    product_a_sha256: str = ""
    product_b_sha256: str = ""
    companion_uid: Optional[int] = None
