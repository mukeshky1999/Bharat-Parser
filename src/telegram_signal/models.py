"""
Data models and canonical enums for Phase 5, Module 5.2:
The Telegram & Signal Deep Decoders.
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


class PlatformFamily(str, Enum):
    """Messaging platform classification."""
    TELEGRAM = "TELEGRAM"
    TELEGRAM_X = "TELEGRAM_X"
    TELEGRAM_FORK_AYUGRAM_NICEGRAM = "TELEGRAM_FORK_AYUGRAM_NICEGRAM"
    SIGNAL = "SIGNAL"


class PeerType(str, Enum):
    """Peer account / group classification."""
    SELF_OWNER_ACCOUNT = "SELF_OWNER_ACCOUNT"
    USER_CONTACT = "USER_CONTACT"
    TELEGRAM_BOT = "TELEGRAM_BOT"
    GROUP_CHAT = "GROUP_CHAT"
    SUPERGROUP_OR_CHANNEL = "SUPERGROUP_OR_CHANNEL"
    SECRET_CHAT_PARTNER = "SECRET_CHAT_PARTNER"


class LocalRoleInGroup(str, Enum):
    """Local user's administrative role in group / channel."""
    CHANNEL_CREATOR_OWNER = "CHANNEL_CREATOR_OWNER"
    GROUP_ADMIN = "GROUP_ADMIN"
    MEMBER = "MEMBER"
    BANNED = "BANNED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ThreadClassification(str, Enum):
    """Thread conversation classification."""
    SAVED_MESSAGES_SELF_VAULT = "SAVED_MESSAGES_SELF_VAULT"
    DIRECT_1ON1_CHAT = "DIRECT_1ON1_CHAT"
    SECRET_E2EE_CHAT = "SECRET_E2EE_CHAT"
    GROUP_OR_SUPERGROUP = "GROUP_OR_SUPERGROUP"
    BROADCAST_CHANNEL = "BROADCAST_CHANNEL"
    BOT_INTERACTION = "BOT_INTERACTION"


@dataclass
class MessagingPeerRecord:
    """Directory peer record for Telegram or Signal contact, group, channel, or bot."""
    platform_family: PlatformFamily
    app_instance_id: int
    account_slot_name: str
    peer_type: PeerType
    native_peer_id: str
    secondary_uuid_or_pni: Optional[str] = None
    username_handle: Optional[str] = None
    phone_number_e164: Optional[str] = None
    display_or_group_name: Optional[str] = None
    local_role_in_group: LocalRoleInGroup = LocalRoleInGroup.NOT_APPLICABLE
    is_scam_or_fake_flagged: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    evidentiary_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    evidentiary_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    evidentiary_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    raw_byte_offset: int = 0
    corroboration_score: float = 1.0
    product_a_sha256: str = ""
    product_b_sha256: str = ""
    peer_record_uid: Optional[int] = None


@dataclass
class MessagingMessageRecord:
    """Normalized message record across Telegram and Signal ecosystems."""
    app_instance_id: int
    account_slot_name: str
    source_vfs_file_id: int
    thread_or_dialog_id: str
    thread_classification: ThreadClassification
    native_message_id: str
    direction: str
    sent_utc_ns: int
    sent_utc_iso: str
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    sender_peer_id: Optional[str] = None
    sender_display_and_handle: Optional[str] = None
    message_text: Optional[str] = None
    is_edited_or_past_revision: int = 0
    pre_edit_or_diff_json: Optional[str] = None
    forwarded_from_info_json: Optional[str] = None
    reply_to_msg_id: Optional[str] = None
    ttl_disappearing_seconds: int = 0
    is_view_once_media: int = 0
    media_attachment_json: Optional[str] = None
    inline_bot_buttons_json: Optional[str] = None
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    evidentiary_existence: EvidentiaryExistence = EvidentiaryExistence.OBSERVED
    evidentiary_access: EvidentiaryAccess = EvidentiaryAccess.PLAINTEXT
    evidentiary_storage: EvidentiaryStorage = EvidentiaryStorage.LIVE_RECORD
    raw_byte_offset: int = 0
    corroboration_score: float = 1.0
    product_a_sha256: str = ""
    product_b_sha256: str = ""
    msg_master_uid: Optional[int] = None
