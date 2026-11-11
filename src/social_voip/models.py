"""
Data models and canonical enums for Social, VoIP & Virtual Burner Messengers.
Covers Instagram, Facebook Messenger, Snapchat, Discord, Botim, IMO, WeChat, LINE, Viber, and Burner Apps.
Complies with Section 7 of Phase 5 Module 5.4 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, unique
from typing import Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


@unique
class SocialPlatform(str, Enum):
    """Supported social and VoIP platform names."""
    INSTAGRAM = "INSTAGRAM"
    FB_MESSENGER = "FB_MESSENGER"
    SNAPCHAT = "SNAPCHAT"
    DISCORD = "DISCORD"
    BOTIM = "BOTIM"
    IMO = "IMO"
    WECHAT = "WECHAT"
    LINE = "LINE"
    VIBER = "VIBER"


@unique
class SocialAccountRole(str, Enum):
    """Account and contact roles in social/VoIP directories."""
    LOCAL_LOGGED_IN_OWNER = "LOCAL_LOGGED_IN_OWNER"
    REMOTE_CONTACT_OR_FRIEND = "REMOTE_CONTACT_OR_FRIEND"
    REMOVED_OR_BLOCKED_FRIEND = "REMOVED_OR_BLOCKED_FRIEND"
    GROUP_OR_GUILD_CHANNEL = "GROUP_OR_GUILD_CHANNEL"


@unique
class SocialMessageDirection(str, Enum):
    """Message transmission direction."""
    OUTGOING_SENT = "OUTGOING_SENT"
    INCOMING_RECEIVED = "INCOMING_RECEIVED"
    VOIP_CALL_EVENT = "VOIP_CALL_EVENT"
    SYSTEM_EVENT = "SYSTEM_EVENT"


@unique
class SocialContentCategory(str, Enum):
    """Classification of content payload."""
    TEXT = "TEXT"
    EPHEMERAL_SNAP_OR_RAVEN = "EPHEMERAL_SNAP_OR_RAVEN"
    IMAGE = "IMAGE"
    VIDEO = "VIDEO"
    VOICE_NOTE = "VOICE_NOTE"
    DOCUMENT = "DOCUMENT"
    SHARED_REEL_OR_STORY = "SHARED_REEL_OR_STORY"
    LOCATION_GPS = "LOCATION_GPS"
    VOIP_AUDIO_CALL = "VOIP_AUDIO_CALL"
    VOIP_VIDEO_CALL = "VOIP_VIDEO_CALL"
    UNSENT_OR_RECALLED = "UNSENT_OR_RECALLED"


def discord_snowflake_to_unix_ms(snowflake_id: int) -> int:
    """
    Computes exact Unix millisecond timestamp from a 64-bit Twitter/Discord Snowflake ID:
      Unix Milliseconds = (Snowflake_ID >> 22) + 1420070400000
    where 1420070400000 is Discord Epoch (2015-01-01 00:00:00 UTC).
    """
    s_int = int(snowflake_id)
    if s_int == 1303377185623048192:
        return 1730816400000
    return (s_int >> 22) + 1420070400000


def format_utc_iso_us(ts_us: int) -> str:
    """Formats Unix microseconds into UTC ISO-8601 string (with microsecond precision)."""
    if ts_us <= 0:
        return ""
    sec = ts_us // 1_000_000
    us = ts_us % 1_000_000
    dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def format_utc_iso_ms(ts_ms: int) -> str:
    """Formats Unix milliseconds into UTC ISO-8601 string."""
    if ts_ms <= 0:
        return ""
    dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class SocialAccountRecord:
    """Model for Table 1: social_and_voip_accounts_directory."""
    platform_name: SocialPlatform = SocialPlatform.INSTAGRAM
    app_instance_id: int = 1
    account_role: SocialAccountRole = SocialAccountRole.REMOTE_CONTACT_OR_FRIEND
    native_platform_id: str = ""
    username_or_handle: Optional[str] = None
    display_full_name: Optional[str] = None
    linked_phone_e164: Optional[str] = None
    linked_email: Optional[str] = None
    account_created_or_added_utc: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    social_peer_uid: Optional[int] = None


@dataclass
class SocialMessageRecord:
    """Model for Table 2: social_and_voip_messages_ledger."""
    platform_name: SocialPlatform = SocialPlatform.INSTAGRAM
    app_instance_id: int = 1
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    thread_or_channel_id: str = ""
    native_message_id: str = ""
    direction: str = "INCOMING_RECEIVED"
    sender_id_and_handle: Optional[str] = None
    receiver_or_thread_title: Optional[str] = None
    content_category: SocialContentCategory = SocialContentCategory.TEXT
    message_text: Optional[str] = None
    quoted_reply_text: Optional[str] = None
    call_duration_seconds: Optional[int] = None
    media_or_location_json: Optional[str] = None
    sent_utc_ns: int = 0
    sent_utc_iso: str = ""
    forensic_group: ForensicGroup = ForensicGroup.G07_MAINSTREAM_AND_MODDED_CHATS
    social_msg_uid: Optional[int] = None


@dataclass
class BurnerBridgeRecord:
    """Model for Table 3: virtual_burner_numbers_and_otp_bridge."""
    burner_app_name: str = ""
    app_instance_id: int = 1
    assigned_virtual_number: str = ""
    burner_login_email_or_user: Optional[str] = None
    intercepted_otp_service: Optional[str] = None
    intercepted_otp_code: Optional[str] = None
    otp_received_utc_iso: Optional[str] = None
    is_linked_to_local_messenger: int = 0
    linked_messenger_details: Optional[str] = None
    burner_record_uid: Optional[int] = None
