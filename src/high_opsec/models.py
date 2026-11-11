"""
Data models and canonical enums for High-OpSec, Decentralized & Privacy Messengers.
Covers Session, SimpleX Chat, Zangi, Threema, Element/Matrix, Briar, XMPP, Wire, and Wickr.
Complies with Section 6 of Phase 5 Module 5.3 Specification and AGENTS.md Constitution.
"""

from dataclasses import dataclass, field
from enum import Enum, unique
import re
from typing import Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)


@unique
class OpSecPlatformName(str, Enum):
    """High-OpSec platform names according to Section 6 Table 1."""
    SESSION = "SESSION"
    SIMPLEX_CHAT = "SIMPLEX_CHAT"
    ZANGI = "ZANGI"
    THREEMA = "THREEMA"
    ELEMENT_MATRIX = "ELEMENT_MATRIX"
    BRIAR = "BRIAR"
    XMPP_CONVERSATIONS = "XMPP_CONVERSATIONS"
    WIRE = "WIRE"
    WICKR = "WICKR"


@unique
class IdentityRole(str, Enum):
    """Cryptographic identity or relay node role."""
    LOCAL_DEVICE_OWNER = "LOCAL_DEVICE_OWNER"
    REMOTE_CONTACT = "REMOTE_CONTACT"
    CLOSED_GROUP = "CLOSED_GROUP"
    OPEN_COMMUNITY_SERVER = "OPEN_COMMUNITY_SERVER"
    SMP_RELAY_QUEUE = "SMP_RELAY_QUEUE"


@unique
class MessageDirection(str, Enum):
    """Message transmission direction."""
    OUTGOING_SENT = "OUTGOING_SENT"
    INCOMING_RECEIVED = "INCOMING_RECEIVED"
    SYSTEM_EVENT = "SYSTEM_EVENT"


@unique
class CovertInvitePlatform(str, Enum):
    """Out-of-band covert invitation or handle classification."""
    SESSION_ID_05 = "SESSION_ID_05"
    SIMPLEX_INVITE_URI = "SIMPLEX_INVITE_URI"
    THREEMA_ID_LINK = "THREEMA_ID_LINK"
    BRIAR_LINK = "BRIAR_LINK"
    MATRIX_ID = "MATRIX_ID"
    ZANGI_NUMBER = "ZANGI_NUMBER"


def is_valid_session_id(s: str) -> bool:
    """
    Validates a 64-character or 66-character hexadecimal Session ID.
    Starts with '05' (standard user / closed group) or '15' / '25' (blinded open group).
    """
    if not isinstance(s, str) or len(s) not in (64, 66):
        return False
    if s[:2] not in ("05", "15", "25"):
        return False
    return all(c in "0123456789abcdefABCDEF" for c in s)


def is_valid_threema_id(s: str) -> bool:
    """Validates an 8-character alphanumeric Threema ID (e.g. ABCD1234, X9K2M4P8)."""
    if not isinstance(s, str) or len(s) != 8:
        return False
    return s.isalnum()


def is_valid_zangi_number(s: str) -> bool:
    """
    Validates a 10-digit virtual Zangi Number.
    Standard format: 10-XXXX-XXXX or 99-XXXX-XXXX, or unhyphenated 10 digits.
    """
    if not isinstance(s, str):
        return False
    pattern = r"^(?:(?:10|99)-\d{4}-\d{4}|(?:10|99)\d{8})$"
    return bool(re.match(pattern, s))


def is_valid_matrix_id(s: str) -> bool:
    """Validates a federated Matrix user identifier (@username:homeserver.org)."""
    if not isinstance(s, str):
        return False
    pattern = r"^@[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, s))


def is_valid_simplex_invite(s: str) -> bool:
    """Validates a SimpleX invitation URI or SMP relay queue string."""
    if not isinstance(s, str):
        return False
    return "simplex.chat/contact#" in s or s.startswith("smp://")


def is_valid_briar_link(s: str) -> bool:
    """Validates a Briar P2P invitation URI."""
    if not isinstance(s, str):
        return False
    return s.startswith("briar://")


@dataclass
class OpSecIdentityRecord:
    """Model for Table 1: opsec_messenger_identities_and_relays."""
    app_platform_name: OpSecPlatformName = OpSecPlatformName.SESSION
    app_instance_id: int = 1
    identity_role: IdentityRole = IdentityRole.REMOTE_CONTACT
    primary_crypto_handle: str = ""
    display_or_nickname: Optional[str] = None
    server_or_relay_url: Optional[str] = None
    public_key_or_omemo_fp: Optional[str] = None
    invitation_link_raw: Optional[str] = None
    created_or_first_seen_utc: Optional[str] = None
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    forensic_group: ForensicGroup = ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS
    opsec_id_uid: Optional[int] = None


@dataclass
class OpSecMessageRecord:
    """Model for Table 2: opsec_messenger_messages_ledger."""
    app_platform_name: OpSecPlatformName = OpSecPlatformName.SESSION
    app_instance_id: int = 1
    source_vfs_file_id: int = 0
    recovery_classification: ResidualConfidence = ResidualConfidence.ORIGINAL_RECORD
    thread_identifier: str = ""
    direction: str = "INCOMING_RECEIVED"
    sender_crypto_handle: Optional[str] = None
    receiver_crypto_handle: Optional[str] = None
    message_body_text: Optional[str] = None
    quoted_reply_text: Optional[str] = None
    ephemeral_ttl_seconds: int = 0
    was_marked_deleted_in_db: int = 0
    attachment_metadata_json: Optional[str] = None
    sent_utc_ns: int = 0
    sent_utc_iso: str = ""
    forensic_group: ForensicGroup = ForensicGroup.G08_HIGH_OPSEC_CRIMINAL_CHATS
    opsec_msg_uid: Optional[int] = None


@dataclass
class CovertInviteDiscoveryRecord:
    """Model for Table 3: cross_app_opsec_invite_links_discovered."""
    target_opsec_platform: CovertInvitePlatform = CovertInvitePlatform.SESSION_ID_05
    extracted_handle_or_uri: str = ""
    found_in_source_app_and_table: str = ""
    shared_timestamp_utc_iso: Optional[str] = None
    invite_discovery_uid: Optional[int] = None
