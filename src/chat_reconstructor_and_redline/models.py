"""
Data models and canonical enums for Phase 9, Module 9.2:
Unified Multi-App Chat Reconstructor, Edit/Revoke Redline Viewer & Cross-Platform Hopping Timeline.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class BubbleLifecycleState(str, Enum):
    """The 5 forensic chat bubble visual and evidentiary lifecycle states."""
    ACTIVE_UNMODIFIED_MESSAGE = "ACTIVE_UNMODIFIED_MESSAGE"
    EDITED_MESSAGE_WITH_REVISION_HISTORY = "EDITED_MESSAGE_WITH_REVISION_HISTORY"
    REVOKED_DELETED_FOR_EVERYONE_RECOVERED = "REVOKED_DELETED_FOR_EVERYONE_RECOVERED"
    REVOKED_TOMBSTONE_UNRECOVERED = "REVOKED_TOMBSTONE_UNRECOVERED"
    EXPIRED_DISAPPEARING_OR_VIEW_ONCE_SURVIVOR = "EXPIRED_DISAPPEARING_OR_VIEW_ONCE_SURVIVOR"


class DiffTokenType(str, Enum):
    """Token classification in the Myers Shortest Edit Script (SES)."""
    EQUAL = "EQUAL"
    DELETE = "DELETE"
    INSERT = "INSERT"


@dataclass
class RedlineDiffToken:
    """Individual segmented token in an edit redline diff."""
    token_type: DiffTokenType
    text: str


@dataclass
class RedlineDiffResult:
    """Composite output of the Unicode grapheme-aware Myers redline diff."""
    original_text: str
    edited_text: str
    tokens: list[RedlineDiffToken]
    rendered_markup: str
    has_financial_or_crypto_token: bool = False

    @property
    def html_rendered_diff(self) -> str:
        parts = []
        for t in self.tokens:
            if t.token_type == DiffTokenType.EQUAL:
                parts.append(t.text)
            elif t.token_type == DiffTokenType.INSERT:
                parts.append(f"<ins>{t.text}</ins>")
            elif t.token_type == DiffTokenType.DELETE:
                parts.append(f"<del>{t.text}</del>")
        return "".join(parts)

    @property
    def insertions_count(self) -> int:
        return sum(1 for t in self.tokens if t.token_type == DiffTokenType.INSERT)

    @property
    def deletions_count(self) -> int:
        return sum(1 for t in self.tokens if t.token_type == DiffTokenType.DELETE)

    @property
    def is_identical(self) -> bool:
        return self.insertions_count == 0 and self.deletions_count == 0


@dataclass
class FourSourceIdentityPill:
    """4-Source unmasking attribution for anonymous group and direct message senders."""
    unmasked_phone_e164: Optional[str] = None
    push_name: Optional[str] = None
    truecaller_name: Optional[str] = None
    bank_cbs_name: Optional[str] = None
    saved_contact_name: Optional[str] = None
    formatted_pill_string: str = ""


@dataclass
class AudioWaveformRecord:
    """Audio metadata, 64-peak RMS envelope, and word-synced speech transcript."""
    source_vfs_file_id: int
    duration_seconds: float
    waveform_64_peaks: list[float]
    audio_cache_uid: Optional[int] = None
    playable_wav_staging_id: Optional[int] = None
    offline_stt_transcript_text: Optional[str] = None
    word_timestamps: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PlatformSwitchBanner:
    """Cross-platform hopping divider banner between consecutive counterparty interactions."""
    previous_platform: str
    current_platform: str
    time_delta_seconds: int
    formatted_time_delta: str
    rendered_banner_text: str
    handoff_token: Optional[str] = None


@dataclass
class ForensicChatBubble:
    """Courtroom-grade composite chat bubble representing a single conversational interaction."""
    bubble_uid: int
    native_message_id: str
    thread_id: str
    timestamp_utc_ns: int
    sender_id: str
    is_outgoing: bool
    lifecycle_state: BubbleLifecycleState
    text_content: str
    source_vfs_file_id: int
    physical_byte_offset: Optional[int] = None
    redline_diff: Optional[RedlineDiffResult] = None
    identity_pill: Optional[FourSourceIdentityPill] = None
    quoted_parent_id: Optional[str] = None
    quoted_preview_text: Optional[str] = None
    audio_waveform: Optional[AudioWaveformRecord] = None
    estimated_height_px: int = 48


@dataclass
class ThreadRosterItem:
    """Roster sidebar item representing a messaging thread or channel."""
    thread_id: str
    display_title: str
    app_name: str
    total_messages: int
    deleted_revoked_count: int
    has_crypto_or_finance: bool = False
