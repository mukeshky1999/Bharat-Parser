"""
Unified Chat Reconstructor Orchestration Engine (Sub-Engine 9.2A - 9.2D).
Assembles 4-Source Identity Pills, binds synchronized physical byte provenance,
and provides roster and thread intelligence helpers.
"""

from typing import Any, Optional

from src.chat_reconstructor_and_redline.models import (
    BubbleLifecycleState,
    ForensicChatBubble,
    FourSourceIdentityPill,
    ThreadRosterItem,
)
from src.chat_reconstructor_and_redline.fenwick_scroller import FenwickTreeVirtualScroller


class UnifiedChatReconstructorEngine:
    """Coordinates conversational thread reconstruction, unmasking pills, and hex synchronization."""

    def build_identity_pill(
        self, profile_data: dict[str, Any]
    ) -> FourSourceIdentityPill:
        """Assembles the 4-Source Identity Unmasking Pill with formatted display string."""
        phone = profile_data.get("unmasked_phone_e164")
        push = profile_data.get("push_name")
        tc = profile_data.get("truecaller_name")
        cbs = profile_data.get("bank_cbs_name")
        saved = profile_data.get("saved_contact_name")

        parts: list[str] = []
        if phone:
            parts.append(f"[WA LID Unmasked: {phone}]")
        if push:
            parts.append(f"[Push: {push}]")
        if tc:
            parts.append(f"[Truecaller: {tc}]")
        if cbs:
            parts.append(f"[Bank CBS: {cbs}]")
        if saved and not parts:
            parts.append(f"[Saved: {saved}]")

        pill_str = " | ".join(parts) if parts else "[Attribution: Unknown]"

        return FourSourceIdentityPill(
            unmasked_phone_e164=phone,
            push_name=push,
            truecaller_name=tc,
            bank_cbs_name=cbs,
            saved_contact_name=saved,
            formatted_pill_string=pill_str,
        )

    def build_chat_bubble_with_provenance(
        self,
        raw_bubble_data: dict[str, Any],
        entity_profile_data: Optional[dict[str, Any]] = None,
    ) -> ForensicChatBubble:
        """Constructs a courtroom-grade ForensicChatBubble bound to physical VFS byte provenance."""
        pill: Optional[FourSourceIdentityPill] = None
        if entity_profile_data:
            pill = self.build_identity_pill(entity_profile_data)

        text = str(raw_bubble_data.get("text_content", ""))
        state = raw_bubble_data.get(
            "lifecycle_state", BubbleLifecycleState.ACTIVE_UNMODIFIED_MESSAGE
        )
        if isinstance(state, str):
            state = BubbleLifecycleState(state)

        estimated_h = FenwickTreeVirtualScroller.estimate_bubble_height(
            text_length=len(text),
            has_quote=bool(raw_bubble_data.get("quoted_parent_id")),
            has_media=bool(raw_bubble_data.get("has_media")),
            is_edited_or_revoked=state
            in (
                BubbleLifecycleState.EDITED_MESSAGE_WITH_REVISION_HISTORY,
                BubbleLifecycleState.REVOKED_DELETED_FOR_EVERYONE_RECOVERED,
            ),
        )

        return ForensicChatBubble(
            bubble_uid=int(raw_bubble_data.get("bubble_uid", 1)),
            native_message_id=str(raw_bubble_data.get("native_message_id", "")),
            thread_id=str(raw_bubble_data.get("thread_id", "")),
            timestamp_utc_ns=int(raw_bubble_data.get("timestamp_utc_ns", 0)),
            sender_id=str(raw_bubble_data.get("sender_id", "")),
            is_outgoing=bool(raw_bubble_data.get("is_outgoing", False)),
            lifecycle_state=state,
            text_content=text,
            source_vfs_file_id=int(raw_bubble_data.get("source_vfs_file_id", 0)),
            physical_byte_offset=raw_bubble_data.get("physical_byte_offset"),
            identity_pill=pill,
            quoted_parent_id=raw_bubble_data.get("quoted_parent_id"),
            quoted_preview_text=raw_bubble_data.get("quoted_preview_text"),
            estimated_height_px=estimated_h,
        )

    def summarize_thread_roster(
        self, thread_items: list[dict[str, Any]]
    ) -> list[ThreadRosterItem]:
        """Converts raw thread metadata into roster summary items."""
        roster: list[ThreadRosterItem] = []
        for item in thread_items:
            roster.append(
                ThreadRosterItem(
                    thread_id=str(item.get("thread_id", "")),
                    display_title=str(item.get("display_title", "Untitled Thread")),
                    app_name=str(item.get("app_name", "Unknown")),
                    total_messages=int(item.get("total_messages", 0)),
                    deleted_revoked_count=int(item.get("deleted_revoked_count", 0)),
                    has_crypto_or_finance=bool(item.get("has_crypto_or_finance", False)),
                )
            )
        return roster
