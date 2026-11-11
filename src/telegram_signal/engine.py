"""
Master Sub-Engine 5.2: The Telegram & Signal Deep Engine.
Coordinates Telegram and Signal multi-account discovery, TL binary deserialization,
edit revisions linking, and exports into telegram_and_signal_engine.sqlite.
Complies with Section 7 of Phase 5 Module 5.2 Specification.
"""

import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import List

from src.telegram_signal.models import (
    MessagingPeerRecord,
    MessagingMessageRecord,
)

logger = logging.getLogger(__name__)


class TelegramSignalEngine:
    """Master engine for decoding and exporting Telegram and Signal forensic records."""

    def __init__(self) -> None:
        self.peers: List[MessagingPeerRecord] = []
        self.messages: List[MessagingMessageRecord] = []

    def register_peers(self, peers: List[MessagingPeerRecord]) -> None:
        """Appends peer directory records to master registry."""
        self.peers.extend(peers)

    def register_messages(self, messages: List[MessagingMessageRecord]) -> None:
        """Appends message records to master registry."""
        self.messages.extend(messages)

    def export_to_master_db(self, export_db_path: str) -> str:
        """
        Creates standardized schema and inserts all peer and message records
        into the target SQLite database.
        """
        Path(export_db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(export_db_path)
        cur = conn.cursor()

        # Table 1: messaging_accounts_and_peers_directory
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messaging_accounts_and_peers_directory (
                peer_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                platform_family TEXT NOT NULL,
                app_instance_id INTEGER NOT NULL,
                account_slot_name TEXT NOT NULL,
                peer_type TEXT NOT NULL,
                native_peer_id TEXT NOT NULL,
                secondary_uuid_or_pni TEXT,
                username_handle TEXT,
                phone_number_e164 TEXT,
                display_or_group_name TEXT,
                local_role_in_group TEXT,
                is_scam_or_fake_flagged INTEGER DEFAULT 0,
                recovery_classification TEXT NOT NULL
            )
        """)

        # Table 2: telegram_and_signal_messages_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS telegram_and_signal_messages_ledger (
                msg_master_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_instance_id INTEGER NOT NULL,
                account_slot_name TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                thread_or_dialog_id TEXT NOT NULL,
                thread_classification TEXT NOT NULL,
                native_message_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                sender_peer_id TEXT,
                sender_display_and_handle TEXT,
                message_text TEXT,
                is_edited_or_past_revision INTEGER DEFAULT 0,
                pre_edit_or_diff_json TEXT,
                forwarded_from_info_json TEXT,
                reply_to_msg_id TEXT,
                ttl_disappearing_seconds INTEGER DEFAULT 0,
                is_view_once_media INTEGER DEFAULT 0,
                media_attachment_json TEXT,
                inline_bot_buttons_json TEXT,
                sent_utc_ns INTEGER NOT NULL,
                sent_utc_iso TEXT NOT NULL
            )
        """)

        # Insert Table 1 Records
        for p in self.peers:
            cur.execute(
                """
                INSERT INTO messaging_accounts_and_peers_directory (
                    platform_family,
                    app_instance_id,
                    account_slot_name,
                    peer_type,
                    native_peer_id,
                    secondary_uuid_or_pni,
                    username_handle,
                    phone_number_e164,
                    display_or_group_name,
                    local_role_in_group,
                    is_scam_or_fake_flagged,
                    recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    p.platform_family.value if hasattr(p.platform_family, "value") else str(p.platform_family),
                    p.app_instance_id,
                    p.account_slot_name,
                    p.peer_type.value if hasattr(p.peer_type, "value") else str(p.peer_type),
                    p.native_peer_id,
                    p.secondary_uuid_or_pni,
                    p.username_handle,
                    p.phone_number_e164,
                    p.display_or_group_name,
                    p.local_role_in_group.value if hasattr(p.local_role_in_group, "value") else str(p.local_role_in_group),
                    p.is_scam_or_fake_flagged,
                    p.recovery_classification.value if hasattr(p.recovery_classification, "value") else str(p.recovery_classification),
                ),
            )

        # Insert Table 2 Records
        for m in self.messages:
            cur.execute(
                """
                INSERT INTO telegram_and_signal_messages_ledger (
                    app_instance_id,
                    account_slot_name,
                    source_vfs_file_id,
                    recovery_classification,
                    thread_or_dialog_id,
                    thread_classification,
                    native_message_id,
                    direction,
                    sender_peer_id,
                    sender_display_and_handle,
                    message_text,
                    is_edited_or_past_revision,
                    pre_edit_or_diff_json,
                    forwarded_from_info_json,
                    reply_to_msg_id,
                    ttl_disappearing_seconds,
                    is_view_once_media,
                    media_attachment_json,
                    inline_bot_buttons_json,
                    sent_utc_ns,
                    sent_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    m.app_instance_id,
                    m.account_slot_name,
                    m.source_vfs_file_id,
                    m.recovery_classification.value if hasattr(m.recovery_classification, "value") else str(m.recovery_classification),
                    m.thread_or_dialog_id,
                    m.thread_classification.value if hasattr(m.thread_classification, "value") else str(m.thread_classification),
                    m.native_message_id,
                    m.direction,
                    m.sender_peer_id,
                    m.sender_display_and_handle,
                    m.message_text,
                    m.is_edited_or_past_revision,
                    m.pre_edit_or_diff_json,
                    m.forwarded_from_info_json,
                    m.reply_to_msg_id,
                    m.ttl_disappearing_seconds,
                    m.is_view_once_media,
                    m.media_attachment_json,
                    m.inline_bot_buttons_json,
                    m.sent_utc_ns,
                    m.sent_utc_iso,
                ),
            )

        conn.commit()
        conn.close()
        return export_db_path
