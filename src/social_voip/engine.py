"""
Master Forensic Engine for Social, VoIP & Virtual Burner Messengers.
Coordinates sub-engines for Meta, Snapchat, Discord, Botim/IMO/WeChat, and Burner Bridges.
Exports normalized records to social_voip_and_burner_engine.sqlite.
Complies with Section 7 of Phase 5 Module 5.4 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import List, Optional

from src.core.enums import ForensicGroup
from src.social_voip.models import (
    SocialPlatform,
    SocialAccountRole,
    SocialMessageDirection,
    SocialContentCategory,
    SocialAccountRecord,
    SocialMessageRecord,
    BurnerBridgeRecord,
)
from src.social_voip.meta_decoder import MetaDecoder
from src.social_voip.snapchat_discord_decoder import SnapchatDiscordDecoder
from src.social_voip.cross_border_voip_decoder import CrossBorderVoIPDecoder
from src.social_voip.burner_bridge import BurnerBridge

logger = logging.getLogger(__name__)


class SocialVoIPBurnerEngine:
    """Master orchestrator and SQLite exporter for Module 5.4."""

    def __init__(self) -> None:
        self.meta_decoder = MetaDecoder()
        self.snapchat_discord_decoder = SnapchatDiscordDecoder()
        self.cross_border_decoder = CrossBorderVoIPDecoder()
        self.burner_bridge = BurnerBridge()

    def init_database(self, db_path: str) -> None:
        """Initializes the three canonical tables in social_voip_and_burner_engine.sqlite."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Table 1: social_and_voip_accounts_directory
        cur.execute("""
            CREATE TABLE IF NOT EXISTS social_and_voip_accounts_directory (
                social_peer_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                platform_name TEXT NOT NULL,
                app_instance_id INTEGER NOT NULL,
                account_role TEXT NOT NULL,
                native_platform_id TEXT NOT NULL,
                username_or_handle TEXT,
                display_full_name TEXT,
                linked_phone_e164 TEXT,
                linked_email TEXT,
                account_created_or_added_utc TEXT,
                recovery_classification TEXT NOT NULL
            )
        """)

        # Table 2: social_and_voip_messages_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS social_and_voip_messages_ledger (
                social_msg_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                platform_name TEXT NOT NULL,
                app_instance_id INTEGER NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                thread_or_channel_id TEXT NOT NULL,
                native_message_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                sender_id_and_handle TEXT,
                receiver_or_thread_title TEXT,
                content_category TEXT NOT NULL,
                message_text TEXT,
                quoted_reply_text TEXT,
                call_duration_seconds INTEGER,
                media_or_location_json TEXT,
                sent_utc_ns INTEGER NOT NULL,
                sent_utc_iso TEXT NOT NULL
            )
        """)

        # Table 3: virtual_burner_numbers_and_otp_bridge
        cur.execute("""
            CREATE TABLE IF NOT EXISTS virtual_burner_numbers_and_otp_bridge (
                burner_record_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                burner_app_name TEXT NOT NULL,
                app_instance_id INTEGER NOT NULL,
                assigned_virtual_number TEXT NOT NULL,
                burner_login_email_or_user TEXT,
                intercepted_otp_service TEXT,
                intercepted_otp_code TEXT,
                otp_received_utc_iso TEXT,
                is_linked_to_local_messenger INTEGER DEFAULT 0,
                linked_messenger_details TEXT
            )
        """)

        conn.commit()
        conn.close()

    def export_to_sqlite(
        self,
        accounts: List[SocialAccountRecord],
        messages: List[SocialMessageRecord],
        burner_records: List[BurnerBridgeRecord],
        output_db_path: str,
    ) -> None:
        """Exports all parsed records to the master SQLite database."""
        self.init_database(output_db_path)
        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        # Insert Accounts
        for acc in accounts:
            cur.execute("""
                INSERT INTO social_and_voip_accounts_directory (
                    platform_name, app_instance_id, account_role,
                    native_platform_id, username_or_handle, display_full_name,
                    linked_phone_e164, linked_email, account_created_or_added_utc,
                    recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(acc.platform_name.value if hasattr(acc.platform_name, "value") else acc.platform_name),
                acc.app_instance_id,
                str(acc.account_role.value if hasattr(acc.account_role, "value") else acc.account_role),
                acc.native_platform_id,
                acc.username_or_handle,
                acc.display_full_name,
                acc.linked_phone_e164,
                acc.linked_email,
                acc.account_created_or_added_utc,
                str(acc.recovery_classification.value if hasattr(acc.recovery_classification, "value") else acc.recovery_classification),
            ))

        # Insert Messages
        for msg in messages:
            cur.execute("""
                INSERT INTO social_and_voip_messages_ledger (
                    platform_name, app_instance_id, source_vfs_file_id,
                    recovery_classification, thread_or_channel_id, native_message_id,
                    direction, sender_id_and_handle, receiver_or_thread_title,
                    content_category, message_text, quoted_reply_text,
                    call_duration_seconds, media_or_location_json, sent_utc_ns, sent_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(msg.platform_name.value if hasattr(msg.platform_name, "value") else msg.platform_name),
                msg.app_instance_id,
                msg.source_vfs_file_id,
                str(msg.recovery_classification.value if hasattr(msg.recovery_classification, "value") else msg.recovery_classification),
                msg.thread_or_channel_id,
                msg.native_message_id,
                str(msg.direction.value if hasattr(msg.direction, "value") else msg.direction),
                msg.sender_id_and_handle,
                msg.receiver_or_thread_title,
                str(msg.content_category.value if hasattr(msg.content_category, "value") else msg.content_category),
                msg.message_text,
                msg.quoted_reply_text,
                msg.call_duration_seconds,
                msg.media_or_location_json,
                msg.sent_utc_ns,
                msg.sent_utc_iso,
            ))

        # Insert Burner Records
        for br in burner_records:
            cur.execute("""
                INSERT INTO virtual_burner_numbers_and_otp_bridge (
                    burner_app_name, app_instance_id, assigned_virtual_number,
                    burner_login_email_or_user, intercepted_otp_service,
                    intercepted_otp_code, otp_received_utc_iso,
                    is_linked_to_local_messenger, linked_messenger_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                br.burner_app_name,
                br.app_instance_id,
                br.assigned_virtual_number,
                br.burner_login_email_or_user,
                br.intercepted_otp_service,
                br.intercepted_otp_code,
                br.otp_received_utc_iso,
                br.is_linked_to_local_messenger,
                br.linked_messenger_details,
            ))

        conn.commit()
        conn.close()
