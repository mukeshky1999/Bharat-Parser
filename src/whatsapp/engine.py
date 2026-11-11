"""
Master Sub-Engine 5.1: The WhatsApp Ecosystem Deep Engine.
Coordinates identity unmasking, message parsing, companion auditing, and recovery,
exporting all evidentiary records into whatsapp_ecosystem_engine.sqlite.
Complies with Section 7 of Phase 5 Module 5.1 Specification.
"""

import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import List

logger = logging.getLogger(__name__)

from src.whatsapp.models import (
    WhatsAppIdentityRecord,
    WhatsAppMessageRecord,
    WhatsAppCompanionDeviceRecord,
)


class WhatsAppEcosystemEngine:
    """Master engine for decoding, recovering, and exporting WhatsApp forensic records."""

    def __init__(self) -> None:
        self.identities: List[WhatsAppIdentityRecord] = []
        self.messages: List[WhatsAppMessageRecord] = []
        self.companion_devices: List[WhatsAppCompanionDeviceRecord] = []

    def register_identities(self, identities: List[WhatsAppIdentityRecord]) -> None:
        """Appends identity records to master registry."""
        self.identities.extend(identities)

    def register_messages(self, messages: List[WhatsAppMessageRecord]) -> None:
        """Appends message records to master registry."""
        self.messages.extend(messages)

    def register_companion_devices(
        self, devices: List[WhatsAppCompanionDeviceRecord]
    ) -> None:
        """Appends companion device records to master registry."""
        self.companion_devices.extend(devices)

    def export_to_master_db(self, export_db_path: str) -> str:
        """
        Creates standardized tables and inserts all identity, message, and companion records
        into the target SQLite database.
        """
        Path(export_db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(export_db_path)
        cur = conn.cursor()

        # Table 1: whatsapp_identities_and_lid_map
        cur.execute("""
            CREATE TABLE IF NOT EXISTS whatsapp_identities_and_lid_map (
                wa_identity_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_instance_id INTEGER NOT NULL,
                jid_row_id INTEGER,
                phone_jid_string TEXT,
                linked_lid_string TEXT,
                extracted_phone_e164 TEXT,
                address_book_display_name TEXT,
                remote_profile_push_name TEXT,
                status_about_text TEXT,
                identity_type TEXT NOT NULL
            )
        """)

        # Table 2: whatsapp_messages_master_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS whatsapp_messages_master_ledger (
                wa_msg_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_instance_id INTEGER NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                recovery_source_detail TEXT NOT NULL,
                chat_jid TEXT NOT NULL,
                chat_display_title TEXT,
                message_key_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                sender_resolved_phone_jid TEXT,
                sender_raw_lid TEXT,
                sender_push_and_saved_name TEXT,
                message_type_category TEXT NOT NULL,
                message_text_or_caption TEXT,
                is_revoked_deleted_for_everyone INTEGER DEFAULT 0,
                recovered_pre_revoke_or_edit_text TEXT,
                quoted_parent_key_id TEXT,
                quoted_parent_text_preview TEXT,
                forwarding_hop_score INTEGER DEFAULT 0,
                ephemeral_timer_seconds INTEGER DEFAULT 0,
                media_metadata_json TEXT,
                reactions_json TEXT,
                sent_utc_ns INTEGER NOT NULL,
                sent_utc_iso TEXT NOT NULL,
                delivered_utc_iso TEXT,
                read_blue_tick_utc_iso TEXT
            )
        """)

        # Table 3: whatsapp_companion_devices_audit
        cur.execute("""
            CREATE TABLE IF NOT EXISTS whatsapp_companion_devices_audit (
                companion_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_instance_id INTEGER NOT NULL,
                companion_device_jid TEXT NOT NULL,
                companion_os_and_browser TEXT,
                paired_login_utc_iso TEXT,
                last_active_utc_iso TEXT,
                recovery_classification TEXT NOT NULL
            )
        """)

        # Insert Table 1 Records
        for ident in self.identities:
            cur.execute(
                """
                INSERT INTO whatsapp_identities_and_lid_map (
                    app_instance_id,
                    jid_row_id,
                    phone_jid_string,
                    linked_lid_string,
                    extracted_phone_e164,
                    address_book_display_name,
                    remote_profile_push_name,
                    status_about_text,
                    identity_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ident.app_instance_id,
                    ident.jid_row_id,
                    ident.phone_jid_string,
                    ident.linked_lid_string,
                    ident.extracted_phone_e164,
                    ident.address_book_display_name,
                    ident.remote_profile_push_name,
                    ident.status_about_text,
                    ident.identity_type.value if hasattr(ident.identity_type, "value") else str(ident.identity_type),
                ),
            )

        # Insert Table 2 Records
        for m in self.messages:
            reactions_val = m.reactions_json
            if reactions_val and "\\u" in reactions_val:
                try:
                    reactions_val = json.dumps(json.loads(reactions_val), ensure_ascii=False)
                except Exception as exc:
                    logger.debug("Failed to decode reactions JSON: %s", exc)

            cur.execute(
                """
                INSERT INTO whatsapp_messages_master_ledger (
                    app_instance_id,
                    source_vfs_file_id,
                    recovery_classification,
                    recovery_source_detail,
                    chat_jid,
                    chat_display_title,
                    message_key_id,
                    direction,
                    sender_resolved_phone_jid,
                    sender_raw_lid,
                    sender_push_and_saved_name,
                    message_type_category,
                    message_text_or_caption,
                    is_revoked_deleted_for_everyone,
                    recovered_pre_revoke_or_edit_text,
                    quoted_parent_key_id,
                    quoted_parent_text_preview,
                    forwarding_hop_score,
                    ephemeral_timer_seconds,
                    media_metadata_json,
                    reactions_json,
                    sent_utc_ns,
                    sent_utc_iso,
                    delivered_utc_iso,
                    read_blue_tick_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    m.app_instance_id,
                    m.source_vfs_file_id,
                    m.recovery_classification.value if hasattr(m.recovery_classification, "value") else str(m.recovery_classification),
                    m.recovery_source_detail,
                    m.chat_jid,
                    m.chat_display_title,
                    m.message_key_id,
                    m.direction.value if hasattr(m.direction, "value") else str(m.direction),
                    m.sender_resolved_phone_jid,
                    m.sender_raw_lid,
                    m.sender_push_and_saved_name,
                    m.message_type_category.value if hasattr(m.message_type_category, "value") else str(m.message_type_category),
                    m.message_text_or_caption,
                    m.is_revoked_deleted_for_everyone,
                    m.recovered_pre_revoke_or_edit_text,
                    m.quoted_parent_key_id,
                    m.quoted_parent_text_preview,
                    m.forwarding_hop_score,
                    m.ephemeral_timer_seconds,
                    m.media_metadata_json,
                    reactions_val,
                    m.sent_utc_ns,
                    m.sent_utc_iso,
                    m.delivered_utc_iso,
                    m.read_blue_tick_utc_iso,
                ),
            )

        # Insert Table 3 Records
        for dev in self.companion_devices:
            cur.execute(
                """
                INSERT INTO whatsapp_companion_devices_audit (
                    app_instance_id,
                    companion_device_jid,
                    companion_os_and_browser,
                    paired_login_utc_iso,
                    last_active_utc_iso,
                    recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    dev.app_instance_id,
                    dev.companion_device_jid,
                    dev.companion_os_and_browser,
                    dev.paired_login_utc_iso,
                    dev.last_active_utc_iso,
                    dev.recovery_classification.value if hasattr(dev.recovery_classification, "value") else str(dev.recovery_classification),
                ),
            )

        conn.commit()
        conn.close()
        return export_db_path
