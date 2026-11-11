"""
High-OpSec Messengers Forensic Engine.
Coordinates sub-engines for Session, SimpleX Chat, Zangi, XMPP Conversations, and Cross-App Covert Hunter.
Exports normalized records to high_opsec_messengers_engine.sqlite.
Complies with Section 6 of Phase 5 Module 5.3 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import List, Optional

from src.core.enums import ForensicGroup
from src.high_opsec.models import (
    OpSecPlatformName,
    IdentityRole,
    MessageDirection,
    CovertInvitePlatform,
    OpSecIdentityRecord,
    OpSecMessageRecord,
    CovertInviteDiscoveryRecord,
)
from src.high_opsec.session_decoder import SessionDecoder
from src.high_opsec.simplex_decoder import SimpleXDecoder
from src.high_opsec.privacy_messengers_decoder import PrivacyMessengersDecoder
from src.high_opsec.cross_app_hunter import CrossAppCovertHandleHunter

logger = logging.getLogger(__name__)


class HighOpSecMessengersEngine:
    """Master orchestrator and SQLite exporter for High-OpSec messenger forensics."""

    def __init__(self) -> None:
        self.session_decoder = SessionDecoder()
        self.simplex_decoder = SimpleXDecoder()
        self.privacy_decoder = PrivacyMessengersDecoder()
        self.hunter = CrossAppCovertHandleHunter()

    def init_database(self, db_path: str) -> None:
        """Initializes the three canonical tables in high_opsec_messengers_engine.sqlite."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Table 1: opsec_messenger_identities_and_relays
        cur.execute("""
            CREATE TABLE IF NOT EXISTS opsec_messenger_identities_and_relays (
                opsec_id_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_platform_name TEXT NOT NULL,
                app_instance_id INTEGER NOT NULL,
                identity_role TEXT NOT NULL,
                primary_crypto_handle TEXT NOT NULL,
                display_or_nickname TEXT,
                server_or_relay_url TEXT,
                public_key_or_omemo_fp TEXT,
                invitation_link_raw TEXT,
                created_or_first_seen_utc TEXT,
                recovery_classification TEXT NOT NULL
            )
        """)

        # Table 2: opsec_messenger_messages_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS opsec_messenger_messages_ledger (
                opsec_msg_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                app_platform_name TEXT NOT NULL,
                app_instance_id INTEGER NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                thread_identifier TEXT NOT NULL,
                direction TEXT NOT NULL,
                sender_crypto_handle TEXT,
                receiver_crypto_handle TEXT,
                message_body_text TEXT,
                quoted_reply_text TEXT,
                ephemeral_ttl_seconds INTEGER DEFAULT 0,
                was_marked_deleted_in_db INTEGER DEFAULT 0,
                attachment_metadata_json TEXT,
                sent_utc_ns INTEGER NOT NULL,
                sent_utc_iso TEXT NOT NULL
            )
        """)

        # Table 3: cross_app_opsec_invite_links_discovered
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cross_app_opsec_invite_links_discovered (
                invite_discovery_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                target_opsec_platform TEXT NOT NULL,
                extracted_handle_or_uri TEXT NOT NULL,
                found_in_source_app_and_table TEXT NOT NULL,
                shared_timestamp_utc_iso TEXT
            )
        """)

        conn.commit()
        conn.close()

    def export_to_sqlite(
        self,
        identities: List[OpSecIdentityRecord],
        messages: List[OpSecMessageRecord],
        covert_links: List[CovertInviteDiscoveryRecord],
        output_db_path: str,
    ) -> None:
        """Exports parsed identities, messages, and cross-app discoveries to master SQLite database."""
        self.init_database(output_db_path)
        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        # Insert Identities
        for ident in identities:
            cur.execute("""
                INSERT INTO opsec_messenger_identities_and_relays (
                    app_platform_name, app_instance_id, identity_role,
                    primary_crypto_handle, display_or_nickname, server_or_relay_url,
                    public_key_or_omemo_fp, invitation_link_raw, created_or_first_seen_utc,
                    recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(ident.app_platform_name.value if hasattr(ident.app_platform_name, "value") else ident.app_platform_name),
                ident.app_instance_id,
                str(ident.identity_role.value if hasattr(ident.identity_role, "value") else ident.identity_role),
                ident.primary_crypto_handle,
                ident.display_or_nickname,
                ident.server_or_relay_url,
                ident.public_key_or_omemo_fp,
                ident.invitation_link_raw,
                ident.created_or_first_seen_utc,
                str(ident.recovery_classification.value if hasattr(ident.recovery_classification, "value") else ident.recovery_classification),
            ))

        # Insert Messages
        for msg in messages:
            cur.execute("""
                INSERT INTO opsec_messenger_messages_ledger (
                    app_platform_name, app_instance_id, source_vfs_file_id,
                    recovery_classification, thread_identifier, direction,
                    sender_crypto_handle, receiver_crypto_handle, message_body_text,
                    quoted_reply_text, ephemeral_ttl_seconds, was_marked_deleted_in_db,
                    attachment_metadata_json, sent_utc_ns, sent_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(msg.app_platform_name.value if hasattr(msg.app_platform_name, "value") else msg.app_platform_name),
                msg.app_instance_id,
                msg.source_vfs_file_id,
                str(msg.recovery_classification.value if hasattr(msg.recovery_classification, "value") else msg.recovery_classification),
                msg.thread_identifier,
                str(msg.direction.value if hasattr(msg.direction, "value") else msg.direction),
                msg.sender_crypto_handle,
                msg.receiver_crypto_handle,
                msg.message_body_text,
                msg.quoted_reply_text,
                msg.ephemeral_ttl_seconds,
                msg.was_marked_deleted_in_db,
                msg.attachment_metadata_json,
                msg.sent_utc_ns,
                msg.sent_utc_iso,
            ))

        # Insert Covert Discoveries
        for link in covert_links:
            cur.execute("""
                INSERT INTO cross_app_opsec_invite_links_discovered (
                    target_opsec_platform, extracted_handle_or_uri,
                    found_in_source_app_and_table, shared_timestamp_utc_iso
                ) VALUES (?, ?, ?, ?)
            """, (
                str(link.target_opsec_platform.value if hasattr(link.target_opsec_platform, "value") else link.target_opsec_platform),
                link.extracted_handle_or_uri,
                link.found_in_source_app_and_table,
                link.shared_timestamp_utc_iso,
            ))

        conn.commit()
        conn.close()
