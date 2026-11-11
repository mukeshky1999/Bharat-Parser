"""
Master Forensic Engine for Regional Messengers, Covert Dead-Drops, and Unified Chat.
Coordinates Truecaller decoding, covert/betting decoders, and cross-platform actor stitching.
Exports normalized records to regional_covert_and_unified_chat_engine.sqlite.
Complies with Section 8 of Phase 5 Module 5.5 Specification and AGENTS.md Constitution.
"""

import logging
import os
from pathlib import Path
import sqlite3
from typing import List, Optional

from src.core.enums import ForensicGroup
from src.unified_chat.models import (
    SpecialChannelCategory,
    UnifiedActorRole,
    TruecallerEnrichmentRecord,
    RegionalMarketplaceRecord,
    UnifiedActorRecord,
    StitchedTimelineEventRecord,
)
from src.unified_chat.truecaller_decoder import TruecallerDecoder
from src.unified_chat.covert_and_betting_decoder import CovertAndBettingDecoder
from src.unified_chat.correlator import UnifiedConversationCorrelator

logger = logging.getLogger(__name__)


class RegionalCovertUnifiedChatEngine:
    """Master orchestrator and SQLite exporter for Module 5.5."""

    def __init__(self) -> None:
        self.truecaller_decoder = TruecallerDecoder()
        self.covert_decoder = CovertAndBettingDecoder()
        self.correlator = UnifiedConversationCorrelator()

    def init_database(self, db_path: str) -> None:
        """Initializes the four canonical tables in regional_covert_and_unified_chat_engine.sqlite."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Table 1: truecaller_global_enrichment_cache
        cur.execute("""
            CREATE TABLE IF NOT EXISTS truecaller_global_enrichment_cache (
                tc_enrich_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                normalized_e164_phone TEXT NOT NULL,
                subscriber_10_tail TEXT,
                tc_resolved_name TEXT NOT NULL,
                is_saved_in_device_contacts INTEGER DEFAULT 0,
                tc_spam_score INTEGER DEFAULT 0,
                tc_carrier_and_circle TEXT,
                tc_extracted_email_or_vpa TEXT,
                was_manually_searched_by_user INTEGER DEFAULT 0,
                last_lookup_utc_iso TEXT,
                recovery_classification TEXT NOT NULL
            )
        """)

        # Table 2: regional_marketplace_betting_and_deaddrop_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS regional_marketplace_betting_and_deaddrop_ledger (
                special_comm_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_category TEXT NOT NULL,
                app_name TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                recovery_classification TEXT NOT NULL,
                thread_or_document_id TEXT NOT NULL,
                thread_or_listing_title TEXT,
                sender_or_author_id TEXT,
                collaborators_or_peers_json TEXT,
                message_or_mutation_text TEXT NOT NULL,
                extracted_utr_vpa_or_phone_json TEXT,
                event_utc_ns INTEGER NOT NULL,
                event_utc_iso TEXT NOT NULL
            )
        """)

        # Table 3: unified_cross_platform_actors
        cur.execute("""
            CREATE TABLE IF NOT EXISTS unified_cross_platform_actors (
                unified_actor_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                primary_display_name TEXT NOT NULL,
                phonebook_saved_name TEXT,
                truecaller_unmasked_name TEXT,
                verified_bank_cbs_name TEXT,
                phone_numbers_e164_json TEXT,
                whatsapp_jids_and_lids_json TEXT,
                telegram_ids_and_handles_json TEXT,
                signal_and_opsec_handles_json TEXT,
                social_and_marketplace_ids_json TEXT,
                linked_upi_vpas_and_banks_json TEXT,
                linked_crypto_addresses_json TEXT,
                deterministic_join_proof_json TEXT NOT NULL
            )
        """)

        # Table 4: unified_stitched_conversation_timeline
        cur.execute("""
            CREATE TABLE IF NOT EXISTS unified_stitched_conversation_timeline (
                timeline_event_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                unified_actor_uid INTEGER NOT NULL,
                source_platform TEXT NOT NULL,
                is_platform_switch_hop INTEGER DEFAULT 0,
                direction TEXT NOT NULL,
                event_summary_text TEXT NOT NULL,
                recovery_classification TEXT NOT NULL,
                event_utc_ns INTEGER NOT NULL,
                event_utc_iso TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

    def export_to_sqlite(
        self,
        truecaller_records: List[TruecallerEnrichmentRecord],
        regional_records: List[RegionalMarketplaceRecord],
        actors: List[UnifiedActorRecord],
        stitched_timeline: List[StitchedTimelineEventRecord],
        output_db_path: str,
    ) -> None:
        """Exports all parsed records to the master SQLite database."""
        self.init_database(output_db_path)
        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        # Insert Truecaller Cache
        for tc in truecaller_records:
            cur.execute("""
                INSERT INTO truecaller_global_enrichment_cache (
                    normalized_e164_phone, subscriber_10_tail, tc_resolved_name,
                    is_saved_in_device_contacts, tc_spam_score, tc_carrier_and_circle,
                    tc_extracted_email_or_vpa, was_manually_searched_by_user,
                    last_lookup_utc_iso, recovery_classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tc.normalized_e164_phone,
                tc.subscriber_10_tail,
                tc.tc_resolved_name,
                tc.is_saved_in_device_contacts,
                tc.tc_spam_score,
                tc.tc_carrier_and_circle,
                tc.tc_extracted_email_or_vpa,
                tc.was_manually_searched_by_user,
                tc.last_lookup_utc_iso,
                str(tc.recovery_classification.value if hasattr(tc.recovery_classification, "value") else tc.recovery_classification),
            ))

        # Insert Regional / Marketplace / Dead-Drop Ledger
        for reg in regional_records:
            cur.execute("""
                INSERT INTO regional_marketplace_betting_and_deaddrop_ledger (
                    channel_category, app_name, source_vfs_file_id,
                    recovery_classification, thread_or_document_id,
                    thread_or_listing_title, sender_or_author_id,
                    collaborators_or_peers_json, message_or_mutation_text,
                    extracted_utr_vpa_or_phone_json, event_utc_ns, event_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(reg.channel_category.value if hasattr(reg.channel_category, "value") else reg.channel_category),
                reg.app_name,
                reg.source_vfs_file_id,
                str(reg.recovery_classification.value if hasattr(reg.recovery_classification, "value") else reg.recovery_classification),
                reg.thread_or_document_id,
                reg.thread_or_listing_title,
                reg.sender_or_author_id,
                reg.collaborators_or_peers_json,
                reg.message_or_mutation_text,
                reg.extracted_utr_vpa_or_phone_json,
                reg.event_utc_ns,
                reg.event_utc_iso,
            ))

        # Insert Unified Actors
        for act in actors:
            cur.execute("""
                INSERT INTO unified_cross_platform_actors (
                    primary_display_name, phonebook_saved_name, truecaller_unmasked_name,
                    verified_bank_cbs_name, phone_numbers_e164_json, whatsapp_jids_and_lids_json,
                    telegram_ids_and_handles_json, signal_and_opsec_handles_json,
                    social_and_marketplace_ids_json, linked_upi_vpas_and_banks_json,
                    linked_crypto_addresses_json, deterministic_join_proof_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                act.primary_display_name,
                act.phonebook_saved_name,
                act.truecaller_unmasked_name,
                act.verified_bank_cbs_name,
                act.phone_numbers_e164_json,
                act.whatsapp_jids_and_lids_json,
                act.telegram_ids_and_handles_json,
                act.signal_and_opsec_handles_json,
                act.social_and_marketplace_ids_json,
                act.linked_upi_vpas_and_banks_json,
                act.linked_crypto_addresses_json,
                act.deterministic_join_proof_json,
            ))

        # Insert Stitched Timeline
        for st in stitched_timeline:
            cur.execute("""
                INSERT INTO unified_stitched_conversation_timeline (
                    unified_actor_uid, source_platform, is_platform_switch_hop,
                    direction, event_summary_text, recovery_classification,
                    event_utc_ns, event_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                st.unified_actor_uid,
                st.source_platform,
                st.is_platform_switch_hop,
                st.direction,
                st.event_summary_text,
                str(st.recovery_classification.value if hasattr(st.recovery_classification, "value") else st.recovery_classification),
                st.event_utc_ns,
                st.event_utc_iso,
            ))

        conn.commit()
        conn.close()
