"""
Sub-Engine 8.1 Master Coordinator: Cross-Phase Entity Graph & Super-Timeline Engine.
Manages resolution, graph edge synthesis, chronological timeline compilation, action burst detection,
and persistence to entity_graph_and_super_timeline.sqlite.
Adheres strictly to AGENTS.md Forensic Invariants and Section 7 of Module 8.1 Specification.
"""

import json
import os
import sqlite3
from typing import List, Optional

from src.entity_and_timeline.models import (
    ActionBurstStoryRecord,
    GraphEdgeRecord,
    MasterEntityProfile,
    SuperTimelineEvent,
)


class EntityGraphAndTimelineEngine:
    """Master engine orchestrating entity resolution, graph edges, super-timeline, and SQLite storage."""

    SCHEMA_DDL = """
    CREATE TABLE IF NOT EXISTS entity_master_profiles (
        entity_master_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_classification TEXT NOT NULL,
        canonical_display_name TEXT NOT NULL,
        all_observed_names_json TEXT NULL,
        tier1_hard_keys_json TEXT NOT NULL,
        phones_e164_json TEXT NULL,
        messaging_handles_json TEXT NULL,
        bank_accounts_and_vpas_json TEXT NULL,
        crypto_addresses_and_uids_json TEXT NULL,
        kyc_documents_and_biometrics_json TEXT NULL,
        linked_locations_and_addresses_json TEXT NULL,
        risk_and_typology_flags_json TEXT NULL,
        deterministic_merge_proof_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS entity_graph_edges_ledger (
        graph_edge_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        source_entity_uid INTEGER NOT NULL,
        target_entity_uid INTEGER NOT NULL,
        edge_verb TEXT NOT NULL,
        interaction_count INTEGER DEFAULT 1,
        total_fiat_value_inr REAL DEFAULT 0.0,
        total_crypto_value_summary TEXT NULL,
        platforms_and_rails_json TEXT NOT NULL,
        has_deleted_or_hidden_evidence INTEGER DEFAULT 0,
        supporting_record_pointers_json TEXT NOT NULL,
        first_interaction_utc_iso TEXT NULL,
        last_interaction_utc_iso TEXT NULL,
        FOREIGN KEY (source_entity_uid) REFERENCES entity_master_profiles(entity_master_uid),
        FOREIGN KEY (target_entity_uid) REFERENCES entity_master_profiles(entity_master_uid)
    );

    CREATE TABLE IF NOT EXISTS unified_super_timeline (
        timeline_event_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_utc_ns INTEGER NOT NULL,
        timestamp_utc_iso TEXT NOT NULL,
        timestamp_ist_iso TEXT NOT NULL,
        timestamp_type_and_precision TEXT NOT NULL,
        clock_integrity_status TEXT NOT NULL,
        originating_phase_and_module TEXT NOT NULL,
        artifact_domain_category TEXT NOT NULL,
        app_package_or_subsystem TEXT NOT NULL,
        android_user_profile_or_locality TEXT NOT NULL,
        actor_source_entity_uid INTEGER NULL,
        actor_target_entity_uid INTEGER NULL,
        event_title_badge TEXT NOT NULL,
        event_detailed_summary TEXT NOT NULL,
        recovery_classification TEXT NOT NULL,
        source_vfs_file_id INTEGER NOT NULL,
        source_table_and_record_uid TEXT NOT NULL,
        action_burst_story_uid INTEGER NULL,
        FOREIGN KEY (actor_source_entity_uid) REFERENCES entity_master_profiles(entity_master_uid),
        FOREIGN KEY (actor_target_entity_uid) REFERENCES entity_master_profiles(entity_master_uid),
        FOREIGN KEY (action_burst_story_uid) REFERENCES forensic_action_burst_stories(story_uid)
    );

    CREATE TABLE IF NOT EXISTS forensic_action_burst_stories (
        story_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        story_signature_code TEXT NOT NULL,
        severity_level TEXT NOT NULL,
        burst_start_utc_iso TEXT NOT NULL,
        burst_end_utc_iso TEXT NOT NULL,
        burst_duration_seconds REAL NOT NULL,
        involved_entity_uids_json TEXT NOT NULL,
        involved_timeline_event_uids TEXT NOT NULL,
        automated_courtroom_narrative TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_timeline_ts_ns ON unified_super_timeline(timestamp_utc_ns ASC, timeline_event_uid ASC);
    CREATE INDEX IF NOT EXISTS idx_edge_source ON entity_graph_edges_ledger(source_entity_uid);
    CREATE INDEX IF NOT EXISTS idx_edge_target ON entity_graph_edges_ledger(target_entity_uid);
    """

    def export_case_database(
        self,
        db_path: str,
        entities: Optional[List[MasterEntityProfile]] = None,
        edges: Optional[List[GraphEdgeRecord]] = None,
        timeline_events: Optional[List[SuperTimelineEvent]] = None,
        stories: Optional[List[ActionBurstStoryRecord]] = None,
    ) -> str:
        """Exports Master Profiles, Graph Edges, Super-Timeline, and Action-Burst Stories to SQLite."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.executescript(self.SCHEMA_DDL)

        # 1. Insert Master Entity Profiles
        if entities:
            cur.executemany(
                """
                INSERT INTO entity_master_profiles (
                    entity_master_uid, entity_classification, canonical_display_name,
                    all_observed_names_json, tier1_hard_keys_json, phones_e164_json,
                    messaging_handles_json, bank_accounts_and_vpas_json,
                    crypto_addresses_and_uids_json, kyc_documents_and_biometrics_json,
                    linked_locations_and_addresses_json, risk_and_typology_flags_json,
                    deterministic_merge_proof_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        e.entity_master_uid,
                        e.entity_classification,
                        e.canonical_display_name,
                        e.all_observed_names_json,
                        e.tier1_hard_keys_json,
                        e.phones_e164_json,
                        e.messaging_handles_json,
                        e.bank_accounts_and_vpas_json,
                        e.crypto_addresses_and_uids_json,
                        e.kyc_documents_and_biometrics_json,
                        e.linked_locations_and_addresses_json,
                        e.risk_and_typology_flags_json,
                        e.deterministic_merge_proof_json,
                    )
                    for e in entities
                ],
            )

        # 2. Insert Graph Edges
        if edges:
            cur.executemany(
                """
                INSERT INTO entity_graph_edges_ledger (
                    graph_edge_uid, source_entity_uid, target_entity_uid, edge_verb,
                    interaction_count, total_fiat_value_inr, total_crypto_value_summary,
                    platforms_and_rails_json, has_deleted_or_hidden_evidence,
                    supporting_record_pointers_json, first_interaction_utc_iso,
                    last_interaction_utc_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        ed.graph_edge_uid,
                        ed.source_entity_uid,
                        ed.target_entity_uid,
                        ed.edge_verb,
                        ed.interaction_count,
                        ed.total_fiat_value_inr,
                        ed.total_crypto_value_summary,
                        ed.platforms_and_rails_json,
                        ed.has_deleted_or_hidden_evidence,
                        ed.supporting_record_pointers_json,
                        ed.first_interaction_utc_iso,
                        ed.last_interaction_utc_iso,
                    )
                    for ed in edges
                ],
            )

        # 3. Insert Action-Burst Stories (before timeline so foreign keys resolve if enforced)
        if stories:
            cur.executemany(
                """
                INSERT INTO forensic_action_burst_stories (
                    story_uid, story_signature_code, severity_level, burst_start_utc_iso,
                    burst_end_utc_iso, burst_duration_seconds, involved_entity_uids_json,
                    involved_timeline_event_uids, automated_courtroom_narrative
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        s.story_uid,
                        s.story_signature_code,
                        s.severity_level,
                        s.burst_start_utc_iso,
                        s.burst_end_utc_iso,
                        s.burst_duration_seconds,
                        s.involved_entity_uids_json,
                        s.involved_timeline_event_uids,
                        s.automated_courtroom_narrative,
                    )
                    for s in stories
                ],
            )

        # 4. Insert Super-Timeline Events
        if timeline_events:
            cur.executemany(
                """
                INSERT INTO unified_super_timeline (
                    timeline_event_uid, timestamp_utc_ns, timestamp_utc_iso,
                    timestamp_ist_iso, timestamp_type_and_precision,
                    clock_integrity_status, originating_phase_and_module,
                    artifact_domain_category, app_package_or_subsystem,
                    android_user_profile_or_locality, actor_source_entity_uid,
                    actor_target_entity_uid, event_title_badge, event_detailed_summary,
                    recovery_classification, source_vfs_file_id,
                    source_table_and_record_uid, action_burst_story_uid
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        t.timeline_event_uid,
                        t.timestamp_utc_ns,
                        t.timestamp_utc_iso,
                        t.timestamp_ist_iso,
                        t.timestamp_type_and_precision,
                        t.clock_integrity_status,
                        t.originating_phase_and_module,
                        t.artifact_domain_category,
                        t.app_package_or_subsystem,
                        t.android_user_profile_or_locality,
                        t.actor_source_entity_uid,
                        t.actor_target_entity_uid,
                        t.event_title_badge,
                        t.event_detailed_summary,
                        t.recovery_classification,
                        t.source_vfs_file_id,
                        t.source_table_and_record_uid,
                        t.action_burst_story_uid,
                    )
                    for t in timeline_events
                ],
            )

        conn.commit()
        conn.close()
        return db_path
