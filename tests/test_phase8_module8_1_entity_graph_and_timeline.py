"""
Acceptance Test Suite for Phase 8, Module 8.1:
The Cross-Phase Entity Resolution, Master Identity Graph & Unified Super-Timeline Engine.

Test Scope (5 Acceptance Tests):
1. test_nontransitive_weak_key_guardrail:
   Enforces Two-Tier Key Hierarchy (Tier 1 Hard Keys vs Tier 2 Soft Attributes);
   proves that two contacts sharing soft display name 'Rahul' are NOT transitively merged,
   while hard phone/VPA keys merge correctly.
2. test_six_phase_mule_identity_unification:
   Fuses 5-6 fragmented observations across Phases 3, 4, 5, 6, and 7 into a single Master Entity Profile
   via deterministic join keys and in-chat handoff edges with full audit trail.
3. test_typed_directed_graph_edges_synthesis:
   Synthesizes typed directed edges (COMMUNICATED_WITH, TRANSFERRED_FIAT_TO, TRANSFERRED_CRYPTO_TO)
   with aggregated metrics, platform tags, and deleted/hidden evidence tracking.
4. test_nanosecond_super_timeline_and_action_burst_story_detection:
   Normalizes events to 64-bit UTC nanoseconds with precomputed IST (+05:30) timestamps;
   slides 60-second window to detect ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW
   and PAYMENT_SCREENSHOT_PROOF_TO_HANDLER action bursts.
5. test_entity_graph_and_timeline_master_sqlite_export:
   Validates export of all 4 canonical tables and indexes into entity_graph_and_super_timeline.sqlite.
"""

import os
import sqlite3
import pytest

from src.entity_and_timeline.models import (
    EntityClassification,
    GraphEdgeVerb,
    ArtifactDomainCategory,
    ClockIntegrityStatus,
    ActionBurstSignature,
    ActionBurstSeverity,
    ResidualRecoveryConfidence,
    AtomicObservation,
    MasterEntityProfile,
    GraphEdgeRecord,
    SuperTimelineEvent,
    ActionBurstStoryRecord,
)
from src.entity_and_timeline.entity_resolver import ConstrainedEntityResolver
from src.entity_and_timeline.edge_synthesizer import GraphEdgeSynthesizer
from src.entity_and_timeline.super_timeline import SuperTimelineNormalizer
from src.entity_and_timeline.action_burst_correlator import ActionBurstCorrelator
from src.entity_and_timeline.engine import EntityGraphAndTimelineEngine


def test_nontransitive_weak_key_guardrail():
    """Acceptance Test 1: Prevents transitive merging on soft keys (No 'Rahul' Snowballing)."""
    resolver = ConstrainedEntityResolver()

    # Observation 1: Contact 1 with phone +919811111111 and display_name "Rahul"
    obs1 = AtomicObservation(
        observation_id="contact_1",
        hard_keys={"phone:+919811111111"},
        soft_attributes={"display_name": "Rahul", "source": "contacts2.db"},
        observed_name="Rahul",
        source_phase_module="PHASE_1_MOD_1_3",
        source_table_record="contacts2.db:101",
    )

    # Observation 2: WhatsApp LID mapping for +919811111111
    obs2 = AtomicObservation(
        observation_id="wa_lid_1",
        hard_keys={"phone:+919811111111", "wa_lid:164829104928172@lid"},
        soft_attributes={"wa_push_name": "~ Rahul V."},
        observed_name="~ Rahul V.",
        source_phase_module="PHASE_5_MOD_5_1",
        source_table_record="msgstore.db:jid_map:42",
    )

    # Observation 3: PhonePe VPA 9811111111@ybl with CBS KYC Name "RAHUL VERMA"
    obs3 = AtomicObservation(
        observation_id="phonepe_vpa_1",
        hard_keys={"phone:+919811111111", "vpa:9811111111@ybl"},
        soft_attributes={"cbs_kyc_name": "RAHUL VERMA"},
        observed_name="RAHUL VERMA",
        source_phase_module="PHASE_3_MOD_3_1",
        source_table_record="paisa.db:vpa:88",
    )

    # Observation 4: Contact 2 with completely different phone +919822222222, but ALSO named "Rahul"
    obs4 = AtomicObservation(
        observation_id="contact_2",
        hard_keys={"phone:+919822222222"},
        soft_attributes={"display_name": "Rahul", "source": "contacts2.db"},
        observed_name="Rahul",
        source_phase_module="PHASE_1_MOD_1_3",
        source_table_record="contacts2.db:102",
    )

    entities = resolver.resolve_entities([obs1, obs2, obs3, obs4])

    # Must produce exactly 2 distinct entities
    assert len(entities) == 2

    # Find the entity containing +919811111111
    e1 = next(e for e in entities if "phone_tail10:9811111111" in e.tier1_hard_keys)
    e2 = next(e for e in entities if "phone_tail10:9822222222" in e.tier1_hard_keys)

    # Verify Entity 1 fused all 3 observations sharing the hard phone key
    assert "vpa:9811111111@ybl" in e1.tier1_hard_keys
    assert "wa_lid:164829104928172@lid" in e1.tier1_hard_keys
    assert e1.canonical_display_name == "RAHUL VERMA"  # Prioritized verified CBS name

    # Verify Entity 2 remains isolated despite sharing soft name "Rahul"
    assert "phone_tail10:9822222222" in e2.tier1_hard_keys
    assert "vpa:9811111111@ybl" not in e2.tier1_hard_keys
    assert e1.entity_master_uid != e2.entity_master_uid


def test_six_phase_mule_identity_unification():
    """Acceptance Test 2: Unifies 5-6 multi-phase observations into a single Master Entity Profile."""
    resolver = ConstrainedEntityResolver()

    # 1. Phase 3: PhonePe transfer to VPA
    obs_p3 = AtomicObservation(
        observation_id="p3_upi",
        hard_keys={"phone:+919876543210", "vpa:9876543210@okaxis"},
        observed_name="Vikram Bhai",
        source_phase_module="PHASE_3_MOD_3_1",
        source_table_record="phonepe.db:tx:99",
    )

    # 2. Phase 4.2: Binance P2P Seller linking VPA to Binance UID and PAN
    obs_p4 = AtomicObservation(
        observation_id="p4_p2p",
        hard_keys={"vpa:9876543210@okaxis", "cex:binance:482910482", "pan:abcps1234k"},
        observed_name="VIKRAM SINGH",
        source_phase_module="PHASE_4_MOD_4_2",
        source_table_record="binance_p2p:orders:412",
    )

    # 3. Phase 5.1 & In-Chat Handoff: WhatsApp chat sender with Tron address handoff
    obs_p5 = AtomicObservation(
        observation_id="p5_chat",
        hard_keys={"phone:+919876543210", "crypto:tron:txyzopyrdj2d9xrtbg411xzz3km5vkaebf"},
        observed_name="Vikram Singh",
        source_phase_module="PHASE_5_MOD_5_1",
        source_table_record="msgstore.db:messages:8012",
        handoff_proof="Chat msg #8012: Pay my Tron wallet TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
    )

    # 4. Phase 6.4: Blinkit delivery address with recipient phone
    obs_p6 = AtomicObservation(
        observation_id="p6_blinkit",
        hard_keys={"phone:+919876543210"},
        soft_attributes={"delivery_address": "Flat 1404, Tower B2, Gomti Nagar, Lucknow"},
        observed_name="Vikram",
        source_phase_module="PHASE_6_MOD_6_4",
        source_table_record="blinkit.db:addresses:14",
    )

    # 5. Phase 7.4: PAN card photo OCR
    obs_p7 = AtomicObservation(
        observation_id="p7_pan_ocr",
        hard_keys={"pan:abcps1234k"},
        soft_attributes={"father_name": "RAMESH SINGH", "dob": "15/08/1990"},
        observed_name="VIKRAM SINGH",
        source_phase_module="PHASE_7_MOD_7_4",
        source_table_record="ocr_index:kyc:501",
    )

    entities = resolver.resolve_entities([obs_p3, obs_p4, obs_p5, obs_p6, obs_p7])

    assert len(entities) == 1
    master_profile = entities[0]

    assert master_profile.canonical_display_name == "VIKRAM SINGH"
    assert "phone_tail10:9876543210" in master_profile.tier1_hard_keys
    assert "vpa:9876543210@okaxis" in master_profile.tier1_hard_keys
    assert "cex:binance:482910482" in master_profile.tier1_hard_keys
    assert "pan:abcps1234k" in master_profile.tier1_hard_keys
    assert "crypto:tron:txyzopyrdj2d9xrtbg411xzz3km5vkaebf" in master_profile.tier1_hard_keys
    assert len(master_profile.deterministic_merge_proof) >= 4


def test_typed_directed_graph_edges_synthesis():
    """Acceptance Test 3: Constructs typed directed relationship edges across entities."""
    synthesizer = GraphEdgeSynthesizer()

    # Create dummy entities
    actor_a = MasterEntityProfile(
        entity_master_uid=1,
        canonical_display_name="Device Owner (Self)",
        entity_classification=EntityClassification.DEVICE_OWNER_SELF.value,
    )
    actor_b = MasterEntityProfile(
        entity_master_uid=2,
        canonical_display_name="Vikram Singh (Accomplice)",
        entity_classification=EntityClassification.EXTERNAL_PERSON_ACTOR.value,
    )

    # Interactions: WhatsApp chat + Telegram Secret chat with deleted message recovered
    comm_interactions = [
        {"platform": "WhatsApp", "is_deleted": False, "utc_iso": "2026-11-05T14:00:00Z"},
        {"platform": "Telegram Secret", "is_deleted": True, "utc_iso": "2026-11-05T14:15:00Z"},
        {"platform": "WhatsApp", "is_deleted": False, "utc_iso": "2026-11-05T14:30:00Z"},
    ]
    edge_comm = synthesizer.create_communication_edge(
        source_uid=1,
        target_uid=2,
        interactions=comm_interactions,
    )
    assert edge_comm.edge_verb == GraphEdgeVerb.COMMUNICATED_WITH.value
    assert edge_comm.interaction_count == 3
    assert edge_comm.has_deleted_or_hidden_evidence == 1
    assert "Telegram Secret" in edge_comm.platforms_and_rails
    assert "WhatsApp" in edge_comm.platforms_and_rails

    # Financial Transfer: ₹95,000 via UPI
    transfers = [
        {"amount_inr": 45000.0, "rail": "UPI", "utr": "630914829101"},
        {"amount_inr": 50000.0, "rail": "UPI", "utr": "630914829102"},
    ]
    edge_fiat = synthesizer.create_fiat_transfer_edge(
        source_uid=1,
        target_uid=2,
        transfers=transfers,
    )
    assert edge_fiat.edge_verb == GraphEdgeVerb.TRANSFERRED_FIAT_TO.value
    assert edge_fiat.total_fiat_value_inr == 95000.0
    assert edge_fiat.interaction_count == 2
    assert "UPI" in edge_fiat.platforms_and_rails


def test_nanosecond_super_timeline_and_action_burst_story_detection():
    """Acceptance Test 4: 64-bit UTC nanoseconds, IST (+05:30) precomputation & 60-second action burst detection."""
    normalizer = SuperTimelineNormalizer()
    correlator = ActionBurstCorrelator()

    # 4 events spanning 22 seconds on 2026-11-05 from 14:10:00.120 to 14:10:22.000 UTC
    # 2026-11-05T14:10:00.120000000Z in Unix nanoseconds = 1793887800120000000
    base_ns = 1793887800120000000

    e1 = normalizer.create_event(
        timestamp_utc_ns=base_ns,  # 14:10:00.120
        originating_phase_and_module="PHASE_6_MOD_6_2",
        artifact_domain_category=ArtifactDomainCategory.SCREEN_LOCK_BIOMETRIC.value,
        app_package_or_subsystem="Android Keyguard",
        event_title_badge="Device Screen Unlocked (KEYGUARD_HIDDEN)",
        event_detailed_summary="Phone unlocked via Face Unlock / Fingerprint while held portrait.",
        source_vfs_file_id=10,
        source_table_and_record_uid="system_events:41",
    )
    assert e1.timestamp_utc_ns == base_ns
    assert "IST (+05:30)" in e1.timestamp_ist_iso
    assert "19:40:00" in e1.timestamp_ist_iso  # 14:10 UTC = 19:40 IST

    e2 = normalizer.create_event(
        timestamp_utc_ns=base_ns + int(2.33 * 1e9),  # 14:10:02.450
        originating_phase_and_module="PHASE_6_MOD_6_2",
        artifact_domain_category=ArtifactDomainCategory.OS_APP_LIFECYCLE.value,
        app_package_or_subsystem="com.phonepe.app",
        event_title_badge="PhonePe Foreground Active",
        event_detailed_summary="User brought PhonePe to foreground focus.",
        source_vfs_file_id=11,
        source_table_and_record_uid="usagestats:events:890",
    )

    e3 = normalizer.create_event(
        timestamp_utc_ns=base_ns + int(14.77 * 1e9),  # 14:10:14.890
        originating_phase_and_module="PHASE_3_MOD_3_1",
        artifact_domain_category=ArtifactDomainCategory.FIAT_UPI_BANK_TX.value,
        app_package_or_subsystem="com.phonepe.app",
        event_title_badge="UPI Outflow ₹95,000.00",
        event_detailed_summary="Outbound UPI payment ₹95,000 to 9876543210@okaxis (UTR: 630914829104)",
        source_vfs_file_id=12,
        source_table_and_record_uid="paisa.db:transactions:901",
    )

    e4 = normalizer.create_event(
        timestamp_utc_ns=base_ns + int(19.18 * 1e9),  # 14:10:19.300
        originating_phase_and_module="PHASE_7_MOD_7_1",
        artifact_domain_category=ArtifactDomainCategory.MEDIA_SNAPSHOT_OCR_QR.value,
        app_package_or_subsystem="com.phonepe.app",
        event_title_badge="Screenshot Captured",
        event_detailed_summary="Payment success receipt screenshot Screenshot_20261105-194019_PhonePe.jpg",
        source_vfs_file_id=13,
        source_table_and_record_uid="media_provenance:88",
    )

    e5 = normalizer.create_event(
        timestamp_utc_ns=base_ns + int(21.88 * 1e9),  # 14:10:22.000
        originating_phase_and_module="PHASE_5_MOD_5_2",
        artifact_domain_category=ArtifactDomainCategory.MESSAGING_CHAT.value,
        app_package_or_subsystem="org.telegram.messenger",
        event_title_badge="Screenshot Sent on Telegram",
        event_detailed_summary="Sent receipt image to handler @vikram_hawala (chat_id: 556677)",
        source_vfs_file_id=14,
        source_table_and_record_uid="cache4.db:messages:1402",
    )

    timeline_events = [e1, e2, e3, e4, e5]

    # Verify monotonic ordering
    for i in range(len(timeline_events) - 1):
        assert timeline_events[i].timestamp_utc_ns < timeline_events[i + 1].timestamp_utc_ns

    # Detect 60-second Action Bursts
    stories = correlator.detect_action_bursts(timeline_events)
    assert len(stories) >= 1

    signatures = {s.story_signature_code for s in stories}
    assert ActionBurstSignature.ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW.value in signatures or \
           ActionBurstSignature.PAYMENT_SCREENSHOT_PROOF_TO_HANDLER.value in signatures

    story = stories[0]
    assert story.severity_level == ActionBurstSeverity.CRITICAL_SMOKING_GUN.value
    assert story.burst_duration_seconds <= 60.0
    assert len(story.automated_courtroom_narrative) > 50


def test_entity_graph_and_timeline_master_sqlite_export():
    """Acceptance Test 5: Verify SQLite export into entity_graph_and_super_timeline.sqlite across 4 tables."""
    db_path = os.path.join(".", ".workspace_tmp", "entity_graph_and_super_timeline.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    entity_records = [
        MasterEntityProfile(
            entity_master_uid=1,
            entity_classification=EntityClassification.EXTERNAL_PERSON_ACTOR.value,
            canonical_display_name="VIKRAM SINGH",
            all_observed_names_json='{"bank_cbs": "VIKRAM SINGH", "contacts": "Vikram Bhai"}',
            tier1_hard_keys_json='["phone_tail10:9876543210", "vpa:9876543210@okaxis", "pan:abcps1234k"]',
            phones_e164_json='["+919876543210"]',
            messaging_handles_json='["wa_lid:164829104928172@lid"]',
            bank_accounts_and_vpas_json='["9876543210@okaxis"]',
            crypto_addresses_and_uids_json='["cex:binance:482910482"]',
            kyc_documents_and_biometrics_json='["ABCPS1234K"]',
            linked_locations_and_addresses_json='["Flat 1404, Tower B2"]',
            risk_and_typology_flags_json='["MULE_PASS_THROUGH_ACCOUNT"]',
            deterministic_merge_proof_json='["phone:+919876543210 joins wa_lid and vpa"]',
        )
    ]

    edge_records = [
        GraphEdgeRecord(
            graph_edge_uid=1,
            source_entity_uid=1,
            target_entity_uid=2,
            edge_verb=GraphEdgeVerb.TRANSFERRED_FIAT_TO.value,
            interaction_count=2,
            total_fiat_value_inr=95000.0,
            total_crypto_value_summary=None,
            platforms_and_rails_json='["PhonePe UPI"]',
            has_deleted_or_hidden_evidence=0,
            supporting_record_pointers_json='["paisa.db:transactions:901"]',
            first_interaction_utc_iso="2026-11-05T14:10:14.890000000Z",
            last_interaction_utc_iso="2026-11-05T14:10:14.890000000Z",
        )
    ]

    timeline_records = [
        SuperTimelineEvent(
            timeline_event_uid=1,
            timestamp_utc_ns=1793887800120000000,
            timestamp_utc_iso="2026-11-05T14:10:00.120000000Z",
            timestamp_ist_iso="2026-11-05 19:40:00.120 IST (+05:30)",
            timestamp_type_and_precision="OCCURRENCE_MS",
            clock_integrity_status=ClockIntegrityStatus.VERIFIED_NORMAL_CLOCK.value,
            originating_phase_and_module="PHASE_6_MOD_6_2",
            artifact_domain_category=ArtifactDomainCategory.SCREEN_LOCK_BIOMETRIC.value,
            app_package_or_subsystem="Android Keyguard",
            android_user_profile_or_locality="User 0 (Main)",
            actor_source_entity_uid=1,
            actor_target_entity_uid=None,
            event_title_badge="Device Screen Unlocked",
            event_detailed_summary="Phone unlocked via biometric match.",
            recovery_classification=ResidualRecoveryConfidence.ORIGINAL_RECORD.value,
            source_vfs_file_id=10,
            source_table_and_record_uid="system_events:41",
            action_burst_story_uid=None,
        )
    ]

    story_records = [
        ActionBurstStoryRecord(
            story_uid=1,
            story_signature_code=ActionBurstSignature.ACTIVE_HUMAN_AUTH_FINANCIAL_OR_CRYPTO_OUTFLOW.value,
            severity_level=ActionBurstSeverity.CRITICAL_SMOKING_GUN.value,
            burst_start_utc_iso="2026-11-05T14:10:00.120000000Z",
            burst_end_utc_iso="2026-11-05T14:10:22.000000000Z",
            burst_duration_seconds=21.88,
            involved_entity_uids_json="[1, 2]",
            involved_timeline_event_uids="[1, 2, 3, 4, 5]",
            automated_courtroom_narrative="Suspect physically unlocked the device and executed payment.",
        )
    ]

    engine = EntityGraphAndTimelineEngine()
    engine.export_case_database(
        db_path=db_path,
        entities=entity_records,
        edges=edge_records,
        timeline_events=timeline_records,
        stories=story_records,
    )

    assert os.path.exists(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM entity_master_profiles")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT count(*) FROM entity_graph_edges_ledger")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT count(*) FROM unified_super_timeline")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT count(*) FROM forensic_action_burst_stories")
    assert cur.fetchone()[0] == 1

    # Verify column schemas
    cur.execute("PRAGMA table_info(entity_master_profiles)")
    cols_ent = [r[1] for r in cur.fetchall()]
    assert "entity_master_uid" in cols_ent
    assert "canonical_display_name" in cols_ent
    assert "tier1_hard_keys_json" in cols_ent

    cur.execute("PRAGMA table_info(unified_super_timeline)")
    cols_time = [r[1] for r in cur.fetchall()]
    assert "timestamp_utc_ns" in cols_time
    assert "timestamp_ist_iso" in cols_time
    assert "clock_integrity_status" in cols_time

    cur.execute("PRAGMA table_info(forensic_action_burst_stories)")
    cols_story = [r[1] for r in cur.fetchall()]
    assert "story_signature_code" in cols_story
    assert "automated_courtroom_narrative" in cols_story

    conn.close()
