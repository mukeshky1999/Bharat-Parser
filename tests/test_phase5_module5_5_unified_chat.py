"""
Test Suite: Phase 5, Module 5.5 — Indian Regional Chat Apps, Covert Dead-Drops, Marketplace/Betting & Unified Correlator.
Covers:
  - Sub-Engine 5.5A: Truecaller IM, Flash messages, and Global Unsaved Caller-ID Cache.
  - Sub-Engine 5.5B: Indian Regional Social & Messaging (ShareChat, Moj, JioChat, Zoho Arattai).
  - Sub-Engine 5.5C: Marketplace Fraud Initiation (OLX India, IndiaMART).
  - Sub-Engine 5.5D: Illegal Betting LiveChat Widgets & Cloud Dead-Drops (Google Keep, Docs, Email Drafts).
  - Sub-Engine 5.5E: Master Cross-Platform Actor Resolution & Conversation Stitching Engine.
Complies with Phase 5 Module 5.5 Specification and AGENTS.md Constitution.
"""

import json
import os
from pathlib import Path
import sqlite3
import pytest

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.unified_chat.models import (
    SpecialChannelCategory,
    UnifiedActorRole,
    TruecallerEnrichmentRecord,
    RegionalMarketplaceRecord,
    UnifiedActorRecord,
    StitchedTimelineEventRecord,
    canonical_phone_10_and_e164,
)
from src.unified_chat.truecaller_decoder import TruecallerDecoder
from src.unified_chat.covert_and_betting_decoder import CovertAndBettingDecoder
from src.unified_chat.correlator import UnifiedConversationCorrelator
from src.unified_chat.engine import RegionalCovertUnifiedChatEngine


# ---------------------------------------------------------------------------
# Test 1: Truecaller Unsaved-Number Unmasking Test
# ---------------------------------------------------------------------------

def test_truecaller_unsaved_number_unmasking():
    """
    Test 1: Acceptance Test 1 from Spec Section 9.1.
    Verifies that Sub-Engine 5.5A extracts cached Truecaller Caller-ID lookups
    for numbers not in the device's native contacts, unmasking 'Rakesh Mule Coordinator'
    with spam_score = 85.
    """
    base_dir = Path("./.workspace_tmp/test_tc_sandbox")
    dbs_dir = base_dir / "databases"
    dbs_dir.mkdir(parents=True, exist_ok=True)

    tc_db_path = dbs_dir / "tc.db"
    if tc_db_path.exists():
        tc_db_path.unlink()

    # 1. Setup Truecaller tc.db
    conn = sqlite3.connect(tc_db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE aggregated_contact (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            normalized_number TEXT NOT NULL,
            contact_name TEXT NOT NULL,
            spam_score INTEGER DEFAULT 0,
            carrier TEXT,
            email TEXT,
            city_area TEXT
        )
    """)
    cur.execute("""
        INSERT INTO aggregated_contact (normalized_number, contact_name, spam_score, carrier, email, city_area)
        VALUES ('+919876543210', 'Rakesh Mule Coordinator', 85, 'Airtel — Delhi', 'rakesh.mule@gmail.com', 'Delhi')
    """)
    conn.commit()
    conn.close()

    # 2. Known saved contacts (does NOT include +919876543210)
    device_contacts_e164 = {"+919111111111", "+919222222222"}

    # 3. Decode Truecaller cache
    decoder = TruecallerDecoder()
    enrich_records = decoder.decode_truecaller_database(
        str(tc_db_path),
        device_contacts_e164=device_contacts_e164,
    )

    assert len(enrich_records) == 1
    rec = enrich_records[0]
    assert rec.normalized_e164_phone == "+919876543210"
    assert rec.subscriber_10_tail == "9876543210"
    assert rec.tc_resolved_name == "Rakesh Mule Coordinator"
    assert rec.is_saved_in_device_contacts == 0
    assert rec.tc_spam_score == 85
    assert "Airtel" in (rec.tc_carrier_and_circle or "")

    # 4. Correlate with UnifiedActorResolver
    correlator = UnifiedConversationCorrelator()
    correlator.register_truecaller_cache(enrich_records)

    raw_actor_identities = [
        {
            "platform": "CELLULAR_CALL",
            "phone_e164": "+919876543210",
            "display_name": None,
        }
    ]
    actors = correlator.resolve_actors(raw_actor_identities)
    assert len(actors) == 1
    actor = actors[0]
    assert actor.truecaller_unmasked_name == "Rakesh Mule Coordinator"
    assert actor.primary_display_name == "Rakesh Mule Coordinator"


# ---------------------------------------------------------------------------
# Test 2: Betting app_webview LiveChat Widget & UTR Bridge Test
# ---------------------------------------------------------------------------

def test_betting_webview_livechat_and_utr_bridge():
    """
    Test 2: Acceptance Test 2 from Spec Section 9.2.
    Scans betting app webview Simple Cache for LiveChat/Tawk.to JSON transcript,
    extracting bookie VPA (bookie77@ybl) and 12-digit UPI UTR (630914829104).
    """
    base_dir = Path("./.workspace_tmp/test_betting_sandbox")
    cache_dir = base_dir / "cache" / "Cache_Data"
    cache_dir.mkdir(parents=True, exist_ok=True)

    cache_file = cache_dir / "livechat_c01_0"
    chat_payload = {
        "url": "https://secure.livechatinc.com/licence/12345/v2/chat/transcripts",
        "app": "Lotus365 WebView",
        "messages": [
            {
                "author": "Deposit Agent 04",
                "text": "Welcome to Lotus365! Deposit to VPA bookie77@ybl to get chips immediately.",
                "timestamp": 1700000000000,
            },
            {
                "author": "Player_991",
                "text": "Done UTR 630914829104 from PhonePe. Please credit 25000 points.",
                "timestamp": 1700000100000,
            }
        ]
    }
    cache_file.write_text(json.dumps(chat_payload), encoding="utf-8")

    decoder = CovertAndBettingDecoder()
    records = decoder.decode_webview_livechats(str(base_dir), app_instance_id=2, source_vfs_file_id=702)

    assert len(records) >= 1
    utr_rec = [r for r in records if "630914829104" in r.message_or_mutation_text][0]
    assert utr_rec.channel_category == SpecialChannelCategory.BETTING_BOOKIE_LIVECHAT
    assert utr_rec.app_name == "Lotus365 WebView"
    assert "630914829104" in (utr_rec.extracted_utr_vpa_or_phone_json or "")
    assert "bookie77@ybl" in (utr_rec.extracted_utr_vpa_or_phone_json or "")


# ---------------------------------------------------------------------------
# Test 3: Shared Google Keep / Email Draft Dead-Drop WAL Recovery Test
# ---------------------------------------------------------------------------

def test_google_keep_deaddrop_wal_recovery():
    """
    Test 3: Acceptance Test 3 from Spec Section 9.3.
    Reconstructs collaborative Google Keep dead-drop note (sharing = handler@proton.me),
    recovering pre-deletion text 'Deliver 20 Lakh to Sector 15 at 6 PM' from uncheckpointed WAL frames.
    """
    base_dir = Path("./.workspace_tmp/test_keep_sandbox")
    dbs_dir = base_dir / "databases"
    dbs_dir.mkdir(parents=True, exist_ok=True)

    keep_db_path = dbs_dir / "keep.db"
    if keep_db_path.exists():
        keep_db_path.unlink()

    conn = sqlite3.connect(keep_db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode = WAL")
    cur.execute("""
        CREATE TABLE tree_entity (
            _id INTEGER PRIMARY KEY,
            title TEXT,
            created_time INTEGER,
            last_modified INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE list_item (
            _id INTEGER PRIMARY KEY,
            tree_entity_id INTEGER NOT NULL,
            text TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE sharing (
            _id INTEGER PRIMARY KEY,
            tree_entity_id INTEGER NOT NULL,
            email TEXT NOT NULL
        )
    """)

    cur.execute("INSERT INTO tree_entity VALUES (1, 'DeadDrop Secret', 1700000000000, 1700000000000)")
    cur.execute("INSERT INTO sharing VALUES (1, 1, 'handler@proton.me')")

    # Step 3a: Write original dead-drop instruction
    cur.execute("INSERT INTO list_item VALUES (1, 1, 'Deliver 20 Lakh to Sector 15 at 6 PM')")
    conn.commit()

    # Step 3b: Overwrite in place to innocent text
    cur.execute("UPDATE list_item SET text = 'Shopping list: milk, bread' WHERE _id = 1")
    conn.commit()

    # Preserve uncheckpointed WAL bytes before conn.close() unlinks the WAL on Windows
    wal_path = Path(str(keep_db_path) + "-wal")
    wal_bytes = wal_path.read_bytes() if wal_path.exists() else None

    conn.close()

    # Re-establish authentic forensic artifact state (uncheckpointed WAL on disk)
    if wal_bytes and not wal_path.exists():
        wal_path.write_bytes(wal_bytes)

    decoder = CovertAndBettingDecoder()
    records = decoder.decode_google_keep_database(str(keep_db_path), app_instance_id=3, source_vfs_file_id=703)

    assert len(records) >= 1
    # Check that collaborator email was identified
    assert any("handler@proton.me" in (r.collaborators_or_peers_json or "") for r in records)
    # Check that overwritten dead-drop text was recovered with HISTORICAL_COMMITTED_RECORD
    recovered_rec = [r for r in records if "Deliver 20 Lakh" in r.message_or_mutation_text][0]
    assert recovered_rec.channel_category == SpecialChannelCategory.GOOGLE_DOCS_KEEP_DEADDROP
    assert recovered_rec.recovery_classification == ResidualConfidence.HISTORICAL_COMMITTED_RECORD


# ---------------------------------------------------------------------------
# Test 4: 5-App Cross-Platform Conversation Stitching & Master Export Test
# ---------------------------------------------------------------------------

def test_5_app_cross_platform_conversation_stitching_and_master_export():
    """
    Test 4: Acceptance Test 4 from Spec Section 9.4.
    Simulates a 4-step multi-app communication sequence:
      14:00 - OLX Chat (+919876543210): 'Call me on WhatsApp 9876543210'
      14:05 - WhatsApp (919876543210@s.whatsapp.net): 'Add my Session ID 05a1b2c3...'
      14:10 - Session (05a1b2c3...): 'Send Rs 50,000 to my PhonePe 9876543210@ybl'
      14:15 - PhonePe (9876543210@ybl, CBS Name 'VIKRAM SINGH'): '₹50,000.00 Sent (UTR 630914829104)'
    Verifies that UnifiedConversationCorrelator fuses all identities into one UnifiedActorRecord,
    stitches the chronological timeline with is_platform_switch_hop = 1 at transitions,
    and exports all 4 tables to regional_covert_and_unified_chat_engine.sqlite.
    """
    export_db_path = Path("./.workspace_tmp/regional_covert_and_unified_chat_engine.sqlite")
    if export_db_path.exists():
        export_db_path.unlink()

    # 1. Phone normalizer check
    e164, tail10 = canonical_phone_10_and_e164("919876543210@s.whatsapp.net")
    assert e164 == "+919876543210"
    assert tail10 == "9876543210"

    e164_b, tail10_b = canonical_phone_10_and_e164("098765 43210")
    assert e164_b == "+919876543210"
    assert tail10_b == "9876543210"

    # 2. Multi-App Events Stream
    session_id_sample = "05a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef01"
    events_stream = [
        {
            "platform": "OLX_CHAT",
            "phone_raw": "+919876543210",
            "sender_handle": "+919876543210",
            "text": "Call me on WhatsApp 9876543210",
            "timestamp_ns": 1700000000000000000,
            "timestamp_iso": "2023-11-14T14:00:00.000000Z",
            "direction": "INCOMING",
        },
        {
            "platform": "WHATSAPP",
            "phone_raw": "919876543210@s.whatsapp.net",
            "sender_handle": "919876543210@s.whatsapp.net",
            "text": f"Add my Session ID {session_id_sample}",
            "timestamp_ns": 1700000300000000000,
            "timestamp_iso": "2023-11-14T14:05:00.000000Z",
            "direction": "INCOMING",
        },
        {
            "platform": "SESSION",
            "session_id": session_id_sample,
            "sender_handle": session_id_sample,
            "text": "Send Rs 50,000 to my PhonePe 9876543210@ybl",
            "timestamp_ns": 1700000600000000000,
            "timestamp_iso": "2023-11-14T14:10:00.000000Z",
            "direction": "INCOMING",
        },
        {
            "platform": "PHONEPE_UPI_TX",
            "upi_vpa": "9876543210@ybl",
            "verified_cbs_name": "VIKRAM SINGH",
            "sender_handle": "9876543210@ybl",
            "text": "₹50,000.00 Sent (UTR 630914829104)",
            "timestamp_ns": 1700000900000000000,
            "timestamp_iso": "2023-11-14T14:15:00.000000Z",
            "direction": "FINANCIAL_TRANSFER",
        },
    ]

    correlator = UnifiedConversationCorrelator()
    actors, stitched_timeline = correlator.fuse_and_stitch(events_stream)

    # Validate Unified Actor Fusion
    assert len(actors) == 1
    actor = actors[0]
    assert actor.primary_display_name == "VIKRAM SINGH"
    assert actor.verified_bank_cbs_name == "VIKRAM SINGH"
    assert "+919876543210" in (actor.phone_numbers_e164_json or "")
    assert "919876543210@s.whatsapp.net" in (actor.whatsapp_jids_and_lids_json or "")
    assert session_id_sample in (actor.signal_and_opsec_handles_json or "")
    assert "9876543210@ybl" in (actor.linked_upi_vpas_and_banks_json or "")

    # Validate Stitched Timeline Hops
    assert len(stitched_timeline) == 4
    # Event 0: First event in timeline (no switch from prior)
    assert stitched_timeline[0].source_platform == "OLX_CHAT"
    assert stitched_timeline[0].is_platform_switch_hop == 0

    # Event 1: Jumped from OLX_CHAT to WHATSAPP
    assert stitched_timeline[1].source_platform == "WHATSAPP"
    assert stitched_timeline[1].is_platform_switch_hop == 1

    # Event 2: Jumped from WHATSAPP to SESSION
    assert stitched_timeline[2].source_platform == "SESSION"
    assert stitched_timeline[2].is_platform_switch_hop == 1

    # Event 3: Jumped from SESSION to PHONEPE_UPI_TX
    assert stitched_timeline[3].source_platform == "PHONEPE_UPI_TX"
    assert stitched_timeline[3].is_platform_switch_hop == 1

    # Master SQLite Export Validation
    engine = RegionalCovertUnifiedChatEngine()
    engine.export_to_sqlite(
        truecaller_records=[],
        regional_records=[],
        actors=actors,
        stitched_timeline=stitched_timeline,
        output_db_path=str(export_db_path),
    )

    assert export_db_path.exists()
    conn_out = sqlite3.connect(export_db_path)
    cur_out = conn_out.cursor()

    cur_out.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur_out.fetchall()}
    assert "truecaller_global_enrichment_cache" in tables
    assert "regional_marketplace_betting_and_deaddrop_ledger" in tables
    assert "unified_cross_platform_actors" in tables
    assert "unified_stitched_conversation_timeline" in tables

    cur_out.execute("SELECT COUNT(*) FROM unified_cross_platform_actors")
    assert cur_out.fetchone()[0] == 1

    cur_out.execute("SELECT COUNT(*) FROM unified_stitched_conversation_timeline")
    assert cur_out.fetchone()[0] == 4

    conn_out.close()
