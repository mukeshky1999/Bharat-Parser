"""
Acceptance Test Suite for Phase 9, Module 9.2:
Unified Multi-App Chat Reconstructor, Edit/Revoke Redline Viewer
& Cross-Platform Conversation Hopping Timeline.

Test Scope (5 Acceptance Tests):
1. test_500k_message_fenwick_tree_variable_height_virtual_scroller:
   Verifies 500,000 variable-height messages (48px - 800px) handled by FenwickTreeVirtualScroller,
   O(log N) binary lifting lookup in < 1ms, and exact prefix sum updates upon DOM resize.
2. test_grapheme_aware_myers_diff_and_orphan_quoted_survivor:
   Validates Unicode grapheme-aware Myers edit script for edited WhatsApp/Signal messages
   producing [-strikethrough-] and [+underline+] tokens, and reconstructs deleted parent from message_quoted.
3. test_4source_identity_unmasking_and_hex_provenance_binding:
   Verifies 4-Source Identity Pill (@lid unmasking, Push Name, Truecaller, Bank CBS)
   and binds physical byte offset and VFS file ID for Pane 3 Hex Inspector synchronization.
4. test_cross_platform_conversation_hopping_follow_the_suspect:
   Validates multi-app timeline stitching across OLX -> Call -> WhatsApp -> Session -> PhonePe,
   verifying automated platform switch detection, time delta calculation, and handoff token identification.
5. test_audio_waveform_cache_and_db_persistence:
   Evaluates 64-sample normalized RMS peak envelope generation and SQLite persistence
   in chat_media_waveforms_and_transcripts_cache with word-synced timestamps.
"""

import os
import sqlite3
import time
import pytest

from src.chat_reconstructor_and_redline.models import (
    BubbleLifecycleState,
    DiffTokenType,
    RedlineDiffToken,
    RedlineDiffResult,
    FourSourceIdentityPill,
    AudioWaveformRecord,
    PlatformSwitchBanner,
    ForensicChatBubble,
    ThreadRosterItem,
)
from src.chat_reconstructor_and_redline.fenwick_scroller import FenwickTreeVirtualScroller
from src.chat_reconstructor_and_redline.myers_redline_engine import GraphemeAwareMyersDiffEngine
from src.chat_reconstructor_and_redline.audio_waveform_processor import AudioWaveformProcessor
from src.chat_reconstructor_and_redline.hopping_timeline_stitcher import CrossPlatformHoppingStitcher
from src.chat_reconstructor_and_redline.engine import UnifiedChatReconstructorEngine


def test_500k_message_fenwick_tree_variable_height_virtual_scroller():
    """Acceptance Test 1: Fenwick Tree (BIT) Prefix-Sum Virtual Scroller over 500,000 variable-height bubbles."""
    total_messages = 500_000
    # Create synthetic heights pattern: 48px, 96px, 160px, 320px, 640px cycling
    height_pattern = [48, 96, 160, 320, 640]
    heights = [height_pattern[i % len(height_pattern)] for i in range(total_messages)]

    scroller = FenwickTreeVirtualScroller.from_heights(heights)

    # 1. Total height matches mathematical sum
    expected_total_height = sum(height_pattern) * (total_messages // len(height_pattern))
    assert scroller.total_height() == expected_total_height

    # 2. Seek to Message #342,109 (1-indexed)
    target_idx = 342_109
    y_target_top = scroller.y_top(target_idx)
    assert y_target_top > 0

    # 3. Binary-lifting lookup from pixel scroll position must take < 1.0 ms
    t0 = time.perf_counter()
    first_visible = scroller.find_first_visible_index(scroll_top_px=y_target_top)
    lookup_duration_ms = (time.perf_counter() - t0) * 1000.0

    assert lookup_duration_ms < 1.0  # O(log N) binary lifting!
    assert first_visible == target_idx

    # 4. Visible viewport windowing
    viewport_height_px = 900
    i_first, i_last = scroller.compute_visible_range(
        scroll_top_px=y_target_top,
        viewport_height_px=viewport_height_px,
        overscan_buffer=10,
    )
    assert i_first <= target_idx <= i_last
    mounted_count = i_last - i_first + 1
    assert mounted_count < 100  # Strict DOM guardrail

    # 5. Dynamic ResizeObserver update in O(log N)
    # Message #342,109 expands by 120px (e.g., audio waveform mounts)
    delta_h = 120
    scroller.update_delta(index=target_idx, delta_h=delta_h)

    assert scroller.total_height() == expected_total_height + delta_h
    assert scroller.y_top(target_idx + 1) == y_target_top + heights[target_idx - 1] + delta_h


def test_grapheme_aware_myers_diff_and_orphan_quoted_survivor():
    """Acceptance Test 2: Unicode Grapheme-Aware Myers Redline Diff & Orphan Quoted-Reply Survivor."""
    diff_engine = GraphemeAwareMyersDiffEngine()

    # 1. Edited WhatsApp/Signal message: Revision 1 vs Revision 2
    old_text = "Send ₹50,000 to 9811223344@ybl"
    new_text = "Send ₹5,000 to 9988776655@ybl"

    diff_result = diff_engine.diff_messages(old_text=old_text, new_text=new_text)

    assert isinstance(diff_result, RedlineDiffResult)
    assert diff_result.has_financial_or_crypto_token is True

    # Assert rendered redline contains strikethrough deleted tokens and underlined inserted tokens
    assert "[-₹50,000-]" in diff_result.rendered_markup
    assert "[-9811223344@ybl-]" in diff_result.rendered_markup
    assert "[+₹5,000+]" in diff_result.rendered_markup
    assert "[+9988776655@ybl+]" in diff_result.rendered_markup
    assert "Send " in diff_result.rendered_markup or "Send" in diff_result.rendered_markup

    # 2. Orphan Quoted-Reply Reconstruction:
    # A revoked parent message was wiped from the message table, but survived in message_quoted
    quoted_row = {
        "quoted_parent_key_id": "3EB099AA7711",
        "quoted_sender_jid": "919876543210@s.whatsapp.net",
        "quoted_text_payload": "Meet at Gate 4 with cash",
        "parent_timestamp_utc_ns": 1762348800000000000,
        "reply_message_key_id": "3EB099BB8822",
        "source_vfs_file_id": 142,
        "physical_byte_offset": 84120,
    }

    reconstructed_bubble = diff_engine.reconstruct_orphan_quote_survivor(quoted_row)

    assert reconstructed_bubble.lifecycle_state in [
        BubbleLifecycleState.REVOKED_DELETED_FOR_EVERYONE_RECOVERED,
        BubbleLifecycleState.EXPIRED_DISAPPEARING_OR_VIEW_ONCE_SURVIVOR,
    ]
    assert "[RECONSTRUCTED FROM SURVIVING QUOTED REPLY]" in reconstructed_bubble.text_content
    assert "Meet at Gate 4 with cash" in reconstructed_bubble.text_content
    assert reconstructed_bubble.native_message_id == "3EB099AA7711"
    assert reconstructed_bubble.physical_byte_offset == 84120


def test_4source_identity_unmasking_and_hex_provenance_binding():
    """Acceptance Test 3: 4-Source Identity Unmasking Pill and Synchronized Pane 3 Hex Jump."""
    engine = UnifiedChatReconstructorEngine()

    # Incoming WhatsApp message from anonymous WhatsApp LID
    raw_bubble_data = {
        "bubble_uid": 1042,
        "native_message_id": "3EB0FFAA1122",
        "thread_id": "919876543210-161928374@g.us",
        "timestamp_utc_ns": 1762349000000000000,
        "sender_id": "164829104928172@lid",
        "is_outgoing": False,
        "text_content": "Send the 20 Lakh hawala ledger to this account.",
        "source_vfs_file_id": 142,
        "physical_byte_offset": 40948,
    }

    # Resolution dictionary simulating Phase 8.1 / Phase 5.5 Entity Master Profile
    entity_profile_data = {
        "unmasked_phone_e164": "+919876543210",
        "push_name": "~ Vikram Boss",
        "truecaller_name": "Vikram Crypto OTC (Spam: 85)",
        "bank_cbs_name": "VIKRAM KUMAR SINGH",
    }

    bubble = engine.build_chat_bubble_with_provenance(raw_bubble_data, entity_profile_data)

    assert bubble.identity_pill is not None
    assert bubble.identity_pill.unmasked_phone_e164 == "+919876543210"
    assert bubble.identity_pill.push_name == "~ Vikram Boss"
    assert "Vikram Crypto OTC" in bubble.identity_pill.truecaller_name
    assert bubble.identity_pill.bank_cbs_name == "VIKRAM KUMAR SINGH"

    pill_str = bubble.identity_pill.formatted_pill_string
    assert "+919876543210" in pill_str
    assert "Vikram Boss" in pill_str
    assert "VIKRAM KUMAR SINGH" in pill_str

    # Synchronized byte offset matches exact physical offset for Pane 3B
    assert bubble.source_vfs_file_id == 142
    assert bubble.physical_byte_offset == 40948


def test_cross_platform_conversation_hopping_follow_the_suspect():
    """Acceptance Test 4: Cross-Platform Conversation Hopping ('Follow the Suspect') Timeline."""
    stitcher = CrossPlatformHoppingStitcher()

    # Synthetic interaction timeline for suspect 'Vikram Singh' across 5 apps
    events = [
        {
            "event_uid": 1,
            "platform": "OLX India Chat",
            "direction": "INCOMING",
            "timestamp_utc_ns": 1762340000000000000,  # 14:00:00 UTC
            "text": "Is the iPhone available? Call me at 9876543210.",
            "handoff_token": "9876543210",
        },
        {
            "event_uid": 2,
            "platform": "Cellular Call",
            "direction": "OUTGOING",
            "timestamp_utc_ns": 1762340192000000000,  # 14:03:12 UTC (+3m 12s)
            "text": "Answered Voice Call (Duration: 2m 14s)",
            "handoff_token": None,
        },
        {
            "event_uid": 3,
            "platform": "WhatsApp Business (Clone 999)",
            "direction": "INCOMING",
            "timestamp_utc_ns": 1762340400000000000,  # 14:06:40 UTC (+3m 28s)
            "text": "Text me on Session ID 05a1b2c3d4e5f6 for account details.",
            "handoff_token": "05a1b2c3d4e5f6",
        },
        {
            "event_uid": 4,
            "platform": "Session Private Messenger",
            "direction": "INCOMING",
            "timestamp_utc_ns": 1762340550000000000,  # 14:09:10 UTC (+2m 30s)
            "text": "Transfer 50,000 to UPI ID merchant.99@okaxis.",
            "handoff_token": "merchant.99@okaxis",
        },
        {
            "event_uid": 5,
            "platform": "PhonePe UPI",
            "direction": "OUTGOING",
            "timestamp_utc_ns": 1762340700000000000,  # 14:11:40 UTC (+2m 30s)
            "text": "SETTLED: ₹50,000.00 to merchant.99@okaxis (UTR 630914829104)",
            "handoff_token": "630914829104",
        },
    ]

    stitched_stream, banners = stitcher.stitch_chronological_events(events)

    # There are 5 events across 5 different platforms -> exactly 4 platform switch banners
    assert len(banners) == 4

    banner1 = banners[0]
    assert banner1.previous_platform == "OLX India Chat"
    assert banner1.current_platform == "Cellular Call"
    assert banner1.time_delta_seconds == 192  # 3 minutes 12 seconds
    assert "3m 12s" in banner1.formatted_time_delta
    assert "PLATFORM SWITCH DETECTED" in banner1.rendered_banner_text

    # Banner 2: Call -> WhatsApp with handoff token
    banner2 = banners[1]
    assert banner2.previous_platform == "Cellular Call"
    assert banner2.current_platform == "WhatsApp Business (Clone 999)"

    # Banner 3: WhatsApp -> Session with 05... Session ID handoff token
    banner3 = banners[2]
    assert banner3.previous_platform == "WhatsApp Business (Clone 999)"
    assert banner3.current_platform == "Session Private Messenger"
    assert banner3.handoff_token == "05a1b2c3d4e5f6"

    # Banner 4: Session -> PhonePe UPI
    banner4 = banners[3]
    assert banner4.previous_platform == "Session Private Messenger"
    assert banner4.current_platform == "PhonePe UPI"
    assert "merchant.99@okaxis" in banner4.handoff_token


def test_audio_waveform_cache_and_db_persistence():
    """Acceptance Test 5: 64-sample RMS peak envelope generation and SQLite persistence."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_audio_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    db_path = os.path.join(sandbox, "chat_media_waveforms_and_transcripts_cache.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    processor = AudioWaveformProcessor()
    processor.initialize_cache_db(db_path)

    # 1. Generate 64-peak array from synthetic PCM audio samples
    synthetic_pcm = bytes([i % 256 for i in range(16000)])  # 1 second of 16kHz audio
    peaks = processor.compute_64_peak_envelope(synthetic_pcm)

    assert len(peaks) == 64
    assert all(0.05 <= p <= 1.0 for p in peaks)

    # 2. Persist record in cache SQLite
    record = AudioWaveformRecord(
        source_vfs_file_id=892,
        duration_seconds=18.4,
        waveform_64_peaks=peaks,
        offline_stt_transcript_text="Bhai payment kar diya UTR ledger dekh lo",
        word_timestamps=[
            {"word": "Bhai", "start_s": 0.2, "end_s": 0.5},
            {"word": "payment", "start_s": 0.6, "end_s": 1.1},
            {"word": "kar", "start_s": 1.2, "end_s": 1.4},
            {"word": "diya", "start_s": 1.5, "end_s": 1.8},
            {"word": "UTR", "start_s": 2.0, "end_s": 2.5},
        ],
    )

    allocated_uid = processor.save_waveform_record(db_path, record)
    assert allocated_uid > 0

    # 3. Read back and verify persistence
    cached = processor.get_waveform_record_by_file_id(db_path, file_id=892)
    assert cached is not None
    assert cached.source_vfs_file_id == 892
    assert cached.duration_seconds == 18.4
    assert len(cached.waveform_64_peaks) == 64
    assert "UTR" in cached.offline_stt_transcript_text
    assert len(cached.word_timestamps) == 5
