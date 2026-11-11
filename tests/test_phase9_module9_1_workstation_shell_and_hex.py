"""
Acceptance Test Suite for Phase 9, Module 9.1:
Core Desktop Workstation Shell, Case Command Center, Virtualized Evidence Grids
& Synchronized 3-Pane Hex/Provenance Verification Layout.

Test Scope (5 Acceptance Tests):
1. test_50_million_row_keyset_scroll_and_quantile_thumb_jump:
   Verifies fixed-pool viewport windowing equations (i_first, i_last) with constant DOM element count (< 100 rows),
   O(log N) keyset cursor pagination, and O(1) quantile milestone seeking for arbitrary scrollbar thumb dragging.
2. test_hostile_xss_sanitization_and_unicode_bidi_spoof_detection:
   Validates anti-XSS sanitization disarming hostile scripts/HTML from extracted device strings,
   and detects Unicode Right-to-Left Override (RLO) control characters badging with [UNICODE-RLO-SPOOF].
3. test_synchronized_wal_frame_byte_offset_and_4layer_hex_highlight:
   Evaluates exact physical byte offset equations for SQLite WAL frames (32 + (frame-1)*(page+24) + 24 + cell_offset),
   4-layer color-coded structural byte highlighting, 12-format live Data Interpreter, and 4 KB aligned range streaming.
4. test_sub_millisecond_roaring_bitmap_facet_intersection:
   Intersects multiple facet dimensions (Phase 5 Messaging, State: RESIDUAL_RECORD, Profile: User 999) in RAM,
   verifying sub-5ms latency and instant dynamic badge count recalculation.
5. test_workstation_ui_state_and_bookmarks_sqlite_export:
   Validates examiner annotations, relied-upon flags, and physical byte bookmarks in workstation_ui_state.sqlite.
"""

import os
import sqlite3
import time
import pytest

from src.workstation_shell_and_hex.models import (
    HexLayerType,
    TimezoneDisplayMode,
    TagCategoryBadge,
    ExaminerBookmarkRecord,
    HexSliceWindow,
    ByteHighlightSpan,
    DataInterpreterResult,
    ViewportVirtualizationState,
    QuantileMilestone,
)
from src.workstation_shell_and_hex.security_sanitizer import HostileEvidenceSanitizer
from src.workstation_shell_and_hex.hex_provenance_inspector import (
    HexProvenanceInspector,
    DataInterpreterDecoder,
)
from src.workstation_shell_and_hex.virtual_grid_pager import (
    VirtualizedGridCalculator,
    QuantileMilestoneSeeker,
)
from src.workstation_shell_and_hex.facet_filter_hub import RoaringFacetFilterHub
from src.workstation_shell_and_hex.engine import WorkstationShellEngine


def test_50_million_row_keyset_scroll_and_quantile_thumb_jump():
    """Acceptance Test 1: Viewport windowing math, keyset cursor pagination, and O(1) milestone seeking."""
    grid_calc = VirtualizedGridCalculator(row_height=36, overscan_buffer=10)

    # 1. Viewport windowing calculation for 50,000,000 rows
    total_rows = 50_000_000
    viewport_height = 800  # 800px window fits ~22 rows + 20 overscan = 42 mounted rows
    scroll_top = 0

    state = grid_calc.compute_viewport_window(
        scroll_top=scroll_top,
        viewport_height=viewport_height,
        total_rows=total_rows,
    )

    assert state.i_first == 0
    assert state.i_last <= 45
    assert (state.i_last - state.i_first + 1) < 100  # Strict DOM element guardrail!

    # Middle scroll
    mid_scroll = 36 * 100_000  # Scrolled down 100,000 rows
    state_mid = grid_calc.compute_viewport_window(
        scroll_top=mid_scroll,
        viewport_height=viewport_height,
        total_rows=total_rows,
    )
    assert state_mid.i_first >= 99_990
    assert (state_mid.i_last - state_mid.i_first + 1) < 100

    # 2. Quantile Milestone Seeking for arbitrary scrollbar thumb dragging
    seeker = QuantileMilestoneSeeker(quantile_interval=10_000)

    # Generate synthetic milestone checkpoints (simulating Phase 8.1 super-timeline index)
    milestones = [
        QuantileMilestone(
            row_index=i * 10_000,
            timestamp_utc_ns=1762348800000000000 + (i * 10_000 * 1_000_000),
            timeline_event_uid=i * 10_000 + 1,
        )
        for i in range(2001)  # 20,000,000 rows covered
    ]
    seeker.load_milestones(milestones)

    # Jump to 65% of 20,000,000 rows = row 13,000,000 (Milestone #1300)
    t0 = time.perf_counter()
    target_row = 13_000_000
    matched_ms = seeker.seek_milestone_for_row(target_row)
    seek_duration_ms = (time.perf_counter() - t0) * 1000.0

    assert seek_duration_ms < 2.0  # O(1) lookup in < 2ms
    assert matched_ms.row_index == 13_000_000
    assert matched_ms.timeline_event_uid == 13_000_001

    # Verify keyset cursor query formulation
    keyset_params = seeker.build_keyset_query_params(matched_ms, limit=250)
    assert keyset_params["cursor_ts_ns"] == matched_ms.timestamp_utc_ns
    assert keyset_params["cursor_uid"] == matched_ms.timeline_event_uid
    assert keyset_params["limit"] == 250


def test_hostile_xss_sanitization_and_unicode_bidi_spoof_detection():
    """Acceptance Test 2: Anti-XSS sanitization and Unicode Right-to-Left Override (RLO) spoof detection."""
    sanitizer = HostileEvidenceSanitizer()

    # 1. Malicious XSS image payload in chat message
    hostile_img = '<img src=x onerror="window.forensicBridge && alert(\'XSS\')">'
    clean_img = sanitizer.sanitize_text(hostile_img)
    assert "<script" not in clean_img.lower()
    assert "onerror=" not in clean_img.lower()
    assert "&lt;img" in clean_img or "<img" not in clean_img

    # 2. Malicious shell exec payload in contact name / SSID
    hostile_exec = "<script>require('child_process').exec('calc')</script>"
    clean_exec = sanitizer.sanitize_text(hostile_exec)
    assert "<script>" not in clean_exec

    # 3. Unicode Right-to-Left Override (U+202E RLO) spoof in filename
    # Disguises "invoice [RLO] gpj.apk" as appearing to end in .jpg
    spoofed_filename = "invoice_\u202Egpj.apk"
    result = sanitizer.inspect_and_badge_string(spoofed_filename)

    assert result.has_unicode_bidi_spoof is True
    assert "[UNICODE-RLO-SPOOF]" in result.rendered_badge_string
    assert "U+202E" in result.spoof_character_details


def test_synchronized_wal_frame_byte_offset_and_4layer_hex_highlight():
    """Acceptance Test 3: Exact physical WAL byte-offset equations, 4-layer highlights, and 12-format Data Interpreter."""
    inspector = HexProvenanceInspector()
    decoder = DataInterpreterDecoder()

    # 1. Exact physical WAL offset calculation from Section 6.4:
    # Page_Size = 4096, Frame_No = 10, Cell_Offset_In_Page = 3812
    # Physical_WAL_Offset = 32 + (10 - 1) * (4096 + 24) + 24 + 3812 = 40,948 (0x00009FF4)
    page_size = 4096
    frame_no = 10
    cell_offset = 3812
    text_col_offset_in_cell = 28
    text_length = 42

    calc_offset = inspector.compute_sqlite_wal_offset(
        page_size=page_size,
        frame_number=frame_no,
        cell_offset_in_page=cell_offset,
    )
    assert calc_offset == 40948
    assert hex(calc_offset).lower() == "0x9ff4"

    # 2. 4-Layer Color-Coded Highlighting Spans
    # Layer 1: WAL Frame Header (24 bytes immediately preceding page content in frame)
    # Frame start = 32 + (10 - 1) * (4096 + 24) = 37112
    # Frame Header = [37112, 37136)
    # Cell Offset = 37136 + 3812 = 40948
    # Layer 2: Cell Varint Header = [40948, 40948 + 28) = [40948, 40976)
    # Layer 3: Text Column Payload = [40976, 40976 + 42) = [40976, 41018) (0x0000A010 to 0x0000A03A)
    # Layer 4: Slack / Freeblock
    spans = inspector.generate_4layer_highlight_spans(
        frame_start_offset=37112,
        cell_physical_offset=calc_offset,
        cell_header_length=text_col_offset_in_cell,
        column_payload_length=text_length,
        slack_range=(41018, 41040),
    )

    layer1 = next(s for s in spans if s.layer_type == HexLayerType.LAYER_1_PAGE_OR_WAL_HEADER)
    assert layer1.start_offset == 37112
    assert layer1.end_offset == 37136
    assert layer1.css_color_class == "hex-layer-slate-blue"

    layer2 = next(s for s in spans if s.layer_type == HexLayerType.LAYER_2_CELL_HEADER)
    assert layer2.start_offset == 40948
    assert layer2.end_offset == 40976
    assert layer2.css_color_class == "hex-layer-amber"

    layer3 = next(s for s in spans if s.layer_type == HexLayerType.LAYER_3_COLUMN_PAYLOAD)
    assert layer3.start_offset == 40976
    assert layer3.end_offset == 41018
    assert layer3.css_color_class == "hex-layer-bright-cyan"

    # 3. 4 KB Page-Aligned Binary Range Streaming
    # Target center = 40,948 -> base = floor(40948 / 4096) * 4096 - 4096 = 9 * 4096 - 4096 = 32768
    slice_window = inspector.compute_aligned_hex_slice_window(
        center_offset=40948,
        total_file_size=100000,
        window_size=16384,
    )
    assert slice_window.base_offset % 4096 == 0
    assert slice_window.base_offset <= 40948 < (slice_window.base_offset + slice_window.length)

    # 4. 12-Format Live Data Interpreter
    # Sample 8 bytes: Unix timestamp in milliseconds for 2025-11-05 13:20:00 UTC = 1762348800000 (0x0000019A54AE3000)
    ts_bytes_be = (1762348800000).to_bytes(8, byteorder="big")
    decoded_ms = decoder.decode_all_formats(ts_bytes_be)

    assert decoded_ms.uint64_be == 1762348800000
    assert "2025" in decoded_ms.unix_ms_ist_utc or "2026" in decoded_ms.unix_ms_ist_utc

    # Sample UTF-8 string bytes: "Delete UTR"
    str_bytes = b"Delete UTR"
    decoded_str = decoder.decode_all_formats(str_bytes)
    assert decoded_str.utf8_string == "Delete UTR"


def test_sub_millisecond_roaring_bitmap_facet_intersection():
    """Acceptance Test 4: Multi-facet Roaring Bitmap intersection in RAM in < 5ms."""
    hub = RoaringFacetFilterHub()

    # Populate 3 synthetic bitmaps representing:
    # 1. Phase 5 Messaging (10,000 events)
    # 2. State: RESIDUAL_RECORD (5,000 events)
    # 3. Profile: User 999 App Cloner (1,000 events)
    phase5_uids = [i for i in range(1, 10001)]
    deleted_uids = [i for i in range(5000, 10001)]
    clone999_uids = [i for i in range(7000, 8001)]  # 1,001 items (7000..8000)

    hub.register_facet_bitmap("forensic_phase", "PHASE_5_MESSAGING", phase5_uids)
    hub.register_facet_bitmap("recovery_classification", "RESIDUAL_RECORD", deleted_uids)
    hub.register_facet_bitmap("user_profile", "USER_999_APP_CLONER", clone999_uids)

    # Intersection of all 3: range [7000, 8000] -> exactly 1001 items
    t0 = time.perf_counter()
    matching_uids = hub.intersect_facets(
        {
            "forensic_phase": "PHASE_5_MESSAGING",
            "recovery_classification": "RESIDUAL_RECORD",
            "user_profile": "USER_999_APP_CLONER",
        }
    )
    duration_ms = (time.perf_counter() - t0) * 1000.0

    assert duration_ms < 5.0  # Must be sub-5ms!
    assert len(matching_uids) == 1001
    assert matching_uids[0] == 7000
    assert matching_uids[-1] == 8000


def test_workstation_ui_state_and_bookmarks_sqlite_export():
    """Acceptance Test 5: Verify persistent bookmarks and relied-upon tags in workstation_ui_state.sqlite."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_workstation_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    db_path = os.path.join(sandbox, "workstation_ui_state.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    engine = WorkstationShellEngine()
    engine.initialize_ui_state_db(db_path)

    bookmark = ExaminerBookmarkRecord(
        target_domain_table="whatsapp_messages_master_ledger",
        target_record_uid=1042,
        source_vfs_file_id=142,
        physical_byte_offset=40948,
        tag_category_badge=TagCategoryBadge.KEY_SMOKING_GUN,
        is_relied_upon_for_sec230_bnss=1,
        examiner_narrative_note="Recovered pre-revoke message instructing mule coordinator to wipe UTR ledger.",
        created_by_examiner="Inspector Rajesh Kumar Verma",
        created_at_ist_iso="2026-11-05 14:30:00 IST (+05:30)",
    )

    engine.add_bookmark(db_path, bookmark)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM examiner_bookmarks_and_tags_ledger;")
    assert cur.fetchone()[0] == 1

    cur.execute("SELECT target_record_uid, tag_category_badge, physical_byte_offset FROM examiner_bookmarks_and_tags_ledger;")
    row = cur.fetchone()
    assert row[0] == 1042
    assert row[1] == "KEY_SMOKING_GUN"
    assert row[2] == 40948
    conn.close()
