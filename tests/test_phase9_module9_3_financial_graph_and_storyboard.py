"""
Acceptance Test Suite for Phase 9, Module 9.3:
WebGL Financial & Crypto Laundering Flow Canvas, Force-Directed Entity Graph
& 60-Second Action-Burst Behavioral Storyboard.

Test Scope (5 Acceptance Tests):
1. test_5stage_sankey_hybrid_scaling_and_circular_feedback_arcs:
   Verifies 5-Stage Rupee-to-USDT Sankey canvas, clamped hybrid root-power ribbon scaling (4px min for ₹1 penny-drop),
   Split-UPI Smurfing Fan grouping, P2P third-party payer triangulation mismatch badges, and top-arched circular feedback arcs.
2. test_webgl_barnes_hut_quadtree_and_label_deocclusion_grid:
   Validates O(V log V) Barnes-Hut quadtree physics approximation (theta = 0.80) and 2D spatial occupancy grid
   prioritizing non-overlapping text labels by Forensic Importance Score (S_rank).
3. test_forensic_graph_algorithms_circular_scc_and_shortest_path:
   Evaluates Tarjan/Johnson circular mule loop detection (A -> B -> C -> A), bidirectional shortest evidentiary path,
   and common syndicate hub (TRON Gas Station / Energy parent wallet) isolation.
4. test_5swimlane_action_burst_storyboard_and_hex_jump:
   Evaluates 5-swimlane micro-timeline alignment across Physical/Biometric, Foreground/AppOps, Telecom/OTP,
   Financial/Crypto, and Visual/Chat, non-linear idle-gap folding, and synchronized Pane 3 byte offset binding.
5. test_polygon_lasso_selection_and_nodal_freeze_cart_persistence:
   Validates ray-casting point-in-polygon lasso node selection, 1-click Nodal Freeze Cart staging for 1930 NCRP / FIU-IND,
   and SQLite persistence in saved_graph_views_and_freeze_cart_state.
"""

import os
import sqlite3
import time
import pytest

from src.financial_graph_and_storyboard.models import (
    SankeyStageColumn,
    SankeyNode,
    SankeyFlowRibbon,
    SankeyLayoutResult,
    GraphNode2D,
    GraphEdge2D,
    CircularMuleLoop,
    ShortestEvidentiaryPath,
    SyndicateHubSummary,
    SwimlaneType,
    StoryboardEventPill,
    ActionBurstStoryboardView,
    NodalFreezeCartItem,
    SavedGraphViewState,
)
from src.financial_graph_and_storyboard.sankey_canvas import SankeyLaunderingCanvas
from src.financial_graph_and_storyboard.graph_physics_engine import (
    BarnesHutQuadtreePhysics,
    LabelDeocclusionSpatialGrid,
    ForensicGraphAlgorithms,
)
from src.financial_graph_and_storyboard.action_burst_storyboard import ActionBurstStoryboardEngine
from src.financial_graph_and_storyboard.freeze_cart_manager import NodalFreezeCartManager
from src.financial_graph_and_storyboard.engine import FinancialGraphAndStoryboardEngine


def test_5stage_sankey_hybrid_scaling_and_circular_feedback_arcs():
    """Acceptance Test 1: 5-Stage Sankey Canvas, Hybrid Power Scaling (₹1 to ₹25L), Smurfing Fan & Circular Feedback."""
    canvas = SankeyLaunderingCanvas(min_width_px=4.0, max_width_px=140.0, gamma=0.40)

    # 1. Hybrid Power Scaling Test: ₹1 penny-drop vs ₹25,00,000 P2P
    v_max = 2_500_000.0  # ₹25 Lakh max flow
    w_penny = canvas.compute_ribbon_thickness(amount=1.0, max_amount=v_max)
    w_50k = canvas.compute_ribbon_thickness(amount=50_000.0, max_amount=v_max)
    w_max = canvas.compute_ribbon_thickness(amount=2_500_000.0, max_amount=v_max)

    # Clamped to guaranteed minimum 4.0px
    assert w_penny == 4.0
    # Scaled sub-linearly so ₹50k is prominent (~29.4px rather than 2.8px linear)
    assert 20.0 <= w_50k <= 35.0
    # Max value reaches max thickness 140.0px
    assert w_max == 140.0

    # 2. 5-Stage Stratification & Laundering Flow Graph
    nodes = [
        SankeyNode(node_id="SRC_VICTIM_A", stage=SankeyStageColumn.STAGE_1_EXTERNAL_INFLOW_SOURCES, label="Victim A (IMPS ₹1L)"),
        SankeyNode(node_id="MULE_SBI", stage=SankeyStageColumn.STAGE_2_LOCAL_MULE_ACCOUNTS_AND_VPAS, label="SBI A/c ...8291 (Jio Bound)"),
        SankeyNode(node_id="MULE_HDFC", stage=SankeyStageColumn.STAGE_2_LOCAL_MULE_ACCOUNTS_AND_VPAS, label="HDFC A/c ...4410 (CBS: Amit Verma)"),
        SankeyNode(node_id="P2P_BINANCE", stage=SankeyStageColumn.STAGE_3_P2P_ESCROW_AND_DOMESTIC_FIU_ONRAMPS, label="Binance P2P (KYC: Rahul Sharma)", is_third_party_mismatch=True),
        SankeyNode(node_id="WALLET_TRON", stage=SankeyStageColumn.STAGE_4_SELF_CUSTODY_AND_CEX_WALLETS, label="TronLink: TXYZ... (BIP-39 Seed #1)"),
        SankeyNode(node_id="EXIT_FIXEDFLOAT", stage=SankeyStageColumn.STAGE_5_OFFSHORE_BOSS_AND_PRIVACY_SWAPS, label="FixedFloat -> 8.42 XMR"),
    ]

    flows = [
        # Normal forward flows
        SankeyFlowRibbon(source_node_id="SRC_VICTIM_A", target_node_id="MULE_SBI", amount_inr=100000.0),
        # Split-UPI Smurfing Fan: 2 transfers into Binance P2P totaling ₹1,80,000
        SankeyFlowRibbon(source_node_id="MULE_SBI", target_node_id="P2P_BINANCE", amount_inr=95000.0, utr="630914829101"),
        SankeyFlowRibbon(source_node_id="MULE_HDFC", target_node_id="P2P_BINANCE", amount_inr=85000.0, utr="630914829102"),
        # Crypto onramp
        SankeyFlowRibbon(source_node_id="P2P_BINANCE", target_node_id="WALLET_TRON", amount_inr=180000.0, crypto_amount=2000.0, crypto_symbol="USDT"),
        SankeyFlowRibbon(source_node_id="WALLET_TRON", target_node_id="EXIT_FIXEDFLOAT", amount_inr=180000.0, crypto_amount=8.42, crypto_symbol="XMR"),
        # Circular return flow: Stage 2 Mule sends ₹50,000 backward to Stage 1 external account
        SankeyFlowRibbon(source_node_id="MULE_HDFC", target_node_id="SRC_VICTIM_A", amount_inr=50000.0, is_circular_return=True),
    ]

    layout: SankeyLayoutResult = canvas.compute_layout(nodes, flows)

    assert len(layout.stages[SankeyStageColumn.STAGE_1_EXTERNAL_INFLOW_SOURCES]) >= 1
    assert len(layout.stages[SankeyStageColumn.STAGE_2_LOCAL_MULE_ACCOUNTS_AND_VPAS]) == 2
    assert len(layout.stages[SankeyStageColumn.STAGE_3_P2P_ESCROW_AND_DOMESTIC_FIU_ONRAMPS]) == 1

    # 3. Verify Split-UPI Smurfing Fan grouping
    assert len(layout.smurfing_fans) >= 1
    fan = layout.smurfing_fans[0]
    assert fan.target_node_id == "P2P_BINANCE"
    assert fan.transfer_count == 2
    assert fan.total_amount_inr == 180000.0
    assert "SPLIT-UPI SMURFING FAN" in fan.rendered_badge_text

    # 4. Verify P2P Triangulation Mismatch Badge
    p2p_node = next(n for n in nodes if n.node_id == "P2P_BINANCE")
    assert p2p_node.is_third_party_mismatch is True
    assert "TRIANGULATION MISMATCH" in p2p_node.rendered_warning_badge

    # 5. Verify Circular Feedback Arc
    circular_ribbon = next(r for r in layout.ribbons if r.is_circular_return)
    assert circular_ribbon.is_top_arched_feedback is True
    assert circular_ribbon.rendered_svg_path != ""


def test_webgl_barnes_hut_quadtree_and_label_deocclusion_grid():
    """Acceptance Test 2: O(V log V) Barnes-Hut quadtree physics and 2D label de-occlusion grid."""
    physics = BarnesHutQuadtreePhysics(theta=0.80)
    deocclusion = LabelDeocclusionSpatialGrid(cell_size_px=16)

    # 1. Generate 500 synthetic nodes distributed in 2D space
    nodes = [
        GraphNode2D(
            entity_uid=i,
            x=(i * 37) % 1200 - 600,
            y=(i * 53) % 1200 - 600,
            mass=1.0,
            degree=i % 12,
            inr_volume=float((i * 1000) % 500_000),
            has_tamper_alert=bool(i % 15 == 0),
            is_bookmarked=bool(i % 25 == 0),
            label=f"Entity_{i}_VPA_{i}@upi",
        )
        for i in range(500)
    ]

    edges = [
        GraphEdge2D(source_uid=i, target_uid=(i * 3) % 500, weight=1.0)
        for i in range(500)
    ]

    # Run 1 step of Barnes-Hut physics simulation
    t0 = time.perf_counter()
    updated_nodes = physics.step_simulation(nodes, edges, time_step=0.016)
    duration_ms = (time.perf_counter() - t0) * 1000.0

    assert duration_ms < 100.0  # O(V log V) step in < 100ms for 500 nodes
    assert len(updated_nodes) == 500

    # 2. Verify Forensic Importance Score (S_rank) ranking and 2D Label De-Occlusion
    # Compute rank for node 0 vs node 25 (bookmarked)
    rank_normal = physics.compute_forensic_rank(nodes[1])
    rank_bookmarked = physics.compute_forensic_rank(nodes[25])
    assert rank_bookmarked > rank_normal

    # Position 2 overlapping nodes at the exact same screen coordinates
    node_a = GraphNode2D(entity_uid=101, x=200, y=200, is_bookmarked=True, label="High_Priority_Mule")
    node_b = GraphNode2D(entity_uid=102, x=202, y=202, is_bookmarked=False, label="Low_Priority_Contact")

    screen_visible_labels = deocclusion.filter_visible_labels([node_a, node_b], zoom_level=1.0)

    # The high priority bookmarked node label wins; low priority overlapping label is culled
    assert "High_Priority_Mule" in screen_visible_labels
    assert "Low_Priority_Contact" not in screen_visible_labels


def test_forensic_graph_algorithms_circular_scc_and_shortest_path():
    """Acceptance Test 3: Tarjan/Johnson Circular Mule Loop Detection, Shortest Path & Syndicate Hub Isolation."""
    algo = ForensicGraphAlgorithms()

    # 1. Circular Mule Loop: A -> B -> C -> A
    nodes = {
        "MULE_A": {"name": "Mule A SBI", "type": "BANK_ACCOUNT"},
        "MULE_B": {"name": "Mule B HDFC", "type": "BANK_ACCOUNT"},
        "MULE_C": {"name": "Mule C ICICI", "type": "BANK_ACCOUNT"},
        "VICTIM": {"name": "Victim Payer", "type": "VICTIM_ACCOUNT"},
        "GAS_PARENT": {"name": "TRON Gas Station TDeg...", "type": "CRYPTO_WALLET"},
        "CHILD_W1": {"name": "TronLink W1 TAAA...", "type": "CRYPTO_WALLET"},
        "CHILD_W2": {"name": "TronLink W2 TBBB...", "type": "CRYPTO_WALLET"},
    }

    edges = [
        {"source": "VICTIM", "target": "MULE_A", "verb": "TRANSFERRED_FIAT_TO", "amount_inr": 100000.0},
        # Circular Loop
        {"source": "MULE_A", "target": "MULE_B", "verb": "TRANSFERRED_FIAT_TO", "amount_inr": 95000.0, "utr": "63091001"},
        {"source": "MULE_B", "target": "MULE_C", "verb": "TRANSFERRED_FIAT_TO", "amount_inr": 92000.0, "utr": "63091002"},
        {"source": "MULE_C", "target": "MULE_A", "verb": "TRANSFERRED_FIAT_TO", "amount_inr": 90000.0, "utr": "63091003"},
        # TRON Gas Activation Hub
        {"source": "GAS_PARENT", "target": "CHILD_W1", "verb": "DELEGATED_ENERGY_TO", "trx": 30.0},
        {"source": "GAS_PARENT", "target": "CHILD_W2", "verb": "DELEGATED_ENERGY_TO", "trx": 30.0},
    ]

    # Algorithm 1: Detect Circular Mule Loops
    loops: list[CircularMuleLoop] = algo.detect_circular_mule_loops(edges)
    assert len(loops) >= 1
    loop = loops[0]
    assert len(loop.cycle_node_ids) == 3
    assert set(loop.cycle_node_ids) == {"MULE_A", "MULE_B", "MULE_C"}
    assert loop.total_retained_commission_inr == 5000.0  # 95,000 started -> 90,000 returned

    # Algorithm 2: Bidirectional Shortest Evidentiary Path
    path: ShortestEvidentiaryPath = algo.find_shortest_evidentiary_path(
        edges=edges, source_id="VICTIM", target_id="MULE_C"
    )
    assert path.hop_count == 3  # VICTIM -> MULE_A -> MULE_B -> MULE_C
    assert path.path_node_ids == ["VICTIM", "MULE_A", "MULE_B", "MULE_C"]
    assert len(path.step_edge_verbs) == 3

    # Algorithm 3: Common Syndicate Hub Isolation (TRON Gas Parent)
    hubs: list[SyndicateHubSummary] = algo.isolate_common_syndicate_hubs(edges)
    gas_hub = next((h for h in hubs if h.hub_node_id == "GAS_PARENT"), None)
    assert gas_hub is not None
    assert gas_hub.connected_child_count == 2
    assert "DELEGATED_ENERGY_TO" in gas_hub.hub_edge_verbs


def test_5swimlane_action_burst_storyboard_and_hex_jump():
    """Acceptance Test 4: 5-Swimlane Action-Burst Behavioral Storyboard & Synchronized Pane 3 Hex Binding."""
    engine = ActionBurstStoryboardEngine()

    # Synthetic Story #04: Active Human-Authenticated Financial Outflow
    raw_burst_events = [
        # Swimlane 1: Physical & Biometric
        {
            "event_uid": 101,
            "swimlane": SwimlaneType.PHYSICAL_AND_BIOMETRIC_STATE,
            "timestamp_utc_ns": 1762348200000000000,  # 14:10:00 UTC
            "title": "Keyguard Hidden / Biometric Match",
            "details": "FaceID Match via biometrickitd",
            "source_vfs_file_id": 42,
            "physical_byte_offset": 1284,
        },
        # Swimlane 2: OS Foreground & Sensor AppOps
        {
            "event_uid": 102,
            "swimlane": SwimlaneType.OS_FOREGROUND_AND_SENSOR_APPOPS,
            "timestamp_utc_ns": 1762348205000000000,  # 14:10:05 UTC (+5s)
            "title": "com.phonepe.app: ACTIVITY_RESUMED",
            "details": "Foreground InFocus (Screen Overlay Check: Clean)",
            "source_vfs_file_id": 88,
            "physical_byte_offset": 5120,
        },
        # Swimlane 3: Telecom, OTP & Location
        {
            "event_uid": 103,
            "swimlane": SwimlaneType.TELECOM_OTP_AND_RADIO_ANCHOR,
            "timestamp_utc_ns": 1762348210000000000,  # 14:10:10 UTC (+10s)
            "title": "DLT SMS: AD-SBIINB-S",
            "details": "OTP 948291 for PhonePe ₹95,000",
            "source_vfs_file_id": 14,
            "physical_byte_offset": 10240,
        },
        # Swimlane 4: Financial & Crypto Rail
        {
            "event_uid": 104,
            "swimlane": SwimlaneType.FINANCIAL_AND_CRYPTO_EXECUTION,
            "timestamp_utc_ns": 1762348215000000000,  # 14:10:15 UTC (+15s)
            "title": "PhonePe Outflow: ₹95,000.00",
            "details": "UTR 630914829104 -> vikram99@okaxis",
            "source_vfs_file_id": 142,
            "physical_byte_offset": 40948,
        },
        # Swimlane 5: Visual Screenshot & Chat Handoff
        {
            "event_uid": 105,
            "swimlane": SwimlaneType.VISUAL_SCREENSHOT_AND_CHAT_HANDOFF,
            "timestamp_utc_ns": 1762348220000000000,  # 14:10:20 UTC (+20s)
            "title": "Screenshot_141019_PhonePe.jpg",
            "details": "Sent in Telegram Secret Chat to Boss",
            "source_vfs_file_id": 204,
            "physical_byte_offset": 65536,
        },
    ]

    storyboard: ActionBurstStoryboardView = engine.build_storyboard_view(
        story_uid=4,
        story_title="ACTIVE HUMAN-AUTHENTICATED UPI OUTFLOW & TELEGRAM SCREENSHOT PROOF",
        raw_events=raw_burst_events,
        idle_gap_threshold_sec=120,
    )

    # 1. Verify 5 swimlanes populated
    assert len(storyboard.swimlanes) == 5
    assert len(storyboard.swimlanes[SwimlaneType.PHYSICAL_AND_BIOMETRIC_STATE]) == 1
    assert len(storyboard.swimlanes[SwimlaneType.FINANCIAL_AND_CRYPTO_EXECUTION]) == 1

    # 2. Verify Verdict Badge
    assert "VERIFIED HUMAN-IN-THE-LOOP" in storyboard.human_in_the_loop_verdict

    # 3. Verify Pane 3B Synchronized Hex Jump Binding
    fin_event = storyboard.swimlanes[SwimlaneType.FINANCIAL_AND_CRYPTO_EXECUTION][0]
    assert fin_event.source_vfs_file_id == 142
    assert fin_event.physical_byte_offset == 40948


def test_polygon_lasso_selection_and_nodal_freeze_cart_persistence():
    """Acceptance Test 5: Ray-casting Polygon Lasso Selection & SQLite Freeze Cart Persistence."""
    sandbox = os.path.join(".", ".workspace_tmp", "test_graph_sandbox")
    os.makedirs(sandbox, exist_ok=True)
    db_path = os.path.join(sandbox, "saved_graph_views_and_freeze_cart.sqlite")
    if os.path.exists(db_path):
        os.remove(db_path)

    cart_mgr = NodalFreezeCartManager()
    cart_mgr.initialize_cart_db(db_path)

    # 1. Ray-Casting Polygon Point-in-Polygon Test
    # Define a rectangular lasso polygon: [100, 100] to [400, 400]
    polygon = [(100.0, 100.0), (400.0, 100.0), (400.0, 400.0), (100.0, 400.0)]

    nodes = [
        {"node_id": "MULE_1", "x": 200.0, "y": 200.0, "account_no": "918281920192", "ifsc": "SBIN0001042", "upi_vpa": "mule1@sbi", "utr": "630914829101"},
        {"node_id": "MULE_2", "x": 300.0, "y": 300.0, "account_no": "440192837410", "ifsc": "HDFC0000441", "upi_vpa": "mule2@hdfc", "utr": "630914829102"},
        {"node_id": "OUTSIDE_NODE", "x": 800.0, "y": 800.0, "account_no": "111122223333", "ifsc": "ICIC0001111", "upi_vpa": "other@icici", "utr": "630914829999"},
    ]

    selected_nodes = cart_mgr.filter_nodes_by_lasso(polygon, nodes)
    assert len(selected_nodes) == 2
    assert {n["node_id"] for n in selected_nodes} == {"MULE_1", "MULE_2"}

    # 2. Stage Selected Nodes into Nodal Freeze Cart Items
    cart_items = [
        NodalFreezeCartItem(
            instrument_type="BANK_ACCOUNT",
            account_or_address=n["account_no"],
            ifsc_or_network=n["ifsc"],
            linked_vpa=n["upi_vpa"],
            linked_utr=n["utr"],
            source_entity_id=n["node_id"],
        )
        for n in selected_nodes
    ]

    view_state = SavedGraphViewState(
        canvas_mode="SANKEY_5_STAGE_LAUNDERING",
        view_title="Rupee-to-USDT Trail for Victim UTR 630914829101",
        pinned_node_positions={"MULE_1": [200.0, 200.0], "MULE_2": [300.0, 300.0]},
        active_filters={"min_amount_inr": 50000.0},
        staged_freeze_cart_items=cart_items,
        updated_at_ist_iso="2026-11-05 15:45:00 IST (+05:30)",
    )

    allocated_uid = cart_mgr.save_graph_view_state(db_path, view_state)
    assert allocated_uid > 0

    # 3. Read back and verify persistence
    loaded = cart_mgr.get_graph_view_state_by_uid(db_path, allocated_uid)
    assert loaded is not None
    assert loaded.canvas_mode == "SANKEY_5_STAGE_LAUNDERING"
    assert len(loaded.staged_freeze_cart_items) == 2
    assert loaded.staged_freeze_cart_items[0].account_or_address == "918281920192"
    assert loaded.staged_freeze_cart_items[0].linked_utr == "630914829101"
