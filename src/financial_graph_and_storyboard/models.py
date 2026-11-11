"""
Data models and canonical enums for Phase 9, Module 9.3:
WebGL Financial & Crypto Laundering Flow Canvas, Force-Directed Entity Graph & 60-Second Action-Burst Storyboard.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class SankeyStageColumn(str, Enum):
    """The 5 stratified horizontal columns of the Rupee-to-USDT Laundering Canvas."""
    STAGE_1_EXTERNAL_INFLOW_SOURCES = "STAGE_1_EXTERNAL_INFLOW_SOURCES"
    STAGE_2_LOCAL_MULE_ACCOUNTS_AND_VPAS = "STAGE_2_LOCAL_MULE_ACCOUNTS_AND_VPAS"
    STAGE_3_P2P_ESCROW_AND_DOMESTIC_FIU_ONRAMPS = "STAGE_3_P2P_ESCROW_AND_DOMESTIC_FIU_ONRAMPS"
    STAGE_4_SELF_CUSTODY_AND_CEX_WALLETS = "STAGE_4_SELF_CUSTODY_AND_CEX_WALLETS"
    STAGE_5_OFFSHORE_BOSS_AND_PRIVACY_SWAPS = "STAGE_5_OFFSHORE_BOSS_AND_PRIVACY_SWAPS"


@dataclass
class SankeyNode:
    """A financial account, P2P order, or crypto wallet node on the Sankey canvas."""
    node_id: str
    stage: SankeyStageColumn
    label: str
    is_third_party_mismatch: bool = False
    rendered_warning_badge: str = ""
    x: float = 0.0
    y: float = 0.0
    height: float = 40.0


@dataclass
class SankeyFlowRibbon:
    """A financial transaction ribbon flowing between two Sankey nodes."""
    source_node_id: str
    target_node_id: str
    amount_inr: float
    crypto_amount: Optional[float] = None
    crypto_symbol: Optional[str] = None
    utr: Optional[str] = None
    is_circular_return: bool = False
    is_top_arched_feedback: bool = False
    thickness_px: float = 4.0
    rendered_svg_path: str = ""


@dataclass
class SmurfingFanGroup:
    """Converging Split-UPI transfers grouped before entering a P2P escrow order."""
    target_node_id: str
    transfer_count: int
    total_amount_inr: float
    rendered_badge_text: str
    incoming_ribbons: list[SankeyFlowRibbon] = field(default_factory=list)


@dataclass
class SankeyLayoutResult:
    """Complete computed visual coordinates for the 5-Stage Sankey Canvas."""
    stages: dict[SankeyStageColumn, list[SankeyNode]]
    ribbons: list[SankeyFlowRibbon]
    smurfing_fans: list[SmurfingFanGroup]


@dataclass
class GraphNode2D:
    """Node in the 2D WebGL instanced force-directed link graph."""
    entity_uid: int
    x: float = 0.0
    y: float = 0.0
    mass: float = 1.0
    degree: int = 0
    inr_volume: float = 0.0
    has_tamper_alert: bool = False
    is_bookmarked: bool = False
    label: str = ""
    vx: float = 0.0
    vy: float = 0.0
    fx: float = 0.0
    fy: float = 0.0


@dataclass
class GraphEdge2D:
    """Directed or undirected edge between two entities in the WebGL graph."""
    source_uid: int
    target_uid: int
    weight: float = 1.0
    edge_verb: str = "CONNECTED_TO"


@dataclass
class CircularMuleLoop:
    """Detected closed circular financial loop (A -> B -> ... -> A)."""
    cycle_node_ids: list[str]
    total_retained_commission_inr: float = 0.0
    loop_duration_seconds: int = 0


@dataclass
class ShortestEvidentiaryPath:
    """Step-by-step multi-phase connection between two target entities."""
    hop_count: int
    path_node_ids: list[str]
    step_edge_verbs: list[str]


@dataclass
class SyndicateHubSummary:
    """Syndicate bridge hub connecting multiple child entities."""
    hub_node_id: str
    connected_child_count: int
    hub_edge_verbs: list[str]


class SwimlaneType(str, Enum):
    """The 5 synchronized behavioral swimlanes in the 60-Second Action-Burst Storyboard."""
    PHYSICAL_AND_BIOMETRIC_STATE = "PHYSICAL_AND_BIOMETRIC_STATE"
    OS_FOREGROUND_AND_SENSOR_APPOPS = "OS_FOREGROUND_AND_SENSOR_APPOPS"
    TELECOM_OTP_AND_RADIO_ANCHOR = "TELECOM_OTP_AND_RADIO_ANCHOR"
    FINANCIAL_AND_CRYPTO_EXECUTION = "FINANCIAL_AND_CRYPTO_EXECUTION"
    VISUAL_SCREENSHOT_AND_CHAT_HANDOFF = "VISUAL_SCREENSHOT_AND_CHAT_HANDOFF"


@dataclass
class StoryboardEventPill:
    """A single micro-event pill plotted inside an Action-Burst swimlane."""
    event_uid: int
    swimlane: SwimlaneType
    timestamp_utc_ns: int
    title: str
    details: str
    source_vfs_file_id: int
    physical_byte_offset: Optional[int] = None
    x_offset_px: float = 0.0


@dataclass
class ActionBurstStoryboardView:
    """5-Swimlane synchronized behavioral storyboard for proving human-in-the-loop action."""
    story_uid: int
    story_title: str
    human_in_the_loop_verdict: str
    swimlanes: dict[SwimlaneType, list[StoryboardEventPill]]
    idle_gap_markers: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class NodalFreezeCartItem:
    """An instrument staged for 1930 NCRP Bank Lien or FIU-IND Crypto Freeze."""
    instrument_type: str
    account_or_address: str
    ifsc_or_network: Optional[str] = None
    linked_vpa: Optional[str] = None
    linked_utr: Optional[str] = None
    source_entity_id: Optional[str] = None


@dataclass
class SavedGraphViewState:
    """Persisted canvas state, pinned node positions, and staged freeze cart items."""
    canvas_mode: str
    view_title: str
    pinned_node_positions: dict[str, list[float]]
    active_filters: dict[str, Any]
    staged_freeze_cart_items: list[NodalFreezeCartItem]
    view_state_uid: Optional[int] = None
    saved_svg_png_snapshot_sha256: Optional[str] = None
    updated_at_ist_iso: str = ""
