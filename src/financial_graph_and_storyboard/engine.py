"""
Financial Graph, Sankey Canvas & Action-Burst Storyboard Orchestrator (Module 9.3).
Integrates Sankey laundering layout, WebGL2 physics, graph algorithms, storyboard views, and freeze cart persistence.
"""

from typing import Any, Optional

from src.financial_graph_and_storyboard.models import (
    ActionBurstStoryboardView,
    CircularMuleLoop,
    GraphEdge2D,
    GraphNode2D,
    NodalFreezeCartItem,
    SankeyFlowRibbon,
    SankeyLayoutResult,
    SankeyNode,
    SavedGraphViewState,
    ShortestEvidentiaryPath,
    SyndicateHubSummary,
)
from src.financial_graph_and_storyboard.sankey_canvas import SankeyLaunderingCanvas
from src.financial_graph_and_storyboard.graph_physics_engine import (
    BarnesHutQuadtreePhysics,
    ForensicGraphAlgorithms,
    LabelDeocclusionSpatialGrid,
)
from src.financial_graph_and_storyboard.action_burst_storyboard import (
    ActionBurstStoryboardEngine,
)
from src.financial_graph_and_storyboard.freeze_cart_manager import (
    NodalFreezeCartManager,
)


class FinancialGraphAndStoryboardEngine:
    """Master engine coordinating financial canvas, graph algorithms, storyboard, and freeze carts."""

    def __init__(self):
        self.sankey_canvas = SankeyLaunderingCanvas()
        self.physics = BarnesHutQuadtreePhysics()
        self.deocclusion = LabelDeocclusionSpatialGrid()
        self.graph_algorithms = ForensicGraphAlgorithms()
        self.storyboard_engine = ActionBurstStoryboardEngine()
        self.freeze_cart_mgr = NodalFreezeCartManager()

    def layout_sankey(
        self, nodes: list[SankeyNode], flows: list[SankeyFlowRibbon]
    ) -> SankeyLayoutResult:
        """Computes 5-stage Sankey layout with hybrid power scaling and feedback arcs."""
        return self.sankey_canvas.compute_layout(nodes, flows)

    def step_physics(
        self,
        nodes: list[GraphNode2D],
        edges: list[GraphEdge2D],
        time_step: float = 0.016,
    ) -> list[GraphNode2D]:
        """Runs one Barnes-Hut quadtree physics simulation step."""
        return self.physics.step_simulation(nodes, edges, time_step)

    def find_circular_loops(
        self, edges: list[dict[str, Any]]
    ) -> list[CircularMuleLoop]:
        """Detects circular financial loops with retained commission."""
        return self.graph_algorithms.detect_circular_mule_loops(edges)

    def find_shortest_path(
        self, edges: list[dict[str, Any]], source_id: str, target_id: str
    ) -> ShortestEvidentiaryPath:
        """Calculates shortest multi-phase evidentiary path between two entities."""
        return self.graph_algorithms.find_shortest_evidentiary_path(
            edges, source_id, target_id
        )

    def find_syndicate_hubs(
        self, edges: list[dict[str, Any]]
    ) -> list[SyndicateHubSummary]:
        """Isolates high-centrality syndicate bridge hubs."""
        return self.graph_algorithms.isolate_common_syndicate_hubs(edges)

    def build_storyboard(
        self,
        story_uid: int,
        story_title: str,
        raw_events: list[dict[str, Any]],
        idle_gap_threshold_sec: int = 120,
    ) -> ActionBurstStoryboardView:
        """Constructs 5-swimlane micro-timeline view with human-in-the-loop verdict."""
        return self.storyboard_engine.build_storyboard_view(
            story_uid, story_title, raw_events, idle_gap_threshold_sec
        )

    def stage_lasso_selection_to_freeze_cart(
        self,
        polygon: list[tuple[float, float]],
        nodes: list[dict[str, Any]],
        db_path: str,
        view_title: str,
    ) -> int:
        """Filters nodes by polygon lasso and saves staged freeze cart items in SQLite."""
        self.freeze_cart_mgr.initialize_cart_db(db_path)
        selected = self.freeze_cart_mgr.filter_nodes_by_lasso(polygon, nodes)

        cart_items: list[NodalFreezeCartItem] = []
        for n in selected:
            cart_items.append(
                NodalFreezeCartItem(
                    instrument_type=n.get("instrument_type", "BANK_ACCOUNT"),
                    account_or_address=n.get("account_or_address", ""),
                    ifsc_or_network=n.get("ifsc_or_network"),
                    linked_vpa=n.get("linked_vpa"),
                    linked_utr=n.get("linked_utr"),
                    source_entity_id=n.get("source_entity_id"),
                )
            )

        state = SavedGraphViewState(
            canvas_mode="WEBGL_ENTITY_LINK_GRAPH",
            view_title=view_title,
            pinned_node_positions={},
            active_filters={},
            staged_freeze_cart_items=cart_items,
        )

        return self.freeze_cart_mgr.save_graph_view_state(db_path, state)
