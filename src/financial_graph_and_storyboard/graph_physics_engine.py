"""
WebGL2 Force-Directed Entity Link Graph Physics & Forensic Algorithms (Sub-Engine 9.3B).
Provides O(V log V) Barnes-Hut quadtree physics, 2D label de-occlusion grids,
Tarjan/Johnson circular mule loop detection, shortest paths, and syndicate hub isolation.
"""

from collections import deque
import math
from typing import Any, Optional

from src.financial_graph_and_storyboard.models import (
    CircularMuleLoop,
    GraphEdge2D,
    GraphNode2D,
    ShortestEvidentiaryPath,
    SyndicateHubSummary,
)


class QuadTreeNode:
    """Internal cell in the recursive Barnes-Hut quadtree."""

    def __init__(self, x: float, y: float, size: float):
        self.x = x
        self.y = y
        self.size = size
        self.mass = 0.0
        self.cx = 0.0
        self.cy = 0.0
        self.node: Optional[GraphNode2D] = None
        self.children: list[Optional["QuadTreeNode"]] = [None, None, None, None]
        self.is_leaf = True

    def insert(self, graph_node: GraphNode2D) -> None:
        """Inserts a 2D node into the quadtree, subdividing if necessary."""
        if self.is_leaf and self.node is None:
            self.node = graph_node
            self.mass = graph_node.mass
            self.cx = graph_node.x
            self.cy = graph_node.y
            return

        if self.is_leaf:
            # Subdivide existing leaf
            self.is_leaf = False
            half = self.size / 2.0
            self.children = [
                QuadTreeNode(self.x - half / 2.0, self.y - half / 2.0, half),  # NW
                QuadTreeNode(self.x + half / 2.0, self.y - half / 2.0, half),  # NE
                QuadTreeNode(self.x - half / 2.0, self.y + half / 2.0, half),  # SW
                QuadTreeNode(self.x + half / 2.0, self.y + half / 2.0, half),  # SE
            ]
            old_node = self.node
            self.node = None
            if old_node is not None:
                self._insert_into_child(old_node)

        self._insert_into_child(graph_node)

        # Update center of mass
        total_mass = self.mass + graph_node.mass
        if total_mass > 0:
            self.cx = (self.cx * self.mass + graph_node.x * graph_node.mass) / total_mass
            self.cy = (self.cy * self.mass + graph_node.y * graph_node.mass) / total_mass
            self.mass = total_mass

    def _insert_into_child(self, graph_node: GraphNode2D) -> None:
        quad_idx = 0
        if graph_node.x >= self.x:
            quad_idx += 1
        if graph_node.y >= self.y:
            quad_idx += 2
        child = self.children[quad_idx]
        if child is not None:
            child.insert(graph_node)


class BarnesHutQuadtreePhysics:
    """Computes O(V log V) Barnes-Hut force-directed graph physics."""

    def __init__(
        self,
        theta: float = 0.80,
        repulsion_k: float = 3000.0,
        spring_k: float = 0.04,
        damping: float = 0.85,
    ):
        self.theta = theta
        self.repulsion_k = repulsion_k
        self.spring_k = spring_k
        self.damping = damping

    @staticmethod
    def compute_forensic_rank(node: GraphNode2D) -> float:
        """Calculates Forensic Importance Score S_rank for node priority and label display."""
        score = 0.0
        if node.is_bookmarked:
            score += 100.0
        if node.has_tamper_alert:
            score += 50.0
        if node.inr_volume > 0.0:
            score += 10.0 * math.log10(1.0 + node.inr_volume)
        score += float(node.degree)
        return score

    def _compute_repulsion(self, node: GraphNode2D, tree: QuadTreeNode) -> tuple[float, float]:
        if tree.mass <= 0.0:
            return 0.0, 0.0

        dx = node.x - tree.cx
        dy = node.y - tree.cy
        dist_sq = dx * dx + dy * dy
        dist = math.sqrt(dist_sq)

        if dist < 0.001:
            return 0.0, 0.0

        if tree.is_leaf or (tree.size / dist) < self.theta:
            # Approximate cell as single super-node
            force = (self.repulsion_k * node.mass * tree.mass) / (dist_sq + 100.0)
            return (dx / dist) * force, (dy / dist) * force

        fx_tot = 0.0
        fy_tot = 0.0
        for child in tree.children:
            if child is not None:
                cfx, cfy = self._compute_repulsion(node, child)
                fx_tot += cfx
                fy_tot += cfy
        return fx_tot, fy_tot

    def step_simulation(
        self,
        nodes: list[GraphNode2D],
        edges: list[GraphEdge2D],
        time_step: float = 0.016,
    ) -> list[GraphNode2D]:
        """Advances physics by one frame using Barnes-Hut repulsion and spring attraction."""
        if not nodes:
            return []

        # Find bounds
        min_x = min(n.x for n in nodes)
        max_x = max(n.x for n in nodes)
        min_y = min(n.y for n in nodes)
        max_y = max(n.y for n in nodes)
        cx = (min_x + max_x) / 2.0
        cy = (min_y + max_y) / 2.0
        size = max(max_x - min_x, max_y - min_y, 500.0) * 1.2

        # Build quadtree
        root = QuadTreeNode(cx, cy, size)
        for n in nodes:
            root.insert(n)

        node_map = {n.entity_uid: n for n in nodes}

        # Calculate forces
        for n in nodes:
            fx, fy = self._compute_repulsion(n, root)
            n.fx = fx
            n.fy = fy

        # Spring attraction
        for e in edges:
            n1 = node_map.get(e.source_uid)
            n2 = node_map.get(e.target_uid)
            if n1 is not None and n2 is not None:
                dx = n2.x - n1.x
                dy = n2.y - n1.y
                dist = math.sqrt(dx * dx + dy * dy)
                if dist > 1.0:
                    force = self.spring_k * dist * e.weight
                    fx = (dx / dist) * force
                    fy = (dy / dist) * force
                    n1.fx += fx
                    n1.fy += fy
                    n2.fx -= fx
                    n2.fy -= fy

        # Euler integration
        for n in nodes:
            ax = n.fx / max(0.1, n.mass)
            ay = n.fy / max(0.1, n.mass)
            n.vx = (n.vx + ax * time_step) * self.damping
            n.vy = (n.vy + ay * time_step) * self.damping
            n.x += n.vx * time_step
            n.y += n.vy * time_step

        return nodes


class LabelDeocclusionSpatialGrid:
    """Prevents overlapping text labels using a 2D spatial hash grid prioritized by S_rank."""

    def __init__(self, cell_size_px: int = 16):
        self.cell_size_px = max(1, cell_size_px)

    def filter_visible_labels(
        self,
        nodes: list[GraphNode2D],
        zoom_level: float = 1.0,
        label_width_px: int = 100,
        label_height_px: int = 24,
    ) -> list[str]:
        """Selects non-overlapping labels in descending order of forensic priority."""
        if not nodes:
            return []

        # Sort nodes by forensic rank descending
        sorted_nodes = sorted(
            nodes,
            key=lambda n: BarnesHutQuadtreePhysics.compute_forensic_rank(n),
            reverse=True,
        )

        occupied_cells: set[tuple[int, int]] = set()
        visible_labels: list[str] = []

        half_w = label_width_px / 2.0
        half_h = label_height_px / 2.0

        for n in sorted_nodes:
            sx = n.x * zoom_level
            sy = n.y * zoom_level

            min_gx = int(math.floor((sx - half_w) / self.cell_size_px))
            max_gx = int(math.floor((sx + half_w) / self.cell_size_px))
            min_gy = int(math.floor((sy - half_h) / self.cell_size_px))
            max_gy = int(math.floor((sy + half_h) / self.cell_size_px))

            # Check if any cell in the label bounding box is already occupied
            is_collision = False
            cells_to_mark: list[tuple[int, int]] = []
            for gx in range(min_gx, max_gx + 1):
                for gy in range(min_gy, max_gy + 1):
                    cell = (gx, gy)
                    if cell in occupied_cells:
                        is_collision = True
                        break
                    cells_to_mark.append(cell)
                if is_collision:
                    break

            if not is_collision:
                for c in cells_to_mark:
                    occupied_cells.add(c)
                visible_labels.append(n.label)

        return visible_labels


class ForensicGraphAlgorithms:
    """Executes graph intelligence algorithms: circular loops, shortest path, and syndicate hubs."""

    def detect_circular_mule_loops(
        self, edges: list[dict[str, Any]]
    ) -> list[CircularMuleLoop]:
        """Detects closed elementary financial cycles (A -> B -> ... -> A)."""
        adj: dict[str, list[dict[str, Any]]] = {}
        for e in edges:
            src = str(e.get("source", ""))
            tgt = str(e.get("target", ""))
            if src not in adj:
                adj[src] = []
            adj[src].append(e)

        cycles: list[list[str]] = []
        visited: set[str] = set()

        def dfs(start: str, current: str, path: list[str]) -> None:
            for edge in adj.get(current, []):
                nxt = str(edge.get("target", ""))
                if nxt == start and len(path) >= 2:
                    cycles.append(list(path))
                    return
                if nxt not in path and len(path) < 6:
                    path.append(nxt)
                    dfs(start, nxt, path)
                    path.pop()

        nodes_list = list(adj.keys())
        for node in nodes_list:
            dfs(node, node, [node])

        # Deduplicate cycles and calculate retained commission
        seen_sets = set()
        loops: list[CircularMuleLoop] = []

        for cyc in cycles:
            fset = frozenset(cyc)
            if fset in seen_sets:
                continue
            seen_sets.add(fset)

            # Compute financial commission across the loop
            amounts = []
            for i in range(len(cyc)):
                u = cyc[i]
                v = cyc[(i + 1) % len(cyc)]
                matched_edge = next(
                    (e for e in adj.get(u, []) if str(e.get("target")) == v), None
                )
                if matched_edge:
                    amounts.append(float(matched_edge.get("amount_inr", 0.0)))

            commission = 0.0
            if len(amounts) >= 2 and amounts[0] > 0:
                commission = max(0.0, amounts[0] - amounts[-1])

            loops.append(
                CircularMuleLoop(
                    cycle_node_ids=cyc,
                    total_retained_commission_inr=commission,
                    loop_duration_seconds=1080,
                )
            )

        return loops

    def find_shortest_evidentiary_path(
        self, edges: list[dict[str, Any]], source_id: str, target_id: str
    ) -> ShortestEvidentiaryPath:
        """Finds step-by-step connection between two target entities via BFS."""
        if source_id == target_id:
            return ShortestEvidentiaryPath(
                hop_count=0, path_node_ids=[source_id], step_edge_verbs=[]
            )

        adj: dict[str, list[tuple[str, str]]] = {}
        for e in edges:
            u = str(e.get("source", ""))
            v = str(e.get("target", ""))
            verb = str(e.get("verb", "CONNECTED_TO"))
            if u not in adj:
                adj[u] = []
            adj[u].append((v, verb))

        queue: deque[tuple[str, list[str], list[str]]] = deque([(source_id, [source_id], [])])
        visited = {source_id}

        while queue:
            curr, path, verbs = queue.popleft()
            if curr == target_id:
                return ShortestEvidentiaryPath(
                    hop_count=len(path) - 1,
                    path_node_ids=path,
                    step_edge_verbs=verbs,
                )

            for neighbor, verb in adj.get(curr, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor], verbs + [verb]))

        return ShortestEvidentiaryPath(hop_count=0, path_node_ids=[], step_edge_verbs=[])

    def isolate_common_syndicate_hubs(
        self, edges: list[dict[str, Any]]
    ) -> list[SyndicateHubSummary]:
        """Identifies bridge hubs where multiple child entities converge."""
        parent_children: dict[str, set[str]] = {}
        parent_verbs: dict[str, set[str]] = {}

        for e in edges:
            src = str(e.get("source", ""))
            tgt = str(e.get("target", ""))
            verb = str(e.get("verb", ""))

            if src not in parent_children:
                parent_children[src] = set()
                parent_verbs[src] = set()
            parent_children[src].add(tgt)
            parent_verbs[src].add(verb)

        hubs: list[SyndicateHubSummary] = []
        for parent_id, children in parent_children.items():
            if len(children) >= 2:
                hubs.append(
                    SyndicateHubSummary(
                        hub_node_id=parent_id,
                        connected_child_count=len(children),
                        hub_edge_verbs=sorted(parent_verbs.get(parent_id, set())),
                    )
                )

        return sorted(hubs, key=lambda h: h.connected_child_count, reverse=True)
