"""
Polygon Lasso Selection & Golden-Hour Nodal Freeze Cart Manager (Sub-Engine 9.3D & Section 7).
Implements ray-casting point-in-polygon filtering and persists views and freeze items in SQLite.
"""

from dataclasses import asdict
import json
import os
import sqlite3
from typing import Any, Optional

from src.financial_graph_and_storyboard.models import (
    NodalFreezeCartItem,
    SavedGraphViewState,
)


class NodalFreezeCartManager:
    """Filters graph entities by polygon lasso and manages freeze cart persistence."""

    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS saved_graph_views_and_freeze_cart_state (
        view_state_uid INTEGER PRIMARY KEY AUTOINCREMENT,
        canvas_mode TEXT NOT NULL,
        view_title TEXT NOT NULL,
        pinned_node_positions_json TEXT,
        active_graph_filters_json TEXT NOT NULL,
        staged_freeze_cart_items_json TEXT,
        saved_svg_png_snapshot_sha256 TEXT,
        updated_at_ist_iso TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_graph_views_mode
        ON saved_graph_views_and_freeze_cart_state(canvas_mode);
    """

    def initialize_cart_db(self, db_path: str) -> None:
        """Initializes SQLite schema for saved graph views and freeze cart state."""
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(self.SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _point_in_polygon(x: float, y: float, poly: list[tuple[float, float]]) -> bool:
        """Determines if point (x, y) is inside polygon using ray-casting."""
        n = len(poly)
        if n < 3:
            return False

        inside = False
        p1x, p1y = poly[0]
        for i in range(n + 1):
            p2x, p2y = poly[i % n]
            if y > min(p1y, p2y):
                if y <= max(p1y, p2y):
                    if x <= max(p1x, p2x):
                        xinters = x
                        if p1y != p2y:
                            xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        if p1x == p2x or x <= xinters:
                            inside = not inside
            p1x, p1y = p2x, p2y
        return inside

    def filter_nodes_by_lasso(
        self, polygon: list[tuple[float, float]], nodes: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Filters a collection of node dictionaries located within a freehand lasso polygon."""
        selected: list[dict[str, Any]] = []
        for node in nodes:
            x = float(node.get("x", 0.0))
            y = float(node.get("y", 0.0))
            if self._point_in_polygon(x, y, polygon):
                selected.append(node)
        return selected

    def save_graph_view_state(
        self, db_path: str, view_state: SavedGraphViewState
    ) -> int:
        """Saves or updates a graph view and staged freeze cart state in SQLite."""
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cart_dicts = [asdict(item) for item in view_state.staged_freeze_cart_items]
            cur.execute(
                """
                INSERT INTO saved_graph_views_and_freeze_cart_state (
                    canvas_mode,
                    view_title,
                    pinned_node_positions_json,
                    active_graph_filters_json,
                    staged_freeze_cart_items_json,
                    saved_svg_png_snapshot_sha256,
                    updated_at_ist_iso
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    view_state.canvas_mode,
                    view_state.view_title,
                    json.dumps(view_state.pinned_node_positions),
                    json.dumps(view_state.active_filters),
                    json.dumps(cart_dicts),
                    view_state.saved_svg_png_snapshot_sha256,
                    view_state.updated_at_ist_iso,
                ),
            )
            conn.commit()
            return cur.lastrowid or 0
        finally:
            conn.close()

    def get_graph_view_state_by_uid(
        self, db_path: str, view_state_uid: int
    ) -> Optional[SavedGraphViewState]:
        """Loads a saved graph view state and staged freeze items by primary key."""
        conn = sqlite3.connect(db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT
                    view_state_uid,
                    canvas_mode,
                    view_title,
                    pinned_node_positions_json,
                    active_graph_filters_json,
                    staged_freeze_cart_items_json,
                    saved_svg_png_snapshot_sha256,
                    updated_at_ist_iso
                FROM saved_graph_views_and_freeze_cart_state
                WHERE view_state_uid = ?;
                """,
                (view_state_uid,),
            )
            row = cur.fetchone()
            if not row:
                return None

            pinned = json.loads(row[3]) if row[3] else {}
            filters = json.loads(row[4]) if row[4] else {}
            raw_cart = json.loads(row[5]) if row[5] else []

            items: list[NodalFreezeCartItem] = []
            for d in raw_cart:
                items.append(
                    NodalFreezeCartItem(
                        instrument_type=d.get("instrument_type", "BANK_ACCOUNT"),
                        account_or_address=d.get("account_or_address", ""),
                        ifsc_or_network=d.get("ifsc_or_network"),
                        linked_vpa=d.get("linked_vpa"),
                        linked_utr=d.get("linked_utr"),
                        source_entity_id=d.get("source_entity_id"),
                    )
                )

            return SavedGraphViewState(
                view_state_uid=row[0],
                canvas_mode=row[1],
                view_title=row[2],
                pinned_node_positions=pinned,
                active_filters=filters,
                staged_freeze_cart_items=items,
                saved_svg_png_snapshot_sha256=row[6],
                updated_at_ist_iso=row[7],
            )
        finally:
            conn.close()
