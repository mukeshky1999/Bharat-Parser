"""
Virtualized Evidence Grid & Keyset Pagination Math (Sub-Engine 9.1D).
Calculates 60 FPS viewport window bounds and performs O(1) quantile milestone seeking over 50M+ rows.
"""

import bisect
import math
from typing import Any, Optional

from src.workstation_shell_and_hex.models import (
    QuantileMilestone,
    ViewportVirtualizationState,
)


class VirtualizedGridCalculator:
    """Computes viewport window bounds for fixed-pool DOM virtualization."""

    def __init__(self, row_height: int = 36, overscan_buffer: int = 10):
        self.row_height = max(1, row_height)
        self.overscan_buffer = max(0, overscan_buffer)

    def compute_viewport_window(
        self, scroll_top: int, viewport_height: int, total_rows: int
    ) -> ViewportVirtualizationState:
        """Calculates i_first and i_last indices according to Section 6.2 windowing equations."""
        if total_rows <= 0:
            return ViewportVirtualizationState(
                i_first=0,
                i_last=0,
                row_height=self.row_height,
                total_rows=0,
                mounted_row_count=0,
            )

        # i_first = max(0, floor(S_top / h_row) - B_over)
        first_raw = math.floor(scroll_top / self.row_height)
        i_first = max(0, first_raw - self.overscan_buffer)

        # i_last = min(N - 1, ceil((S_top + H_view) / h_row) + B_over)
        last_raw = math.ceil((scroll_top + viewport_height) / self.row_height)
        i_last = min(total_rows - 1, last_raw + self.overscan_buffer)

        mounted_count = max(0, i_last - i_first + 1)

        return ViewportVirtualizationState(
            i_first=i_first,
            i_last=i_last,
            row_height=self.row_height,
            total_rows=total_rows,
            mounted_row_count=mounted_count,
        )


class QuantileMilestoneSeeker:
    """Maintains an indexed quantile milestone seek map for O(1) scrollbar thumb jumping."""

    def __init__(self, quantile_interval: int = 10_000):
        self.quantile_interval = max(1, quantile_interval)
        self.milestones: list[QuantileMilestone] = []

    def load_milestones(self, milestones: list[QuantileMilestone]) -> None:
        """Loads and sorts quantile milestones by row_index."""
        self.milestones = sorted(milestones, key=lambda m: m.row_index)

    def seek_milestone_for_row(self, target_row: int) -> QuantileMilestone:
        """Finds the nearest preceding milestone checkpoint for an arbitrary scroll target in O(1)/O(log M)."""
        if not self.milestones:
            return QuantileMilestone(row_index=0, timestamp_utc_ns=0, timeline_event_uid=0)

        row_keys = [m.row_index for m in self.milestones]
        idx = bisect.bisect_right(row_keys, target_row) - 1

        if idx < 0:
            return self.milestones[0]
        if idx >= len(self.milestones):
            return self.milestones[-1]

        return self.milestones[idx]

    def build_keyset_query_params(
        self, milestone: QuantileMilestone, limit: int = 250
    ) -> dict[str, Any]:
        """Constructs keyset cursor query parameters for FastAPI."""
        return {
            "cursor_ts_ns": milestone.timestamp_utc_ns,
            "cursor_uid": milestone.timeline_event_uid,
            "limit": limit,
        }
