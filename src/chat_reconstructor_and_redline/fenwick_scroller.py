"""
Dynamic Fenwick-Tree (Binary Indexed Tree) Variable-Height Virtual Scroller (Sub-Engine 9.2A).
Maintains prefix sums of 500,000+ arbitrary bubble heights in O(log N) time,
enabling sub-millisecond binary lifting seeking and 60 FPS viewport windowing.
"""

import math
from typing import Sequence


class FenwickTreeVirtualScroller:
    """Maintains 1-indexed dynamic Fenwick Tree of bubble heights for variable-height virtualization."""

    def __init__(self, size: int):
        self.size = max(1, size)
        self._tree = [0] * (self.size + 1)
        self._heights = [0] * self.size

    @classmethod
    def from_heights(cls, heights: Sequence[int]) -> "FenwickTreeVirtualScroller":
        """Constructs and initializes the Fenwick Tree from an initial array of heights in O(N)."""
        n = len(heights)
        scroller = cls(size=n)
        scroller._heights = list(heights)

        # O(N) linear construction
        for i in range(1, n + 1):
            scroller._tree[i] += heights[i - 1]
            parent = i + (i & (-i))
            if parent <= n:
                scroller._tree[parent] += scroller._tree[i]

        return scroller

    def prefix_sum(self, k: int) -> int:
        """Returns the sum of heights from bubble 1 to k (1-indexed)."""
        if k <= 0:
            return 0
        idx = min(k, self.size)
        total = 0
        while idx > 0:
            total += self._tree[idx]
            idx -= idx & (-idx)
        return total

    def total_height(self) -> int:
        """Returns the total scrollable container height in pixels."""
        return self.prefix_sum(self.size)

    def y_top(self, index: int) -> int:
        """Returns the exact top Y pixel offset for bubble at index (1-indexed)."""
        if index <= 1:
            return 0
        return self.prefix_sum(index - 1)

    def update_delta(self, index: int, delta_h: int) -> None:
        """Propagates a DOM resize height change (delta_h) in O(log N) time."""
        if index < 1 or index > self.size or delta_h == 0:
            return

        self._heights[index - 1] += delta_h
        idx = index
        while idx <= self.size:
            self._tree[idx] += delta_h
            idx += idx & (-idx)

    def find_first_visible_index(self, scroll_top_px: int) -> int:
        """Finds the 1-indexed bubble index for a scroll offset via O(log N) binary lifting (< 1ms)."""
        if scroll_top_px <= 0:
            return 1

        # Largest power of 2 <= size
        p = 1
        while (p << 1) <= self.size:
            p <<= 1

        idx = 0
        accum_px = 0
        while p > 0:
            candidate = idx + p
            if candidate <= self.size and (accum_px + self._tree[candidate]) <= scroll_top_px:
                idx = candidate
                accum_px += self._tree[candidate]
            p >>= 1

        return min(self.size, idx + 1)

    def compute_visible_range(
        self, scroll_top_px: int, viewport_height_px: int, overscan_buffer: int = 10
    ) -> tuple[int, int]:
        """Calculates visible mounted bubble range (i_first, i_last) bounded by DOM element guards."""
        i_first_raw = self.find_first_visible_index(scroll_top_px)
        i_first = max(1, i_first_raw - max(0, overscan_buffer))

        scroll_bottom_px = scroll_top_px + viewport_height_px
        i_last_raw = self.find_first_visible_index(scroll_bottom_px)
        i_last = min(self.size, i_last_raw + max(0, overscan_buffer))

        return i_first, i_last

    @staticmethod
    def estimate_bubble_height(
        text_length: int,
        has_quote: bool = False,
        has_media: bool = False,
        is_edited_or_revoked: bool = False,
    ) -> int:
        """Computes deterministic estimated height h_est in O(1) from message metadata."""
        h_chrome = 38
        c_chars_per_line = 35
        l_line_px = 20
        h_quote = 56 if has_quote else 0
        h_media = 240 if has_media else 0
        h_redline = 32 if is_edited_or_revoked else 0

        lines = math.ceil(max(1, text_length) / c_chars_per_line)
        return h_chrome + (lines * l_line_px) + h_quote + h_media + h_redline
