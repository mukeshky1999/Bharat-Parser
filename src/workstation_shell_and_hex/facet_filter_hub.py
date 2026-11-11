"""
Sub-Millisecond Roaring-Bitmap Facet Filter Hub (Sub-Engine 9.1C).
Maintains 32-bit Roaring Bitmaps across forensic dimensions for sub-5ms RAM facet filtering.
"""

from typing import Optional
from src.zero_omission_and_fts5.fts5_roaring_engine import RoaringBitmap32


class RoaringFacetFilterHub:
    """Manages pre-computed 32-bit Roaring Bitmaps across forensic dimensions."""

    def __init__(self):
        # Maps dimension -> {value: RoaringBitmap32}
        self._facet_bitmaps: dict[str, dict[str, RoaringBitmap32]] = {}

    def register_facet_bitmap(
        self, dimension: str, value: str, uids: list[int]
    ) -> None:
        """Indexes a list of timeline event UIDs into a compressed RoaringBitmap32."""
        bitmap = RoaringBitmap32()
        for uid in uids:
            bitmap.add(uid)

        if dimension not in self._facet_bitmaps:
            self._facet_bitmaps[dimension] = {}
        self._facet_bitmaps[dimension][value] = bitmap

    def get_facet_bitmap(
        self, dimension: str, value: str
    ) -> Optional[RoaringBitmap32]:
        """Retrieves a registered RoaringBitmap32 or None if not found."""
        dim_map = self._facet_bitmaps.get(dimension)
        if not dim_map:
            return None
        return dim_map.get(value)

    def get_facet_cardinality(self, dimension: str, value: str) -> int:
        """Returns the population count of records matching a specific facet value."""
        bm = self.get_facet_bitmap(dimension, value)
        if bm is None:
            return 0
        return bm.cardinality()

    def intersect_facets(self, facet_filters: dict[str, str]) -> list[int]:
        """Intersects multiple facet dimensions in RAM and returns sorted list of matching UIDs."""
        if not facet_filters:
            return []

        # Collect the matching bitmaps for active filter keys
        active_bitmaps: list[RoaringBitmap32] = []
        for dim, val in facet_filters.items():
            bm = self.get_facet_bitmap(dim, val)
            if bm is None:
                # If any selected facet value has no records, intersection is empty
                return []
            active_bitmaps.append(bm)

        if not active_bitmaps:
            return []

        # Sort by cardinality to intersect smallest bitmap first for performance
        sorted_bitmaps = sorted(active_bitmaps, key=lambda b: b.cardinality())

        result_bm = sorted_bitmaps[0]
        for next_bm in sorted_bitmaps[1:]:
            result_bm = result_bm.intersection(next_bm)
            if result_bm.cardinality() == 0:
                return []

        return result_bm.to_list()

    def recalculate_badge_counts(
        self, active_filters: dict[str, str]
    ) -> dict[str, dict[str, int]]:
        """Recalculates dynamic (N) record counts for all sidebar facet badges given active filters."""
        # Baseline intersection of current active filters
        base_bm: Optional[RoaringBitmap32] = None
        for dim, val in active_filters.items():
            bm = self.get_facet_bitmap(dim, val)
            if bm is None:
                base_bm = RoaringBitmap32()
                break
            if base_bm is None:
                base_bm = bm
            else:
                base_bm = base_bm.intersection(bm)

        counts: dict[str, dict[str, int]] = {}
        for dim, val_map in self._facet_bitmaps.items():
            counts[dim] = {}
            for val, bm in val_map.items():
                if base_bm is None:
                    counts[dim][val] = bm.cardinality()
                else:
                    counts[dim][val] = base_bm.intersection(bm).cardinality()

        return counts
