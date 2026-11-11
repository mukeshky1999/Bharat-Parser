"""
64-Bit Perceptual Difference Hash (dHash) & Near-Duplicate Media Clustering (Sub-Engine 9.4B).
Computes horizontal gradient hashes and clusters re-compressed/forwarded copies (dH <= 6).
"""

from typing import Sequence

from src.geospatial_media_and_tamper.models import (
    MediaClusterStackCard,
    PerceptualDHashResult,
)


class PerceptualDHashClusterer:
    """Computes 64-bit dHash and clusters visual assets into unified stack cards."""

    def __init__(self, hamming_threshold: int = 6):
        self.hamming_threshold = max(0, min(64, hamming_threshold))

    def compute_dhash_uint64(self, pixels_9x8: Sequence[Sequence[int]]) -> int:
        """Calculates 64-bit perceptual hash by comparing adjacent horizontal pixels in 9x8 grid."""
        dhash = 0
        bit_index = 0

        for y in range(min(8, len(pixels_9x8))):
            row = pixels_9x8[y]
            row_len = len(row)
            for x in range(min(8, row_len - 1)):
                if row[x] > row[x + 1]:
                    dhash |= 1 << bit_index
                bit_index += 1

        return dhash

    @staticmethod
    def compute_hamming_distance(hash_a: int, hash_b: int) -> int:
        """Computes bitwise Hamming distance between two 64-bit hashes using POPCNT."""
        xor_val = hash_a ^ hash_b
        return xor_val.bit_count()

    def cluster_media_items(
        self, items: list[PerceptualDHashResult]
    ) -> list[MediaClusterStackCard]:
        """Groups near-duplicate media into cluster stacks based on Hamming distance threshold."""
        if not items:
            return []

        n = len(items)
        # Disjoint set / union-find for clustering
        parent = list(range(n))

        def find(i: int) -> int:
            path = []
            curr = i
            while parent[curr] != curr:
                path.append(curr)
                curr = parent[curr]
            for node in path:
                parent[node] = curr
            return curr

        def union(i: int, j: int) -> None:
            root_i = find(i)
            root_j = find(j)
            if root_i != root_j:
                parent[root_j] = root_i

        # Connect items whose distance <= threshold
        for i in range(n):
            for j in range(i + 1, n):
                dist = self.compute_hamming_distance(
                    items[i].dhash_uint64, items[j].dhash_uint64
                )
                if dist <= self.hamming_threshold:
                    union(i, j)

        # Group by root
        cluster_groups: dict[int, list[PerceptualDHashResult]] = {}
        for idx, item in enumerate(items):
            root = find(idx)
            if root not in cluster_groups:
                cluster_groups[root] = []
            cluster_groups[root].append(item)

        cards: list[MediaClusterStackCard] = []
        cluster_counter = 1

        for group in cluster_groups.values():
            master_id = group[0].image_id
            copy_count = len(group)
            member_ids = [item.image_id for item in group]

            # Preserve unique order of apps
            seen_apps = []
            for item in group:
                if item.originating_app and item.originating_app not in seen_apps:
                    seen_apps.append(item.originating_app)

            apps_str = " -> ".join(seen_apps) if seen_apps else "Device"
            badge = f"[📚 {copy_count} Copies: {apps_str}]"

            cards.append(
                MediaClusterStackCard(
                    cluster_id=cluster_counter,
                    master_image_id=master_id,
                    total_copy_count=copy_count,
                    member_image_ids=member_ids,
                    stack_badge_text=badge,
                    apps_involved=seen_apps,
                )
            )
            cluster_counter += 1

        return cards
