"""
4 KB Sliding-Window Shannon Block Entropy Skyline Profiler (Sub-Engine 9.5A).
Computes H(b_k) across contiguous 4 KB pages, 4-class byte compositions, and 256-bin Chi-Square histograms.
"""

from collections import Counter
import math

from src.unk_triage_and_bsa_studio.models import (
    BlockByteComposition,
    BlockEntropyResult,
    ChiSquareHistogramResult,
)


class SlidingWindowEntropyProfiler:
    """Profiles block entropy curves and byte class stacks to isolate encrypted vs plaintext regions."""

    def __init__(self, block_size_bytes: int = 4096):
        self.block_size_bytes = max(512, block_size_bytes)

    def compute_block_entropy_skyline(self, file_bytes: bytes) -> BlockEntropyResult:
        """Calculates per-block Shannon entropy and 4-class byte composition."""
        total_len = len(file_bytes)
        if total_len == 0:
            return BlockEntropyResult(
                block_size_bytes=self.block_size_bytes,
                total_file_bytes=0,
                block_count=0,
                block_entropies=[],
                block_compositions=[],
            )

        block_count = math.ceil(total_len / self.block_size_bytes)
        entropies: list[float] = []
        compositions: list[BlockByteComposition] = []

        for k in range(block_count):
            start = k * self.block_size_bytes
            end = min(total_len, (k + 1) * self.block_size_bytes)
            chunk = file_bytes[start:end]
            n_k = len(chunk)

            if n_k == 0:
                continue

            counts = Counter(chunk)

            # Shannon Entropy: -sum((c / n) * log2(c / n))
            h = 0.0
            for count in counts.values():
                p = count / n_k
                if p > 0.0:
                    h -= p * math.log2(p)
            entropies.append(round(h, 4))

            # 4-class byte composition
            null_count = counts.get(0, 0)
            all_ones_count = counts.get(255, 0)

            printable_count = 0
            high_bit_count = 0

            for b, cnt in counts.items():
                if b in (9, 10, 13) or (32 <= b <= 126):
                    printable_count += cnt
                elif 128 <= b <= 254:
                    high_bit_count += cnt

            comp = BlockByteComposition(
                null_zero_pct=round((null_count / n_k) * 100.0, 2),
                printable_ascii_pct=round((printable_count / n_k) * 100.0, 2),
                high_bit_structured_pct=round((high_bit_count / n_k) * 100.0, 2),
                all_ones_erase_pct=round((all_ones_count / n_k) * 100.0, 2),
            )
            compositions.append(comp)

        return BlockEntropyResult(
            block_size_bytes=self.block_size_bytes,
            total_file_bytes=total_len,
            block_count=len(entropies),
            block_entropies=entropies,
            block_compositions=compositions,
        )

    @staticmethod
    def compute_256bin_chi_squared(data_bytes: bytes) -> ChiSquareHistogramResult:
        """Builds 256-bin byte frequency histogram and computes Chi-Square statistic against ideal uniform distribution."""
        n = len(data_bytes)
        observed = [0] * 256
        for b in data_bytes:
            observed[b] += 1

        ideal = n / 256.0
        chi_sq = 0.0
        if ideal > 0.0:
            for obs in observed:
                diff = obs - ideal
                chi_sq += (diff * diff) / ideal

        # Standard Chi-Square uniformity range for degrees of freedom = 255 at alpha=0.05 is [180, 350]
        is_uniform = 180.0 <= chi_sq <= 350.0

        return ChiSquareHistogramResult(
            observed_counts=observed,
            ideal_uniform_reference=ideal,
            chi_squared_statistic=round(chi_sq, 2),
            is_likely_uniform_ciphertext=is_uniform,
        )
