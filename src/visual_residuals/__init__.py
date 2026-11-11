"""
Phase 7 Module 7.2: Ephemeral Visual Residuals: OS App-Switcher Snapshots,
Thumbnail Caches & Disguised Calculator Vault Unmasking.
Complies with AGENTS.md Constitution.
"""

from src.visual_residuals.models import (
    SnapshotPlatform,
    CacheEngineType,
    VaultUnmaskingMethod,
    AppSwitcherSnapshotRecord,
    ReconstructedThumbnailRecord,
    UnmaskedVaultItemRecord,
    decode_task_snapshot_proto,
    parse_ktx_header,
    write_rgba_png,
)
from src.visual_residuals.app_switcher_decoder import AppSwitcherDecoder
from src.visual_residuals.thumbnail_cache_reconstructor import ThumbnailCacheReconstructor
from src.visual_residuals.vault_unmasker import VaultUnmasker
from src.visual_residuals.engine import VisualResidualsEngine

__all__ = [
    "SnapshotPlatform",
    "CacheEngineType",
    "VaultUnmaskingMethod",
    "AppSwitcherSnapshotRecord",
    "ReconstructedThumbnailRecord",
    "UnmaskedVaultItemRecord",
    "decode_task_snapshot_proto",
    "parse_ktx_header",
    "write_rgba_png",
    "AppSwitcherDecoder",
    "ThumbnailCacheReconstructor",
    "VaultUnmasker",
    "VisualResidualsEngine",
]
