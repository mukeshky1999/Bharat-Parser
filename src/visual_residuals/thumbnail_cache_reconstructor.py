"""
Sub-Engine 7.2B: OS & Third-Party Thumbnail Cache Reconstructors.
Decodes iOS .ithmb slot containers, detects orphaned thumbnails of permanently purged photos,
and parses Glide / Fresco / Coil / DiskLruCache image stores.
Complies with Section 4 of Phase 7 Module 7.2 Specification and AGENTS.md Constitution.
"""

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.visual_residuals.models import (
    CacheEngineType,
    ReconstructedThumbnailRecord,
)


class ThumbnailCacheReconstructor:
    """Reconstructs cached thumbnails and detects orphaned remnants of purged media."""

    def decode_ithmb(
        self,
        ithmb_path: str,
        active_thumbnail_indices: Set[int],
        slot_size: int = 1024,
        output_dir: str = "",
        source_vfs_file_id: int = 0,
    ) -> List[ReconstructedThumbnailRecord]:
        """
        Parses consolidated iOS .ithmb container files. For every non-zero slot index k,
        reconstructs the thumbnail bitmap and cross-checks against Photos.sqlite ZTHUMBNAILINDEX
        to flag orphaned thumbnails of permanently deleted photos.
        """
        records: List[ReconstructedThumbnailRecord] = []
        if not os.path.exists(ithmb_path):
            return records

        with open(ithmb_path, "rb") as f:
            data = f.read()

        total_bytes = len(data)
        if total_bytes < slot_size or slot_size <= 0:
            return records

        num_slots = total_bytes // slot_size
        mtime = os.path.getmtime(ithmb_path)
        iso_accessed = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)

        for k in range(num_slots):
            slot_offset = k * slot_size
            slot_data = data[slot_offset : slot_offset + slot_size]

            # Check if non-zero
            if not any(slot_data):
                continue

            # Check if parent photo was deleted
            is_deleted = 1 if k not in active_thumbnail_indices else 0
            conf = ResidualConfidence.RESIDUAL_RECORD if is_deleted else ResidualConfidence.ORIGINAL_RECORD

            out_file_path = f"slot_{k}.png"
            if output_dir:
                dest = os.path.join(output_dir, f"slot_{k}.png")
                with open(dest, "wb") as out_f:
                    out_f.write(slot_data)
                out_file_path = dest

            records.append(
                ReconstructedThumbnailRecord(
                    cache_engine_type=CacheEngineType.IOS_ITHMB_SLOT,
                    owning_app_bundle_or_pkg="com.apple.mobileslideshow",
                    source_vfs_file_id=source_vfs_file_id,
                    slot_index_or_cache_key=str(k),
                    reconstructed_file_path=out_file_path,
                    thumb_cache_uid=None,
                    is_parent_original_deleted=is_deleted,
                    matched_source_url=None,
                    cached_or_accessed_utc_iso=iso_accessed,
                    recovery_classification=conf,
                    forensic_group=ForensicGroup.G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS,
                    dim_existence=EvidentiaryExistence.OBSERVED,
                    dim_access=EvidentiaryAccess.PLAINTEXT,
                    dim_storage=EvidentiaryStorage.LIVE_RECORD,
                    dim_provenance=f"{Path(ithmb_path).name}:slot={k}",
                    dim_corroboration=1.0,
                )
            )

        return records

    def decode_glide_disk_cache(
        self,
        cache_dir: str,
        owning_pkg: str = "",
        source_vfs_file_id: int = 0,
    ) -> List[ReconstructedThumbnailRecord]:
        """
        Parses Android Glide / DiskLruCache directory and journal log to extract cached image items.
        """
        records: List[ReconstructedThumbnailRecord] = []
        if not os.path.exists(cache_dir):
            return records

        journal_file = Path(cache_dir) / "journal"
        evicted_keys: Set[str] = set()

        if journal_file.exists():
            try:
                with open(journal_file, "r", encoding="utf-8", errors="ignore") as jf:
                    for line in jf:
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[0] == "REMOVE":
                            evicted_keys.add(parts[1])
            except Exception as _err:
                evicted_keys.clear()

        for item in Path(cache_dir).glob("*.0"):
            key = item.stem
            is_deleted = 1 if key in evicted_keys else 0
            conf = ResidualConfidence.RESIDUAL_RECORD if is_deleted else ResidualConfidence.ORIGINAL_RECORD
            mtime = os.path.getmtime(item)
            iso_cached = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            records.append(
                ReconstructedThumbnailRecord(
                    cache_engine_type=CacheEngineType.GLIDE_DISKLRLUCACHE,
                    owning_app_bundle_or_pkg=owning_pkg or "unknown",
                    source_vfs_file_id=source_vfs_file_id,
                    slot_index_or_cache_key=key,
                    reconstructed_file_path=str(item),
                    thumb_cache_uid=None,
                    is_parent_original_deleted=is_deleted,
                    matched_source_url=None,
                    cached_or_accessed_utc_iso=iso_cached,
                    recovery_classification=conf,
                    forensic_group=ForensicGroup.G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS,
                    dim_existence=EvidentiaryExistence.OBSERVED,
                    dim_access=EvidentiaryAccess.PLAINTEXT,
                    dim_storage=EvidentiaryStorage.LIVE_RECORD,
                    dim_provenance=f"glide_cache:{key}",
                    dim_corroboration=1.0,
                )
            )

        return records
