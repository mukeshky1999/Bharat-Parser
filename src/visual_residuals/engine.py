"""
VisualResidualsEngine: Master orchestrator and SQLite exporter for OS App-Switcher Snapshots,
Thumbnail Caches, and Unmasked Vault Media.
Complies with Section 6 of Phase 7 Module 7.2 Specification and AGENTS.md Constitution.
"""

import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from src.visual_residuals.models import (
    AppSwitcherSnapshotRecord,
    ReconstructedThumbnailRecord,
    UnmaskedVaultItemRecord,
)
from src.visual_residuals.app_switcher_decoder import AppSwitcherDecoder
from src.visual_residuals.thumbnail_cache_reconstructor import ThumbnailCacheReconstructor
from src.visual_residuals.vault_unmasker import VaultUnmasker


class VisualResidualsEngine:
    """Master orchestrator for Ephemeral Visual Residuals Forensics."""

    def __init__(self) -> None:
        self.app_switcher_decoder = AppSwitcherDecoder()
        self.thumbnail_reconstructor = ThumbnailCacheReconstructor()
        self.vault_unmasker = VaultUnmasker()

    def export_to_sqlite(
        self,
        snapshots: List[AppSwitcherSnapshotRecord],
        thumbnails: List[ReconstructedThumbnailRecord],
        vault_items: List[UnmaskedVaultItemRecord],
        output_db_path: str,
    ) -> None:
        """
        Creates ephemeral_visual_residuals_engine.sqlite schema and persists all records.
        """
        out_dir = Path(output_db_path).parent
        out_dir.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        # Table 1: os_app_switcher_snapshots_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS os_app_switcher_snapshots_ledger (
                snapshot_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                os_platform TEXT NOT NULL,
                android_user_profile_id INTEGER DEFAULT 0,
                source_vfs_file_id INTEGER NOT NULL,
                converted_png_staging_id INTEGER,
                snapshot_file_path TEXT NOT NULL,
                captured_app_bundle_or_pkg TEXT NOT NULL,
                captured_activity_or_scene TEXT,
                is_real_content_snapshot INTEGER DEFAULT 1,
                pixel_dimensions_and_orient TEXT,
                snapshot_captured_utc_iso TEXT NOT NULL,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL,
                dim_existence TEXT NOT NULL,
                dim_access TEXT NOT NULL,
                dim_storage TEXT NOT NULL,
                dim_provenance TEXT,
                dim_corroboration REAL
            )
        """)

        # Table 2: reconstructed_thumbnails_and_disk_caches
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reconstructed_thumbnails_and_disk_caches (
                thumb_cache_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                cache_engine_type TEXT NOT NULL,
                owning_app_bundle_or_pkg TEXT NOT NULL,
                source_vfs_file_id INTEGER NOT NULL,
                slot_index_or_cache_key TEXT NOT NULL,
                reconstructed_file_path TEXT NOT NULL,
                is_parent_original_deleted INTEGER DEFAULT 0,
                matched_source_url TEXT,
                cached_or_accessed_utc_iso TEXT,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL,
                dim_existence TEXT NOT NULL,
                dim_access TEXT NOT NULL,
                dim_storage TEXT NOT NULL,
                dim_provenance TEXT,
                dim_corroboration REAL
            )
        """)

        # Table 3: unmasked_vault_and_hidden_media_ledger
        cur.execute("""
            CREATE TABLE IF NOT EXISTS unmasked_vault_and_hidden_media_ledger (
                vault_item_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                vault_app_name_and_pkg TEXT NOT NULL,
                obfuscated_vfs_file_id INTEGER NOT NULL,
                unmasking_method_applied TEXT NOT NULL,
                recovered_xor_or_aes_key_hex TEXT,
                original_filename_from_vault_db TEXT,
                restored_mime_type TEXT NOT NULL,
                restored_file_path TEXT NOT NULL,
                restored_derivative_staging_id INTEGER NOT NULL,
                hidden_into_vault_utc_iso TEXT,
                recovery_classification TEXT NOT NULL,
                forensic_group TEXT NOT NULL,
                dim_existence TEXT NOT NULL,
                dim_access TEXT NOT NULL,
                dim_storage TEXT NOT NULL,
                dim_provenance TEXT,
                dim_corroboration REAL
            )
        """)

        # Insert Snapshots
        for s in snapshots:
            cur.execute("""
                INSERT INTO os_app_switcher_snapshots_ledger (
                    os_platform, android_user_profile_id, source_vfs_file_id,
                    converted_png_staging_id, snapshot_file_path, captured_app_bundle_or_pkg,
                    captured_activity_or_scene, is_real_content_snapshot, pixel_dimensions_and_orient,
                    snapshot_captured_utc_iso, recovery_classification, forensic_group,
                    dim_existence, dim_access, dim_storage, dim_provenance, dim_corroboration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                s.os_platform.value if hasattr(s.os_platform, "value") else str(s.os_platform),
                s.android_user_profile_id,
                s.source_vfs_file_id,
                s.converted_png_staging_id,
                s.snapshot_file_path,
                s.captured_app_bundle_or_pkg,
                s.captured_activity_or_scene,
                s.is_real_content_snapshot,
                s.pixel_dimensions_and_orient,
                s.snapshot_captured_utc_iso,
                s.recovery_classification.value if hasattr(s.recovery_classification, "value") else str(s.recovery_classification),
                s.forensic_group.value if hasattr(s.forensic_group, "value") else str(s.forensic_group),
                s.dim_existence.value if hasattr(s.dim_existence, "value") else str(s.dim_existence),
                s.dim_access.value if hasattr(s.dim_access, "value") else str(s.dim_access),
                s.dim_storage.value if hasattr(s.dim_storage, "value") else str(s.dim_storage),
                s.dim_provenance,
                s.dim_corroboration,
            ))

        # Insert Thumbnails
        for t in thumbnails:
            cur.execute("""
                INSERT INTO reconstructed_thumbnails_and_disk_caches (
                    cache_engine_type, owning_app_bundle_or_pkg, source_vfs_file_id,
                    slot_index_or_cache_key, reconstructed_file_path, is_parent_original_deleted,
                    matched_source_url, cached_or_accessed_utc_iso, recovery_classification,
                    forensic_group, dim_existence, dim_access, dim_storage, dim_provenance,
                    dim_corroboration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                t.cache_engine_type.value if hasattr(t.cache_engine_type, "value") else str(t.cache_engine_type),
                t.owning_app_bundle_or_pkg,
                t.source_vfs_file_id,
                t.slot_index_or_cache_key,
                t.reconstructed_file_path,
                t.is_parent_original_deleted,
                t.matched_source_url,
                t.cached_or_accessed_utc_iso,
                t.recovery_classification.value if hasattr(t.recovery_classification, "value") else str(t.recovery_classification),
                t.forensic_group.value if hasattr(t.forensic_group, "value") else str(t.forensic_group),
                t.dim_existence.value if hasattr(t.dim_existence, "value") else str(t.dim_existence),
                t.dim_access.value if hasattr(t.dim_access, "value") else str(t.dim_access),
                t.dim_storage.value if hasattr(t.dim_storage, "value") else str(t.dim_storage),
                t.dim_provenance,
                t.dim_corroboration,
            ))

        # Insert Vault Items
        for v in vault_items:
            cur.execute("""
                INSERT INTO unmasked_vault_and_hidden_media_ledger (
                    vault_app_name_and_pkg, obfuscated_vfs_file_id, unmasking_method_applied,
                    recovered_xor_or_aes_key_hex, original_filename_from_vault_db,
                    restored_mime_type, restored_file_path, restored_derivative_staging_id,
                    hidden_into_vault_utc_iso, recovery_classification, forensic_group,
                    dim_existence, dim_access, dim_storage, dim_provenance, dim_corroboration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                v.vault_app_name_and_pkg,
                v.obfuscated_vfs_file_id,
                v.unmasking_method_applied.value if hasattr(v.unmasking_method_applied, "value") else str(v.unmasking_method_applied),
                v.recovered_xor_or_aes_key_hex,
                v.original_filename_from_vault_db,
                v.restored_mime_type,
                v.restored_file_path,
                v.restored_derivative_staging_id,
                v.hidden_into_vault_utc_iso,
                v.recovery_classification.value if hasattr(v.recovery_classification, "value") else str(v.recovery_classification),
                v.forensic_group.value if hasattr(v.forensic_group, "value") else str(v.forensic_group),
                v.dim_existence.value if hasattr(v.dim_existence, "value") else str(v.dim_existence),
                v.dim_access.value if hasattr(v.dim_access, "value") else str(v.dim_access),
                v.dim_storage.value if hasattr(v.dim_storage, "value") else str(v.dim_storage),
                v.dim_provenance,
                v.dim_corroboration,
            ))

        conn.commit()
        conn.close()
