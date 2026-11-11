"""
OSMediaLibraryEngine: Master orchestrator and SQLite exporter for Mobile OS Media Library Forensics.
Persists unified findings into os_media_library_and_provenance.sqlite.
Complies with Section 6 of Phase 7 Module 7.1 Specification and AGENTS.md Constitution.
"""

import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from src.media_library.models import (
    MediaAssetRecord,
)
from src.media_library.ios_photos_decoder import IOSPhotosDecoder
from src.media_library.android_mediaprovider_decoder import AndroidMediaProviderDecoder
from src.media_library.binary_provenance_carver import BinaryProvenanceCarver


class OSMediaLibraryEngine:
    """Master orchestrator for Mobile Media Library Forensics and Provenance Attribution."""

    def __init__(self) -> None:
        self.ios_decoder = IOSPhotosDecoder()
        self.android_decoder = AndroidMediaProviderDecoder()
        self.provenance_carver = BinaryProvenanceCarver()

    def export_to_sqlite(
        self,
        records: List[MediaAssetRecord],
        output_db_path: str,
    ) -> None:
        """
        Creates os_media_library_and_provenance.sqlite schema and persists all media records.
        """
        out_dir = Path(output_db_path).parent
        out_dir.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(output_db_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS os_media_library_master_ledger (
                media_asset_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                os_platform_source TEXT NOT NULL,
                vfs_file_id INTEGER,
                recovery_classification TEXT NOT NULL,
                canonical_file_path TEXT NOT NULL,
                original_pre_import_filename TEXT,
                provenance_classification TEXT NOT NULL,
                originating_app_bundle_or_pkg TEXT,
                user_concealment_state TEXT NOT NULL,
                trashed_or_deleted_utc_iso TEXT,
                has_uncropped_original_recovered INTEGER DEFAULT 0,
                mutations_edited_vfs_file_id INTEGER,
                mutations_edited_file_path TEXT,
                paired_live_or_motion_video_id INTEGER,
                paired_video_file_path TEXT,
                linked_chat_syndication_id TEXT,
                capture_created_utc_iso TEXT,
                library_imported_utc_iso TEXT,
                capture_timezone_offset_str TEXT,
                gps_lat_lon_alt_heading_json TEXT,
                camera_make_model_lens TEXT,
                file_sha256 TEXT,
                forensic_group TEXT NOT NULL,
                dim_existence TEXT NOT NULL,
                dim_access TEXT NOT NULL,
                dim_storage TEXT NOT NULL,
                dim_provenance TEXT,
                dim_corroboration REAL
            )
        """)

        for r in records:
            cur.execute("""
                INSERT INTO os_media_library_master_ledger (
                    os_platform_source, vfs_file_id, recovery_classification,
                    canonical_file_path, original_pre_import_filename,
                    provenance_classification, originating_app_bundle_or_pkg,
                    user_concealment_state, trashed_or_deleted_utc_iso,
                    has_uncropped_original_recovered, mutations_edited_vfs_file_id,
                    mutations_edited_file_path, paired_live_or_motion_video_id,
                    paired_video_file_path, linked_chat_syndication_id,
                    capture_created_utc_iso, library_imported_utc_iso,
                    capture_timezone_offset_str, gps_lat_lon_alt_heading_json,
                    camera_make_model_lens, file_sha256, forensic_group,
                    dim_existence, dim_access, dim_storage, dim_provenance,
                    dim_corroboration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.os_platform_source.value if hasattr(r.os_platform_source, "value") else str(r.os_platform_source),
                r.vfs_file_id,
                r.recovery_classification.value if hasattr(r.recovery_classification, "value") else str(r.recovery_classification),
                r.canonical_file_path,
                r.original_pre_import_filename,
                r.provenance_classification.value if hasattr(r.provenance_classification, "value") else str(r.provenance_classification),
                r.originating_app_bundle_or_pkg,
                r.user_concealment_state.value if hasattr(r.user_concealment_state, "value") else str(r.user_concealment_state),
                r.trashed_or_deleted_utc_iso,
                r.has_uncropped_original_recovered,
                r.mutations_edited_vfs_file_id,
                r.mutations_edited_file_path,
                r.paired_live_or_motion_video_id,
                r.paired_video_file_path,
                r.linked_chat_syndication_id,
                r.capture_created_utc_iso,
                r.library_imported_utc_iso,
                r.capture_timezone_offset_str,
                r.gps_lat_lon_alt_heading_json,
                r.camera_make_model_lens,
                r.file_sha256,
                r.forensic_group.value if hasattr(r.forensic_group, "value") else str(r.forensic_group),
                r.dim_existence.value if hasattr(r.dim_existence, "value") else str(r.dim_existence),
                r.dim_access.value if hasattr(r.dim_access, "value") else str(r.dim_access),
                r.dim_storage.value if hasattr(r.dim_storage, "value") else str(r.dim_storage),
                r.dim_provenance,
                r.dim_corroboration,
            ))

        conn.commit()
        conn.close()
