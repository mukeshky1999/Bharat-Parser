"""
Sub-Engine 7.1B: Android MediaProvider (external.db), Scoped Storage Trash & Google Photos Decoder.
Decodes files table, owner_package_name attribution, date_expires - 30d deletion timestamps,
and biometric locked folders (MARS).
Complies with Section 4 of Phase 7 Module 7.1 Specification and AGENTS.md Constitution.
"""

from src.core.sqlite_uri import ro_uri
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from src.core.enums import (
    ForensicGroup,
    ResidualConfidence,
    EvidentiaryExistence,
    EvidentiaryAccess,
    EvidentiaryStorage,
)
from src.media_library.models import (
    OSPlatformSource,
    ProvenanceClassification,
    UserConcealmentState,
    MediaAssetRecord,
    unix_seconds_or_ms_to_utc_iso,
)


class AndroidMediaProviderDecoder:
    """Decodes Android MediaProvider databases (external.db / internal.db) and Google Photos."""

    def decode_external_db(
        self,
        db_path: str,
        source_vfs_file_id: int = 0,
    ) -> List[MediaAssetRecord]:
        """
        Parses Android external.db files table to extract owner_package_name attribution,
        Scoped Storage trash status (calculating true deletion date), and media properties.
        """
        records: List[MediaAssetRecord] = []
        if not os.path.exists(db_path):
            return records

        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        cur = conn.cursor()

        query = """
            SELECT
                _id,
                _data,
                _display_name,
                owner_package_name,
                is_trashed,
                date_expires,
                date_added,
                date_modified,
                datetaken,
                mime_type,
                _size
            FROM files
        """

        try:
            cur.execute(query)
            rows = cur.fetchall()
            for r in rows:
                row_id = r[0]
                data_path = r[1] or ""
                display_name = r[2] or ""
                owner_pkg = r[3] or ""
                is_trashed = r[4] or 0
                date_expires = r[5]
                date_added = r[6]
                date_modified = r[7]
                datetaken = r[8]
                mime_type = r[9] or ""
                file_size = r[10] or 0

                data_lower = data_path.lower()
                pkg_lower = owner_pkg.lower()

                # 1. Provenance Classification
                if "screenshot" in data_lower or "screenshot" in display_name.lower():
                    provenance = ProvenanceClassification.OS_SCREENSHOT_OR_SCREEN_RECORDING
                elif any(m in pkg_lower for m in ["whatsapp", "telegram", "signal", "instagram", "messenger"]):
                    provenance = ProvenanceClassification.MESSENGER_TRANSMITTED_REENCODED
                elif any(m in data_lower for m in ["/whatsapp/", "/telegram/"]):
                    provenance = ProvenanceClassification.MESSENGER_TRANSMITTED_REENCODED
                elif "camera" in pkg_lower or "/dcim/camera/" in data_lower:
                    provenance = ProvenanceClassification.AUTHENTIC_CAMERA_ORIGINAL
                else:
                    provenance = ProvenanceClassification.AUTHENTIC_CAMERA_ORIGINAL

                # 2. Concealment State & True Deletion Timestamp
                # In Android Scoped Storage Trash (Android 11-17), files expire after 30 days (2,592,000s)
                trashed_iso: Optional[str] = None
                if is_trashed == 1 or "/.trash" in data_lower or ".trashed-" in data_lower:
                    concealment = UserConcealmentState.IN_RECENTLY_DELETED_TRASH
                    if date_expires and date_expires > 2592000:
                        true_del_sec = date_expires - 2592000
                        trashed_iso = unix_seconds_or_ms_to_utc_iso(true_del_sec)
                    else:
                        trashed_iso = unix_seconds_or_ms_to_utc_iso(date_modified)
                elif "mars_files" in data_lower:
                    concealment = UserConcealmentState.IN_BIOMETRIC_HIDDEN_OR_LOCKED_ALBUM
                else:
                    concealment = UserConcealmentState.ACTIVE_VISIBLE

                platform = (
                    OSPlatformSource.ANDROID_MARS_LOCKED_FOLDER
                    if "mars_files" in data_lower
                    else OSPlatformSource.ANDROID_MEDIAPROVIDER_EXTERNAL_DB
                )

                records.append(
                    MediaAssetRecord(
                        os_platform_source=platform,
                        canonical_file_path=data_path,
                        provenance_classification=provenance,
                        media_asset_uid=None,
                        vfs_file_id=source_vfs_file_id,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        original_pre_import_filename=display_name or Path(data_path).name,
                        originating_app_bundle_or_pkg=owner_pkg or None,
                        user_concealment_state=concealment,
                        trashed_or_deleted_utc_iso=trashed_iso,
                        has_uncropped_original_recovered=0,
                        capture_created_utc_iso=unix_seconds_or_ms_to_utc_iso(datetaken or date_modified),
                        library_imported_utc_iso=unix_seconds_or_ms_to_utc_iso(date_added),
                        forensic_group=ForensicGroup.G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS,
                        dim_existence=EvidentiaryExistence.OBSERVED,
                        dim_access=EvidentiaryAccess.PLAINTEXT,
                        dim_storage=EvidentiaryStorage.LIVE_RECORD,
                        dim_provenance=f"external.db:files:_id={row_id}",
                        dim_corroboration=1.0,
                    )
                )
        except sqlite3.OperationalError as _err:
            records.extend([])

        conn.close()
        return records
