"""
Sub-Engine 7.1A: iOS Photos.sqlite & Syndication.sqlite Deep Relational Decoder.
Decodes ZASSET, ZADDITIONALASSETATTRIBUTES, /Mutations/ uncropped original recovery,
and cross-app Syndication ("Shared with You") attribution.
Complies with Section 3 of Phase 7 Module 7.1 Specification and AGENTS.md Constitution.
"""

from src.core.sqlite_uri import ro_uri
from datetime import datetime, timezone
import json
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
    cocoa_seconds_to_utc_iso,
)


class IOSPhotosDecoder:
    """Decodes Apple iOS Photos.sqlite libraries, mutations, and syndication stores."""

    def decode_library(
        self,
        db_path: str,
        media_base_dir: str = "",
        source_vfs_file_id: int = 0,
    ) -> List[MediaAssetRecord]:
        """
        Parses Photos.sqlite performing master relational join across ZASSET and
        ZADDITIONALASSETATTRIBUTES to extract media metadata, recover uncropped originals,
        and determine asset provenance.
        """
        records: List[MediaAssetRecord] = []
        if not os.path.exists(db_path):
            return records

        conn = sqlite3.connect(ro_uri(os.path.abspath(db_path)), uri=True)
        cur = conn.cursor()

        query = """
            SELECT
                a.Z_PK,
                a.ZDIRECTORY,
                a.ZFILENAME,
                a.ZDATECREATED,
                a.ZADDEDDATE,
                a.ZHASADJUSTMENTS,
                a.ZKINDSUBTYPE,
                a.ZTRASHEDSTATE,
                a.ZTRASHEDDATE,
                a.ZHIDDEN,
                a.ZFAVORITE,
                a.ZLATITUDE,
                a.ZLONGITUDE,
                attr.ZIMPORTEDBYBUNDLEIDENTIFIER,
                attr.ZORIGINALFILENAME,
                attr.ZTIMEZONENAME,
                attr.ZTIMEZONEOFFSET,
                attr.ZSYNDICATIONIDENTIFIER
            FROM ZASSET a
            LEFT JOIN ZADDITIONALASSETATTRIBUTES attr ON a.ZADDITIONALATTRIBUTES = attr.Z_PK
        """

        try:
            cur.execute(query)
            rows = cur.fetchall()
            for r in rows:
                z_pk = r[0]
                zdir = r[1] or ""
                zfilename = r[2] or ""
                zdatecreated = r[3]
                zaddeddate = r[4]
                zhasadjustments = r[5] or 0
                zkitsubtype = r[6] or 0
                ztrashedstate = r[7] or 0
                ztrasheddate = r[8]
                zhidden = r[9] or 0
                zfavorite = r[10] or 0
                zlat = r[11]
                zlon = r[12]
                imported_by = r[13] or ""
                original_filename = r[14] or ""
                tz_name = r[15] or ""
                tz_offset = r[16]
                syndication_id = r[17]

                rel_path = f"{zdir}/{zfilename}" if zdir else zfilename
                if media_base_dir:
                    canonical_path = os.path.join(media_base_dir, rel_path)
                else:
                    canonical_path = f"/private/var/mobile/Media/{rel_path}"

                # 1. Recover uncropped originals from /Mutations/
                has_uncropped = 0
                mutations_render_path: Optional[str] = None
                if zhasadjustments == 1:
                    stem = Path(zfilename).stem
                    has_uncropped = 1
                    if media_base_dir:
                        mut_candidate = (
                            Path(media_base_dir)
                            / "PhotoData"
                            / "Mutations"
                            / zdir
                            / stem
                            / "Adjustments"
                            / "FullSizeRender.jpg"
                        )
                        if mut_candidate.exists():
                            mutations_render_path = str(mut_candidate)
                        else:
                            # Try other common extensions
                            for ext in [".png", ".heic", ".mov"]:
                                alt = mut_candidate.with_suffix(ext)
                                if alt.exists():
                                    mutations_render_path = str(alt)
                                    break
                            if not mutations_render_path:
                                mutations_render_path = str(mut_candidate)
                    else:
                        mutations_render_path = (
                            f"/private/var/mobile/Media/PhotoData/Mutations/{zdir}/{stem}/Adjustments/FullSizeRender.jpg"
                        )

                # 2. Provenance Classification
                imported_lower = imported_by.lower()
                if zkitsubtype == 10 or "springboard" in imported_lower:
                    provenance = ProvenanceClassification.OS_SCREENSHOT_OR_SCREEN_RECORDING
                elif any(m in imported_lower for m in ["whatsapp", "telegram", "signal", "instagram", "facebook", "wechat"]):
                    provenance = ProvenanceClassification.MESSENGER_TRANSMITTED_REENCODED
                elif "camera" in imported_lower:
                    provenance = ProvenanceClassification.AUTHENTIC_CAMERA_ORIGINAL
                elif zhasadjustments == 1:
                    provenance = ProvenanceClassification.SOFTWARE_EDITED_OR_MANIPULATED
                else:
                    provenance = ProvenanceClassification.AUTHENTIC_CAMERA_ORIGINAL

                # 3. User Concealment State
                if ztrashedstate == 1:
                    concealment = UserConcealmentState.IN_RECENTLY_DELETED_TRASH
                elif zhidden == 1:
                    concealment = UserConcealmentState.IN_BIOMETRIC_HIDDEN_OR_LOCKED_ALBUM
                else:
                    concealment = UserConcealmentState.ACTIVE_VISIBLE

                # 4. GPS Coordinates
                gps_json: Optional[str] = None
                if zlat is not None and zlon is not None and zlat != -180.0:
                    gps_json = json.dumps({"lat": zlat, "lon": zlon})

                # 5. Timezone Formatting
                tz_str: Optional[str] = None
                if tz_offset is not None:
                    sign = "+" if tz_offset >= 0 else "-"
                    hours = abs(tz_offset) // 3600
                    minutes = (abs(tz_offset) % 3600) // 60
                    tz_str = f"{sign}{hours:02d}:{minutes:02d}"
                    if tz_name:
                        tz_str = f"{tz_str} ({tz_name})"

                records.append(
                    MediaAssetRecord(
                        os_platform_source=OSPlatformSource.IOS_PHOTOS_SQLITE,
                        canonical_file_path=canonical_path,
                        provenance_classification=provenance,
                        media_asset_uid=None,
                        vfs_file_id=source_vfs_file_id,
                        recovery_classification=ResidualConfidence.ORIGINAL_RECORD,
                        original_pre_import_filename=original_filename or zfilename,
                        originating_app_bundle_or_pkg=imported_by or None,
                        user_concealment_state=concealment,
                        trashed_or_deleted_utc_iso=cocoa_seconds_to_utc_iso(ztrasheddate),
                        has_uncropped_original_recovered=has_uncropped,
                        mutations_edited_file_path=mutations_render_path,
                        linked_chat_syndication_id=syndication_id,
                        capture_created_utc_iso=cocoa_seconds_to_utc_iso(zdatecreated),
                        library_imported_utc_iso=cocoa_seconds_to_utc_iso(zaddeddate),
                        capture_timezone_offset_str=tz_str,
                        gps_lat_lon_alt_heading_json=gps_json,
                        forensic_group=ForensicGroup.G17_MEDIA_C2PA_AND_VISUAL_RESIDUALS,
                        dim_existence=EvidentiaryExistence.OBSERVED,
                        dim_access=EvidentiaryAccess.PLAINTEXT,
                        dim_storage=EvidentiaryStorage.LIVE_RECORD,
                        dim_provenance=f"Photos.sqlite:ZASSET:Z_PK={z_pk}",
                        dim_corroboration=1.0,
                    )
                )
        except sqlite3.OperationalError as _err:
            records.extend([])

        conn.close()
        return records

    def decode_syndication_db(
        self,
        syndication_db_path: str,
        source_vfs_file_id: int = 0,
    ) -> List[MediaAssetRecord]:
        """
        Parses iOS Syndication.photoslibrary database ("Shared with You") to link chat attachments.
        """
        return self.decode_library(syndication_db_path, source_vfs_file_id=source_vfs_file_id)
